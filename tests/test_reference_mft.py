"""참조 $MFT 파서 테스트 (analyzeMFT 기반, 임시 구현).

자체 파서가 나오면 이 파일의 기대값이 **양쪽에 똑같이 적용됩니다.**
그때 `tools/compare_mft.py --reference` 로 두 구현을 맞춰 봅니다.

여기서 특히 고정하는 것은 **원본의 두 한계를 어댑터가 우회하는가**입니다.
fixup 미적용과 타임스탬프 float 정밀도 — 둘 다 조용히 틀리는 유형이라
테스트가 없으면 아무도 모릅니다.
"""

from __future__ import annotations

import datetime as dt
import io as _io
from pathlib import Path

import pytest

from src.common import schema
from src.stage04_parse import evidence, flagging
from src.stage04_parse.parsers import reference_mft
from src.stage04_parse.parsers.base import Scope
from tests.test_mft_parser import build_record

UTC = dt.timezone.utc
RECORD_SIZE = 1024


def build_mft(records: dict[int, dict], slots: int | None = None) -> bytes:
    """레코드 번호 = 파일 내 위치가 되도록 빈 슬롯을 채운 가짜 ``$MFT``.

    실제 ``$MFT``도 그렇습니다. 그래서 오프셋이 ``번호 × 레코드크기``로
    나옵니다.
    """
    total = slots if slots is not None else max(records) + 1
    blob = bytearray()
    for number in range(total):
        spec = records.get(number)
        blob += build_record(record_number=number, **spec) if spec else bytes(RECORD_SIZE)
    return bytes(blob)


#: 웹루트 아래 웹셸이 있는 최소 볼륨.
WEBSHELL_TREE = {
    5: {"name": ".", "parent_record": 5, "is_directory": True},
    6: {"name": "inetpub", "parent_record": 5, "is_directory": True},
    7: {"name": "wwwroot", "parent_record": 6, "is_directory": True},
    8: {"name": "upload", "parent_record": 7, "is_directory": True},
    9: {
        "name": "shell.aspx",
        "parent_record": 8,
        "si_times": {k: dt.datetime(2026, 7, 20, 3, 14, 22, tzinfo=UTC) for k in ("btime", "ctime", "mtime", "atime")},
        "fn_times": {k: dt.datetime(2026, 7, 21, 9, 2, 11, tzinfo=UTC) for k in ("btime", "ctime", "mtime")},
    },
    10: {"name": "notes.txt", "parent_record": 8},
}


@pytest.fixture
def parser():
    return reference_mft.ReferenceMftParser(volume_letter="C:")


def parse(parser, mft: bytes, scope=None) -> list[dict]:
    return list(parser.parse(_io.BytesIO(mft), Scope.from_selection(scope)))


# ================================================================ 기본


def test_the_parser_does_not_set_flags_itself(parser):
    # 룰을 한 곳(flagging.py)에 모아야 어휘가 갈라지지 않는다.
    # base.py 가 정한 계약이다.
    assert all("flags" not in record for record in parse(parser, build_mft(WEBSHELL_TREE)))


def test_records_validate_after_flagging(parser):
    # parse.py 는 항상 flagging 을 거쳐 쓴다. 스키마가 보는 것은 그 결과다.
    for record in flagging.apply_all(parse(parser, build_mft(WEBSHELL_TREE))):
        schema.validate(record, "parsed_record")


def test_full_path_is_rebuilt_through_the_parent_chain(parser):
    records = {r["record_num"]: r for r in parse(parser, build_mft(WEBSHELL_TREE))}
    assert records[9]["path"] == "C:\\inetpub\\wwwroot\\upload\\shell.aspx"


def test_offset_is_the_position_in_the_mft(parser):
    # 원본 바이트 위치를 남기는 것이 이 프로젝트의 핵심 주장이다.
    records = {r["record_num"]: r for r in parse(parser, build_mft(WEBSHELL_TREE))}
    assert records[9]["offset"] == f"0x{9 * RECORD_SIZE:X}"
    assert records[10]["offset"] == f"0x{10 * RECORD_SIZE:X}"


def test_unused_slots_are_skipped(parser):
    # 빈 슬롯이 레코드로 나오면 재현율 분모가 오염된다.
    records = parse(parser, build_mft(WEBSHELL_TREE, slots=40))
    assert {r["record_num"] for r in records} == {5, 6, 7, 8, 9, 10}


def test_the_volume_letter_is_configurable(parser):
    parser.volume_letter = "D:"
    records = {r["record_num"]: r for r in parse(parser, build_mft(WEBSHELL_TREE))}
    assert records[9]["path"].startswith("D:\\")


def test_a_non_seekable_stream_is_refused(parser):
    class Pipe:
        def seekable(self):
            return False

    with pytest.raises(Exception, match="되감을 수 있는"):
        list(parser.parse(Pipe(), Scope.from_selection(None)))


# =============================================== 원본의 한계를 우회하는가


def test_fixups_are_applied_before_handing_bytes_over(parser):
    # analyzeMFT는 업데이트 시퀀스를 읽기만 하고 되돌리지 않는다.
    # 우회하지 않으면 섹터 경계(오프셋 510, 1022)의 2바이트가 깨진 채
    # 파싱된다. 레코드 대부분은 멀쩡해서 원인을 찾기 어렵다.
    long_name = "a" * 200 + ".aspx"
    tree = dict(WEBSHELL_TREE)
    tree[11] = {"name": long_name, "parent_record": 8}

    records = {r["record_num"]: r for r in parse(parser, build_mft(tree))}
    assert records[11]["path"].endswith(long_name)


def test_timestamp_microseconds_survive(parser):
    # WindowsTime.get_unix_time()은 float 나눗셈이라 마이크로초가 틀어진다.
    # 어댑터가 low/high에서 정수로 다시 계산한다.
    moment = dt.datetime(2026, 7, 20, 3, 14, 22, 123456, tzinfo=UTC)
    tree = dict(WEBSHELL_TREE)
    tree[9] = {**WEBSHELL_TREE[9], "si_times": {"btime": moment, "ctime": moment, "mtime": moment, "atime": moment}}

    records = {r["record_num"]: r for r in parse(parser, build_mft(tree))}
    assert records[9]["si_btime"].startswith("2026-07-20T03:14:22.123456")


def test_zeroed_timestamps_become_null_not_1601(parser):
    tree = dict(WEBSHELL_TREE)
    tree[9] = {**WEBSHELL_TREE[9], "si_times": {"btime": dt.datetime(1601, 1, 1, tzinfo=UTC)}}
    records = {r["record_num"]: r for r in parse(parser, build_mft(tree))}
    assert records[9]["si_btime"] is None


# ==================================================== scope 를 지키는가


def test_scope_narrows_by_path_and_extension(parser):
    scope = {"path_prefix": ["C:\\inetpub\\wwwroot"], "extensions": [".aspx"]}
    records = parse(parser, build_mft(WEBSHELL_TREE), scope)
    assert {r["record_num"] for r in records} == {9}


def test_a_directory_outside_the_prefix_is_dropped(parser):
    tree = dict(WEBSHELL_TREE)
    tree[11] = {"name": "elsewhere.aspx", "parent_record": 5}
    scope = {"path_prefix": ["C:\\inetpub\\wwwroot"], "extensions": [".aspx"]}
    assert {r["record_num"] for r in parse(parser, build_mft(tree), scope)} == {9}


def test_an_empty_scope_takes_everything(parser):
    assert len(parse(parser, build_mft(WEBSHELL_TREE), {})) == 6


# ================================================= 플래그가 붙는가


def test_the_webshell_is_flagged_from_real_bytes(parser):
    # $SI가 $FN보다 이르다 — 타임스탬프 조작 정황. 파싱부터 판정까지
    # 실제 바이트에서 나오는지 확인한다.
    records = list(flagging.apply_all(parse(parser, build_mft(WEBSHELL_TREE))))
    by_number = {r["record_num"]: r for r in records}
    assert "timestamp_mismatch" in by_number[9]["flags"]
    assert by_number[10]["flags"] == []


def test_records_outside_the_window_are_marked_not_dropped(parser):
    # 시간 추론이 틀렸을 때 되짚으려면 레코드가 남아 있어야 한다.
    old = dt.datetime(2020, 1, 1, tzinfo=UTC)
    tree = dict(WEBSHELL_TREE)
    tree[10] = {"name": "old.aspx", "parent_record": 8,
                "si_times": {k: old for k in ("btime", "ctime", "mtime", "atime")}}
    scope_dict = {"time_range": {"start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z"}}
    scope = Scope.from_selection(scope_dict)

    records = list(flagging.apply_all(parse(parser, build_mft(tree), scope_dict), scope))
    by_number = {r["record_num"]: r for r in records}
    assert "outside_time_range" in by_number[10]["flags"]


# ==================================================== 고아 레코드


def test_an_orphan_record_still_comes_out(parser):
    # 부모가 재할당된 삭제 파일. 경로가 없다고 버리면 삭제 흔적을
    # 통째로 놓친다.
    tree = dict(WEBSHELL_TREE)
    tree[12] = {"name": "deleted.aspx", "parent_record": 9999, "in_use": False}

    records = {r["record_num"]: r for r in parse(parser, build_mft(tree))}
    assert 12 in records
    assert records[12]["path"].endswith("deleted.aspx")
    assert records[12]["allocated"] is False


# ================================================== 볼륨 문자 유추


@pytest.mark.parametrize(
    "path,expected",
    [("/mnt/kape/C", "C:"), ("/mnt/kape/D%3A", "D:"), ("/mnt/kape/E_", "E:")],
)
def test_volume_letter_is_inferred_from_the_evidence_path(path, expected):
    assert evidence.volume_letter(path) == expected


def test_an_unrecognisable_path_falls_back_to_c(tmp_path):
    # 틀려도 경로 접두어 비교에서 결과가 비어 나오므로 드러난다.
    assert evidence.volume_letter(tmp_path / "extracted_artifacts") == "C:"


# ============================================ 두 구현 대조 하네스


def test_comparing_a_parser_against_itself_passes(tmp_path, parser):
    from src.common import io
    from tools import compare_mft

    records = parse(parser, build_mft(WEBSHELL_TREE))
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    io.write_jsonl(a, records)
    io.write_jsonl(b, records)

    report = compare_mft.compare(compare_mft.load_ours(a), compare_mft.load_ours(b), full=True)
    assert report.passed(), report.summary()


def test_a_disagreeing_implementation_is_caught(tmp_path, parser):
    from src.common import io
    from tools import compare_mft

    records = parse(parser, build_mft(WEBSHELL_TREE))
    wrong = [dict(r) for r in records]
    wrong[0]["si_btime"] = "2020-01-01T00:00:00Z"

    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    io.write_jsonl(a, records)
    io.write_jsonl(b, wrong)

    report = compare_mft.compare(compare_mft.load_ours(a), compare_mft.load_ours(b))
    assert not report.passed()
    assert report.mismatches[0].field == "si_btime"


# ================================================== 등록과 격리


def test_the_reference_parser_is_registered_separately():
    from src.stage04_parse import parsers

    # 자체 구현으로는 아직 아무것도 없고, 참조로는 $MFT가 있다.
    assert parsers.get("$MFT", "native") is None
    assert parsers.get("$MFT", "reference") is not None


def test_an_unknown_implementation_is_refused():
    from src.stage04_parse import parsers

    with pytest.raises(ValueError, match="알 수 없는 구현"):
        parsers.get("$MFT", "vibes")


def test_vendored_code_keeps_its_licence():
    # MIT의 의무다. 지우면 안 된다.
    root = Path(__file__).resolve().parents[1] / "third_party/analyzeMFT"
    licence = (root / "LICENSE").read_text(encoding="utf-8")
    assert "MIT" in licence
    assert "Copyright" in licence
    assert (root / "NOTICE.md").is_file()
