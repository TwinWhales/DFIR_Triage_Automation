"""RecentFileCache 파서 테스트 — Windows 7의 실행 흔적.

온디스크 구조가 전부 우리 구현이라(``structs/recentfilecache_record.py``)
프리패치 테스트처럼 **구조 읽기까지 여기서 고정합니다.** 바이너리 픽스처는
두지 않고 아래 ``build_bcf``가 합성합니다.

**이 파일이 특히 중요한 이유가 있습니다.** 이 아티팩트는 Windows 7 실물로
대조한 적이 없습니다(저장소에 Win7 이미지가 없습니다). 즉 "명세가 맞다"는
증명이 없는 상태이고, 그래서 여기서 고정하는 것의 절반은 **어긋났을 때
그럴듯한 값을 내지 않고 거부하는가**입니다.

- 시그니처가 다르면 파일 전체를 거부하고 실제로 본 바이트를 말한다
- 길이 필드의 단위를 잘못 잡으면(문자 수 ↔ 바이트) 종결자에서 걸린다
- 중간에서 어긋나면 **거기까지 낸 것은 유지하고** 남은 바이트를 센다

Win7 실물이 들어오면 ``RecentFileCacheParser``(Eric Zimmerman)와 대조하고
``docs/artifact-notes.md``에 기록해야 합니다. 그 전까지 이 테스트가
고정하는 것은 "우리가 정한 구조대로 읽는다"이지 "그 구조가 맞다"가
아닙니다.
"""

from __future__ import annotations

import io as _io
import struct
from pathlib import Path

import pytest

from src.common import refs, schema
from src.stage04_parse import flagging
from src.stage04_parse.parsers import recentfilecache as rfc_parser
from src.stage04_parse.parsers.base import Scope
from src.stage04_parse.structs import recentfilecache_record as rfc

EMPTY = Scope()

CMD = "C:\\Windows\\System32\\cmd.exe"
EVIL = "C:\\Users\\Public\\banker.exe"


def build_bcf(paths: "list[str] | None" = None, *, signature: bytes = rfc.SIGNATURE) -> bytes:
    """``RecentFileCache.bcf`` 하나를 합성한다.

    헤더 20바이트(시그니처 + 미상 16바이트) 뒤에 항목이 이어 붙습니다.
    항목은 ``길이(문자 수) + UTF-16LE 경로 + 0x0000``입니다.
    """
    paths = [CMD, EVIL] if paths is None else paths
    out = bytearray(signature + b"\x00" * (rfc.HEADER_SIZE - len(signature)))
    for path in paths:
        out += struct.pack("<I", len(path))
        out += path.encode("utf-16-le")
        out += b"\x00\x00"
    return bytes(out)


def run(parser: rfc_parser.RecentFileCacheParser, data: bytes, scope: Scope = EMPTY):
    parser.source_path = Path("RecentFileCache.bcf")
    return list(parser.parse(_io.BytesIO(data), scope))


@pytest.fixture
def parser():
    return rfc_parser.RecentFileCacheParser()


# ============================================================ 기본 규약


def test_each_entry_becomes_one_record(parser):
    records = run(parser, build_bcf())

    assert [r["path"] for r in records] == [CMD, EVIL]
    assert parser.stats["records"] == 2
    assert parser.stats["parse_errors"] == 0


def test_the_ref_is_the_entry_offset_in_decimal(parser):
    records = run(parser, build_bcf())

    # 첫 항목은 헤더 바로 뒤에서 시작한다.
    assert records[0]["record_num"] == rfc.HEADER_SIZE
    assert records[0]["ref"] == f"RFCACHE#{rfc.HEADER_SIZE}"
    assert records[0]["offset"] == f"0x{rfc.HEADER_SIZE:X}"
    assert refs.parse_ref(records[0]["ref"]).artifact == "recentfilecache"

    # 두 번째는 첫 항목의 길이만큼 뒤다. 4(길이) + 경로*2 + 2(종결자).
    second = rfc.HEADER_SIZE + 4 + len(CMD) * 2 + 2
    assert records[1]["record_num"] == second


def test_the_path_keeps_the_case_and_separators_on_disk(parser):
    # 비교는 normalize_path 가 양쪽에 적용한다. 여기서 접으면 원본과 다른
    # 값을 기록하게 되고, 06단계가 인용문을 원본과 대조할 수 없다.
    record = run(parser, build_bcf([CMD]))[0]
    assert record["path"] == "C:\\Windows\\System32\\cmd.exe"
    assert record["name"] == "cmd.exe"


def test_there_is_no_timestamp(parser):
    """항목에 시각이 없으므로 레코드에도 없다.

    파일 수정 시각을 레코드마다 복사해 넣으면 "이 프로그램이 그때
    실행됐다"로 읽히는데, 그것은 파일 전체가 마지막으로 갱신된 시각이지
    이 항목의 시각이 아니다.
    """
    assert all("timestamp" not in r for r in run(parser, build_bcf()))


def test_records_validate_against_the_schema(parser):
    for record in flagging.apply_all(iter(run(parser, build_bcf())), EMPTY):
        schema.validate(record, "parsed_record")


def test_a_non_ascii_path_survives(parser):
    korean = "C:\\사용자\\바탕화면\\악성.exe"
    assert run(parser, build_bcf([korean]))[0]["path"] == korean


# ==================================================================== 범위


def test_out_of_scope_entries_are_not_emitted(parser):
    # 04단계가 만드는 것과 같은 경로로 Scope 를 만든다. from_selection 이
    # 접두어를 정규화하므로, 직접 생성자를 부르면 대소문자가 그대로 남아
    # 매칭이 조용히 실패한다.
    scope = Scope.from_selection({"path_prefix": ["C:\\Users\\Public"]})
    records = run(parser, build_bcf(), scope)

    assert [r["path"] for r in records] == [EVIL]
    assert parser.stats["out_of_scope"] == 1


def test_an_extension_filter_applies(parser):
    scope = Scope.from_selection({"extensions": [".dll"]})
    assert run(parser, build_bcf(), scope) == []
    assert parser.stats["out_of_scope"] == 2


# ============================================ 어긋나면 거부한다


def test_a_wrong_signature_refuses_the_whole_file(parser):
    """헤더가 다르면 파일 전체를 거부한다.

    **이 구조는 실물로 대조한 적이 없다.** 시그니처가 틀렸다면 모든 실물
    파일이 여기서 거부되는데, 그 편이 엉뚱한 자리를 경로로 읽어 보고서에
    싣는 것보다 낫다. 그래서 메시지가 실제로 본 바이트를 말해야 한다 —
    한 줄 고치면 되는 일임이 드러나야 하기 때문이다.
    """
    with pytest.raises(ValueError) as e:
        run(parser, build_bcf(signature=b"\xde\xad\xbe\xef"))

    assert "deadbeef" in str(e.value)
    assert rfc.SIGNATURE.hex() in str(e.value)


def test_an_empty_file_is_refused(parser):
    with pytest.raises(ValueError):
        run(parser, b"")


def test_a_truncated_header_is_refused(parser):
    with pytest.raises(ValueError):
        run(parser, rfc.SIGNATURE + b"\x00\x00")


def test_a_length_in_bytes_instead_of_characters_is_caught(parser):
    """길이 필드의 단위를 잘못 잡으면 종결자에서 걸린다.

    이 아티팩트에서 가장 조용히 틀릴 수 있는 자리다. 문자 수를 바이트로
    읽으면 경로가 정확히 절반에서 잘리는데, UTF-16LE 의 앞 절반은 여전히
    읽을 수 있는 문자열이라 **그럴듯한 경로가 나온다.** 종결자 검사가
    그것을 막는 유일한 방벽이다.
    """
    data = bytearray(build_bcf([CMD]))
    struct.pack_into("<I", data, rfc.HEADER_SIZE, len(CMD) * 2)  # 문자 수 대신 바이트

    records = run(parser, bytes(data))

    assert records == []
    assert parser.stats["parse_errors"] == 1


def test_a_zero_length_entry_stops_the_walk(parser):
    data = bytearray(build_bcf([CMD]))
    struct.pack_into("<I", data, rfc.HEADER_SIZE, 0)

    assert run(parser, bytes(data)) == []
    assert parser.stats["parse_errors"] == 1


def test_a_length_past_the_end_stops_the_walk(parser):
    data = bytearray(build_bcf([CMD]))
    struct.pack_into("<I", data, rfc.HEADER_SIZE, 9999)

    assert run(parser, bytes(data)) == []
    assert parser.stats["parse_errors"] == 1


def test_entries_before_the_break_are_kept(parser):
    """중간에서 어긋나도 앞의 것은 증거다.

    그리고 **못 읽은 바이트 수를 센다.** 조용히 버리면 "여기서 끝났다"와
    "여기서부터 못 읽었다"가 구별되지 않고, 그 구별이 이 프로젝트의
    존재 이유다.
    """
    good = build_bcf([CMD])
    data = bytearray(good + struct.pack("<I", 9999) + b"\x00" * 32)

    records = run(parser, bytes(data))

    assert [r["path"] for r in records] == [CMD]
    assert parser.stats["parse_errors"] == 1
    assert parser.stats["unreadable_bytes"] == len(data) - len(good)


def test_trailing_bytes_after_the_last_entry_are_counted(parser):
    """항목이 될 수 없는 꼬리는 패딩이고, 될 수 있는 꼬리는 못 읽은 것이다."""
    padded = build_bcf([CMD]) + b"\x00\x00"  # 길이 필드보다 짧다
    run(parser, padded)
    assert parser.stats["unreadable_bytes"] == 0


def test_a_null_inside_a_path_skips_only_that_entry(parser):
    data = bytearray(build_bcf([CMD, EVIL]))
    # 첫 경로 한가운데를 널로 덮는다. 길이 필드는 그대로라 다음 항목의
    # 자리는 여전히 알 수 있다.
    struct.pack_into("<H", data, rfc.HEADER_SIZE + 4 + 6, 0)

    records = run(parser, bytes(data))

    assert [r["path"] for r in records] == [EVIL]
    assert parser.stats["parse_errors"] == 0


# ================================================================== 등록


def test_the_parser_is_registered_under_both_implementations():
    from src.stage04_parse import parsers

    assert "recentfilecache" in parsers.registered("native")
    assert "recentfilecache" in parsers.registered("reference")


def test_the_artifact_has_an_output_filename():
    # 등록소와 별개 테이블이다. 빠뜨리면 증거를 열기도 전에 KeyError 로 죽는다.
    from src.stage04_parse.parse import OUTPUT_FILENAMES

    assert OUTPUT_FILENAMES["recentfilecache"] == "recentfilecache.jsonl"
