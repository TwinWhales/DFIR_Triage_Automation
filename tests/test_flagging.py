"""04단계 flags 룰 테스트.

플래그는 **LLM에 전달할 레코드를 추리는 필터**입니다. 여기서 안 붙으면
그 레코드는 사실상 없는 것이 되고, 놓친 결과가 "선별 재현율 저하"로
잘못 집계됩니다. 반대로 남발하면 필터가 일을 안 하게 됩니다.

그래서 "붙어야 할 때 붙는가"와 "안 붙어야 할 때 안 붙는가"를 같은 비중으로
확인합니다.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.common import io, schema
from src.stage04_parse import flagging
from src.stage04_parse.parsers.base import Scope

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK = REPO_ROOT / "benchmark/datasets/C-001-webshell/mock"
PARSED = MOCK / "04_parsed"


def _mft(**fields):
    record = {
        "ref": "MFT#1",
        "artifact": "$MFT",
        "record_num": 1,
        "offset": "0x1000",
        "path": "C:\\x.aspx",
        "allocated": True,
        "is_directory": False,
        "size": 10,
        "si_btime": "2026-07-20T03:00:00Z",
        "si_ctime": "2026-07-20T03:00:00Z",
        "si_mtime": "2026-07-20T03:00:00Z",
        "si_atime": "2026-07-20T03:00:00Z",
        "fn_btime": "2026-07-20T03:00:00Z",
        "fn_ctime": "2026-07-20T03:00:00Z",
        "fn_mtime": "2026-07-20T03:00:00Z",
    }
    record.update(fields)
    return record


def _evtx(event_id, **fields):
    return {
        "ref": f"EVTX-SEC#{event_id}",
        "artifact": "evtx:Security",
        "record_num": event_id,
        "offset": "0x2000",
        "event_id": event_id,
        "timestamp": "2026-07-20T03:22:15Z",
        "channel": "Security",
        "computer": "WEB01",
        "fields": fields,
    }


# ==================================================== 목업 재현 (기준선)


@pytest.mark.parametrize("filename", ["mft.jsonl", "evtx_security.jsonl"])
def test_reproduces_the_flags_in_the_mock(filename):
    for record in io.read_jsonl(PARSED / filename):
        stripped = {k: v for k, v in record.items() if k != "flags"}
        assert flagging.apply(stripped)["flags"] == record["flags"], record["ref"]


# ================================================== timestamp_mismatch


def test_si_created_earlier_than_fn_is_a_mismatch():
    # 파일이 자기 이름 항목보다 먼저 존재할 수 없다. 조작 도구는 대개
    # $SI만 과거로 되돌리므로 이 형태가 남는다.
    record = _mft(si_btime="2026-07-20T03:00:00Z", fn_btime="2026-07-21T09:00:00Z")
    assert "timestamp_mismatch" in flagging.apply(record)["flags"]


def test_si_later_than_fn_is_not_a_mismatch():
    # 이름이 바뀐 파일은 정상적으로 $FN이 $SI보다 이르다. 단순 불일치로
    # 잡으면 rename된 파일이 전부 걸려 필터가 무의미해진다.
    record = _mft(si_ctime="2026-07-21T09:00:00Z", fn_ctime="2026-07-20T03:00:00Z")
    assert "timestamp_mismatch" not in flagging.apply(record)["flags"]


def test_identical_timestamps_are_not_a_mismatch():
    assert "timestamp_mismatch" not in flagging.apply(_mft())["flags"]


def test_a_copied_file_is_not_a_mismatch():
    # 실제 이미지에서 발견한 오탐 패턴. 파일을 복사하면 $SI의 ctime·mtime은
    # 원본에서 보존되고 $FN은 새 디렉터리 항목이 만들어진 시각이 된다.
    # 생성 시각만 같으면 조작이 아니다.
    #
    # 이 쌍까지 보던 초기 룰은 실제 이미지 154건 중 91건(59%)을 걸렀고
    # 전부 오탐이었다. 필터로 쓸 수 없는 비율이다.
    record = _mft(
        si_btime="2026-07-24T00:28:07Z", fn_btime="2026-07-24T00:28:07Z",
        si_ctime="2026-07-23T08:51:16Z", fn_ctime="2026-07-24T00:28:07Z",
        si_mtime="2026-07-23T08:51:16Z", fn_mtime="2026-07-24T00:28:07Z",
    )
    assert flagging.apply(record)["flags"] == []


def test_only_creation_times_drive_the_mismatch_rule():
    assert flagging.MISMATCH_PAIRS == (("si_btime", "fn_btime"),)


def test_si_and_fn_field_lists_line_up():
    # 짝이 어긋나면 엉뚱한 타임스탬프끼리 비교한다.
    assert len(flagging.SI_FIELDS) == len(flagging.FN_FIELDS)
    for si, fn in zip(flagging.SI_FIELDS, flagging.FN_FIELDS):
        assert si.removeprefix("si_") == fn.removeprefix("fn_")


# ============================================================= 그 외 MFT


def test_unallocated_record_is_deleted():
    assert "deleted" in flagging.apply(_mft(allocated=False))["flags"]


def test_allocated_record_is_not_deleted():
    assert "deleted" not in flagging.apply(_mft(allocated=True))["flags"]


@pytest.mark.parametrize("value", ["1601-01-01T00:00:00Z", "어제", ""])
def test_zeroed_or_unreadable_timestamp_is_flagged(value):
    # 이런 레코드를 버리지 않고 표시하는 이유는 그 이상함 자체가 증거이기
    # 때문이다. 조작 도구가 타임스탬프를 0으로 밀어 버린다.
    assert "zero_timestamp" in flagging.apply(_mft(si_btime=value))["flags"]


def test_normal_timestamps_are_not_zero_flagged():
    assert "zero_timestamp" not in flagging.apply(_mft())["flags"]


# ================================================================ EVTX


def test_account_creation_event_is_flagged():
    assert "account_created" in flagging.apply(_evtx(4720, TargetUserName="svc_backup"))["flags"]


@pytest.mark.parametrize("event_id", [4728, 4732])
def test_adding_to_a_privileged_group_is_flagged(event_id):
    record = _evtx(event_id, TargetUserName="Administrators", MemberName="svc_backup")
    assert "privileged_group_add" in flagging.apply(record)["flags"]


def test_adding_to_an_ordinary_group_is_not_flagged():
    record = _evtx(4732, TargetUserName="Users", MemberName="svc_backup")
    assert "privileged_group_add" not in flagging.apply(record)["flags"]


def test_group_name_matching_ignores_case():
    record = _evtx(4732, TargetUserName="ADMINISTRATORS")
    assert "privileged_group_add" in flagging.apply(record)["flags"]


def test_unrelated_event_gets_no_flag():
    # 4634(로그오프)는 어느 룰에도 걸리지 않는다. 4624 를 쓰면 안 된다 —
    # logon_success 가 생기면서 "관계없는 이벤트"가 아니게 됐다.
    assert flagging.apply(_evtx(4634, TargetUserName="Administrators"))["flags"] == []


def test_service_install_event_is_flagged():
    record = {**_evtx(7045), "artifact": "evtx:System"}
    assert "service_installed" in flagging.apply(record)["flags"]


def test_logon_events_are_flagged():
    # 4672 는 관리자 세션에서 4624 직후에 따라붙는다. 같은 이름으로 묶은
    # 이유가 여기 있다 — 나누면 한 로그온이 두 어휘로 갈라진다.
    for event_id in (4624, 4672):
        record = {**_evtx(event_id), "artifact": "evtx:Security"}
        assert "logon_success" in flagging.apply(record)["flags"], event_id


def test_failed_logon_is_a_separate_flag():
    record = {**_evtx(4625), "artifact": "evtx:Security"}
    flags = flagging.apply(record)["flags"]
    assert "logon_failed" in flags
    assert "logon_success" not in flags


def test_service_config_change_is_flagged():
    record = {**_evtx(7040), "artifact": "evtx:System"}
    flags = flagging.apply(record)["flags"]
    assert "service_config_changed" in flags
    # 7045(설치)와 뜻이 다르다. 섞이면 "언제 껐나"를 못 가린다.
    assert "service_installed" not in flags


def test_privileged_groups_come_from_the_mapping_file():
    declared = yaml.safe_load(
        (REPO_ROOT / "mappings/_flags.yaml").read_text(encoding="utf-8")
    )["privileged_groups"]
    loaded = flagging.privileged_groups()
    assert {name.lower() for name in declared} == set(loaded)


# ================================================== outside_time_range


def test_record_outside_the_selected_window_is_marked():
    scope = Scope.from_selection(
        {"time_range": {"start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z"}}
    )
    record = _mft(**{f: "2026-01-01T00:00:00Z" for f in ("si_btime", "si_ctime", "si_mtime", "si_atime")})
    assert "outside_time_range" in flagging.apply(record, scope)["flags"]


def test_record_inside_the_window_is_not_marked():
    scope = Scope.from_selection(
        {"time_range": {"start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z"}}
    )
    assert "outside_time_range" not in flagging.apply(_mft(), scope)["flags"]


def test_without_a_scope_the_flag_is_never_added():
    record = _mft(**{f: "2026-01-01T00:00:00Z" for f in ("si_btime", "si_ctime", "si_mtime", "si_atime")})
    assert "outside_time_range" not in flagging.apply(record)["flags"]


def test_one_timestamp_inside_the_window_is_enough():
    # 생성은 범위 밖인데 접근이 범위 안인 파일은 봐야 한다.
    scope = Scope.from_selection(
        {"time_range": {"start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z"}}
    )
    record = _mft(
        si_btime="2026-01-01T00:00:00Z",
        si_ctime="2026-01-01T00:00:00Z",
        si_mtime="2026-01-01T00:00:00Z",
        si_atime="2026-07-20T03:15:00Z",
        fn_btime="2026-01-01T00:00:00Z",
        fn_ctime="2026-01-01T00:00:00Z",
        fn_mtime="2026-01-01T00:00:00Z",
    )
    assert "outside_time_range" not in flagging.apply(record, scope)["flags"]


# ============================================================ 어휘 고정


def test_vocabulary_matches_the_schema():
    # 어휘의 원본은 mappings/_flags.yaml 이고 스키마 enum 은 그것의
    # 생성물이다. 어긋났다면 손으로 맞추지 말고 생성기를 돌린다.
    in_schema = schema.load_schema("parsed_record")["properties"]["flags"]["items"]["enum"]
    assert set(flagging.FLAGS) == set(in_schema), (
        "parsed_record 스키마의 enum 이 어휘와 어긋났다. tools/sync_flag_enum.py 를 돌린다."
    )


def test_an_unregistered_flag_is_refused():
    # 오타 하나가 record_filter를 통과해 05단계에 엉뚱한 레코드를 보낸다.
    record = _mft(flags=["looks_suspicious"])
    with pytest.raises(ValueError, match="미등록 플래그"):
        flagging.apply(record)


def test_parser_supplied_flags_are_kept():
    record = _mft(allocated=False, flags=["zero_timestamp"])
    flags = flagging.apply(record)["flags"]
    assert "zero_timestamp" in flags and "deleted" in flags


def test_flag_order_is_stable():
    # 같은 레코드가 항상 같은 JSON을 내야 재실행 결과를 비교할 수 있다.
    record = _mft(allocated=False, si_ctime="2026-07-20T03:00:00Z", fn_ctime="2026-07-21T09:00:00Z")
    flags = flagging.apply(record)["flags"]
    assert flags == [f for f in flagging.FLAGS if f in set(flags)]


def test_flags_land_at_the_end_of_the_record():
    # JSONL을 눈으로 훑을 때 줄 끝에 플래그가 오면 읽기 쉽다.
    assert list(flagging.apply(_mft()))[-1] == "flags"


def test_records_are_not_mutated_in_place():
    record = _mft(allocated=False)
    flagging.apply(record)
    assert "flags" not in record


def test_apply_all_streams_every_record():
    records = [_mft(ref=f"MFT#{i}", record_num=i) for i in range(3)]
    assert len(list(flagging.apply_all(records))) == 3
