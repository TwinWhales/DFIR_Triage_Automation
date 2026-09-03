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
from casepaths import FIXTURES

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPINGS_DIR = REPO_ROOT / "mappings"
PARSED = FIXTURES / "04_parsed"


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


def _sysmon(event_id, **fields):
    return {
        "ref": f"SYSMON#{event_id}",
        "artifact": "evtx:Sysmon",
        "record_num": event_id,
        "offset": "0x3000",
        "event_id": event_id,
        "timestamp": "2026-08-25T09:12:00Z",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "KIOSK01",
        "fields": fields,
    }


def _channel(artifact, ref_prefix, event_id, **fields):
    return {
        "ref": f"{ref_prefix}#{event_id}",
        "artifact": artifact,
        "record_num": event_id,
        "offset": "0x4000",
        "event_id": event_id,
        "timestamp": "2026-08-25T09:12:00Z",
        "channel": artifact,
        "computer": "KIOSK01",
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


def test_a_missing_timestamp_key_is_flagged_the_same_as_a_zero_one():
    """mft.py는 FILETIME 0을 null이 아니라 키 생략으로 낸다(스키마가 null을

    막는다 — 실물 이미지에서 실측). ``record.get()``을 쓰는 이유가
    이것이다 — 키가 없는 것과 값이 None인 것을 같게 다뤄야 신호가
    사라지지 않는다.
    """
    record = _mft()
    del record["si_btime"]
    assert "zero_timestamp" in flagging.apply(record)["flags"]


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


def _an_event_id_no_rule_mentions() -> int:
    """어느 룰에도 안 적힌 event_id 를 **골라서** 돌려준다.

    예전에는 여기에 숫자를 박아 뒀는데 두 번 깨졌다. 4624 를 쓰다
    ``logon_success`` 가 생기면서, 4634 를 쓰다 ``session_state_changed``
    가 생기면서(2026-08-25). 어휘가 늘 때마다 "관계없는 이벤트"의 후보가
    줄어드는 것은 정상이므로, 박아 두지 말고 그때그때 고른다.
    """
    vocab = yaml.safe_load((MAPPINGS_DIR / "_flags.yaml").read_text(encoding="utf-8"))["flags"]
    used = {
        value
        for spec in vocab.values()
        for clause in (spec.get("rule") or {}).get("when", [])
        if clause.get("match") == "event_id"
        for value in clause["values"]
    }
    return next(candidate for candidate in range(1, 100000) if candidate not in used)


def test_unrelated_event_gets_no_flag():
    """어느 룰도 언급하지 않는 이벤트에는 아무것도 안 붙는다.

    플래그가 필터인 이상, "안 붙어야 할 때 안 붙는가"가 "붙어야 할 때
    붙는가"만큼 중요하다.
    """
    event_id = _an_event_id_no_rule_mentions()
    assert flagging.apply(_evtx(event_id, TargetUserName="Administrators"))["flags"] == []


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



# ============================================ K-001 키오스크 채널의 flags
#
# 채널만 등록하고 여기를 빠뜨리면 게이트 4에서 조용히 막힌다 — 03단계는
# "봤다"고 적고 04단계는 파싱까지 하는데 모델에만 한 건도 안 간다.
# 그래서 "붙는가"와 "안 붙어야 할 때 안 붙는가"를 같은 비중으로 본다.


def test_a_shell_started_from_the_order_ui_is_flagged():
    """K-001 Stage 3의 결정적 신호. 주문 UI가 셸을 자식으로 만든다."""
    record = _sysmon(1, Image=r"C:\Windows\System32\cmd.exe",
                     ParentImage=r"C:\kiosk\order.exe")
    assert "shell_spawned" in flagging.apply(record)["flags"]


def test_an_ordinary_process_creation_is_not_flagged():
    """**EID 1 전체에 붙으면 필터가 일을 안 한다.**

    프로세스 생성은 이 장비에서 가장 흔한 이벤트다. 정상 서비스가 뜨는
    것까지 후보로 올리면 05단계 쿼터를 혼자 태운다.

    예전에는 부모를 ``explorer.exe`` 로 썼는데, 잠긴 키오스크에서 셸이
    주문 UI 로 대체된다는 점을 근거로 ``unexpected_parent_process`` 가
    생기면서(2026-08-25) 그것이 더는 "평범한" 부모가 아니게 됐다.
    """
    record = _sysmon(
        1,
        Image=r"C:\Windows\System32\svchost.exe",
        ParentImage=r"C:\Windows\System32\services.exe",
    )
    assert flagging.apply(record)["flags"] == []


def test_the_shell_list_matches_on_the_path_separator():
    """구분자 없이 이름만 비교하면 이름이 겹치는 프로그램이 함께 걸린다."""
    assert "shell_spawned" not in flagging.apply(
        _sysmon(1, Image=r"C:\tools\evilcmd.exe"))["flags"]
    assert "shell_spawned" in flagging.apply(
        _sysmon(1, Image=r"D:\portable\CMD.EXE"))["flags"]


def test_a_sysmon_network_connection_is_flagged():
    assert "network_connection" in flagging.apply(_sysmon(3))["flags"]


@pytest.mark.parametrize(
    ("artifact", "prefix", "event_id"),
    [
        ("evtx:DriverFrameworks", "EVTX-DRV", 2003),
        ("evtx:KernelPnP", "EVTX-PNP", 410),
    ],
)
def test_device_events_share_one_flag(artifact, prefix, event_id):
    # 채널 둘이 같은 사실을 다르게 남긴다. 어휘를 나누면 05단계가
    # 한쪽을 놓친다.
    record = _channel(artifact, prefix, event_id)
    assert "device_connected" in flagging.apply(record)["flags"]


@pytest.mark.parametrize(
    ("artifact", "prefix"),
    [
        ("evtx:AssignedAccess", "EVTX-AAOP"),
        ("evtx:AssignedAccessAdmin", "EVTX-AAADM"),
        ("evtx:AssignedAccessBroker", "EVTX-AABRK"),
    ],
)
def test_every_assigned_access_record_is_flagged(artifact, prefix):
    """세 채널은 event_id 로 좁히지 않는다.

    로그가 작고, 여기 남는 것 자체가 키오스크 구성·이탈과 관련된
    사건이다. 전 레코드에 붙는 플래그는 필터 역할을 못 한다는 원칙의
    의도적 예외이며, 근거는 _flags.yaml 의 note 에 있다.
    """
    assert "kiosk_restriction_event" in flagging.apply(_channel(artifact, prefix, 4005))["flags"]


@pytest.mark.parametrize(
    ("artifact", "prefix", "event_id"),
    [("evtx:RDPConnection", "EVTX-RDPCM", 1149), ("evtx:RDPSession", "EVTX-RDPLSM", 21)],
)
def test_remote_session_events_share_one_flag(artifact, prefix, event_id):
    assert "remote_session" in flagging.apply(_channel(artifact, prefix, event_id))["flags"]


def test_an_application_error_is_flagged_but_an_info_event_is_not():
    """Application 로그는 크다(실측 8,257건). 좁히지 않으면 필터가 죽는다."""
    assert "app_crash" in flagging.apply(_channel("evtx:Application", "EVTX-APP", 1000))["flags"]
    assert flagging.apply(_channel("evtx:Application", "EVTX-APP", 4))["flags"] == []


# ================================================== timestamp_truncated


def test_second_aligned_si_timestamps_are_flagged():
    """K-001 Stage 5의 두 번째 탐지 포인트.

    조작 도구가 초 단위로 값을 써 넣으면 100ns 자리가 0으로 정렬된다.
    """
    record = _mft(
        si_btime="2026-08-25T09:16:00.0000000Z",
        si_ctime="2026-08-25T09:16:00.0000000Z",
        si_mtime="2026-08-25T09:16:00.0000000Z",
        fn_btime="2026-08-25T09:16:00.0000000Z",
        fn_ctime="2026-08-25T09:16:00.0000000Z",
        fn_mtime="2026-08-25T09:16:00.0000000Z",
    )
    assert "timestamp_truncated" in flagging.apply(record)["flags"]


def test_a_normal_file_with_random_subseconds_is_not_flagged():
    """실물 170,946 레코드(Win7·Win10)에서 오탐 0건이었던 조건이다."""
    record = _mft(
        si_btime="2026-08-25T09:16:00.1234567Z",
        si_ctime="2026-08-25T09:16:00.7654321Z",
        si_mtime="2026-08-25T09:16:00.9999999Z",
    )
    assert "timestamp_truncated" not in flagging.apply(record)["flags"]


def test_one_aligned_timestamp_is_not_enough():
    """하나만 보면 우연히 걸리는 것이 반드시 나온다.

    타임스탬프 하나가 우연히 .0000000 일 확률은 1/10^7 이지만 레코드가
    수십만 건이면 나온다. 조작 도구는 값을 한꺼번에 써 넣으므로 있는
    것이 다 정렬된다.
    """
    record = _mft(
        si_btime="2026-08-25T09:16:00.0000000Z",
        si_ctime="2026-08-25T09:16:00.4242424Z",
        si_mtime="2026-08-25T09:16:00.8888888Z",
    )
    assert "timestamp_truncated" not in flagging.apply(record)["flags"]


def test_a_timestamp_without_a_fraction_is_unknown_not_zero():
    """소수부가 없는 표기는 "서브초가 0"이 아니라 "모른다"다.

    우리 $MFT 파서는 항상 100ns 일곱 자리를 쓴다. 없는 것을 0으로 읽으면
    다른 데서 온 레코드가 전부 걸린다 — 이 파일의 _mft() 헬퍼가 그
    표기를 쓰고 있어 처음 구현에서 실제로 오탐이 났다.
    """
    assert "timestamp_truncated" not in flagging.apply(_mft())["flags"]


def test_a_missing_si_field_does_not_count_as_aligned():
    # FILETIME 0 이면 파서가 키를 빼고 낸다. 그것을 "정렬됨"으로 읽으면
    # 접근 시각 갱신을 꺼 둔 시스템의 파일이 전부 걸린다.
    record = _mft(si_btime="2026-08-25T09:16:00.0000000Z")
    del record["si_ctime"], record["si_mtime"]
    assert "timestamp_truncated" not in flagging.apply(record)["flags"]

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


# ================================ 이름을 모르는 채로 맥락으로 가르는가
#
# shell_spawned 는 **이름**으로 건다. 공격자가 무엇을 실행할지는 모르므로
# 그것만으로는 K-001 Stage 2(USB 안의 비승인 실행파일)를 못 잡는다.
# 아래 둘이 그 반쪽을 맡는다 — 어디에 있나, 누가 실행시켰나.


def test_a_binary_run_straight_from_a_usb_drive_is_flagged():
    """K-001 Stage 1→2 의 주 경로. 이름을 몰라도 볼륨으로 걸린다."""
    record = _sysmon(1, Image=r"E:\banker.exe", ParentImage=r"C:\kiosk\order.exe")
    assert "execution_from_unusual_path" in flagging.apply(record)["flags"]


def test_a_binary_copied_to_a_writable_folder_is_flagged():
    """USB 에서 직접 실행하지 않고 로컬로 복사한 경우."""
    for image in (
        r"C:\Users\kiosk\AppData\Local\Temp\banker.exe",
        r"C:\Windows\Temp\banker.exe",
        r"C:\Users\Public\banker.exe",
    ):
        record = _sysmon(1, Image=image, ParentImage=r"C:\kiosk\order.exe")
        assert "execution_from_unusual_path" in flagging.apply(record)["flags"], image


def test_a_binary_in_a_normal_install_location_is_not_flagged():
    """정상 앱이 걸리면 필터가 일을 안 한다."""
    for image in (
        r"C:\Program Files\POS\pos.exe",
        r"C:\Windows\System32\svchost.exe",
        r"C:\kiosk\order.exe",
    ):
        record = _sysmon(1, Image=image, ParentImage=r"C:\Windows\System32\services.exe")
        assert flagging.apply(record)["flags"] == [], image


def test_the_path_fragments_carry_separators():
    """구분자 없이 조각만 쓰면 엉뚱한 데서 걸린다.

    ``temp`` 로 썼다면 ``C:\Program Files\Tempo\app.exe`` 가 걸린다.
    """
    record = _sysmon(1, Image=r"C:\Program Files\Tempo\app.exe",
                     ParentImage=r"C:\Windows\System32\services.exe")
    assert flagging.apply(record)["flags"] == []


def test_a_child_of_explorer_is_flagged_on_a_locked_kiosk():
    """잠긴 키오스크에서는 셸이 주문 UI 로 대체되어 explorer 가 부모가 되지 않는다.

    그래서 explorer 가 부모로 나오는 것 자체가 제한 환경을 벗어난 정황이다.
    **이 전제는 초기 접근 모델에 달려 있다**(설계서 §1.3) — 서드파티 키오스크
    SW 가 explorer 위에서 도는 구성이면 정상 부모가 될 수 있다.
    """
    record = _sysmon(1, Image=r"C:\kiosk\tool.exe", ParentImage=r"C:\Windows\explorer.exe")
    assert "unexpected_parent_process" in flagging.apply(record)["flags"]


def test_a_child_of_a_script_host_or_document_viewer_is_flagged():
    for parent in (r"C:\Windows\System32\wscript.exe", r"C:\Program Files\Adobe\AcroRd32.exe"):
        record = _sysmon(1, Image=r"C:\kiosk\tool.exe", ParentImage=parent)
        assert "unexpected_parent_process" in flagging.apply(record)["flags"], parent


def test_a_browser_spawning_itself_is_not_evidence_of_who_launched_it():
    """이 룰이 보는 것은 "누가 실행시켰나"다.

    브라우저가 탭·GPU 프로세스로 자기 자신을 여러 번 띄우는 것은 그 질문에
    아무 말도 하지 않으면서 부모 이름만 보는 룰에는 걸린다. 실측
    (`K-LIVE-0902-wide`, 2026-09-03)에서 258건 중 157건이 이것이었다.
    """
    edge = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    record = _sysmon(1, Image=edge, ParentImage=edge)

    assert "unexpected_parent_process" not in flagging.apply(record)["flags"]


def test_a_helper_inside_the_parents_own_install_tree_is_not_flagged():
    """같은 설치 트리 안의 도우미 프로세스. 실측에서 36건이었다.

    **이름이 아니라 관계로 본다.** Edge 를 아는 것이 아니라 "자식이 부모
    전용 디렉터리 하위인가"를 보므로, 다른 다중 프로세스 프로그램도 함께
    걸러진다.
    """
    record = _sysmon(
        1,
        Image=r"C:\Program Files\Microsoft\Edge\Application\130.0.1\identity_helper.exe",
        ParentImage=r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    )

    assert "unexpected_parent_process" not in flagging.apply(record)["flags"]


@pytest.mark.parametrize(
    "image",
    [
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\WindowsPowerShell1.0\powershell.exe",
        r"C:\Windows\System32\mmc.exe",
    ],
)
def test_a_shared_system_directory_is_not_a_parents_own_tree(image):
    """**이 검사가 없으면 신호를 지운다.**

    부모가 ``C:\Windows\explorer.exe`` 이면 ``System32`` 전체가 "부모
    디렉터리 하위"라, explorer → cmd.exe 가 같은 프로그램으로 묶인다.
    그것이 이 룰이 잡으라고 있는 바로 그것이다 — 실측에서 explorer → cmd
    아홉 건, → powershell 다섯 건, → mmc 네 건이 걸려 있었다.
    """
    record = _sysmon(1, Image=image, ParentImage=r"C:\Windows\explorer.exe")

    assert "unexpected_parent_process" in flagging.apply(record)["flags"]


def test_a_missing_image_field_does_not_silence_the_signal():
    """판단할 근거가 없을 때 신호를 지우면, 파서가 필드를 못 읽은 것이 곧
    탐지 누락이 된다. 모르면 좁히지 않는다."""
    record = _sysmon(1, ParentImage=r"C:\Windows\explorer.exe")

    assert "unexpected_parent_process" in flagging.apply(record)["flags"]


def test_the_three_sysmon_signals_do_not_collapse_into_one():
    """셋이 겹치지 않는 사실을 본다. 하나로 합치면 어느 쪽이 걸렸는지 모른다."""
    shell = _sysmon(1, Image=r"C:\Windows\System32\cmd.exe",
                    ParentImage=r"C:\kiosk\order.exe")
    usb = _sysmon(1, Image=r"E:\banker.exe", ParentImage=r"C:\kiosk\order.exe")
    parent = _sysmon(1, Image=r"C:\kiosk\tool.exe", ParentImage=r"C:\Windows\explorer.exe")

    assert flagging.apply(shell)["flags"] == ["shell_spawned"]
    assert flagging.apply(usb)["flags"] == ["execution_from_unusual_path"]
    assert flagging.apply(parent)["flags"] == ["unexpected_parent_process"]
