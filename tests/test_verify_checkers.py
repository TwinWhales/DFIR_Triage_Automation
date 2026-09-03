"""06단계 검증 로직 테스트.

검증기는 두 방향으로 틀릴 수 있고 둘 다 위험하다.

- **너무 느슨하면** 환각이 통과해 도구의 신뢰성 근거가 사라진다.
- **너무 엄격하면** 정상 문장이 대량 기각되어 환각률이 표기 문제를 센다.

그래서 "걸러야 할 것을 거른다"와 "걸러선 안 될 것을 통과시킨다"를 같은
비중으로 확인한다.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.common import io
from src.stage06_verify import checkers, comparators, verify as verify_mod
from src.stage06_verify.verify import load_records, verify
from casepaths import FIXTURES, GOLDEN

PARSED = FIXTURES / "04_parsed"


@pytest.fixture(scope="module")
def records():
    return load_records(PARSED)


@pytest.fixture
def findings():
    return copy.deepcopy(io.read_json(FIXTURES / "05_findings.json"))


def _finding(**overrides):
    """claims 하나를 가진 최소 finding."""
    base = {
        "id": "F1",
        "statement": "테스트 문장",
        "refs": ["MFT#12345"],
        "claims": [{"ref": "MFT#12345", "field": "size", "value": 4821}],
        "technique": "T1505.003",
        "severity": "high",
    }
    base.update(overrides)
    return base


def _doc(*findings_, input_refs=("MFT#12345", "MFT#12346", "EVTX-SEC#40912", "EVTX-SEC#40915")):
    return {"case_id": "C-001", "input_refs": list(input_refs), "findings": list(findings_)}


# ============================================================ comparators


@pytest.mark.parametrize(
    "value",
    [
        "2026-07-20T03:14:22Z",
        "2026-07-20T03:14:22.1234567Z",  # NTFS 100ns, datetime 한계를 넘는다
        "2026-07-20T03:14:22.123Z",
        "2026-07-20T03:14:22",
        "2026-07-20 03:14:22",
    ],
)
def test_timestamp_formats_that_must_parse(value):
    assert comparators.parse_timestamp(value) is not None


@pytest.mark.parametrize("value", ["어제", "2026-07-20", "", None, 1234, "03:14:22"])
def test_non_timestamps_do_not_parse(value):
    assert comparators.parse_timestamp(value) is None


def test_offset_timezone_is_converted_not_ignored():
    utc = comparators.parse_timestamp("2026-07-20T03:14:22Z")
    kst = comparators.parse_timestamp("2026-07-20T12:14:22+09:00")
    assert utc == kst


def test_truncated_timestamp_passes_within_tolerance():
    # 이 규칙이 없으면 03:14:22 대 03:14:22.1234567Z 에서 대량 오탐이 난다.
    assert comparators.compare(
        "si_ctime", "2026-07-20T03:14:22Z", "2026-07-20T03:14:22.1234567Z", tolerance_seconds=1
    )


def test_tolerance_does_not_swallow_a_real_difference():
    assert not comparators.compare(
        "si_ctime", "2026-07-19T22:00:00Z", "2026-07-20T03:14:22.1234567Z", tolerance_seconds=1
    )


def test_zero_tolerance_still_ignores_sub_second_noise_only_when_asked():
    assert not comparators.compare(
        "si_ctime", "2026-07-20T03:14:22Z", "2026-07-20T03:14:22.5Z", tolerance_seconds=0
    )


def test_a_timestamp_never_matches_a_non_timestamp():
    assert not comparators.compare("si_ctime", "2026-07-20T03:14:22Z", "언젠가")


@pytest.mark.parametrize(
    "claimed,actual",
    [
        ("C:/inetpub/wwwroot/upload/shell.aspx", "C:\\inetpub\\wwwroot\\upload\\shell.aspx"),
        ("c:\\INETPUB\\wwwroot\\upload\\SHELL.aspx", "C:\\inetpub\\wwwroot\\upload\\shell.aspx"),
        ("C:\\inetpub\\wwwroot\\", "C:\\inetpub\\wwwroot"),
    ],
)
def test_paths_compare_case_insensitively_with_separators_normalised(claimed, actual):
    assert comparators.compare("path", claimed, actual)


def test_a_different_path_is_still_a_mismatch():
    assert not comparators.compare(
        "path", "C:\\inetpub\\wwwroot\\upload\\other.aspx",
        "C:\\inetpub\\wwwroot\\upload\\shell.aspx",
    )


@pytest.mark.parametrize(
    "field",
    ["Image", "ParentImage", "TargetFilename", "OriginalFileName",
     "ProcessName", "NewProcessName", "ImageLoaded", "fields.ParentImage"],
)
def test_sysmon_and_security_path_fields_are_compared_as_paths(field):
    """K-001 Stage 2·3 이 기대는 필드들. 여기서 이름이 빠지면 대소문자 하나로
    정상 문장이 기각되고 환각률이 표기 차이를 세게 된다."""
    assert comparators.is_path_field(field)
    assert comparators.compare(field, "c:\\windows\\system32\\cmd.exe",
                               "C:\\Windows\\System32\\cmd.exe")


@pytest.mark.parametrize(
    "field",
    ["Image", "ParentImage", "TargetFilename", "ProcessName"],
)
def test_widened_path_fields_did_not_go_soft(field):
    """이름을 늘린 것이 검증을 무르게 하지 않았는가. 경로가 실제로 다르면
    여전히 기각돼야 한다 — 이 확인이 없으면 위 테스트는 '전부 통과'만
    보장하는 셈이 된다."""
    assert not comparators.compare(field, "C:\\Windows\\System32\\cmd.exe",
                                   "C:\\Windows\\System32\\powershell.exe")
    assert not comparators.compare(field, "E:\\banker.exe", "C:\\banker.exe")


def test_registry_date_notation_is_absorbed():
    """Amcache `InstallDate` 는 하이브에 `RegSZ` 로, 미국식 표기로 적혀 있다.

    실측 이미지의 `InventoryApplication` 78건이 전부 그렇다. 이 프로젝트의
    다른 시각은 전부 ISO 8601 이라, 흡수하지 않으면 설치 시각을 인용한
    정상 문장이 **전량** 기각된다.
    """
    assert comparators.compare(
        "fields.InstallDate", "2017-03-20T03:53:52Z", "03/20/2017 03:53:52"
    )
    assert comparators.compare("InstallDate", "2017-03-20T00:00:00Z", "03/20/2017")


def test_the_date_rule_is_keyed_on_the_name_not_the_value():
    """값의 생김새로 판단하면 이 모듈이 처음부터 거부한 방식이 된다.

    같은 값이라도 이름이 허락하지 않으면 흡수하지 않는다 — 버전 문자열이나
    일련번호가 우연히 날짜처럼 보이는 자리에서 오작동한다.
    """
    assert not comparators.is_date_field("Publisher")
    assert not comparators.compare("Publisher", "2017-03-20T03:53:52Z", "03/20/2017 03:53:52")


def test_the_date_rule_did_not_go_soft():
    """흡수한 것은 **표기**이지 값이 아니다. 다른 날짜는 여전히 기각된다."""
    assert not comparators.compare(
        "fields.InstallDate", "2017-03-21T03:53:52Z", "03/20/2017 03:53:52"
    )
    # 하루 안이라도 시각이 다르면 기각이다. 정밀도 차이는 이 프로젝트의
    # 다른 시각 필드와 같은 규칙(tolerance_seconds)이 정하고, 이 변경이
    # 그것을 건드리지 않는다.
    assert not comparators.compare(
        "fields.InstallDate", "2017-03-20T00:00:00Z", "03/20/2017 03:53:52"
    )
    # ISO 가 먼저다. 모호한 표기를 미국식으로 재해석하지 않는다.
    assert comparators.compare(
        "fields.InstallDate", "2017-03-04T00:00:00Z", "2017-03-04T00:00:00Z"
    )


def test_command_line_is_not_a_path_field():
    """앞머리는 경로지만 뒤는 인자다. 경로 규칙으로 대소문자를 지우면
    인자의 실제 차이까지 같이 지워진다."""
    assert not comparators.is_path_field("CommandLine")
    assert not comparators.compare(
        "CommandLine", "cmd.exe /c WHOAMI", "cmd.exe /c whoami"
    )


def test_substring_does_not_count_as_a_match():
    # 허용하면 경로를 대충 쓴 문장이 전부 통과해 검증이 무의미해진다.
    assert not comparators.compare("path", "shell.aspx", "C:\\inetpub\\wwwroot\\shell.aspx")
    assert not comparators.compare("statement", "svc", "svc_backup")


def test_number_written_as_string_still_matches():
    assert comparators.compare("size", "4821", 4821)
    assert comparators.compare("size", 4821, "4821")
    assert not comparators.compare("size", "4822", 4821)


def test_true_does_not_match_one():
    # 파이썬에서 True == 1 이라 순서를 잘못 두면 allocated 주장이 통과한다.
    assert not comparators.compare("allocated", 1, True)
    assert not comparators.compare("allocated", True, 1)
    assert comparators.compare("allocated", True, True)
    assert comparators.compare("allocated", "true", True)


def test_claiming_one_flag_matches_the_flag_array():
    # 문장은 timestamp_mismatch 하나를 지목하는데 레코드는 배열을 들고 있다.
    assert comparators.compare("flags", "timestamp_mismatch", ["timestamp_mismatch"])
    assert not comparators.compare("flags", "deleted", ["timestamp_mismatch"])
    assert not comparators.compare("flags", "deleted", [])


def test_dotted_field_reaches_into_evtx_fields(records):
    record = records["EVTX-SEC#40912"]
    assert comparators.get_field(record, "fields.TargetUserName") == "svc_backup"


def test_missing_field_reports_where_it_broke(records):
    with pytest.raises(comparators.FieldMissing, match="fields.Nope"):
        comparators.get_field(records["EVTX-SEC#40912"], "fields.Nope")
    with pytest.raises(comparators.FieldMissing):
        comparators.get_field(records["MFT#12345"], "path.deeper")


# ------------------------------------------- fields. 접두어 (네 번째 관대함)
#
# 값이 최상위에 있는 아티팩트($MFT)와 fields 아래 있는 아티팩트(evtx·
# 레지스트리·프리패치)가 섞여 있어 모델이 양쪽으로 다 틀린다. 실측에서
# ref·필드명·값이 전부 맞는 문장이 표기 하나로 기각돼 환각률 100%가
# 나왔다(2026-08-24). 흡수하되 **검증이 물러지지 않아야** 한다.


def test_a_bare_name_finds_the_value_under_fields(records):
    record = records["EVTX-SEC#40912"]
    assert comparators.get_field(record, "TargetUserName") == "svc_backup"


def test_a_stray_fields_prefix_still_finds_a_top_level_value(records):
    """반대 방향. $MFT 는 path 를 최상위에 둔다."""
    record = records["MFT#12345"]
    assert comparators.get_field(record, "fields.path") == comparators.get_field(record, "path")


def test_the_top_level_wins_when_both_places_have_the_name():
    """원래 표기가 먼저 시도되므로 모호해질 수 없다."""
    record = {"ref": "X#1", "state": "top", "fields": {"state": "nested"}}
    assert comparators.get_field(record, "state") == "top"
    assert comparators.get_field(record, "fields.state") == "nested"


def test_an_invented_field_is_still_missing_in_both_notations(records):
    """흡수가 "못 찾으면 통과"로 새면 검증 자체가 무의미해진다."""
    for notation in ("Nope", "fields.Nope"):
        with pytest.raises(comparators.FieldMissing):
            comparators.get_field(records["EVTX-SEC#40912"], notation)


def test_the_break_point_is_reported_in_the_notation_the_model_used(records):
    """기각 사유가 모델이 쓰지도 않은 경로를 가리키면 되짚을 수 없다."""
    with pytest.raises(comparators.FieldMissing) as caught:
        comparators.get_field(records["EVTX-SEC#40912"], "Nope")
    assert str(caught.value) == "Nope"


def test_a_wrong_value_is_still_rejected_after_the_notation_is_absorbed(records):
    """표기를 흡수해도 값 대조는 그대로다 — value_mismatch 로 기각돼야 한다."""
    finding = _finding(
        claims=[{"ref": "EVTX-SEC#40912", "field": "TargetUserName", "value": "administrator"}]
    )
    rejected = verify(_doc(finding), records)["rejected"][0]
    assert rejected["reason"] == "value_mismatch"


def test_the_bare_notation_passes_end_to_end(records):
    finding = _finding(
        claims=[{"ref": "EVTX-SEC#40912", "field": "TargetUserName", "value": "svc_backup"}]
    )
    result = verify(_doc(finding), records)
    assert result["rejected"] == []
    assert result["stats"]["hallucination_rate"] == 0.0


# =============================================================== 판정 규칙


def test_all_claims_matching_passes(records):
    result = verify(_doc(_finding()), records)
    assert [p["id"] for p in result["passed"]] == ["F1"]
    assert result["passed"][0] == {"id": "F1", "checks": 1, "checks_passed": 1}


def test_one_wrong_claim_rejects_the_whole_statement(records):
    # 부분 통과는 없다. 하나라도 틀린 문장은 신뢰할 수 없다.
    finding = _finding(
        claims=[
            {"ref": "MFT#12345", "field": "size", "value": 4821},
            {"ref": "MFT#12345", "field": "path", "value": "C:\\wrong\\path.aspx"},
            {"ref": "MFT#12345", "field": "allocated", "value": True},
        ]
    )
    result = verify(_doc(finding), records)
    assert result["passed"] == []
    assert result["rejected"][0]["reason"] == "value_mismatch"
    assert result["stats"]["rejected"] == 1


def test_empty_claims_is_unverifiable_not_rejected(records):
    finding = _finding(refs=[], claims=[], technique=None, severity="info")
    result = verify(_doc(finding), records)
    assert result["unverifiable"] == [{"id": "F1", "reason": verify_mod.UNVERIFIABLE_REASON}]
    assert result["rejected"] == []


def test_a_fabricated_ref_beats_unverifiable(records):
    # claims가 비었어도 지어낸 근거를 달았다면 환각이다.
    finding = _finding(refs=["MFT#99999"], claims=[])
    result = verify(_doc(finding), records)
    assert result["unverifiable"] == []
    assert result["rejected"][0]["reason"] == "ref_not_found"


# --------------------------------------------------------- 체커별 동작


def test_nonexistent_record_is_ref_not_found(records):
    finding = _finding(refs=["MFT#99999"], claims=[{"ref": "MFT#99999", "field": "size", "value": 1}])
    result = verify(_doc(finding), records)
    assert result["rejected"][0]["reason"] == "ref_not_found"
    assert result["rejected"][0]["detail"]["ref"] == "MFT#99999"


def test_record_not_given_to_the_llm_is_ref_not_in_input(records):
    # MFT#12400은 파싱은 됐으나 input_refs에 없다.
    finding = _finding(refs=["MFT#12400"], claims=[])
    result = verify(_doc(finding), records)
    assert result["rejected"][0]["reason"] == "ref_not_in_input"


def test_ref_exists_runs_before_ref_in_input(records):
    # MFT#99999는 파싱 결과에도 input_refs에도 없다. 스펙은 이것을
    # ref_not_found로 판정한다. 순서가 뒤집히면 환각 유형 분포가 왜곡된다.
    finding = _finding(refs=["MFT#99999"], claims=[])
    assert verify(_doc(finding), records)["rejected"][0]["reason"] == "ref_not_found"


def test_a_claim_ref_outside_refs_is_still_checked(records):
    # refs에는 안 적고 claims에만 몰래 넣는 경우.
    finding = _finding(refs=["MFT#12345"], claims=[{"ref": "MFT#99999", "field": "size", "value": 1}])
    assert verify(_doc(finding), records)["rejected"][0]["reason"] == "ref_not_found"


def test_inventing_a_field_is_not_the_same_as_getting_a_value_wrong(records):
    finding = _finding(claims=[{"ref": "MFT#12345", "field": "entropy", "value": 7.9}])
    rejected = verify(_doc(finding), records)["rejected"][0]
    assert rejected["reason"] == "field_not_found"
    assert rejected["detail"]["field"] == "entropy"


# ------------------------------------------------------ --checkers 조합


def test_disabling_a_checker_changes_the_verdict(records):
    finding = _finding(refs=["MFT#12400"], claims=[])
    assert verify(_doc(finding), records)["rejected"][0]["reason"] == "ref_not_in_input"
    # 끄면 통과한다 — 검증 강도별 실험이 성립한다는 뜻이다.
    loose = verify(_doc(finding), records, checker_names=["ref_exists"])
    assert loose["rejected"] == []


def test_turning_off_ref_exists_reclassifies_the_rejection(records):
    # schemas/README.md 3번에 적어 둔 주의사항이 실제로 일어나는지 확인한다.
    finding = _finding(refs=["MFT#99999"], claims=[])
    result = verify(_doc(finding), records, checker_names=["ref_in_input", "value_match"])
    assert result["rejected"][0]["reason"] == "ref_not_in_input"


def test_value_match_alone_still_catches_a_missing_record(records):
    finding = _finding(claims=[{"ref": "MFT#99999", "field": "size", "value": 1}])
    result = verify(_doc(finding), records, checker_names=["value_match"])
    assert result["rejected"][0]["reason"] == "ref_not_found"


def test_checks_count_is_zero_when_nothing_was_compared(records):
    result = verify(_doc(_finding()), records, checker_names=["ref_exists"])
    assert result["passed"][0] == {"id": "F1", "checks": 0, "checks_passed": 0}


def test_checker_order_is_fixed_regardless_of_input_order():
    assert [n for n, _ in checkers.resolve(["value_match", "ref_exists"])] == [
        "ref_exists",
        "value_match",
    ]


def test_unknown_checker_name_is_refused():
    with pytest.raises(ValueError, match="알 수 없는 체커"):
        checkers.resolve(["ref_exists", "vibes"])


# ==================================================== 목업 픽스처 재현


def _without_volatile(doc):
    doc = copy.deepcopy(doc)
    doc.pop("generated_at", None)
    return doc


def test_reproduces_the_passing_fixture_exactly(records, findings):
    expected = io.read_json(GOLDEN / "06_verified.json")
    got = verify(findings, records, tolerance_seconds=1)
    assert _without_volatile(got) == _without_volatile(expected)


def test_reproduces_the_rejection_fixture_exactly(records):
    bad = io.read_json(FIXTURES / "05_findings.bad.json")
    expected = io.read_json(GOLDEN / "06_verified.bad.json")
    got = verify(bad, records, tolerance_seconds=1, generator="mock (negative fixture)")
    assert _without_volatile(got) == _without_volatile(expected)


def test_hallucination_rate_excludes_unverifiable(records, findings):
    # F3(종합 판단)이 분모에 들어가면 2/3 = 0.667이 나온다. 0이어야 맞다.
    result = verify(findings, records)
    assert result["stats"] == {
        "total_findings": 3,
        "passed": 2,
        "rejected": 0,
        "unverifiable": 1,
        "hallucination_rate": 0.0,
    }


def test_all_rejected_gives_a_rate_of_one(records):
    bad = io.read_json(FIXTURES / "05_findings.bad.json")
    assert verify(bad, records)["stats"]["hallucination_rate"] == 1.0


def test_no_findings_does_not_divide_by_zero(records):
    assert verify(_doc(), records)["stats"]["hallucination_rate"] == 0.0


# ========================================================== load_records


def test_load_records_indexes_every_parsed_file(records):
    assert set(records) == {
        "MFT#12345", "MFT#12346", "MFT#12400", "EVTX-SEC#40912", "EVTX-SEC#40915",
    }


def test_duplicate_ref_across_files_is_a_hard_error(tmp_path):
    # 조용히 덮어쓰면 판정이 파일 읽는 순서에 좌우된다.
    io.write_jsonl(tmp_path / "a.jsonl", [{"ref": "MFT#1", "artifact": "$MFT"}])
    io.write_jsonl(tmp_path / "b.jsonl", [{"ref": "MFT#1", "artifact": "$MFT"}])
    with pytest.raises(verify_mod.DuplicateRefError, match="MFT#1"):
        load_records(tmp_path)


def test_record_without_a_ref_is_rejected(tmp_path):
    io.write_jsonl(tmp_path / "a.jsonl", [{"artifact": "$MFT"}])
    with pytest.raises(ValueError, match="ref 없는"):
        load_records(tmp_path)


# ================================================================== CLI


def test_cli_writes_a_schema_valid_document(tmp_path, capsys):
    out = tmp_path / "06_verified.json"
    code = verify_mod.main(
        ["--findings", str(FIXTURES / "05_findings.json"), "--parsed", str(PARSED), "--out", str(out)]
    )
    assert code == 0
    from src.common import schema

    written = io.read_json(out)
    schema.validate(written, "verified")
    assert written["stats"]["passed"] == 2
    assert "passed 2" in capsys.readouterr().out


def test_cli_rejects_an_unknown_checker_without_touching_errors_jsonl(tmp_path, capsys):
    out = tmp_path / "06_verified.json"
    code = verify_mod.main(
        [
            "--findings", str(FIXTURES / "05_findings.json"),
            "--parsed", str(PARSED),
            "--out", str(out),
            "--checkers", "vibes",
        ]
    )
    assert code == 2
    # 사용자 입력 오류는 파이프라인 실패가 아니므로 통계에 섞지 않는다.
    assert not (tmp_path / "errors.jsonl").exists()


def test_cli_aborts_and_logs_when_the_input_violates_its_schema(tmp_path):
    broken = tmp_path / "05_findings.json"
    doc = io.read_json(FIXTURES / "05_findings.json")
    doc["findings"][0]["severity"] = "catastrophic"
    io.write_json(broken, doc)

    with pytest.raises(SystemExit) as e:
        verify_mod.main(
            [
                "--findings", str(broken),
                "--parsed", str(PARSED),
                "--out", str(tmp_path / "06_verified.json"),
            ]
        )
    assert e.value.code == 1
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["type"] == "schema_violation"
    assert logged[0]["action"] == "abort"
    assert logged[0]["detail"]["field"] == "findings[0].severity"


def test_cli_aborts_when_the_parse_output_is_empty(tmp_path):
    empty = tmp_path / "04_parsed"
    empty.mkdir()
    with pytest.raises(SystemExit):
        verify_mod.main(
            [
                "--findings", str(FIXTURES / "05_findings.json"),
                "--parsed", str(empty),
                "--out", str(tmp_path / "06_verified.json"),
            ]
        )
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["type"] == "empty_result"


def test_cli_output_is_lf_only(tmp_path):
    out = tmp_path / "06_verified.json"
    verify_mod.main(
        ["--findings", str(FIXTURES / "05_findings.json"), "--parsed", str(PARSED), "--out", str(out)]
    )
    assert b"\r\n" not in out.read_bytes()
    assert json.loads(out.read_text(encoding="utf-8"))["stage"] == "06_verify"


# ==================================================== technique_supported


SUPPORTED = {
    "T1505.003": frozenset({"$MFT", "$UsnJrnl", "evtx:System"}),
    "T1059.003": frozenset({"evtx:Sysmon", "prefetch"}),
}


def _tech_ctx(**overrides):
    base = dict(records={}, input_refs=frozenset(), technique_artifacts=SUPPORTED)
    base.update(overrides)
    return checkers.CheckContext(**base)


def _run_tech(finding, ctx=None):
    return checkers.CHECKERS["technique_supported"](finding, ctx or _tech_ctx())


def test_a_technique_backed_by_the_cited_artifact_passes():
    result = _run_tech(_finding(technique="T1505.003", refs=["MFT#12345"]))

    assert result.rejection is None


def test_a_technique_the_evidence_cannot_support_is_rejected():
    """**이것이 이 체커의 전부다.** 값이 아니라 함의를 본다.

    claims 를 파이썬이 조립하면 value_match 는 항등식이 되고, ref 는 출력
    문법이 이미 막는다. 모델에게 남은 자유도 중 결정론적으로 잴 수 있는
    것이 이것 하나다.
    """
    finding = _finding(technique="T1505.003", refs=["SRUM-NET#12"], claims=[])

    result = _run_tech(finding)

    assert result.rejection is not None
    assert result.rejection.reason == "technique_unsupported"
    assert result.rejection.detail["cited_artifacts"] == ["srum:NetworkUsage"]


def test_one_supporting_reference_is_enough():
    """맥락으로 다른 아티팩트를 함께 인용하는 것은 정상이다.

    전부가 근거여야 한다고 하면 과엄격 쪽으로 넘어가고, 환각률이 실제
    환각이 아니라 문장의 풍부함을 벌하게 된다.
    """
    finding = _finding(technique="T1505.003", refs=["SRUM-NET#12", "MFT#12345"], claims=[])

    assert _run_tech(finding).rejection is None


def test_claims_only_citations_are_judged_too():
    """``refs`` 에 없고 ``claims`` 에만 있는 ref 가 실제로 나온다."""
    finding = _finding(
        technique="T1505.003",
        refs=[],
        claims=[{"ref": "SRUM-NET#9", "field": "x", "value": "y"}],
    )

    assert _run_tech(finding).rejection is not None


@pytest.mark.parametrize(
    "finding",
    [
        # 종합 판단 문장. 동결 스키마가 null 을 허용한다.
        _finding(technique=None, refs=["SRUM-NET#12"], claims=[]),
        # 매핑이 없는 기법 — 03단계의 매핑 결손이지 05단계의 잘못이 아니다.
        _finding(technique="T9999", refs=["SRUM-NET#12"], claims=[]),
        # 인용한 것이 없으면 볼 것이 없다.
        _finding(technique="T1505.003", refs=[], claims=[]),
    ],
)
def test_what_cannot_be_judged_is_not_rejected(finding):
    """판정할 수 없는 것을 기각하면 환각률이 우리 무지를 센다."""
    assert _run_tech(finding).rejection is None


def test_an_empty_mapping_table_rejects_nothing():
    """매핑을 못 읽었는데 전부 기각하면 증거가 아니라 우리 설정을 재게 된다."""
    finding = _finding(technique="T1505.003", refs=["SRUM-NET#12"], claims=[])

    assert _run_tech(finding, _tech_ctx(technique_artifacts={})).rejection is None


def test_a_malformed_ref_is_left_to_ref_exists():
    """같은 잘못이 두 유형으로 집계되면 분포가 왜곡된다."""
    finding = _finding(technique="T1505.003", refs=["NOT-A-REF"], claims=[])

    assert _run_tech(finding).rejection is None


def test_the_technique_check_does_not_count_as_a_claims_check():
    """``checks`` 는 claims 대조 횟수여야 한다. 문장 단위 조건은 안 센다."""
    result = _run_tech(_finding(technique="T1505.003", refs=["MFT#12345"]))

    assert result.checks == 0
    assert result.checks_passed == 0


def test_the_shipped_mapping_table_is_actually_loaded():
    """표가 조용히 비면 이 체커가 있으나 마나가 된다."""
    table = verify_mod.technique_artifacts("mappings")

    assert "T1505.003" in table
    assert "$MFT" in table["T1505.003"]
    assert "srum:NetworkUsage" not in table["T1505.003"]


def test_a_missing_mapping_directory_gives_an_empty_table():
    """매핑이 없어도 06단계는 돌아야 한다 — 결정론적 구간이다."""
    assert verify_mod.technique_artifacts("no/such/directory") == {}
