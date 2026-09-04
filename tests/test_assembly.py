"""05단계 결정론적 조립 테스트.

모델이 고른 ``ref`` 로 파이썬이 findings 문서를 만든다. 이 조립이 틀리면
모델은 옳게 골랐는데 산출물이 틀리고, 그 잘못은 환각으로 집계된다.

그래서 둘을 같은 비중으로 본다.

- **원본을 그대로 옮기는가** — 손대는 순간 06단계가 우리가 만든 불일치를
  기각하고, 그것이 환각률에 잡힌다.
- **못 하는 일을 조용히 하지 않는가** — 없는 필드를 지어내 채우면 그
  순간 06단계가 우리가 만든 값을 검증하게 된다.
"""

from __future__ import annotations

import pytest

from src.common import io, schema
from src.stage04_parse.flagging import ClaimFields, claim_fields
from src.stage05_interpret.assembly import (
    AssemblyError,
    assemble_body,
    claim_for,
    walk_field,
)
from src.stage06_verify.verify import technique_artifacts, verify

FIELDS = ClaimFields(max_items=4, names=("path", "name", "fields.CommandLine", "timestamp"))


def _sysmon(ref="SYSMON#1", **fields):
    base = {
        "ref": ref,
        "artifact": "evtx:Sysmon",
        "record_num": 1,
        "offset": "0x0",
        "event_id": 1,
        "timestamp": "2026-08-26T00:33:07Z",
        "flags": ["shell_spawned"],
        "fields": {"Image": r"C:\Windows\System32\cmd.exe", **fields},
    }
    return base


def _usn(ref="USN#1", **overrides):
    """``$UsnJrnl`` 은 ``fields`` 가 없다. 최상위만으로 claim 이 되어야 한다."""
    base = {
        "ref": ref,
        "artifact": "$UsnJrnl",
        "record_num": 1,
        "offset": "0x0",
        "name": "shell.aspx",
        "reason": ["file_create", "close"],
        "timestamp": "2026-07-20T03:14:22Z",
        "flags": ["file_created"],
    }
    base.update(overrides)
    return base


def _pick(ref, **overrides):
    base = {"ref": ref, "technique": "T1059.003", "reason": "의심 정황", "severity": "high"}
    base.update(overrides)
    return base


# ==================================================================== walk


def test_a_nested_field_is_found_by_dotted_name():
    found, value = walk_field(_sysmon(CommandLine="cmd /c x"), "fields.CommandLine")

    assert (found, value) == (True, "cmd /c x")


def test_a_null_value_counts_as_missing():
    """스키마가 claim 의 value 를 스칼라로 못 박아 None 은 실을 수 없다.

    실을 수 없는 것을 골라 두면 조립이 뒤에서 터진다.
    """
    assert walk_field({"path": None}, "path") == (False, None)


# =================================================================== claims


def test_claims_copy_the_record_verbatim():
    record = _sysmon(CommandLine="cmd.exe /c whoami")

    claims = claim_for(record, FIELDS)

    assert {"ref": "SYSMON#1", "field": "fields.CommandLine", "value": "cmd.exe /c whoami"} in claims


def test_claims_follow_the_vocabulary_order_up_to_the_cap():
    record = _sysmon(CommandLine="x")
    record["path"] = r"C:\a.exe"
    record["name"] = "a.exe"

    claims = claim_for(record, ClaimFields(max_items=2, names=FIELDS.names))

    assert [c["field"] for c in claims] == ["path", "name"]


def test_an_artifact_without_a_fields_bag_still_gets_claims():
    """``$UsnJrnl`` 은 ``fields`` 가 아예 없다. 최상위만으로 서야 한다."""
    claims = claim_for(_usn(), FIELDS)

    assert [c["field"] for c in claims] == ["name", "timestamp"]


def test_list_values_are_not_carried_into_claims():
    """동결 스키마가 value 를 스칼라로 못 박았다.

    ``$UsnJrnl`` 의 ``reason`` 은 배열이라, 실으면 스키마 위반이고 그
    위반은 모델이 아니라 우리가 만든 것이다.
    """
    claims = claim_for(_usn(), ClaimFields(max_items=4, names=("reason", "name")))

    assert [c["field"] for c in claims] == ["name"]


def test_no_matching_field_leaves_the_claims_empty():
    """지어내 채우면 06단계가 우리가 만든 값을 검증하게 된다.

    빈 claims 는 06단계에서 unverifiable 이 되고, 그것이 정직한 결과다.
    """
    record = {"ref": "SYSMON#1", "artifact": "evtx:Sysmon", "flags": []}

    assert claim_for(record, ClaimFields(max_items=4, names=("path", "name"))) == []


# ================================================================= assemble


def test_the_model_only_supplies_the_choice_and_the_sentence():
    records = {"SYSMON#1": _sysmon(CommandLine="cmd /c x")}

    body = assemble_body([_pick("SYSMON#1")], records, FIELDS)
    finding = body["findings"][0]

    assert finding["statement"] == "의심 정황"       # 모델이 쓴 유일한 문자열
    assert finding["technique"] == "T1059.003"
    assert finding["refs"] == ["SYSMON#1"]
    assert finding["claims"]                          # 나머지는 파이썬이 옮겼다


def test_the_same_record_chosen_twice_yields_one_finding():
    """기준이 있어야 같은 입력에 같은 문서가 나온다."""
    records = {"SYSMON#1": _sysmon()}

    body = assemble_body([_pick("SYSMON#1"), _pick("SYSMON#1")], records, FIELDS)

    assert [f["id"] for f in body["findings"]] == ["F1"]


def test_the_timeline_is_ordered_by_event_time_not_by_choice_order():
    """보고서에서 읽히려면 소견 순서가 아니라 사건 순서여야 한다."""
    records = {
        "SYSMON#1": _sysmon("SYSMON#1"),
        "SYSMON#2": _sysmon("SYSMON#2"),
    }
    records["SYSMON#1"]["timestamp"] = "2026-08-26T02:00:00Z"
    records["SYSMON#2"]["timestamp"] = "2026-08-26T01:00:00Z"

    body = assemble_body([_pick("SYSMON#1"), _pick("SYSMON#2")], records, FIELDS)

    assert [entry["ts"] for entry in body["timeline"]] == [
        "2026-08-26T01:00:00Z",
        "2026-08-26T02:00:00Z",
    ]


def test_a_record_without_a_readable_time_still_becomes_a_finding():
    """시각을 못 읽는 것과 증거가 아닌 것은 다르다."""
    record = _sysmon()
    del record["timestamp"]
    body = assemble_body([_pick("SYSMON#1")], {"SYSMON#1": record}, FIELDS)

    assert len(body["findings"]) == 1
    assert body["timeline"] == []


def test_a_ref_we_did_not_ship_is_our_bug_not_the_models():
    """문법 enum 이 이번에 보낸 ref 만 허용한다. 여기 오면 우리가 잘못 짝지은 것이다.

    조용히 건너뛰면 모델이 고른 증거가 소리 없이 사라진다.
    """
    with pytest.raises(AssemblyError, match="SYSMON#99"):
        assemble_body([_pick("SYSMON#99")], {"SYSMON#1": _sysmon()}, FIELDS)


def test_an_empty_reason_is_refused():
    with pytest.raises(AssemblyError, match="reason"):
        assemble_body([_pick("SYSMON#1", reason="   ")], {"SYSMON#1": _sysmon()}, FIELDS)


def test_a_missing_technique_becomes_null_not_a_guess():
    records = {"SYSMON#1": _sysmon()}

    body = assemble_body([_pick("SYSMON#1", technique=None)], records, FIELDS)

    assert body["findings"][0]["technique"] is None


# ================================================== 06단계와의 왕복


def _doc(body, refs):
    return io.new_document("C-001", "05_interpret", "assembly-test", input_refs=refs, **body)


def test_the_assembled_document_satisfies_the_frozen_schema():
    records = {"SYSMON#1": _sysmon(CommandLine="cmd /c x"), "USN#1": _usn()}
    body = assemble_body([_pick("SYSMON#1"), _pick("USN#1")], records, FIELDS)

    schema.validate(_doc(body, list(records)), "findings")


def test_the_verifier_agrees_with_what_the_assembler_wrote():
    """조립이 꺼낸 자리와 검증이 보는 자리가 다르면, 우리가 넣은 claim 을
    우리가 기각한다. **이 통과는 성능이 아니라 항등식이다** — 그래서
    아래 테스트가 함께 있어야 한다."""
    records = {"SYSMON#1": _sysmon(CommandLine="cmd /c x")}
    body = assemble_body([_pick("SYSMON#1")], records, FIELDS)

    result = verify(_doc(body, ["SYSMON#1"]), records)

    assert result["stats"]["rejected"] == 0
    assert result["stats"]["passed"] == 1


def test_the_technique_gate_still_bites_on_the_assembled_path():
    """조립해도 재는 것이 남아 있는가. **이 구조의 핵심 근거다.**

    `value_match` 는 우리가 복사한 값을 우리가 대조하는 항등식이라 반드시
    통과한다. 그런데도 기각이 나오면, 06단계가 값이 아니라 함의를 보고
    있다는 뜻이다(`docs/limitations.md` 의 환각 유형 표 넷째 줄).
    """
    records = {"PF#1": {**_sysmon("PF#1"), "artifact": "prefetch", "name": "CMD.EXE-1.pf"}}
    # 프리패치로 웹셸(T1505.003)을 주장한다. 매핑은 $MFT·$UsnJrnl·evtx:System 만 인정한다.
    body = assemble_body([_pick("PF#1", technique="T1505.003")], records, FIELDS)

    result = verify(
        _doc(body, ["PF#1"]), records, supported_artifacts=technique_artifacts("mappings")
    )

    assert result["stats"]["rejected"] == 1
    assert result["rejected"][0]["reason"] == "technique_unsupported"


def test_the_shipped_claim_vocabulary_is_actually_loaded():
    """어휘가 조용히 비면 모든 소견이 unverifiable 이 된다."""
    fields = claim_fields()

    assert fields.max_items > 0
    assert "path" in fields.names
    assert "fields.CommandLine" in fields.names
