"""schemas/ 6개가 C-001 목업을 실제로 통과시키는지 확인한다.

스키마를 목업에서 역산했으므로, 목업이 통과하지 못하면 역산이 틀린 것이다.
이 테스트가 "스키마 동결"의 근거다. 통과하는 인스턴스가 존재하지 않는
스키마를 동결하면 담당자들이 각자 다른 해석으로 구현하게 된다.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from src.common import io, refs, schema

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK = REPO_ROOT / "benchmark/datasets/C-001-webshell/mock"
DATASET = REPO_ROOT / "benchmark/datasets/C-001-webshell"


# --------------------------------------------------- 스키마 파일 자체


@pytest.mark.parametrize(
    "name", ["input", "scenario", "selection", "parsed_record", "findings", "verified"]
)
def test_every_schema_loads_and_is_itself_valid(name):
    import jsonschema

    doc = schema.load_schema(name)
    jsonschema.Draft202012Validator.check_schema(doc)


def test_stage_schema_map_points_at_files_that_exist():
    for stage, name in schema.STAGE_SCHEMA.items():
        assert schema.load_schema(name), stage


# ------------------------------------------------------- 정상 목업 통과


@pytest.mark.parametrize(
    "filename,schema_name",
    [
        ("01_input.json", "input"),
        ("02_scenario.json", "scenario"),
        ("03_selection.json", "selection"),
        ("05_findings.json", "findings"),
        ("06_verified.json", "verified"),
        ("05_findings.bad.json", "findings"),
        ("06_verified.bad.json", "verified"),
    ],
)
def test_mock_documents_validate(filename, schema_name):
    schema.validate(io.read_json(MOCK / filename), schema_name)


def test_dataset_entry_point_validates():
    schema.validate(io.read_json(DATASET / "input.json"), "input")


def test_validate_stage_dispatches_by_header():
    for filename in ["01_input.json", "02_scenario.json", "03_selection.json",
                     "05_findings.json", "06_verified.json"]:
        schema.validate_stage(io.read_json(MOCK / filename))


@pytest.mark.parametrize("filename", ["mft.jsonl", "evtx_security.jsonl"])
def test_every_parsed_record_validates(filename):
    records = list(io.read_jsonl(MOCK / "04_parsed" / filename))
    assert records
    for record in records:
        schema.validate(record, "parsed_record")


def test_parsed_record_ref_agrees_with_record_num():
    # 스키마는 두 필드를 각각만 본다. 서로 어긋나는 것은 여기서 잡는다.
    for filename in ["mft.jsonl", "evtx_security.jsonl"]:
        for record in io.read_jsonl(MOCK / "04_parsed" / filename):
            parsed = refs.parse_ref(record["ref"])
            assert parsed.record_num == record["record_num"], record["ref"]
            assert parsed.artifact == record["artifact"], record["ref"]


def test_manifest_record_counts_match_the_actual_files():
    manifest = io.read_json(MOCK / "04_parsed/_manifest.json")
    for entry in manifest["files"]:
        assert entry["record_count"] == io.count_jsonl(MOCK / "04_parsed" / entry["path"])
    assert manifest["total_records"] == sum(f["record_count"] for f in manifest["files"])


# ------------------------------------------------- 위반이 실제로 걸리는가
#
# 통과만 확인하면 "무엇이든 통과시키는 스키마"도 초록불이 된다.


def _scenario():
    return copy.deepcopy(io.read_json(MOCK / "02_scenario.json"))


def test_empty_techniques_is_a_violation():
    # 스펙의 명시적 규칙. 기법을 하나도 못 뽑았으면 선별할 것이 없다.
    doc = _scenario()
    doc["techniques"] = []
    with pytest.raises(schema.SchemaViolation, match="techniques"):
        schema.validate(doc, "scenario")


def test_confidence_out_of_range_is_a_violation():
    doc = _scenario()
    doc["techniques"][0]["confidence"] = 1.5
    with pytest.raises(schema.SchemaViolation) as e:
        schema.validate(doc, "scenario")
    # errors.jsonl 의 detail.field 가 이 형식이어야 집계가 된다.
    assert e.value.field == "techniques[0].confidence"


def test_malformed_attack_id_is_a_violation_and_reports_its_position():
    doc = _scenario()
    doc["techniques"][0]["id"] = "웹셸"
    with pytest.raises(schema.SchemaViolation) as e:
        schema.validate(doc, "scenario")
    assert e.value.field == "techniques[0].id"
    assert e.value.value == "웹셸"


def test_unknown_target_os_is_a_violation():
    doc = _scenario()
    doc["target_os"] = "macos"
    with pytest.raises(schema.SchemaViolation, match="target_os"):
        schema.validate(doc, "scenario")


def test_naive_timestamp_without_z_is_a_violation():
    # UTC Z 표기로 고정하지 않으면 단계별 소요 시간 계산이 틀어진다.
    doc = _scenario()
    doc["time_range"]["start"] = "2026-07-18 00:00:00"
    with pytest.raises(schema.SchemaViolation, match="time_range"):
        schema.validate(doc, "scenario")


def test_case_id_cannot_escape_the_cases_directory():
    doc = _scenario()
    doc["case_id"] = "../../etc"
    with pytest.raises(schema.SchemaViolation, match="case_id"):
        schema.validate(doc, "scenario")


def test_unexpected_field_is_a_violation():
    # 스키마 변경이 조용히 흘러가지 않게 한다.
    doc = _scenario()
    doc["confidence_v2"] = 0.9
    with pytest.raises(schema.SchemaViolation):
        schema.validate(doc, "scenario")


def test_malformed_ref_in_findings_is_a_violation():
    doc = copy.deepcopy(io.read_json(MOCK / "05_findings.json"))
    doc["findings"][0]["refs"] = ["MFT12345"]
    with pytest.raises(schema.SchemaViolation, match=r"findings\[0\]\.refs"):
        schema.validate(doc, "findings")


def test_claim_requires_all_three_of_ref_field_value():
    doc = copy.deepcopy(io.read_json(MOCK / "05_findings.json"))
    del doc["findings"][0]["claims"][0]["value"]
    with pytest.raises(schema.SchemaViolation, match=r"findings\[0\]\.claims\[0\]"):
        schema.validate(doc, "findings")


def test_unknown_flag_is_a_violation():
    record = next(io.read_jsonl(MOCK / "04_parsed/mft.jsonl"))
    record = copy.deepcopy(record)
    record["flags"] = ["looks_suspicious"]
    with pytest.raises(schema.SchemaViolation, match="flags"):
        schema.validate(record, "parsed_record")


def test_mft_record_must_carry_both_si_and_fn_timestamps():
    # $SI 와 $FN 을 다 읽지 않으면 timestamp_mismatch 자체를 판정할 수 없다.
    record = copy.deepcopy(next(io.read_jsonl(MOCK / "04_parsed/mft.jsonl")))
    del record["fn_ctime"]
    with pytest.raises(schema.SchemaViolation):
        schema.validate(record, "parsed_record")


def test_offset_must_be_hex():
    record = copy.deepcopy(next(io.read_jsonl(MOCK / "04_parsed/mft.jsonl")))
    record["offset"] = "123456"
    with pytest.raises(schema.SchemaViolation, match="offset"):
        schema.validate(record, "parsed_record")


def test_unknown_rejection_reason_is_a_violation():
    # 환각 유형 분포가 발표 수치이므로 어휘를 벗어나면 막는다.
    doc = copy.deepcopy(io.read_json(MOCK / "06_verified.bad.json"))
    doc["rejected"][0]["reason"] = "looks_wrong"
    with pytest.raises(schema.SchemaViolation, match="rejected"):
        schema.validate(doc, "verified")


def test_iter_violations_reports_every_problem_at_once():
    doc = _scenario()
    doc["techniques"][0]["confidence"] = 2.0
    doc["target_os"] = "macos"
    fields = {v.field for v in schema.iter_violations(doc, "scenario")}
    assert {"target_os", "techniques[0].confidence"} <= fields
