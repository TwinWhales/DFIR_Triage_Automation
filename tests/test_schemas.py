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
from casepaths import FIXTURES, GOLDEN, case_file

REPO_ROOT = Path(__file__).resolve().parents[1]
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
    schema.validate(io.read_json(case_file(filename)), schema_name)


def test_dataset_entry_point_validates():
    schema.validate(io.read_json(DATASET / "input.json"), "input")


def test_validate_stage_dispatches_by_header():
    for filename in ["01_input.json", "02_scenario.json", "03_selection.json",
                     "05_findings.json", "06_verified.json"]:
        schema.validate_stage(io.read_json(case_file(filename)))


@pytest.mark.parametrize("filename", ["mft.jsonl", "evtx_security.jsonl"])
def test_every_parsed_record_validates(filename):
    records = list(io.read_jsonl(FIXTURES / "04_parsed" / filename))
    assert records
    for record in records:
        schema.validate(record, "parsed_record")


def test_parsed_record_ref_agrees_with_record_num():
    # 스키마는 두 필드를 각각만 본다. 서로 어긋나는 것은 여기서 잡는다.
    for filename in ["mft.jsonl", "evtx_security.jsonl"]:
        for record in io.read_jsonl(FIXTURES / "04_parsed" / filename):
            parsed = refs.parse_ref(record["ref"])
            assert parsed.record_num == record["record_num"], record["ref"]
            assert parsed.artifact == record["artifact"], record["ref"]


def test_manifest_record_counts_match_the_actual_files():
    manifest = io.read_json(FIXTURES / "04_parsed/_manifest.json")
    for entry in manifest["files"]:
        assert entry["record_count"] == io.count_jsonl(FIXTURES / "04_parsed" / entry["path"])
    assert manifest["total_records"] == sum(f["record_count"] for f in manifest["files"])


# ------------------------------------------------- 위반이 실제로 걸리는가
#
# 통과만 확인하면 "무엇이든 통과시키는 스키마"도 초록불이 된다.


def _scenario():
    return copy.deepcopy(io.read_json(FIXTURES / "02_scenario.json"))


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
    doc = copy.deepcopy(io.read_json(FIXTURES / "05_findings.json"))
    doc["findings"][0]["refs"] = ["MFT12345"]
    with pytest.raises(schema.SchemaViolation, match=r"findings\[0\]\.refs"):
        schema.validate(doc, "findings")


def test_claim_requires_all_three_of_ref_field_value():
    doc = copy.deepcopy(io.read_json(FIXTURES / "05_findings.json"))
    del doc["findings"][0]["claims"][0]["value"]
    with pytest.raises(schema.SchemaViolation, match=r"findings\[0\]\.claims\[0\]"):
        schema.validate(doc, "findings")


def test_unknown_flag_is_a_violation():
    record = next(io.read_jsonl(FIXTURES / "04_parsed/mft.jsonl"))
    record = copy.deepcopy(record)
    record["flags"] = ["looks_suspicious"]
    with pytest.raises(schema.SchemaViolation, match="flags"):
        schema.validate(record, "parsed_record")


def test_mft_si_and_fn_timestamps_are_optional():
    """FILETIME이 0/판독 불가면 mft.py가 null이 아니라 키를 뺀다.

    null을 허용하면 스키마가 막고(타입이 string 뿐), 그렇다고 required로
    두면 실물 데이터에서 매번 위반이 난다 — 실측(108,582레코드 MFT)에서
    si_atime이 0인 레코드가 다수였다. NTFS는 최근 접근 시각 갱신을
    기본적으로 꺼 둔다. $UsnJrnl·registry의 timestamp와 같은 규약이다.
    """
    record = copy.deepcopy(next(io.read_jsonl(FIXTURES / "04_parsed/mft.jsonl")))
    del record["fn_ctime"]
    del record["si_atime"]
    schema.validate(record, "parsed_record")  # 예외가 나면 안 된다


def test_mft_record_still_needs_its_core_fields():
    record = copy.deepcopy(next(io.read_jsonl(FIXTURES / "04_parsed/mft.jsonl")))
    del record["path"]
    with pytest.raises(schema.SchemaViolation):
        schema.validate(record, "parsed_record")


def test_offset_must_be_hex():
    record = copy.deepcopy(next(io.read_jsonl(FIXTURES / "04_parsed/mft.jsonl")))
    record["offset"] = "123456"
    with pytest.raises(schema.SchemaViolation, match="offset"):
        schema.validate(record, "parsed_record")


def test_unknown_rejection_reason_is_a_violation():
    # 환각 유형 분포가 발표 수치이므로 어휘를 벗어나면 막는다.
    doc = copy.deepcopy(io.read_json(GOLDEN / "06_verified.bad.json"))
    doc["rejected"][0]["reason"] = "looks_wrong"
    with pytest.raises(schema.SchemaViolation, match="rejected"):
        schema.validate(doc, "verified")


def test_iter_violations_reports_every_problem_at_once():
    doc = _scenario()
    doc["techniques"][0]["confidence"] = 2.0
    doc["target_os"] = "macos"
    fields = {v.field for v in schema.iter_violations(doc, "scenario")}
    assert {"target_os", "techniques[0].confidence"} <= fields


# --------------------------------------------------- ref 접두어 (스키마 ↔ refs.py)
#
# 실물 이미지 관통에서 드러난 자리입니다. 프리패치 파서를 붙이면서
# parsed_record 의 패턴에는 PF 를 넣었는데 findings 쪽을 빠뜨렸고,
# **프리패치가 05단계에 닿는 케이스가 통째로 기각**됐습니다.
# input_refs 는 우리 코드가 만드는 값이라 모델이 무엇을 내든 통과할 수
# 없었고, 집계에는 모델의 schema_violation 으로 잡혔습니다.


def _ref_patterns() -> "list[tuple[str, str]]":
    """``ref`` 를 제약하는 스키마들. (파일명, 패턴).

    두 군데를 본다 — ``findings`` 는 ``$defs.ref`` 로 빼 두었고
    ``parsed_record`` 는 ``properties.ref`` 에 바로 적었다. 자리가 다른
    것이 이번 결함이 눈에 안 띈 이유 중 하나다.
    """
    found = []
    for path in sorted((REPO_ROOT / "schemas").glob("*.json")):
        document = io.read_json(path)
        for holder in (document.get("$defs", {}), document.get("properties", {})):
            pattern = holder.get("ref", {}).get("pattern")
            if pattern:
                found.append((path.name, pattern))
                break
    return found


def test_the_schemas_that_constrain_refs_are_the_ones_we_expect():
    """새 스키마가 ref 를 제약하기 시작하면 아래 대조 대상에 자동으로 든다."""
    names = [name for name, _ in _ref_patterns()]
    assert names == ["findings.schema.json", "parsed_record.schema.json"]


@pytest.mark.parametrize("name,pattern", _ref_patterns())
def test_every_prefix_in_refs_py_is_accepted(name, pattern):
    """``refs.py``가 만드는 ref 를 스키마가 거부하면 그 아티팩트는 못 지나간다."""
    import re

    rejected = [
        prefix for prefix in sorted(refs.PREFIX_ARTIFACT) if not re.match(pattern, f"{prefix}#1")
    ]
    assert rejected == [], f"{name} 이 거부하는 접두어: {rejected}"


@pytest.mark.parametrize("name,pattern", _ref_patterns())
def test_the_pattern_invents_no_prefix_of_its_own(name, pattern):
    """반대 방향. 스키마에만 있는 접두어는 아무도 만들지 못한다."""
    import re

    inside = re.match(r"\^\(([^)]+)\)#", pattern)
    assert inside is not None, f"{name}: ref 패턴 모양이 바뀌었다 — {pattern}"
    unknown = sorted(set(inside.group(1).split("|")) - set(refs.PREFIX_ARTIFACT))
    assert unknown == [], f"{name} 에만 있는 접두어: {unknown}"
