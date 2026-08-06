"""07단계 보고서 생성 테스트.

이 단계의 가장 중요한 성질은 **기각된 문장이 보고서에 실리지 않는 것**이다.
앞의 모든 검증은 이것을 위한 것이므로, 여기서 새면 전부 무의미해진다.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from src.common import io
from src.stage07_report import report as report_mod
from src.stage07_report.report import build_context, render

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK = REPO_ROOT / "benchmark/datasets/C-001-webshell/mock"
PARSED = MOCK / "04_parsed"


@pytest.fixture
def docs():
    return {
        "verified": copy.deepcopy(io.read_json(MOCK / "06_verified.json")),
        "findings": copy.deepcopy(io.read_json(MOCK / "05_findings.json")),
        "selection": copy.deepcopy(io.read_json(MOCK / "03_selection.json")),
        "scenario": copy.deepcopy(io.read_json(MOCK / "02_scenario.json")),
    }


def _context(docs, records=None):
    return build_context(
        docs["verified"], docs["findings"], docs["selection"], docs["scenario"], records
    )


# ================================================ 기각된 내용이 새지 않는가


def test_a_rejected_finding_never_reaches_the_report(docs):
    docs["verified"]["passed"] = [{"id": "F1", "checks": 3, "checks_passed": 3}]
    docs["verified"]["rejected"] = [
        {"id": "F2", "reason": "value_mismatch", "detail": {"ref": "EVTX-SEC#40912"}}
    ]
    docs["verified"]["stats"]["passed"] = 1
    docs["verified"]["stats"]["rejected"] = 1

    text = render(_context(docs))
    assert "F1" in text
    assert "svc_backup" not in text  # F2의 문장이 통째로 빠져야 한다


def test_a_rejected_findings_timeline_entry_is_dropped_too(docs):
    # 타임라인이 남으면 보고서가 검증을 우회하게 된다.
    docs["verified"]["passed"] = [{"id": "F1", "checks": 3, "checks_passed": 3}]
    docs["verified"]["rejected"] = [{"id": "F2", "reason": "value_mismatch", "detail": {}}]

    timeline_refs = {
        ref for entry in _context(docs)["timeline"] for ref in entry["refs"]
    }
    assert timeline_refs == {"MFT#12345"}


def test_rejected_count_is_still_reported(docs):
    docs["verified"]["passed"] = []
    docs["verified"]["rejected"] = [{"id": "F1", "reason": "ref_not_found", "detail": {}}]
    docs["verified"]["stats"] = {
        "total_findings": 3, "passed": 0, "rejected": 1, "unverifiable": 1,
        "hallucination_rate": 1.0,
    }
    text = render(_context(docs))
    assert "기각 1" in text
    assert "근거 검증을 통과한 항목이 없습니다" in text


# ==================================================== 고정 섹션이 남는가


def test_the_fixed_sections_are_always_present(docs):
    # 미검증 항목과 분석 범위 한계가 이 도구의 신뢰성 근거다.
    # 자동 생성에서 누락되지 않아야 한다.
    text = render(_context(docs))
    for heading in ("## 개요", "## 확인된 사항", "## 미검증 항목", "## 분석 범위 한계"):
        assert heading in text


def test_sections_survive_an_empty_case(docs):
    docs["verified"]["passed"] = []
    docs["verified"]["unverifiable"] = []
    docs["selection"]["excluded"] = []
    docs["selection"]["deferred"] = []
    text = render(_context(docs))
    assert "## 미검증 항목" in text and "없습니다" in text
    assert "## 분석 범위 한계" in text


def test_unverifiable_statements_are_quoted_verbatim(docs):
    context = _context(docs)
    assert context["unverifiable"][0]["statement"] == docs["findings"]["findings"][2]["statement"]


def test_scope_limits_merge_excluded_and_unfired_deferred(docs):
    limits = {entry["artifact"]: entry["reason"] for entry in _context(docs)["limits"]}
    assert "수집 불가" in limits["prefetch"]
    assert "Tier 2 조건 미충족" in limits["$UsnJrnl"]
    assert "Tier 2 조건 미충족" in limits["evtx:System"]


def test_the_disclaimer_is_in_every_report(docs):
    # 상용 벤더와 같은 포지셔닝을 취해 증거능력 질문을 사전에 방어한다.
    text = render(_context(docs))
    assert "수사상 참고 자료" in text
    assert "포렌식 감정 결과나" in text


# ============================================================ 근거 표기


def test_offsets_appear_when_parsed_records_are_supplied(docs):
    records = io.read_parsed_records(PARSED)
    context = _context(docs, records)
    assert context["passed"][0]["evidence"] == ["$MFT 레코드 12345 (오프셋 0x1E000)"]


def test_evidence_degrades_gracefully_without_parsed_records(docs):
    assert _context(docs)["passed"][0]["evidence"] == ["$MFT 레코드 12345"]


def test_titles_come_from_the_technique_not_from_prose(docs):
    # 문장에서 요약 제목을 만들면 그것이 검증되지 않은 새 문장이 된다.
    assert _context(docs)["passed"][0]["title"] == "T1505.003 Server Software Component: Web Shell"


def test_severity_is_shown_in_korean(docs):
    assert _context(docs)["passed"][0]["severity_label"] == "높음"


# ================================================================== CLI


def test_cli_reproduces_the_report_fixture(tmp_path):
    out = tmp_path / "07_report.md"
    code = report_mod.main(
        [
            "--in", str(MOCK / "06_verified.json"),
            "--findings", str(MOCK / "05_findings.json"),
            "--selection", str(MOCK / "03_selection.json"),
            "--scenario", str(MOCK / "02_scenario.json"),
            "--parsed", str(PARSED),
            "--out", str(out),
        ]
    )
    assert code == 0

    def strip_volatile(text: str) -> list[str]:
        return [line for line in text.splitlines() if not line.startswith("생성: ")]

    assert strip_volatile(out.read_text(encoding="utf-8")) == strip_volatile(
        (MOCK / "07_report.md").read_text(encoding="utf-8")
    )


def test_cli_output_is_lf_only(tmp_path):
    out = tmp_path / "07_report.md"
    report_mod.main(
        [
            "--in", str(MOCK / "06_verified.json"),
            "--findings", str(MOCK / "05_findings.json"),
            "--selection", str(MOCK / "03_selection.json"),
            "--out", str(out),
        ]
    )
    assert b"\r\n" not in out.read_bytes()


def test_cli_aborts_on_a_schema_violating_input(tmp_path):
    broken = tmp_path / "06_verified.json"
    doc = io.read_json(MOCK / "06_verified.json")
    doc["stats"]["hallucination_rate"] = 5.0
    io.write_json(broken, doc)

    with pytest.raises(SystemExit):
        report_mod.main(
            [
                "--in", str(broken),
                "--findings", str(MOCK / "05_findings.json"),
                "--selection", str(MOCK / "03_selection.json"),
                "--out", str(tmp_path / "07_report.md"),
            ]
        )
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["type"] == "schema_violation"
