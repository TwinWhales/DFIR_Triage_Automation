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


def _context(docs, records=None, manifest=None):
    return build_context(
        docs["verified"], docs["findings"], docs["selection"], docs["scenario"], records, manifest
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
    # 미검증 항목과 분석 범위가 이 도구의 신뢰성 근거다.
    # 자동 생성에서 누락되지 않아야 한다.
    text = render(_context(docs))
    for heading in (
        "## 개요",
        "## 확인된 사항",
        "## 미검증 항목",
        "## 분석 범위",
        "### 확인한 아티팩트",
        "### 확인하지 못한 아티팩트",
    ):
        assert heading in text


def test_sections_survive_an_empty_case(docs):
    docs["verified"]["passed"] = []
    docs["verified"]["unverifiable"] = []
    docs["selection"]["excluded"] = []
    docs["selection"]["deferred"] = []
    text = render(_context(docs))
    assert "## 미검증 항목" in text and "없습니다" in text
    assert "## 분석 범위" in text


def test_unverifiable_statements_are_quoted_verbatim(docs):
    context = _context(docs)
    assert context["unverifiable"][0]["statement"] == docs["findings"]["findings"][2]["statement"]


def test_scope_limits_merge_excluded_and_unfired_deferred(docs):
    limits = {entry["artifact"]: entry["reason"] for entry in _context(docs)["limits"]}
    assert "미지원" in limits["$LogFile"]
    # Tier 2 루프백이 없으므로 조건을 **평가한 적이 없다.** "조건 미충족"은
    # 평가했는데 안 걸린 것처럼 읽혀 사실과 다르다(docs/limitations.md 3).
    for artifact in ("$UsnJrnl", "evtx:System"):
        assert "미평가" in limits[artifact]
        assert "조건 미충족" not in limits[artifact]


# ==================================== 04가 읽지 못한 것이 보고서에 실리는가
#
# docs/limitations.md 4-1. 고치기 전에는 04단계가 건너뛴 아티팩트가
# errors.jsonl 에만 남고 보고서에는 **언급조차 되지 않았다.** 실제 증거로
# 재현했을 때 보고서는 "카탈로그의 모든 아티팩트를 확인했습니다"라고
# 적었다 — 누락이 아니라 거짓 진술이었다.


def _manifest(files=(), skipped=()):
    return {"files": list(files), "skipped": list(skipped)}


def test_an_artifact_stage_04_could_not_read_appears_in_the_report(docs):
    manifest = _manifest(
        files=[{"artifact": "$MFT", "record_count": 3}],
        skipped=[
            {
                "artifact": "evtx:Security",
                "reason": "artifact_not_found",
                "message": "Windows/System32/winevt/Logs/Security.evtx 를 찾지 못함",
            }
        ],
    )
    limits = {e["artifact"]: e["reason"] for e in _context(docs, manifest=manifest)["limits"]}
    assert "evtx:Security" in limits, "04가 못 읽은 아티팩트가 보고서에서 사라졌다"
    assert "수집 누락" in limits["evtx:Security"]


def test_skip_reasons_are_distinguished(docs):
    """사유마다 분석가가 할 일이 다르다. 뭉뚱그리면 조치를 정할 수 없다."""
    manifest = _manifest(
        skipped=[
            {"artifact": "evtx:Security", "reason": "artifact_not_found", "message": "없음"},
            {"artifact": "$UsnJrnl", "reason": "empty_artifact", "message": "0바이트"},
            {"artifact": "registry:SYSTEM", "reason": "parser_missing", "message": "미등록"},
        ]
    )
    limits = {e["artifact"]: e["reason"] for e in _context(docs, manifest=manifest)["limits"]}
    assert "수집 누락" in limits["evtx:Security"]
    assert "추출 확인" in limits["$UsnJrnl"]
    assert "미지원" in limits["registry:SYSTEM"]


def test_a_version_mismatch_is_not_reported_as_a_collection_gap(docs):
    """"이 버전엔 원래 없다"와 "수집 누락"은 분석가가 할 일이 다르다.

    앞의 것은 **다시 뽑아도 없다.** 가르지 않으면 존재하지 않는 파일을
    다시 뽑으러 간다(`src/stage04_parse/osinfo.py`).
    """
    manifest = _manifest(
        skipped=[
            {
                "artifact": "registry:Amcache",
                "reason": "version_not_applicable",
                "message": "빌드 7601 < 9200. Amcache.hve는 Windows 8부터 기본 탑재입니다.",
            }
        ]
    )
    reason = {e["artifact"]: e["reason"] for e in _context(docs, manifest=manifest)["limits"]}[
        "registry:Amcache"
    ]

    assert "재수집 불필요" in reason
    assert "수집 누락" not in reason
    # 근거인 빌드 번호는 살아 있어야 한다. 라벨만 남으면 왜 그렇게
    # 판정했는지 보고서만 보고 알 수 없다.
    assert "7601" in reason


def test_the_detected_windows_version_reaches_the_report(docs):
    manifest = _manifest()
    manifest["windows"] = {
        "determined": True,
        "build": 15063,
        "family": "win10",
        "product_name": "Windows 10 Pro",
        "release_id": "1703",
        "installation_type": "Client",
        "revision": 0,
    }
    line = _context(docs, manifest=manifest)["windows"]

    assert line == "Windows 10 Pro (빌드 15063.0, 1703, Client)"


def test_an_undetermined_version_says_so_instead_of_guessing(docs):
    manifest = _manifest()
    manifest["windows"] = {"determined": False, "reason": "SOFTWARE 하이브를 찾지 못했습니다"}

    line = _context(docs, manifest=manifest)["windows"]

    assert line.startswith("판정 불가")
    assert "SOFTWARE" in line


def test_an_old_manifest_without_the_windows_block_prints_nothing(docs):
    # 04단계가 이 필드를 쓰기 전의 산출물이다. 빈 문자열이면 템플릿이
    # 아무것도 그리지 않는다 — 모르는 것을 "미상"이라고 단정하지 않는다.
    assert _context(docs, manifest=_manifest())["windows"] == ""


def test_parser_missing_does_not_leak_source_paths_into_the_report(docs):
    """분석가가 읽는 문서에 소스 파일 경로를 싣지 않는다."""
    manifest = _manifest(
        skipped=[
            {
                "artifact": "registry:SYSTEM",
                "reason": "parser_missing",
                "message": "src/stage04_parse/parsers/__init__.py 참조.",
            }
        ]
    )
    limits = {e["artifact"]: e["reason"] for e in _context(docs, manifest=manifest)["limits"]}
    assert "__init__.py" not in limits["registry:SYSTEM"]


def test_a_selected_artifact_with_no_record_anywhere_is_still_reported(docs):
    """04가 기록을 빠뜨려도 차집합이 잡는다. 조용히 사라지는 것보다 낫다."""
    docs["selection"]["selected"] = [{"artifact": "$MFT", "scope": {}}]
    limits = {e["artifact"]: e["reason"] for e in _context(docs, manifest=_manifest())["limits"]}
    assert "$MFT" in limits
    assert "사유를 남기지 않" in limits["$MFT"]


def test_no_manifest_means_no_guessing(docs):
    """--parsed 없이 부르면 04가 뭘 했는지 모른다. 모르는 것을 단정하지 않는다."""
    limits = {e["artifact"] for e in _context(docs)["limits"]}
    assert "$MFT" not in limits


# ======================================== 무엇을 봤는지도 적히는가


def test_examined_artifacts_are_listed_with_their_size(docs):
    manifest = _manifest(files=[{"artifact": "$MFT", "record_count": 306857}])
    (row,) = _context(docs, manifest=manifest)["examined"]
    assert row["artifact"] == "$MFT"
    assert row["records"] == "306,857건"


def test_zero_records_counts_as_examined_not_as_a_limit(docs):
    """파싱은 됐는데 범위에 없었던 것 = "봤는데 없었다". 못 본 것과 다르다."""
    manifest = _manifest(files=[{"artifact": "evtx:Security", "record_count": 0}])
    context = _context(docs, manifest=manifest)
    assert [r["artifact"] for r in context["examined"]] == ["evtx:Security"]
    assert "evtx:Security" not in {e["artifact"] for e in context["limits"]}


def test_a_partial_read_is_marked_but_not_called_unexamined(docs):
    """실측: $J 306,857건을 읽고 503,752바이트를 못 읽었다.

    "안 봤다"가 아니지만 "다 봤다"도 아니므로 비고로 적는다.
    """
    manifest = _manifest(
        files=[
            {
                "artifact": "$UsnJrnl",
                "record_count": 306857,
                "parse_errors": 1,
                "unreadable_bytes": 503752,
            }
        ]
    )
    docs["selection"]["selected"] = [{"artifact": "$UsnJrnl", "scope": {}}]
    docs["selection"]["excluded"] = []
    docs["selection"]["deferred"] = []
    context = _context(docs, manifest=manifest)
    (row,) = context["examined"]
    assert "부분 판독" in row["note"]
    assert "503,752" in row["note"]
    assert context["limits"] == [], "부분 판독은 '못 봤다'가 아니다"


def test_an_artifact_that_was_read_is_never_also_listed_as_unexamined(docs):
    """03이 Tier 1으로 읽는 것을 deferred 에서 빼지 못했더라도, 산출물이
    있으면 읽은 것이다. 같은 아티팩트가 양쪽에 실리면 보고서가 모순된다.
    """
    manifest = _manifest(files=[{"artifact": "$UsnJrnl", "record_count": 5}])
    context = _context(docs, manifest=manifest)
    examined = {r["artifact"] for r in context["examined"]}
    limited = {e["artifact"] for e in context["limits"]}
    assert examined & limited == set()


def test_a_skipped_empty_candidate_is_surfaced_in_the_report(docs):
    """0바이트 껍데기를 건너뛰고 읽었다는 사실은 추출 진단이다."""
    manifest = _manifest(
        files=[
            {
                "artifact": "$UsnJrnl",
                "record_count": 10,
                "source_empty_skipped": ["C/$Extend/$UsnJrnl"],
            }
        ]
    )
    (row,) = _context(docs, manifest=manifest)["examined"]
    assert "추출 확인" in row["note"]


def test_the_report_never_claims_it_checked_everything(docs):
    """고치기 전 실제로 나왔던 문장. 선별 밖은 알 수 없으므로 단정할 수 없다."""
    docs["selection"]["excluded"] = []
    docs["selection"]["deferred"] = []
    docs["selection"]["selected"] = [{"artifact": "$MFT", "scope": {}}]
    text = render(_context(docs, manifest=_manifest(files=[{"artifact": "$MFT", "record_count": 3}])))
    assert "카탈로그의 모든 아티팩트를 확인했습니다" not in text


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
