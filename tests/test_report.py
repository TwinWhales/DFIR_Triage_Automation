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
from casepaths import FIXTURES, GOLDEN

PARSED = FIXTURES / "04_parsed"


@pytest.fixture
def docs():
    return {
        "verified": copy.deepcopy(io.read_json(GOLDEN / "06_verified.json")),
        "findings": copy.deepcopy(io.read_json(FIXTURES / "05_findings.json")),
        "selection": copy.deepcopy(io.read_json(GOLDEN / "03_selection.json")),
        "scenario": copy.deepcopy(io.read_json(FIXTURES / "02_scenario.json")),
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
    # 경고 항목과 미확인 범위가 이 도구의 신뢰성 근거다.
    # 자동 생성에서 누락되지 않아야 한다.
    text = render(_context(docs))
    for heading in (
        "## 개요",
        "## 확인된 사실 (🟢 Passed)",
        "## 주의 필요 소견 (🟡 Warning - 분석가 교차 검증 요망)",
        "## 미확인 사항 (⚪ Unknowns)",
        "### 분석 범위",
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
    assert "## 주의 필요 소견" in text and "없습니다" in text
    assert "## 미확인 사항" in text


def test_unverifiable_statements_are_quoted_verbatim(docs):
    context = _context(docs)
    assert context["unverifiable"][0]["statement"] == docs["findings"]["findings"][2]["statement"]


def test_warning_keeps_reason_evidence_and_timeline_context(docs):
    docs["verified"]["passed"] = [
        entry for entry in docs["verified"]["passed"] if entry["id"] != "F1"
    ]
    docs["verified"]["unverifiable"] = [
        {"id": "F1", "reason": "서술 일부를 자동 검증하지 못함"}
    ]
    context = _context(docs)
    warning = context["warnings"][0]
    assert warning["reason"]
    assert warning["evidence"]
    timeline = next(item for item in context["timeline"] if "MFT#12345" in item["refs"])
    assert timeline["verification"] == "Warning"

    text = render(context)
    assert "⚠️ 분석가 확인 권장:" in text


def test_verified_command_line_is_visible_without_rewriting_it(docs):
    finding = docs["findings"]["findings"][0]
    finding["claims"].append(
        {"ref": "MFT#12345", "field": "fields.CommandLine", "value": "tool.exe --fetch a b"}
    )

    text = render(_context(docs))

    assert "> 검증값: fields.CommandLine: tool.exe --fetch a b" in text


def test_scope_limits_merge_excluded_and_unfired_deferred(docs):
    limits = {entry["artifact"]: entry["reason"] for entry in _context(docs)["limits"]}
    assert "미지원" in limits["$LogFile"]
    # Tier 2 루프백이 없으므로 조건을 **평가한 적이 없다.** "조건 미충족"은
    # 평가했는데 안 걸린 것처럼 읽혀 사실과 다르다(docs/limitations.md 3-1).
    for artifact in ("$UsnJrnl", "evtx:System"):
        assert "미평가" in limits[artifact]
        assert "조건 미충족" not in limits[artifact]


# ==================================== 04가 읽지 못한 것이 보고서에 실리는가
#
# docs/limitations-log.md 4-1. 고치기 전에는 04단계가 건너뛴 아티팩트가
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


def test_a_dirty_hive_is_visible_without_the_console_warning(docs):
    """파일이 있고, 파서가 성공하고, 값이 낡았다.

    ``parse_errors`` 는 0 이라 지금까지 이 표가 "정상"으로만 보였다.
    콘솔 경고를 놓치면 보고서만 읽는 사람은 알 방법이 없었다.
    """
    manifest = _manifest(
        files=[
            {"artifact": "registry:SYSTEM", "record_count": 34855, "dirty_hive": 1}
        ]
    )
    (row,) = _context(docs, manifest=manifest)["examined"]
    assert "더티 하이브" in row["note"]
    assert ".LOG1" in row["note"], "분석가가 무엇을 해야 하는지가 문구에 있어야 한다"


def test_recovered_chunks_say_the_records_came_from_outside_the_header(docs):
    """실측: 헤더가 chunk_count=1 인데 청크 4개를 복구했다(Sysmon 244건).

    그 레코드가 정상 경로에서 나온 것이 아니라는 사실이 산출물에 남아야 한다.
    """
    manifest = _manifest(
        files=[
            {"artifact": "evtx:Sysmon", "record_count": 244, "recovered_chunks": 3}
        ]
    )
    (row,) = _context(docs, manifest=manifest)["examined"]
    assert "선언하지 않은 청크 3개" in row["note"]


def test_fixup_failures_point_at_the_sector_size_not_just_corruption(docs):
    """4Kn 디스크에서 나오는 것은 오류가 아니라 "$MFT: 0건" 이다.

    비율로 판단하라는 말이 문구에 있어야 그 표에서 바로 갈린다.
    """
    manifest = _manifest(
        files=[{"artifact": "$MFT", "record_count": 0, "fixup_errors": 98151}]
    )
    (row,) = _context(docs, manifest=manifest)["examined"]
    assert "98,151" in row["note"]
    assert "섹터 크기" in row["note"]


def test_reasons_stack_instead_of_overwriting_each_other(docs):
    """못 읽은 것과 액면대로 보면 안 되는 것은 다른 사실이다.

    예전에는 ``note`` 가 문자열 하나라 나중 것이 앞엣것을 덮었다.
    """
    manifest = _manifest(
        files=[
            {
                "artifact": "evtx:Security",
                "record_count": 912,
                "parse_errors": 2,
                "bad_chunks": 5,
            }
        ]
    )
    (row,) = _context(docs, manifest=manifest)["examined"]
    assert "부분 판독" in row["note"]
    assert "체크섬" in row["note"]


def test_a_clean_read_gets_no_note(docs):
    """0인 집계는 문장을 만들지 않는다. 다 적으면 아무도 안 읽는 표가 된다."""
    manifest = _manifest(
        files=[
            {
                "artifact": "$MFT",
                "record_count": 98151,
                "dirty_hive": 0,
                "bad_chunks": 0,
                "fixup_errors": 0,
            }
        ]
    )
    (row,) = _context(docs, manifest=manifest)["examined"]
    assert row["note"] == ""


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
            "--in", str(GOLDEN / "06_verified.json"),
            "--findings", str(FIXTURES / "05_findings.json"),
            "--selection", str(GOLDEN / "03_selection.json"),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--parsed", str(PARSED),
            "--out", str(out),
        ]
    )
    assert code == 0

    def strip_volatile(text: str) -> list[str]:
        return [line for line in text.splitlines() if not line.startswith("생성: ")]

    assert strip_volatile(out.read_text(encoding="utf-8")) == strip_volatile(
        (GOLDEN / "07_report.md").read_text(encoding="utf-8")
    )


def test_cli_output_is_lf_only(tmp_path):
    out = tmp_path / "07_report.md"
    report_mod.main(
        [
            "--in", str(GOLDEN / "06_verified.json"),
            "--findings", str(FIXTURES / "05_findings.json"),
            "--selection", str(GOLDEN / "03_selection.json"),
            "--out", str(out),
        ]
    )
    assert b"\r\n" not in out.read_bytes()


def test_cli_aborts_on_a_schema_violating_input(tmp_path):
    broken = tmp_path / "06_verified.json"
    doc = io.read_json(GOLDEN / "06_verified.json")
    doc["stats"]["hallucination_rate"] = 5.0
    io.write_json(broken, doc)

    with pytest.raises(SystemExit):
        report_mod.main(
            [
                "--in", str(broken),
                "--findings", str(FIXTURES / "05_findings.json"),
                "--selection", str(GOLDEN / "03_selection.json"),
                "--out", str(tmp_path / "07_report.md"),
            ]
        )
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["type"] == "schema_violation"


def test_the_report_pairs_each_technique_with_its_evidence_quote():
    """기법 옆에 02단계가 근거로 삼은 구간이 실린다.

    **오배정을 기계가 판정하지 않는 대신 사람에게 보인다.** 어느 절이 어느
    기법이어야 하는지를 아는 표를 두면 그 표가 곧 분석이 되어 02단계를
    대체한다(`work.md` 7-2). 그래서 나란히 놓기만 한다.

    실측(`K-LIVE-0902-wide` 3차, 2026-09-04): `계정 관련 변경이` 가
    `T1543.003`(Windows Service 생성)에 붙었는데, 기법 ID 만 인쇄하던
    때에는 보고서 어디에도 드러나지 않았다.
    """
    scenario = io.read_json(FIXTURES / "02_scenario.json")
    context = report_mod.build_context(
        io.read_json(GOLDEN / "06_verified.json"),
        io.read_json(FIXTURES / "05_findings.json"),
        io.read_json(GOLDEN / "03_selection.json"),
        manifest=io.read_json(FIXTURES / "04_parsed" / "_manifest.json"),
        scenario=scenario,
    )
    pairs = {item["id"]: item["evidence_text"] for item in context["technique_evidence"]}
    assert pairs, "기법-근거 쌍이 비었다"
    for technique in scenario["techniques"]:
        assert pairs[technique["id"]] == technique["evidence_text"]

    rendered = report_mod.render(context)
    for technique in scenario["techniques"]:
        assert technique["evidence_text"] in rendered


# ============================================== 서사는 판정된 문장만 싣는가


def _with_story(docs, sentences, review):
    docs["findings"]["incident_story"] = {
        "summary": "요약",
        "critical_threat": "위협",
        "sentences": sentences,
    }
    docs["verified"]["story_review"] = review
    return docs


def test_the_narrative_carries_only_sentences_stage_06_upheld(docs):
    """기각·부족 판정을 받은 서사 문장은 본문에 실리지 않는다.

    소견은 전부 대조하면서 산문만 검증을 우회하면, 보고서에서 가장 먼저
    읽히는 자리가 검증되지 않은 문장이 된다.
    """
    docs = _with_story(
        docs,
        [
            {"id": "N1", "text": "웹셸이 업로드됐다", "kind": "observed_fact", "refs": ["MFT#12345"]},
            {"id": "N2", "text": "공격자가 관리자를 탈취했다", "kind": "analytical_assessment", "refs": []},
        ],
        [
            {"sentence_id": "N1", "verdict": "supported", "reason": ""},
            {"sentence_id": "N2", "verdict": "insufficient", "reason": "근거 없음"},
        ],
    )
    context = _context(docs)
    assert [item["id"] for item in context["story"]["sentences"]] == ["N1"]
    assert context["story"]["dropped"] == 1

    text = render(context)
    assert "웹셸이 업로드됐다" in text
    assert "공격자가 관리자를 탈취했다" not in text
    assert "서사 1문장은 인용 근거가 기각되었거나 부족하여 제외" in text


def test_a_warning_sentence_survives_with_its_reason(docs):
    """노란불 문장은 버리지 않고 사유와 함께 남긴다.

    표기 차이 하나로 서사가 통째로 끊기던 자리다. 남기되 분석가가 볼
    것을 함께 적지 않으면 초록불과 구별되지 않는다.
    """
    docs = _with_story(
        docs,
        [{"id": "N1", "text": "OneDrive 가 범위 밖에서 실행됐다", "kind": "observed_fact", "refs": ["MFT#12345"]}],
        [
            {
                "sentence_id": "N1",
                "verdict": "supported_with_warning",
                "reason": "핵심 근거는 보존하되 수동 검증이 필요함",
            }
        ],
    )
    text = render(_context(docs))
    assert "OneDrive 가 범위 밖에서 실행됐다" in text
    assert "분석가 확인 권장: 핵심 근거는 보존하되 수동 검증이 필요함" in text


def test_an_unreviewed_narrative_is_counted_not_printed(docs):
    """06단계가 보지 않은 서사는 개수만 밝히고 본문에 넣지 않는다.

    05단계가 ``story_critic`` 을 내지 않으면 ``story_review`` 자체가 없다.
    그때 서사를 그대로 인쇄하면 검증을 우회한 산문이 되고, 아무 말도 하지
    않으면 05단계 설정이 빠진 것을 아무도 모른다.
    """
    docs = _with_story(
        docs,
        [{"id": "N1", "text": "검토되지 않은 문장", "kind": "unknown", "refs": []}],
        [],
    )
    docs["verified"].pop("story_review", None)
    context = _context(docs)
    assert context["story"] == {"sentences": [], "dropped": 0, "unreviewed": 1}

    text = render(context)
    assert "검토되지 않은 문장" not in text
    assert "06단계 검토 기록이 없어 제외" in text


def test_no_narrative_means_no_section(docs):
    """05단계가 서사를 내지 않으면 섹션 자체가 없다."""
    text = render(_context(docs))
    assert "사건 개요 서사" not in text


# ================================================ 2차 조사 요청 (05→02 루프백)
#
# 이 절의 요지는 **기각된 요청**입니다. 모델이 "더 봐야 한다"고 했는데 보지
# 않은 자리이므로 미확인 사항이고, 사유가 함께 실리지 않으면 분석가는 그런
# 요청이 있었는지조차 모릅니다.


def _requests_doc(*items):
    return io.new_document(
        "C-001",
        "05_investigate",
        "interpret.py / qwen2.5:latest",
        round=1,
        requests=list(items),
    )


def _accepted_technique():
    return {
        "type": "request_technique",
        "based_on_ref": "EVTX-SEC#40912",
        "rationale": "생성된 계정으로 데이터가 나갔는지 봐야 한다",
        "technique_id": "T1041",
        "disposition": {
            "verdict": "accepted",
            "reason": "applied",
            "detail": "T1041 를 시나리오에 추가했습니다 (2차 조사 요청).",
        },
    }


def _rejected_artifact():
    return {
        "type": "request_artifact",
        "based_on_ref": "MFT#12345",
        "rationale": "대화형 파워셸 입력 이력 확인",
        "artifact": "psreadline_history",
        "disposition": {
            "verdict": "rejected",
            "reason": "unsupported_artifact",
            "detail": "psreadline_history: 본 버전 미지원 (전용 파서 없음)",
        },
    }


def test_without_a_request_file_the_section_is_absent(docs):
    """루프백을 안 돌린 케이스에까지 "돌리지 않았습니다"를 인쇄하면
    그 문장이 곧 소음이 된다."""
    assert "2차 조사 요청" not in render(_context(docs))


def test_a_rejected_request_says_what_was_not_looked_at(docs):
    context = build_context(
        docs["verified"], docs["findings"], docs["selection"], docs["scenario"],
        requests_doc=_requests_doc(_rejected_artifact()),
    )
    text = render(context)

    assert "2차 조사 요청과 그 처리" in text
    assert "확인하지 않음" in text
    # 사유는 스키마의 어휘가 아니라 사람이 읽을 문장으로 나온다.
    assert "이 버전이 읽지 못하는 아티팩트입니다" in text
    # 모델이 왜 그것을 보자고 했는지도 남아야 한다. 사유만 있으면 그 요청이
    # 무엇을 쫓고 있었는지가 사라진다.
    assert "대화형 파워셸 입력 이력 확인" in text


def test_an_accepted_request_says_what_changed(docs):
    context = build_context(
        docs["verified"], docs["findings"], docs["selection"], docs["scenario"],
        requests_doc=_requests_doc(_accepted_technique()),
    )
    text = render(context)

    assert "2차에서 확인" in text
    assert "T1041" in text


def test_a_time_request_prints_the_window_it_asked_for(docs):
    context = build_context(
        docs["verified"], docs["findings"], docs["selection"], docs["scenario"],
        requests_doc=_requests_doc(
            {
                "type": "expand_time_range",
                "based_on_ref": "MFT#12345",
                "rationale": "유입 경로가 기간 밖일 수 있다",
                "pivot_time": "2026-07-20T03:14:22Z",
                "window_hours": 6,
                "disposition": {
                    "verdict": "rejected",
                    "reason": "no_widening",
                    "detail": "이미 1차 범위 안입니다.",
                },
            }
        ),
    )
    text = render(context)
    assert "2026-07-20T03:14:22Z ± 6시간" in text
    assert "이미 분석 기간이 덮고 있습니다" in text


def test_every_rejection_reason_has_a_sentence():
    """스키마의 어휘가 늘었는데 보고서가 모르면, 그 사유는 코드값 그대로
    인쇄되어 분석가가 읽을 수 없게 된다."""
    from src.common import schema

    document = schema.load_schema("investigation")
    vocabulary = set(document["$defs"]["disposition"]["properties"]["reason"]["enum"])
    # applied 는 수용이라 detail 을 그대로 싣는다. 나머지는 전부 문장이 있어야 한다.
    assert vocabulary - {"applied"} == set(report_mod.REJECTION_LABELS)


def test_every_request_kind_has_a_label():
    """요청 종류가 늘었을 때도 같다."""
    from src.common import schema

    document = schema.load_schema("investigation")
    kinds = {
        branch["properties"]["type"]["const"]
        for branch in document["properties"]["requests"]["items"]["oneOf"]
    }
    assert kinds == set(report_mod.REQUEST_LABELS)
