"""평가 계층 테스트.

평가는 파이프라인을 채점하는 쪽이라, **여기가 틀리면 모든 수치가
거짓이 됩니다.** 특히 두 가지를 고정합니다.

- 놓친 증거가 **어느 단계에서** 끊겼는지 정확히 가리키는가
- 자기채점 케이스에 경고가 뜨는가
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from benchmark import evaluate, validator_check
from src.common import io, schema
from casepaths import FIXTURES, case_file

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "benchmark/datasets/C-001-webshell"


@pytest.fixture
def case_dir(tmp_path):
    """목업을 그대로 옮긴 케이스 디렉터리."""
    import shutil

    target = tmp_path / "C-001"
    target.mkdir()
    for name in (
        "01_input.json", "02_scenario.json", "03_selection.json",
        "05_findings.json", "06_verified.json", "errors.jsonl",
    ):
        shutil.copy(case_file(name), target / name)
    shutil.copytree(FIXTURES / "04_parsed", target / "04_parsed")
    return target


@pytest.fixture
def truth():
    return copy.deepcopy(io.read_json(DATASET / "ground_truth.json"))


def _dataset_with(tmp_path, truth):
    directory = tmp_path / "dataset"
    directory.mkdir()
    io.write_json(directory / "ground_truth.json", truth)
    return directory


# ==================================================== 정답 파일 자체


def test_shipped_ground_truth_matches_its_schema():
    document = io.read_json(DATASET / "ground_truth.json")
    import jsonschema

    jsonschema.validate(document, io.read_json(REPO_ROOT / "benchmark/ground_truth_schema.json"))


def test_ground_truth_refs_exist_in_the_parsed_mock():
    # 정답이 실재하지 않는 레코드를 가리키면 재현율이 영원히 100%에 못 간다.
    parsed = set(io.read_parsed_records(FIXTURES / "04_parsed"))
    for entry in io.read_json(DATASET / "ground_truth.json")["required_refs"]:
        assert entry["ref"] in parsed, entry["ref"]


# ======================================================= 전체 평가


def test_a_clean_run_scores_perfectly(case_dir, truth, tmp_path):
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)
    assert result["techniques"]["recall"] == 1.0
    assert result["selection"]["recall"] == 1.0
    assert result["evidence"]["end_to_end_recall"] == 1.0
    assert result["interpretation"]["hallucination_rate"] == 0.0


def test_missing_stages_are_reported_not_scored_as_zero(truth, tmp_path):
    # 아직 안 돌린 것과 돌렸는데 실패한 것은 다르다.
    empty = tmp_path / "empty-case"
    empty.mkdir()
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), empty)
    assert result["techniques"]["status"] == "미실행"
    assert result["selection"]["status"] == "미실행"
    assert result["interpretation"]["status"] == "미실행"


def test_zero_denominator_gives_none_not_zero():
    # 0.0으로 두면 "완벽히 실패"로 잘못 읽힌다.
    assert evaluate._ratio(0, 0) is None
    assert evaluate._ratio(0, 2) == 0.0


# ------------------------------- 환각률 0.0% 가 두 뜻으로 읽히던 것
#
# 실측(`docs/limitations.md` 실물 규모 A/B) — 제약을 끈 쪽이 소견 1건을
# `claims` 빈 배열로 내 06 이 unverifiable 로 넘겼다. 분모가 0이라 환각률이
# 0.0% 로 찍혔고, 제약을 켠 쪽의 **진짜** 0.0%(판정 3건 전부 통과)와 표에서
# 구별되지 않았다.


def _stats(passed, rejected, unverifiable):
    """06 이 실제로 싣는 모양. 동결 스키마가 ``number`` 를 요구하므로
    ``hallucination_rate`` 는 판정 0건일 때도 0.0 이다."""
    judged = passed + rejected
    return {
        "total_findings": passed + rejected + unverifiable,
        "passed": passed,
        "rejected": rejected,
        "unverifiable": unverifiable,
        "hallucination_rate": round(rejected / judged, 4) if judged else 0.0,
    }


def test_nothing_judged_is_not_a_rate():
    from src.stage06_verify import verify as verify_mod

    assert verify_mod.judged_rate(_stats(0, 0, 1)) is None
    assert verify_mod.judged_rate(_stats(3, 0, 0)) == 0.0, "이쪽은 진짜 0%다"
    assert verify_mod.judged_rate(_stats(1, 1, 5)) == 0.5


def test_the_printed_line_says_which_zero_it_is():
    from src.stage06_verify import verify as verify_mod

    assert "판정 0건" in verify_mod.format_rate(_stats(0, 0, 1))
    assert "0.0%" in verify_mod.format_rate(_stats(3, 0, 0))
    assert "판정 3건" in verify_mod.format_rate(_stats(3, 0, 0))


def test_a_case_with_nothing_judged_reports_no_rate(case_dir, truth, tmp_path):
    verified = io.read_json(case_dir / "06_verified.json")
    verified["unverifiable"] = [
        {"id": e["id"], "reason": "claims 없음 (종합 판단 문장)"}
        for e in verified["passed"] + verified["rejected"]
    ] + verified["unverifiable"]
    verified["passed"] = []
    verified["rejected"] = []
    verified["stats"] = _stats(0, 0, len(verified["unverifiable"]))
    io.write_json(case_dir / "06_verified.json", verified)

    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)
    assert result["interpretation"]["status"] == "평가됨"
    assert result["interpretation"]["hallucination_rate"] is None
    assert result["interpretation"]["judged"] == 0


def test_an_unjudged_case_does_not_drag_the_average_to_zero():
    """이것이 이 결함의 실제 대가다 — 잴 것이 없던 실행이 다른 케이스의
    환각률을 절반으로 깎아 발표 수치를 좋게 만든다."""
    real = {
        "provenance": "human_analysis",
        "techniques": {}, "selection": {}, "evidence": {},
        "interpretation": {"status": "평가됨", "hallucination_rate": 0.4},
    }
    nothing = {
        "provenance": "human_analysis",
        "techniques": {}, "selection": {}, "evidence": {},
        "interpretation": {"status": "평가됨", "hallucination_rate": None},
    }
    totals = evaluate.aggregate([real, nothing])
    assert totals["hallucination_rate"] == 0.4, "0.2 가 되면 평균에 0을 섞은 것이다"
    assert totals["hallucination_cases"] == 1
    assert totals["cases_with_nothing_judged"] == 1, "빠졌다는 사실 자체가 수치다"


# -------------------------------------------- 어디서 놓쳤는지 가리는가


def test_a_technique_the_model_missed_is_named(case_dir, truth, tmp_path):
    truth["expected_techniques"] = ["T1505.003", "T1136.001", "T1486"]
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)
    assert result["techniques"]["missed"] == ["T1486"]
    assert result["techniques"]["recall"] == pytest.approx(2 / 3, abs=1e-4)


def test_an_artifact_pushed_to_tier2_counts_as_missed(case_dir, truth, tmp_path):
    # 본 버전은 Tier 2 루프백이 없으므로 deferred는 결국 안 본 것이다.
    truth["required_artifacts"] = ["$MFT", "$UsnJrnl"]
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)

    statuses = {row["artifact"]: row["status"] for row in result["selection"]["detail"]}
    assert statuses["$UsnJrnl"] == "deferred"
    assert result["selection"]["recall"] == 0.5


def test_an_excluded_artifact_reports_the_reason(case_dir, truth, tmp_path):
    # prefetch 가 한때 이 자리였다. 파서가 생겨 supported 로 뒤집히면서
    # 제외 사유가 "미지원"에서 "매핑되지 않음"으로 바뀌었고, 이 테스트가
    # 보려는 것은 앞엣것이라 $LogFile 로 옮겼다.
    truth["required_artifacts"] = ["$MFT", "$LogFile"]
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)

    row = next(r for r in result["selection"]["detail"] if r["artifact"] == "$LogFile")
    assert row["status"] == "excluded"
    assert "미지원" in row["why"]


def test_an_artifact_the_tool_never_heard_of_is_distinguished(case_dir, truth, tmp_path):
    # 카탈로그에 없는 것과 제외된 것은 대응이 다르다.
    truth["required_artifacts"] = ["$MFT", "browser:chrome"]
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)

    row = next(r for r in result["selection"]["detail"] if r["artifact"] == "browser:chrome")
    assert row["status"] == "unknown_to_tool"


# ------------------------------------------------- 증거 깔때기


def test_the_funnel_shows_every_stage(case_dir, truth, tmp_path):
    evidence = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)["evidence"]
    assert evidence["parsed"] == evidence["delivered"] == evidence["cited"] == evidence["verified"] == 3


def test_a_record_parsed_but_never_delivered_breaks_at_delivery(case_dir, truth, tmp_path):
    # MFT#12400은 파싱은 됐으나 record_filter가 걸러 LLM에 안 갔다.
    truth["required_refs"] = [{"ref": "MFT#12400", "why": "테스트"}]
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)

    row = result["evidence"]["funnel"][0]
    assert row["parsed"] is True
    assert row["delivered"] is False
    assert evaluate._first_break(row) == "delivered"


def test_a_record_that_was_never_parsed_breaks_at_parsing(case_dir, truth, tmp_path):
    truth["required_refs"] = [{"ref": "MFT#99999", "why": "존재하지 않음"}]
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)
    assert evaluate._first_break(result["evidence"]["funnel"][0]) == "parsed"


def test_a_rejected_finding_does_not_count_as_verified(case_dir, truth, tmp_path):
    verified = io.read_json(case_dir / "06_verified.json")
    verified["passed"] = [e for e in verified["passed"] if e["id"] != "F1"]
    verified["rejected"] = [{"id": "F1", "reason": "value_mismatch", "detail": {}}]
    io.write_json(case_dir / "06_verified.json", verified)

    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)
    row = next(r for r in result["evidence"]["funnel"] if r["ref"] == "MFT#12345")
    assert row["cited"] is True and row["verified"] is False


def test_without_stage04_the_funnel_says_so(truth, tmp_path):
    import shutil

    partial = tmp_path / "partial"
    partial.mkdir()
    for name in ("02_scenario.json", "03_selection.json", "05_findings.json", "06_verified.json"):
        shutil.copy(case_file(name), partial / name)

    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), partial)
    assert "04 미실행" in result["evidence"]["status"]
    assert result["evidence"]["funnel"][0]["parsed"] is None


# ------------------------------------------------------ 자기채점 경고


def test_ground_truth_not_written_by_a_human_is_flagged(case_dir, truth, tmp_path):
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)
    assert evaluate.aggregate([result])["cases_missing_human_ground_truth"] == 1


def test_human_analysed_ground_truth_is_not_flagged(case_dir, truth, tmp_path):
    truth["provenance"] = "human_analysis"
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)
    assert evaluate.aggregate([result])["cases_missing_human_ground_truth"] == 0


def test_a_named_author_is_not_mistaken_for_self_scoring(case_dir, truth, tmp_path):
    """**판정 회귀.**

    예전에는 ``authored_by`` 가 정확히 ``"human"`` 인지로 갈랐다. 담당자가
    자기 이름을 적으면 그 케이스가 "정답을 사람이 만들지 않았다"로 집계돼,
    증거를 직접 보고 만든 정답이 자기채점 취급을 받는다. 넘겨받는 사람이
    가장 먼저 밟을 자리다.
    """
    truth["authored_by"] = "홍길동 (2026-09-05, PECmd·EvtxECmd 로 직접 분석)"
    truth["provenance"] = "human_analysis"
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)
    assert evaluate.aggregate([result])["cases_missing_human_ground_truth"] == 0


def test_ground_truth_without_provenance_is_treated_as_self_scored(case_dir, truth, tmp_path):
    """틀리는 방향이 "자기채점을 발표에 쓴다" 가 되면 안 된다."""
    truth.pop("provenance", None)
    result = evaluate.evaluate_case(_dataset_with(tmp_path, truth), case_dir)
    assert evaluate.aggregate([result])["cases_missing_human_ground_truth"] == 1


def test_the_shipped_dataset_admits_it_is_not_scorable():
    # 스펙 예시에서 역산한 정답이다. 자기채점이라 발표에 쓸 수 없다.
    assert io.read_json(DATASET / "ground_truth.json")["provenance"] != "human_analysis"


# --------------------------------------------------- ref 접두어 어휘


def test_every_known_artifact_prefix_fits_the_schema():
    """**스키마에 접두어 목록을 베껴 두지 않는다.**

    예전 스키마는 여섯 종(``MFT``·``USN``·``EVTX-SEC``·``EVTX-SYS``·
    ``REG-SYS``·``REG-SW``)만 받았다. 그래서 키오스크 정답의 핵심 증거인
    프리패치(``PF``)·Sysmon·Amcache 는 **적을 자리가 없었다.** 지금 스키마는
    모양만 보고 어휘는 ``refs.py`` 가 본다.
    """
    import re

    from src.common import refs

    schema = io.read_json(REPO_ROOT / "benchmark/ground_truth_schema.json")
    pattern = re.compile(
        schema["properties"]["required_refs"]["items"]["properties"]["ref"]["pattern"]
    )
    for prefix in sorted(set(refs.ARTIFACT_PREFIX.values())):
        assert pattern.match(f"{prefix}#1"), f"{prefix} 를 정답에 적을 수 없다"


def test_an_unknown_ref_prefix_is_refused_not_counted_as_missed(truth, tmp_path):
    """오타를 조용히 넘기면 그 레코드는 영원히 "놓친 증거" 로 집계된다."""
    truth["required_refs"] = [{"ref": "MTF#12345", "why": "오타"}]
    with pytest.raises(ValueError, match="알 수 없는 ref"):
        evaluate.evaluate_case(_dataset_with(tmp_path, truth))


# ---------------------------------------------------------------- CLI


def test_evaluate_cli_writes_a_report(case_dir, truth, tmp_path, capsys):
    out = tmp_path / "result.json"
    assert (
        evaluate.main(
            ["--dataset", str(_dataset_with(tmp_path, truth)), "--case", str(case_dir),
             "--out", str(out)]
        )
        == 0
    )
    report = io.read_json(out)
    assert report["totals"]["cases"] == 1
    assert "자기채점" in capsys.readouterr().out


def test_evaluate_cli_refuses_case_with_multiple_datasets(tmp_path, truth):
    dataset = _dataset_with(tmp_path, truth)
    with pytest.raises(SystemExit):
        evaluate.main(["--dataset", str(dataset), "--dataset", str(dataset), "--case", "x"])


# ================================================ validator_check


def test_every_hand_authored_statement_survives_verification():
    # 하나라도 기각되면 검증기가 과엄격한 것이다. 환각률이 실제 환각이
    # 아니라 표기 차이를 세고 있다는 뜻이다.
    report = validator_check.run(io.read_json(validator_check.DEFAULT_CASES), validator_check.DEFAULT_PARSED)
    assert report["false_rejections"] == 0, [
        (r["id"], r["rejection"])
        for r in report["results"]
        if r["got"] == "rejected" and r["expected"] != "rejected"
    ]
    assert report["pass_rate"] == 1.0


def test_known_gaps_carry_a_reason_and_are_still_broken():
    """expect 가 rejected 인 사례는 '아직 못 고친 것'이다.

    둘을 함께 본다 — 사유(``gap``)가 적혀 있는가, 그리고 **아직도 실제로
    기각되는가.** 고쳐졌는데 목록에 남아 있으면 그 자리에서 진짜 회귀가
    일어나도 기대대로라고 보고된다. `_KNOWN_GAPS` 가 낡지 않게 하는
    test_flag_rules 의 검사와 같은 취지다.
    """
    cases = io.read_json(validator_check.DEFAULT_CASES)["cases"]
    gaps = [c for c in cases if c.get("expect") == "rejected"]
    for case in gaps:
        assert case.get("gap"), f"{case['id']}: 어디서 고쳐야 하는지 적혀 있지 않다"

    if not gaps:
        return
    report = validator_check.run(
        io.read_json(validator_check.DEFAULT_CASES), validator_check.DEFAULT_PARSED
    )
    got = {r["id"]: r["got"] for r in report["results"]}
    for case in gaps:
        assert got[case["id"]] == "rejected", (
            f"{case['id']} 이 이제 통과합니다 — 고쳐졌으니 expect 를 passed 로 "
            "되돌리고 gap 을 지우십시오."
        )


def test_the_check_actually_catches_an_over_strict_verifier():
    # 항상 통과라고 말하는 검사기는 쓸모없다.
    report = validator_check.run(
        io.read_json(validator_check.DEFAULT_CASES),
        validator_check.DEFAULT_PARSED,
        tolerance_seconds=0,
    )
    assert report["false_rejections"] > 0
    assert "V1" in {r["id"] for r in report["results"] if r["got"] == "rejected"}


def test_validator_cases_build_a_schema_valid_document():
    document = validator_check.build_findings(io.read_json(validator_check.DEFAULT_CASES))
    schema.validate(document, "findings")


def test_summary_statements_are_expected_to_be_unverifiable():
    cases = io.read_json(validator_check.DEFAULT_CASES)["cases"]
    unverifiable = [c for c in cases if c.get("expect") == "unverifiable"]
    assert unverifiable, "종합 판단 사례가 없으면 그 경로를 시험하지 못한다"
    for case in unverifiable:
        assert case["claims"] == []


def test_every_case_documents_the_risk_it_covers():
    # 왜 이 사례가 있는지 적혀 있지 않으면 나중에 지워도 되는지 알 수 없다.
    for case in io.read_json(validator_check.DEFAULT_CASES)["cases"]:
        assert case.get("risk"), case["id"]
        assert case.get("why"), case["id"]


def test_case_ids_are_unique():
    ids = [c["id"] for c in io.read_json(validator_check.DEFAULT_CASES)["cases"]]
    assert len(ids) == len(set(ids))


def test_validator_cli_reports_success(capsys):
    assert validator_check.main([]) == 0
    assert "오탐 없음" in capsys.readouterr().out


def test_validator_cli_fails_when_the_verifier_is_too_strict(capsys):
    assert validator_check.main(["--tolerance-seconds", "0"]) == 1
    assert "과엄격" in capsys.readouterr().out


# ================================================== 기각 대장 (work.md 10번)


def _run_with_rejection(case_id, technique, artifacts, also=()):
    return {
        "case_id": case_id,
        "started_at": "2026-09-04T00:00:00Z",
        "steps": [
            {
                "key": "stage06",
                "measures": {
                    "rejections": [
                        {
                            "id": "F1",
                            "reason": "technique_unsupported",
                            "detail": {
                                "technique": technique,
                                "cited_artifacts": list(artifacts),
                                "supported_artifacts": ["$MFT"],
                                "also_supports": list(also),
                            },
                        }
                    ]
                },
            }
        ],
    }


def test_the_same_combination_across_runs_is_counted_once_with_a_tally():
    # 소견 단위로 세면 같은 원인이 실행마다 다른 항목으로 보인다. 매핑을
    # 넓힐 때 적는 값이 (기법, 인용 아티팩트) 조합이므로 그 단위로 묶는다.
    from benchmark import collect

    runs = [
        _run_with_rejection("A", "T1091", ["evtx:Sysmon"]),
        _run_with_rejection("B", "T1091", ["evtx:Sysmon"]),
        _run_with_rejection("B", "T1505.003", ["prefetch"]),
    ]
    rows = collect.rejections(runs)
    by_technique = {row["technique"]: row for row in rows}
    assert by_technique["T1091"]["count"] == 2
    assert by_technique["T1091"]["cases"] == ["A", "B"]
    assert by_technique["T1505.003"]["count"] == 1


def test_other_rejection_reasons_are_not_counted():
    # 이 표는 매핑을 넓힐 근거만 모은다. ref_in_input 같은 기각이 섞이면
    # "매핑이 좁다"는 신호가 희석된다.
    from benchmark import collect

    run = _run_with_rejection("A", "T1091", ["evtx:Sysmon"])
    run["steps"][0]["measures"]["rejections"][0]["reason"] = "value_mismatch"
    assert collect.rejections([run]) == []


def test_an_adjudicated_combination_is_marked_and_sinks(monkeypatch):
    """가른 것은 아래로 내린다 — 표의 첫 줄이 곧 할 일이어야 한다."""
    from benchmark import collect

    monkeypatch.setattr(
        collect,
        "load_ledger",
        lambda *a, **k: {("T1091", ("evtx:Sysmon",)): {"verdict": "model_wrong", "decided_on": "x"}},
    )
    rows = collect.rejections(
        [
            _run_with_rejection("A", "T1091", ["evtx:Sysmon"]),
            _run_with_rejection("A", "T1091", ["evtx:Sysmon"]),
            _run_with_rejection("A", "T1505.003", ["prefetch"]),
        ]
    )
    # 안 가른 T1505.003 은 1회뿐인데도 2회짜리 T1091 보다 위다.
    assert [row["technique"] for row in rows] == ["T1505.003", "T1091"]
    assert rows[1]["verdict"] == "model_wrong"


def test_the_shipped_ledger_is_readable_and_uses_known_verdicts():
    # 이 파일은 손으로 쓴다. 오타가 조용히 흘러가면 이미 가른 기각이
    # 표에 다시 올라오고, 같은 것을 두 번 판단하게 된다.
    from benchmark import collect

    ledger = collect.load_ledger()
    assert ledger, "benchmark/rejections.yaml 을 읽지 못했다"
    for (technique, artifacts), entry in ledger.items():
        assert technique.startswith("T"), technique
        assert artifacts, technique
        assert entry["verdict"] in {"model_wrong", "mapping_narrow"}, entry
        assert entry.get("note"), f"{technique}: 근거 없는 판단은 나중에 뒤집을 수 없다"


def test_a_mapping_narrow_verdict_must_be_reflected_in_corroborates():
    """`mapping_narrow` 라고 적었으면 그 매핑이 실제로 넓어져 있어야 한다.

    적어 놓고 YAML 을 안 고치면 그 기각은 표에서 사라지는데 검사기는 여전히
    기각한다 — **판단했다는 기록이 판단하지 않은 것을 덮는다.**
    """
    from benchmark import collect
    from src.stage06_verify.verify import technique_artifacts

    table = technique_artifacts(REPO_ROOT / "mappings")
    for (technique, artifacts), entry in collect.load_ledger().items():
        if entry["verdict"] != "mapping_narrow":
            continue
        supported = table.get(technique, frozenset())
        missing = sorted(set(artifacts) - supported)
        assert not missing, f"{technique} 의 corroborates 에 {missing} 가 없다"
