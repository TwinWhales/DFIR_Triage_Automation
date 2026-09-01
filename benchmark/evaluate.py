"""파이프라인 산출물을 정답과 대조해 수치를 낸다.

평가는 파이프라인의 일부가 아니라 **파이프라인을 대상으로 하는 별개
작업**입니다. `src/`를 몰라도 CLI만 호출해서 평가할 수 있어야 합니다.

## 수치만 내지 않고 어디서 놓쳤는지를 가른다

"재현율 60%"만으로는 무엇을 고쳐야 할지 알 수 없습니다. 증거를 놓치는
경로가 넷이고 대응이 전부 다릅니다.

======================  ====================================================
놓친 지점                고칠 곳
======================  ====================================================
기법을 식별 못 함         02 프롬프트 또는 모델
기법은 맞는데 미선별      매핑 테이블 (``mappings/``)
선별은 됐는데 미파싱      파서 또는 ``scope`` 범위
파싱은 됐는데 미인용      05 프롬프트 또는 ``record_filter`` 상한
======================  ====================================================

그래서 정답 레코드마다 **파싱 → 전달 → 인용 → 검증통과** 네 단계를
따로 셉니다. 어디서 끊겼는지가 바로 보입니다.

사용법::

    python benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell
    python benchmark/evaluate.py --dataset benchmark/datasets/* --out benchmark/results/run1.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import errors as errlog  # noqa: E402
from src.common import io  # noqa: E402
from src.common import refs  # noqa: E402

__all__ = ["evaluate_case", "aggregate", "main", "STAGE_FILES"]

#: 단계 → 케이스 디렉터리 안의 산출물. 소요 시간 계산에 쓴다.
STAGE_FILES: tuple[tuple[str, str], ...] = (
    ("01_input", "01_input.json"),
    ("02_normalize", "02_scenario.json"),
    ("03_select", "03_selection.json"),
    ("04_parse", "04_parsed/_manifest.json"),
    ("05_interpret", "05_findings.json"),
    ("06_verify", "06_verified.json"),
)


def _load(path: Path) -> dict[str, Any] | None:
    """없으면 ``None``. 부분 실행된 케이스도 평가할 수 있어야 한다."""
    try:
        return io.read_json(path)
    except (FileNotFoundError, ValueError):
        return None


def _ratio(hit: int, total: int) -> float | None:
    """분모가 0이면 ``None``. 0.0으로 두면 "완벽히 실패"로 잘못 읽힌다."""
    return None if total == 0 else round(hit / total, 4)


# ------------------------------------------------------------ 기법 식별


def _techniques(truth: dict[str, Any], scenario: dict[str, Any] | None) -> dict[str, Any]:
    expected = set(truth.get("expected_techniques", []))
    if scenario is None:
        return {"status": "미실행", "expected": sorted(expected)}

    identified = {t["id"] for t in scenario.get("techniques", [])}
    return {
        "status": "평가됨",
        "expected": sorted(expected),
        "identified": sorted(identified),
        "recall": _ratio(len(expected & identified), len(expected)),
        "precision": _ratio(len(expected & identified), len(identified)),
        "missed": sorted(expected - identified),
        "extra": sorted(identified - expected),
    }


# -------------------------------------------------------- 아티팩트 선별


def _selection(truth: dict[str, Any], selection: dict[str, Any] | None) -> dict[str, Any]:
    required = list(truth.get("required_artifacts", []))
    if selection is None:
        return {"status": "미실행", "required": required}

    selected = {e["artifact"] for e in selection.get("selected", [])}
    deferred = {e["artifact"]: e.get("trigger", "") for e in selection.get("deferred", [])}
    excluded = {e["artifact"]: e.get("reason", "") for e in selection.get("excluded", [])}

    detail = []
    for artifact in required:
        if artifact in selected:
            detail.append({"artifact": artifact, "status": "selected"})
        elif artifact in deferred:
            # Tier 2로 밀렸다. 본 버전은 루프백이 없으므로 결국 안 본 것이다.
            detail.append(
                {"artifact": artifact, "status": "deferred", "why": deferred[artifact]}
            )
        elif artifact in excluded:
            detail.append(
                {"artifact": artifact, "status": "excluded", "why": excluded[artifact]}
            )
        else:
            # 카탈로그에도 없다. 도구가 존재를 모르는 아티팩트다.
            detail.append({"artifact": artifact, "status": "unknown_to_tool"})

    acceptable = set(truth.get("acceptable_artifacts", []))
    return {
        "status": "평가됨",
        "recall": _ratio(sum(1 for d in detail if d["status"] == "selected"), len(required)),
        "detail": detail,
        # 정답도 허용목록도 아닌데 선별된 것. 낭비이지 오류는 아니다.
        "unnecessary": sorted(selected - set(required) - acceptable),
        "mapping_table_version": selection.get("mapping_table_version"),
    }


# ------------------------------------------- 증거 레코드 (4단계 깔때기)


def _evidence(
    truth: dict[str, Any],
    parsed_refs: set[str] | None,
    findings: dict[str, Any] | None,
    verified: dict[str, Any] | None,
) -> dict[str, Any]:
    required = [entry["ref"] for entry in truth.get("required_refs", [])]
    reasons = {entry["ref"]: entry.get("why", "") for entry in truth.get("required_refs", [])}
    if not required:
        return {"status": "정답 없음"}

    delivered = set(findings.get("input_refs", [])) if findings else set()
    cited = (
        {ref for f in findings.get("findings", []) for ref in f.get("refs", [])}
        if findings
        else set()
    )
    passed_ids = {e["id"] for e in verified.get("passed", [])} if verified else set()
    verified_refs = (
        {
            ref
            for f in (findings or {}).get("findings", [])
            if f["id"] in passed_ids
            for ref in f.get("refs", [])
        }
        if findings
        else set()
    )

    funnel = []
    for ref in required:
        funnel.append(
            {
                "ref": ref,
                "why": reasons[ref],
                "parsed": None if parsed_refs is None else ref in parsed_refs,
                "delivered": ref in delivered,
                "cited": ref in cited,
                "verified": ref in verified_refs,
            }
        )

    def _count(key: str) -> int:
        return sum(1 for row in funnel if row[key] is True)

    return {
        "status": "평가됨" if parsed_refs is not None else "부분 (04 미실행)",
        "total": len(required),
        "parsed": _count("parsed"),
        "delivered": _count("delivered"),
        "cited": _count("cited"),
        "verified": _count("verified"),
        "end_to_end_recall": _ratio(_count("verified"), len(required)),
        "funnel": funnel,
    }


# -------------------------------------------------------------- 해석 품질


def _interpretation(verified: dict[str, Any] | None) -> dict[str, Any]:
    if verified is None:
        return {"status": "미실행"}
    stats = verified.get("stats", {})
    total = stats.get("total_findings", 0)
    return {
        "status": "평가됨",
        "total_findings": total,
        "passed": stats.get("passed", 0),
        "rejected": stats.get("rejected", 0),
        "unverifiable": stats.get("unverifiable", 0),
        "hallucination_rate": stats.get("hallucination_rate"),
        "unverifiable_rate": _ratio(stats.get("unverifiable", 0), total),
        "rejection_reasons": _rejection_reasons(verified),
    }


def _rejection_reasons(verified: dict[str, Any]) -> dict[str, int]:
    """환각 유형별 분포. 프롬프트를 어디부터 고칠지 알려 준다."""
    counts: dict[str, int] = {}
    for entry in verified.get("rejected", []):
        reason = entry.get("reason", "?")
        counts[reason] = counts.get(reason, 0) + 1
    return counts


# ------------------------------------------------------------- 소요 시간


def _durations(case_dir: Path) -> dict[str, Any]:
    """단계별 소요 시간. 각 산출물의 ``generated_at`` 차이로 잰다.

    실행 시간을 따로 재지 않는 이유는, 산출물만 있으면 나중에도 계산할 수
    있어야 하기 때문입니다. 중간부터 재실행하면 값이 뒤틀리므로 음수는
    ``null``로 둡니다.
    """
    stamps: dict[str, Any] = {}
    for stage, relative in STAGE_FILES:
        document = _load(case_dir / relative)
        if document:
            stamps[stage] = io.parse_timestamp(document.get("generated_at"))

    seconds: dict[str, float | None] = {}
    previous_stage: str | None = None
    for stage, _ in STAGE_FILES:
        moment = stamps.get(stage)
        if moment is None:
            previous_stage = None
            continue
        if previous_stage is not None:
            delta = (moment - stamps[previous_stage]).total_seconds()
            seconds[stage] = round(delta, 3) if delta >= 0 else None
        previous_stage = stage
    return seconds


# ---------------------------------------------------------------- 케이스


def _check_refs(truth: dict[str, Any], dataset: Path) -> None:
    """정답의 ``ref`` 접두어를 ``src/common/refs.py`` 로 검사한다.

    **스키마는 모양만 봅니다.** 접두어 목록을 스키마에 베껴 두면 아티팩트가
    늘 때마다 조용히 갈라집니다 — 실제로 프리패치(``PF``)·Sysmon·Amcache 가
    빠져 있어서, 그 셋이 핵심 증거인 케이스는 정답을 **적을 자리가 없었습니다.**

    어휘의 원본은 ``ARTIFACT_PREFIX`` 하나뿐이므로 여기서 그것으로 봅니다.
    오타를 조용히 넘기면 그 레코드는 영원히 "놓친 증거"로 집계됩니다.
    """
    bad: list[str] = []
    for entry in truth.get("required_refs", []):
        try:
            refs.parse_ref(entry["ref"])
        except refs.RefError as e:
            bad.append(f"  {entry['ref']!r} — {e}")
    if bad:
        raise ValueError(
            f"{dataset / 'ground_truth.json'}: 알 수 없는 ref 가 있습니다." + "\n"
            + "\n".join(bad)
            + "\n  접두어 어휘는 src/common/refs.py 의 ARTIFACT_PREFIX 가 원본입니다."
        )


def evaluate_case(dataset_dir: str | Path, case_dir: str | Path | None = None) -> dict[str, Any]:
    """데이터셋 하나를 평가한다."""
    dataset = Path(dataset_dir)
    truth = _load(dataset / "ground_truth.json")
    if truth is None:
        raise FileNotFoundError(f"정답 파일 없음: {dataset / 'ground_truth.json'}")
    _check_refs(truth, dataset)

    case = Path(case_dir) if case_dir else REPO_ROOT / "cases" / truth["case_id"]

    scenario = _load(case / "02_scenario.json")
    selection = _load(case / "03_selection.json")
    findings = _load(case / "05_findings.json")
    verified = _load(case / "06_verified.json")

    parsed_dir = case / "04_parsed"
    parsed_refs: set[str] | None = None
    if parsed_dir.is_dir() and any(parsed_dir.glob("*.jsonl")):
        parsed_refs = set(io.read_parsed_records(parsed_dir))

    errors_path = case / "errors.jsonl"
    error_tally = errlog.tally(errors_path) if errors_path.is_file() else {"total": 0}

    return {
        "case_id": truth["case_id"],
        "dataset": str(dataset),
        "case_dir": str(case),
        "authored_by": truth.get("authored_by", "?"),
        # **채점 가능 여부는 이 값이 가른다.** 없으면 사람이 만들었다고 보지
        # 않는다 — 틀리는 방향이 "자기채점을 발표에 쓴다"가 되면 안 된다.
        "provenance": truth.get("provenance", "derived_from_pipeline"),
        "generators": {
            "02_normalize": (scenario or {}).get("generator"),
            "05_interpret": (findings or {}).get("generator"),
        },
        "techniques": _techniques(truth, scenario),
        "selection": _selection(truth, selection),
        "evidence": _evidence(truth, parsed_refs, findings, verified),
        "interpretation": _interpretation(verified),
        "errors": error_tally,
        "durations_seconds": _durations(case),
    }


def aggregate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """케이스별 결과를 합친다. 분모가 다른 값을 평균 내지 않는다."""

    def _mean(values: list[float]) -> float | None:
        return round(sum(values) / len(values), 4) if values else None

    selection_recalls = [
        c["selection"]["recall"] for c in cases if c["selection"].get("recall") is not None
    ]
    technique_recalls = [
        c["techniques"]["recall"] for c in cases if c["techniques"].get("recall") is not None
    ]
    end_to_end = [
        c["evidence"]["end_to_end_recall"]
        for c in cases
        if c["evidence"].get("end_to_end_recall") is not None
    ]
    hallucination = [
        c["interpretation"]["hallucination_rate"]
        for c in cases
        if c["interpretation"].get("hallucination_rate") is not None
    ]

    # 예전에는 authored_by 가 정확히 "human" 인지로 봤다. 그러면 담당자
    # 이름을 적은 정답이 자기채점으로 집계되고, 반대로 "human" 이라고만
    # 적으면 누가 만들었는지가 사라진다. 두 질문을 필드 둘로 나눴다 —
    # authored_by 는 "누가", provenance 는 "어디서 왔나".
    human_authored = sum(1 for c in cases if c["provenance"] != "human_analysis")
    return {
        "cases": len(cases),
        "technique_recall": _mean(technique_recalls),
        "selection_recall": _mean(selection_recalls),
        "end_to_end_recall": _mean(end_to_end),
        "hallucination_rate": _mean(hallucination),
        "cases_missing_human_ground_truth": human_authored,
    }


# -------------------------------------------------------------- 출력


def _format(report: dict[str, Any]) -> str:
    lines: list[str] = []
    for case in report["cases"]:
        lines.append(f"\n=== {case['case_id']} ({case['dataset']}) ===")
        lines.append(f"  모델: {case['generators']['02_normalize'] or '미실행'}")

        tech = case["techniques"]
        if tech["status"] == "평가됨":
            lines.append(
                f"  기법 식별   재현율 {_pct(tech['recall'])}"
                f" / 정밀도 {_pct(tech['precision'])}"
                + (f"  놓침: {', '.join(tech['missed'])}" if tech["missed"] else "")
            )
        else:
            lines.append("  기법 식별   미실행")

        sel = case["selection"]
        if sel["status"] == "평가됨":
            lines.append(f"  아티팩트 선별  재현율 {_pct(sel['recall'])}")
            for row in sel["detail"]:
                if row["status"] != "selected":
                    lines.append(
                        f"      놓침: {row['artifact']} — {row['status']}"
                        + (f" ({row['why']})" if row.get("why") else "")
                    )
        else:
            lines.append("  아티팩트 선별  미실행")

        ev = case["evidence"]
        if ev["status"] != "정답 없음":
            lines.append(
                f"  증거 깔때기  파싱 {ev['parsed']}/{ev['total']}"
                f" → 전달 {ev['delivered']} → 인용 {ev['cited']}"
                f" → 검증통과 {ev['verified']}"
            )
            for row in ev["funnel"]:
                if not row["verified"]:
                    stage = _first_break(row)
                    lines.append(f"      끊김: {row['ref']} at {stage} — {row['why']}")

        interp = case["interpretation"]
        if interp["status"] == "평가됨":
            lines.append(
                f"  해석 품질   환각률 {_pct(interp['hallucination_rate'])}"
                f" / 검증불가 {_pct(interp['unverifiable_rate'])}"
                + (f"  {interp['rejection_reasons']}" if interp["rejection_reasons"] else "")
            )

        if case["errors"]["total"]:
            lines.append(f"  errors.jsonl  {case['errors']['total']}건 {case['errors'].get('by_type', {})}")

    totals = report["totals"]
    lines.append(f"\n=== 종합 ({totals['cases']}개 케이스) ===")
    lines.append(f"  기법 식별 재현율   {_pct(totals['technique_recall'])}")
    lines.append(f"  아티팩트 선별 재현율 {_pct(totals['selection_recall'])}")
    lines.append(f"  종단 증거 재현율   {_pct(totals['end_to_end_recall'])}")
    lines.append(f"  환각률            {_pct(totals['hallucination_rate'])}")

    if totals["cases_missing_human_ground_truth"]:
        lines.append(
            f"\n  주의: 정답을 사람이 만들지 않은 케이스가 "
            f"{totals['cases_missing_human_ground_truth']}건 있습니다. "
            "그 수치는 자기채점이라 발표에 쓸 수 없습니다."
        )
    return "\n".join(lines)


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value:.1%}"


def _first_break(row: dict[str, Any]) -> str:
    """깔때기에서 처음 끊긴 지점."""
    for stage in ("parsed", "delivered", "cited", "verified"):
        if row[stage] is not True:
            return stage
    return "?"


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python benchmark/evaluate.py",
        description="파이프라인 산출물을 정답과 대조해 수치를 낸다.",
    )
    parser.add_argument(
        "--dataset", action="append", required=True, help="정답이 있는 데이터셋 디렉터리 (반복 가능)"
    )
    parser.add_argument("--case", default=None, help="산출물 디렉터리. 생략하면 cases/<case_id>")
    parser.add_argument("--out", default=None, help="결과 JSON 경로")
    args = parser.parse_args(argv)

    io.configure_console()

    if args.case and len(args.dataset) > 1:
        parser.error("--case 는 데이터셋이 하나일 때만 쓸 수 있습니다")

    cases = [evaluate_case(dataset, args.case) for dataset in args.dataset]
    report = io.new_document(
        cases[0]["case_id"] if len(cases) == 1 else "ALL",
        "benchmark",
        io.make_generator("evaluate.py"),
        cases=cases,
        totals=aggregate(cases),
    )

    print(_format(report))
    if args.out:
        io.write_json(args.out, report)
        print(f"\n결과: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
