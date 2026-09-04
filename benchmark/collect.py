"""``results/`` 에 쌓인 실행 기록을 한 표로 모은다.

**발표에 쓸 세 수치가 세 군데서 나온다** — 재현율은 ``evaluate.py``, 환각률은
``06_verified.json``, 소요 시간은 ``live_check.json``. 실행을 한 번 할 때마다
그 값들을 손으로 옮겨 적으면, 옮겨 적다 틀린 것과 실제로 달라진 것을 구별할 수
없다. 그래서 옮겨 적지 않고 읽는다.

읽는 것은 ``tools/live_check.py`` 가 남긴 기록뿐이다. 재현율은 정답 데이터가
있어야 나오므로 ``evaluate.py`` 가 따로 낸다 — 여기서 흉내 내지 않는다.

사용법::

    python benchmark/collect.py                 # 표
    python benchmark/collect.py --json          # 원본 그대로
    python benchmark/collect.py --case LC-      # 케이스 이름으로 거른다
    python benchmark/collect.py --rejections    # 기각을 조합별로 센다

``--rejections`` 는 다른 것을 본다. 위의 표가 "이번 실행이 어땠나"라면
이쪽은 **"매핑을 넓힐 근거가 쌓였나"** 다. ``technique_unsupported`` 기각
하나는 두 원인을 섞으므로(모델이 틀렸나, 매핑이 좁나) 사람이 갈라야 하고,
가른 결과는 ``benchmark/rejections.yaml`` 에 남는다. 이 표는 **아직 안 가른
것**을 위로 올린다 — 첫 줄이 곧 할 일이다(``work.md`` 10번).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import io  # noqa: E402

__all__ = ["collect", "summarize", "rejections", "load_ledger", "main"]

RESULTS_DIR = REPO_ROOT / "benchmark/results"


def collect(results_dir: Path, prefix: str | None = None) -> list[dict[str, Any]]:
    """기록을 시작 시각 순으로 읽는다. 읽을 수 없는 파일은 건너뛰지 않고 알린다."""
    runs: list[dict[str, Any]] = []
    for path in sorted(results_dir.glob("*.json")):
        try:
            document = io.read_json(path)
        except (ValueError, FileNotFoundError) as e:
            print(f"[collect] 건너뜀 {path.name}: {e}", file=sys.stderr)
            continue
        if prefix and not str(document.get("case_id", "")).startswith(prefix):
            continue
        document["_file"] = path.name
        runs.append(document)
    return sorted(runs, key=lambda d: d.get("started_at", ""))


def summarize(run: dict[str, Any]) -> dict[str, Any]:
    """실행 하나에서 표에 쓸 값만 뽑는다."""
    steps = run.get("steps", [])
    by_key = {s["key"]: s for s in steps}

    verdicts = [s.get("verdict") for s in steps]
    measures = by_key.get("stage06", {}).get("measures", {})

    llm = sum(s.get("seconds", 0.0) for s in steps if s.get("llm"))
    total = sum(s.get("seconds", 0.0) for s in steps)

    # 판정이 하나라도 FAIL 이면 그 실행의 수치는 부분적이다. 표에서 그것을
    # 숨기면 완주한 실행과 나란히 놓여 같은 무게로 읽힌다.
    failed = [s["key"] for s in steps if s.get("verdict") == "FAIL"]

    return {
        "case_id": run.get("case_id"),
        "started_at": run.get("started_at", "")[:19],
        "source_type": run.get("source_type"),
        "model": run.get("model_interpret") or run.get("model_normalize"),
        "passed": verdicts.count("PASS"),
        "steps": len(steps),
        "failed_at": failed[0] if failed else None,
        "findings": measures.get("total_findings"),
        # 06 이 파일에 싣는 값은 판정 0건일 때도 0.0 이다(동결 스키마가
        # ``number`` 를 요구한다). 그대로 찍으면 "전부 맞음"과 "잴 것이
        # 없었음"이 같은 칸에 앉으므로 여기서 분모를 보고 가른다.
        "judged": _judged(measures),
        "hallucination_rate": (
            measures.get("hallucination_rate") if _judged(measures) else None
        ),
        "unverifiable": measures.get("unverifiable"),
        "llm_seconds": round(llm, 1),
        "total_seconds": round(total, 1),
        "file": run.get("_file"),
    }


def _judged(measures: dict[str, Any]) -> int:
    """환각률의 분모. ``passed + rejected`` 이고 ``unverifiable`` 은 뺀다."""
    return int(measures.get("passed") or 0) + int(measures.get("rejected") or 0)


def _rate(value: Any) -> str:
    return "—" if value is None else f"{float(value):.1%}"


def _num(value: Any) -> str:
    return "—" if value is None else str(value)


def render(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return (
            f"{RESULTS_DIR} 에 기록이 없습니다.\n"
            "tools/live_check.py 를 한 번 돌리면 여기에 쌓입니다."
        )

    header = (
        # 앞의 "관문" 은 live_check 의 단계 판정 수, 뒤의 "판정" 은 06 이
        # 실제로 채점한 문장 수(= 환각률의 분모)다. 둘 다 "판정"이라고 쓰면
        # 환각률 옆의 수가 무엇의 분모인지 표에서 사라진다.
        f"{'케이스':<16} {'시작':<20} {'모델':<18} {'관문':>7} "
        f"{'findings':>9} {'판정':>5} {'환각률':>8} {'미검증':>7} {'LLM':>8} {'전체':>8}"
    )
    lines = [header, "─" * len(header)]
    for row in rows:
        verdict = f"{row['passed']}/{row['steps']}"
        if row["failed_at"]:
            verdict += "!"
        lines.append(
            f"{str(row['case_id']):<16} {row['started_at']:<20} {str(row['model'])[:18]:<18} "
            f"{verdict:>7} {_num(row['findings']):>9} {row['judged']:>5} "
            f"{_rate(row['hallucination_rate']):>8} "
            f"{_num(row['unverifiable']):>7} {row['llm_seconds']:>7.1f}초 {row['total_seconds']:>7.1f}초"
        )

    incomplete = [r for r in rows if r["failed_at"]]
    if incomplete:
        lines.append("")
        lines.append("! 는 완주하지 못한 실행이다. 수치가 부분적이므로 나란히 비교하지 않는다.")
        for row in incomplete:
            lines.append(f"    {row['case_id']}  {row['failed_at']} 에서 멈춤")
    return "\n".join(lines)


# ==================================================== 기각 대장

LEDGER_PATH = REPO_ROOT / "benchmark/rejections.yaml"

#: 06단계가 실행마다 덧붙이는 기각 대장. 사람이 가른 기록
#: (``LEDGER_PATH``)과 다르다 — 이쪽은 원자료다.
LEDGER_JSONL = REPO_ROOT / "benchmark/results/rejections.jsonl"

#: 기각을 묶는 열쇠. **기법과 인용 아티팩트 조합**이다.
#:
#: 소견 단위로 세면 같은 원인이 실행마다 다른 항목으로 보이고, 기법 단위로만
#: 세면 "어느 아티팩트 때문에 걸렸나"가 사라진다. 매핑을 넓힐 때 적는 값이
#: 정확히 이 조합이므로 이 단위로 묶는다.
def _group_key(detail: dict[str, Any]) -> "tuple[str, tuple[str, ...]]":
    return (
        str(detail.get("technique", "?")),
        tuple(sorted(str(a) for a in detail.get("cited_artifacts") or [])),
    )


def load_ledger(path: Path = LEDGER_PATH) -> dict:
    """사람이 이미 가른 기각. 없으면 빈 표를 낸다."""
    if not path.is_file():
        return {}
    import yaml

    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    decided = {}
    for entry in document.get("decided") or []:
        key = (
            str(entry.get("technique", "?")),
            tuple(sorted(str(a) for a in entry.get("artifacts") or [])),
        )
        decided[key] = entry
    return decided


def _rejection_rows(runs: list[dict[str, Any]], ledger: Path) -> list[dict[str, Any]]:
    """대장과 (옛) 실행 기록에서 기각을 하나씩 모은다.

    **두 곳을 읽는 이유는 과도기다.** 2026-09-05 이전에는
    ``tools/live_check.py`` 만 기각을 실행 기록의 ``measures`` 에 실었고,
    그 뒤로는 06단계가 대장에 직접 덧붙인다(``stage06_verify.runlog``).
    입구가 셋인데 하나만 기록하던 것을 고친 것이라, 그전 기록도 계속 보이게
    둘 다 읽는다.

    **겹치지 않는다.** 옛 실행에는 대장 줄이 없고, 새 실행에는 ``measures``
    항목이 없다. 한 실행이 두 곳에 실리는 경우가 생기지 않는다.

    같은 실행을 두 번 세지 않도록 ``(case_id, 시각, 소견 id)`` 로 거른다 —
    대장은 append 만 하므로 같은 줄이 두 번 붙을 수 있다.
    """
    seen: set[tuple] = set()
    rows: list[dict[str, Any]] = []

    if ledger.is_file():
        for entry in io.read_jsonl(ledger):
            key = (entry.get("case_id"), entry.get("verified_at"), entry.get("id"))
            if key in seen:
                continue
            seen.add(key)
            rows.append(entry)

    for run in runs:
        for step in run.get("steps", []):
            for entry in (step.get("measures") or {}).get("rejections") or []:
                key = (run.get("case_id"), run.get("started_at"), entry.get("id"))
                if key in seen:
                    continue
                seen.add(key)
                rows.append({**entry, "case_id": run.get("case_id")})

    return rows


def rejections(
    runs: list[dict[str, Any]], ledger: "Path | None" = None
) -> list[dict[str, Any]]:
    """``technique_unsupported`` 기각을 조합별로 센다.

    **묶는 단위는 (기법, 인용 아티팩트)다.** 소견 단위로 세면 같은 원인이
    실행마다 다른 항목으로 보이고, 기법 단위로만 세면 "어느 아티팩트 때문에
    걸렸나"가 사라진다. 매핑을 넓힐 때 적는 값이 정확히 이 조합이다.
    """
    groups: dict[tuple, dict[str, Any]] = {}
    for item in _rejection_rows(runs, ledger or LEDGER_JSONL):
        if item.get("reason") != "technique_unsupported":
            continue
        detail = item.get("detail") or {}
        key = _group_key(detail)
        group = groups.setdefault(
            key,
            {
                "technique": key[0],
                "cited_artifacts": list(key[1]),
                "count": 0,
                "cases": set(),
                "supported_artifacts": sorted(detail.get("supported_artifacts") or []),
                "also_supports": sorted(detail.get("also_supports") or []),
            },
        )
        group["count"] += 1
        group["cases"].add(str(item.get("case_id", "?")))

    decided = load_ledger()
    rows = []
    for key, group in groups.items():
        entry = decided.get(key)
        group["cases"] = sorted(group["cases"])
        group["verdict"] = (entry or {}).get("verdict")
        group["decided_on"] = (entry or {}).get("decided_on")
        rows.append(group)
    # 안 본 것을 위로, 그다음 잦은 것을 위로. 표의 첫 줄이 곧 할 일이다.
    return sorted(rows, key=lambda r: (r["verdict"] is not None, -r["count"], r["technique"]))


def render_rejections(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return (
            "기각 기록이 없습니다.\n"
            "  technique_unsupported 기각이 쌓여야 매핑을 넓힐 근거가 생깁니다"
            " (work.md 10번).\n"
            "  tools/live_check.py 를 돌리면 실행마다 여기에 쌓입니다."
        )

    lines = []
    pending = [r for r in rows if not r["verdict"]]
    lines.append(f"technique_unsupported 기각 {sum(r['count'] for r in rows)}건 / 조합 {len(rows)}개")
    lines.append(f"  아직 안 가른 것 {len(pending)}개  ← 여기부터 본다")
    lines.append("")
    for row in rows:
        mark = {
            None: "판단 없음",
            "model_wrong": "모델 오류 (매핑 그대로)",
            "mapping_narrow": "매핑 미비 (corroborates 대상)",
        }.get(row["verdict"], str(row["verdict"]))
        lines.append(
            f"  {row['technique']:<12} ← {', '.join(row['cited_artifacts']):<32} "
            f"{row['count']:>3}회  [{mark}]"
        )
        lines.append(f"      등재된 근거   {', '.join(row['supported_artifacts']) or '(없음)'}")
        lines.append(f"      케이스        {', '.join(row['cases'])}")
        if row["also_supports"]:
            shown = row["also_supports"][:8]
            more = "" if len(row["also_supports"]) <= 8 else f" 외 {len(row['also_supports']) - 8}개"
            lines.append(f"      이 증거를 인정하는 다른 기법  {', '.join(shown)}{more}")
        lines.append("")

    if pending:
        lines.append("가르는 법 — 근거 레코드를 열어 보고 둘 중 하나를 정한다.")
        lines.append("  모델이 기법을 잘못 붙였다  → benchmark/rejections.yaml 에")
        lines.append("                              verdict: model_wrong 으로 적는다.")
        lines.append("                              **매핑은 고치지 않는다.**")
        lines.append("  증거는 맞는데 매핑이 좁다  → 그 기법 YAML 의 corroborates: 에 넣고,")
        lines.append("                              verdict: mapping_narrow 로 적는다.")
    return "\n".join(lines)


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    parser = argparse.ArgumentParser(
        prog="python benchmark/collect.py",
        description="benchmark/results/ 의 실행 기록을 한 표로 모은다.",
    )
    parser.add_argument("--results", default=str(RESULTS_DIR), help="기본 %(default)s")
    parser.add_argument("--case", default=None, help="case_id 가 이 문자열로 시작하는 것만")
    parser.add_argument("--json", action="store_true", help="표 대신 원본 그대로")
    parser.add_argument(
        "--rejections",
        action="store_true",
        help="technique_unsupported 기각을 조합별로 센다 (매핑을 넓힐 근거)",
    )
    args = parser.parse_args(argv)

    runs = collect(Path(args.results), args.case)
    if args.rejections:
        rows = rejections(runs)
        print(json.dumps(rows, ensure_ascii=False, indent=2) if args.json else render_rejections(rows))
        return 0
    if args.json:
        print(json.dumps(runs, ensure_ascii=False, indent=2))
        return 0

    print(render([summarize(run) for run in runs]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
