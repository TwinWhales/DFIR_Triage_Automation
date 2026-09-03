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

__all__ = ["collect", "summarize", "main"]

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


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    parser = argparse.ArgumentParser(
        prog="python benchmark/collect.py",
        description="benchmark/results/ 의 실행 기록을 한 표로 모은다.",
    )
    parser.add_argument("--results", default=str(RESULTS_DIR), help="기본 %(default)s")
    parser.add_argument("--case", default=None, help="case_id 가 이 문자열로 시작하는 것만")
    parser.add_argument("--json", action="store_true", help="표 대신 원본 그대로")
    args = parser.parse_args(argv)

    runs = collect(Path(args.results), args.case)
    if args.json:
        print(json.dumps(runs, ensure_ascii=False, indent=2))
        return 0

    print(render([summarize(run) for run in runs]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
