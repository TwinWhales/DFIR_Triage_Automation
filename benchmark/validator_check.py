"""검증기 자체의 오탐을 확인한다.

06단계 검증기는 두 방향으로 틀릴 수 있습니다.

- **너무 느슨하면** 환각이 통과해 도구의 신뢰성 근거가 사라진다
- **너무 엄격하면** 정상 문장이 대량 기각되어, 환각률이 실제 환각이 아니라
  표기 차이를 센다

환각률은 앞쪽만 감시합니다. 뒤쪽을 감시하는 것이 이 스크립트입니다.

사람이 "이건 맞는 문장"이라고 판단한 사례를 넣어 몇 건이 통과하는지 봅니다.
**하나라도 기각되면 검증기 결함입니다.** 비교 규칙을 고칠 때마다 돌리십시오.

    python benchmark/validator_check.py

``benchmark/validator/cases.json``에 사례가 있습니다. 새 비교 규칙을
넣거나 실제 데이터에서 오탐을 발견하면 거기에 사례를 추가하십시오.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import io, schema  # noqa: E402
from src.stage06_verify.verify import verify  # noqa: E402

__all__ = ["build_findings", "run", "main"]

DEFAULT_CASES = REPO_ROOT / "benchmark/validator/cases.json"
#: 사례가 대조할 레코드. **두 곳입니다.**
#:
#: C-001 목업은 웹셸 벤치마크의 입력이라 표기 시험용 레코드를 넣으면
#: 파싱 건수와 05단계 배분이 함께 흔들립니다. 그래서 표기 경계 사례는
#: ``benchmark/validator/records/`` 에 따로 둡니다.
DEFAULT_PARSED = (
    REPO_ROOT / "benchmark/fixtures/C-001-webshell/04_parsed",
    REPO_ROOT / "benchmark/validator/records",
)


def read_records(parsed_dirs: "str | Path | Sequence[str | Path]") -> dict[str, dict[str, Any]]:
    """여러 디렉터리의 파싱 결과를 ref 하나의 색인으로 합친다.

    ``read_parsed_records``와 같은 이유로 ref 중복은 즉시 실패입니다 —
    어느 레코드를 검증했는지 모르게 되면 이 스크립트가 재는 것이
    무의미해집니다.
    """
    if isinstance(parsed_dirs, (str, Path)):
        parsed_dirs = [parsed_dirs]

    merged: dict[str, dict[str, Any]] = {}
    origin: dict[str, str] = {}
    for directory in parsed_dirs:
        for ref, record in io.read_parsed_records(directory).items():
            if ref in merged:
                raise io.DuplicateRefError(
                    f"ref 중복: {ref} ({origin[ref]}, {directory}). "
                    "사례용 레코드가 목업의 ref 를 다시 쓰고 있다."
                )
            merged[ref] = record
            origin[ref] = str(directory)
    return merged


def build_findings(cases: dict[str, Any], case_id: str = "VALIDATOR") -> dict[str, Any]:
    """사례를 05단계 findings 문서 모양으로 만든다.

    스키마 검증을 함께 거칩니다. 사례 자체가 형식을 어기고 있으면
    검증기를 시험하기 전에 여기서 걸립니다.
    """
    findings = []
    for index, case in enumerate(cases["cases"], start=1):
        findings.append(
            {
                "id": f"F{index}",
                "statement": case["statement"],
                "refs": case.get("refs", []),
                "claims": case.get("claims", []),
                "technique": None,
                "severity": "info",
            }
        )
    return io.new_document(
        case_id,
        "05_interpret",
        io.make_generator("validator_check.py"),
        input_refs=cases["input_refs"],
        findings=findings,
        timeline=[],
    )


def run(
    cases: dict[str, Any],
    parsed_dir: "str | Path | Sequence[str | Path]",
    *,
    tolerance_seconds: float = 1.0,
    checker_names: "list[str] | None" = None,
) -> dict[str, Any]:
    """사례를 검증기에 통과시키고 결과를 사례 단위로 되돌린다."""
    document = build_findings(cases)
    schema.validate(document, "findings")

    records = read_records(parsed_dir)
    verified = verify(
        document,
        records,
        checker_names=checker_names,
        tolerance_seconds=tolerance_seconds,
        generator="validator_check.py",
    )

    verdicts: dict[str, str] = {}
    detail: dict[str, dict[str, Any]] = {}
    for entry in verified["passed"]:
        verdicts[entry["id"]] = "passed"
    for entry in verified["unverifiable"]:
        verdicts[entry["id"]] = "unverifiable"
    for entry in verified["rejected"]:
        verdicts[entry["id"]] = "rejected"
        detail[entry["id"]] = {"reason": entry["reason"], "detail": entry["detail"]}

    results = []
    for index, case in enumerate(cases["cases"], start=1):
        finding_id = f"F{index}"
        expected = case.get("expect", "passed")
        got = verdicts.get(finding_id, "?")
        results.append(
            {
                "id": case["id"],
                "risk": case.get("risk", ""),
                "why": case.get("why", ""),
                "expected": expected,
                "got": got,
                "ok": got == expected,
                "gap": case.get("gap", ""),
                "rejection": detail.get(finding_id),
                "statement": case["statement"],
            }
        )

    passed = sum(1 for r in results if r["ok"])

    # **기대하지 않은 기각만** 오탐으로 센다. expect 가 rejected 인 사례는
    # 아직 못 고친 것이고 gap 에 사유가 적혀 있다 — 그것을 오탐으로 세면
    # 이 스크립트가 상시 실패해서 진짜 회귀가 묻힌다.
    false_rejections = [r for r in results if r["got"] == "rejected" and r["expected"] != "rejected"]
    known_gaps = [r for r in results if r["expected"] == "rejected"]
    return {
        "total": len(results),
        "ok": passed,
        "pass_rate": round(passed / len(results), 4) if results else None,
        "false_rejections": len(false_rejections),
        "known_gaps": len(known_gaps),
        "results": results,
    }


def _format(report: dict[str, Any]) -> str:
    lines = [
        f"검증기 오탐 확인 — 사례 {report['total']}건 중 {report['ok']}건 기대대로 "
        f"({report['pass_rate']:.1%})"
    ]

    # 아는 구멍은 통과하든 말든 항상 보여 준다. 조용하면 잊히고, 잊히면
    # 고쳐진 뒤에도 expect: rejected 가 남아 진짜 회귀를 덮는다.
    gaps = [r for r in report["results"] if r["expected"] == "rejected"]
    if gaps:
        lines.append(f"\n아는 구멍 {len(gaps)}건 (기각될 것을 알고 넣어 둔 사례):")
        for row in gaps:
            mark = "여전히 기각" if row["got"] == "rejected" else f"**이제 {row['got']}**"
            lines.append(f"\n  [{row['id']}] {row['risk']} — {mark}")
            lines.append(f"    고칠 자리: {row['gap']}")
            if row["got"] != "rejected":
                lines.append("    → 고쳐졌습니다. 이 사례의 expect 를 passed 로 되돌리십시오.")

    failures = [r for r in report["results"] if not r["ok"]]
    if not failures:
        lines.append("\n오탐 없음. 검증기가 정상 문장을 기각하지 않습니다.")
        return "\n".join(lines)

    lines.append(f"\n문제 {len(failures)}건:")
    for row in failures:
        lines.append(f"\n  [{row['id']}] {row['risk']}")
        lines.append(f"    기대 {row['expected']} → 실제 {row['got']}")
        lines.append(f"    문장: {row['statement']}")
        lines.append(f"    이유: {row['why']}")
        if row["rejection"]:
            lines.append(f"    기각 사유: {row['rejection']['reason']} {row['rejection']['detail']}")

    if report["false_rejections"]:
        lines.append(
            f"\n{report['false_rejections']}건이 기각되었습니다. **검증기가 과엄격합니다.**"
            "\n환각률이 실제 환각이 아니라 표기 차이를 세고 있을 수 있습니다."
            "\nsrc/stage06_verify/comparators.py 를 확인하십시오."
        )
    return "\n".join(lines)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python benchmark/validator_check.py",
        description="사람이 옳다고 판단한 문장을 검증기에 넣어 오탐을 확인한다.",
    )
    parser.add_argument("--cases", default=str(DEFAULT_CASES))
    parser.add_argument(
        "--parsed",
        action="append",
        default=None,
        help="대조할 04_parsed 디렉터리. 여러 번 주면 합쳐서 읽는다 "
        "(기본: C-001 픽스처 + benchmark/validator/records)",
    )
    parser.add_argument("--tolerance-seconds", type=float, default=1.0)
    parser.add_argument(
        "--checkers", default=None, help="검증 강도별 실험용. 쉼표로 구분"
    )
    parser.add_argument("--out", default=None, help="결과 JSON 경로")
    args = parser.parse_args(argv)

    io.configure_console()

    checker_names = (
        [name.strip() for name in args.checkers.split(",") if name.strip()]
        if args.checkers
        else None
    )
    report = run(
        io.read_json(args.cases),
        args.parsed or DEFAULT_PARSED,
        tolerance_seconds=args.tolerance_seconds,
        checker_names=checker_names,
    )

    print(_format(report))
    if args.out:
        io.write_json(args.out, report)
        print(f"\n결과: {args.out}")
    return 0 if report["false_rejections"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
