"""06단계 — 근거 검증.

05단계의 해석 문장이 실제 증거에 근거하는지 기계적으로 대조한다.
LLM은 여기에 관여하지 않는다. 판정 주체가 또 LLM이면 순환 논리가 된다.

판정 규칙:

===============================================  ================
조건                                              판정
===============================================  ================
``claims``의 모든 항목이 파싱 결과와 일치          ``passed``
``claims`` 중 하나라도 불일치 또는 참조 없음       ``rejected``
``claims``가 빈 배열                              ``unverifiable``
``refs``가 ``input_refs`` 밖 레코드를 포함         ``rejected``
===============================================  ================

부분 통과를 두지 않는 이유는 하나라도 틀린 문장은 신뢰할 수 없기 때문이다.

``claims``가 비었으면서 동시에 없는 레코드를 참조하는 문장은 **기각이
우선한다.** 종합 판단이라도 지어낸 근거를 달았다면 그것은 환각이다.
스펙의 규칙 표에 두 조건이 함께 걸리는 경우가 명시되어 있지 않아
여기서 정한다.

사용법::

    python -m src.stage06_verify.verify \\
        --findings cases/C-001/05_findings.json \\
        --parsed   cases/C-001/04_parsed/ \\
        --out      cases/C-001/06_verified.json

검증 강도별 실험::

    ... --checkers ref_exists,value_match
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from ..common import errors as errlog
from ..common import io, schema
from . import checkers

__all__ = ["verify", "load_records", "main"]

STAGE = "06_verify"
DEFAULT_TOLERANCE_SECONDS = 1.0

#: ``unverifiable``에 남기는 사유. 보고서가 이 문구로 미검증 항목을 구분한다.
UNVERIFIABLE_REASON = "claims 없음 (종합 판단 문장)"


class DuplicateRefError(ValueError):
    """같은 ref를 가진 레코드가 둘 이상이다. 파서 쪽 결함이다."""


def load_records(parsed_dir: str | Path) -> dict[str, dict[str, Any]]:
    """``04_parsed/*.jsonl``을 전부 읽어 ref로 색인한다.

    ref가 겹치면 즉시 실패한다. 조용히 덮어쓰면 검증이 어느 레코드를 봤는지
    알 수 없게 되고, 통과·기각 판정이 파일 읽는 순서에 좌우된다.
    """
    directory = Path(parsed_dir)
    if not directory.is_dir():
        raise NotADirectoryError(f"파싱 결과 디렉터리 없음: {directory}")

    records: dict[str, dict[str, Any]] = {}
    sources: dict[str, str] = {}
    for path in sorted(directory.glob("*.jsonl")):
        for record in io.read_jsonl(path):
            ref = record.get("ref")
            if ref is None:
                raise ValueError(f"{path}: ref 없는 레코드")
            if ref in records:
                raise DuplicateRefError(
                    f"ref 중복: {ref} ({sources[ref]}, {path.name}). "
                    "레코드 번호는 아티팩트 내부에서 고유해야 한다."
                )
            records[ref] = record
            sources[ref] = path.name
    return records


def verify(
    findings_doc: dict[str, Any],
    records: dict[str, dict[str, Any]],
    *,
    checker_names: "list[str] | None" = None,
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    generator: str = "verify.py",
) -> dict[str, Any]:
    """판정을 수행하고 ``06_verified.json`` 문서를 만든다.

    파일을 읽지도 쓰지도 않는다. 순수 함수라 목업만으로 완주할 수 있고,
    그것이 이 단계를 04·05보다 먼저 구현할 수 있는 이유다.
    """
    active = checkers.resolve(checker_names)
    ctx = checkers.CheckContext(
        records=records,
        input_refs=frozenset(findings_doc.get("input_refs", [])),
        tolerance_seconds=tolerance_seconds,
    )

    passed: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    unverifiable: list[dict[str, Any]] = []

    for finding in findings_doc.get("findings", []):
        rejection = None
        checks = checks_passed = 0

        for _name, run in active:
            result = run(finding, ctx)
            checks += result.checks
            checks_passed += result.checks_passed
            if result.rejection is not None:
                rejection = result.rejection
                break  # 부분 통과가 없으므로 더 볼 이유가 없다

        if rejection is not None:
            rejected.append(
                {"id": finding["id"], "reason": rejection.reason, "detail": rejection.detail}
            )
        elif not finding.get("claims"):
            unverifiable.append({"id": finding["id"], "reason": UNVERIFIABLE_REASON})
        else:
            passed.append(
                {"id": finding["id"], "checks": checks, "checks_passed": checks_passed}
            )

    total = len(passed) + len(rejected) + len(unverifiable)
    judged = len(passed) + len(rejected)
    return io.new_document(
        findings_doc["case_id"],
        STAGE,
        generator,
        tolerance={"timestamp_seconds": _tidy_number(tolerance_seconds)},
        passed=passed,
        rejected=rejected,
        unverifiable=unverifiable,
        stats={
            "total_findings": total,
            "passed": len(passed),
            "rejected": len(rejected),
            "unverifiable": len(unverifiable),
            # unverifiable은 분모에서 뺀다. 검증 대상이 아니었던 문장을
            # 환각으로 셀 수 없다.
            "hallucination_rate": round(len(rejected) / judged, 4) if judged else 0.0,
        },
    )


def _tidy_number(value: float) -> float | int:
    """``1.0``을 ``1``로. 결과 파일을 사람이 읽기 좋게 한다."""
    return int(value) if float(value).is_integer() else value


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage06_verify.verify",
        description="05단계 해석 문장을 파싱 결과와 대조해 검증한다.",
    )
    parser.add_argument("--findings", required=True, help="05_findings.json 경로")
    parser.add_argument("--parsed", required=True, help="04_parsed/ 디렉터리")
    parser.add_argument("--out", required=True, help="06_verified.json 출력 경로")
    parser.add_argument(
        "--checkers",
        default=None,
        help=(
            "쉼표로 구분한 체커 목록. 생략하면 전부 사용. "
            f"사용 가능: {','.join(checkers.DEFAULT_ORDER)}"
        ),
    )
    parser.add_argument(
        "--tolerance-seconds",
        type=float,
        default=DEFAULT_TOLERANCE_SECONDS,
        help="타임스탬프 비교 허용 오차(초). 기본 %(default)s",
    )
    parser.add_argument(
        "--errors",
        default=None,
        help="errors.jsonl 경로. 생략하면 --out과 같은 디렉터리",
    )
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    out_path = Path(args.out)
    log = errlog.ErrorLog(Path(args.errors) if args.errors else out_path.parent / "errors.jsonl")

    checker_names = (
        [name.strip() for name in args.checkers.split(",") if name.strip()]
        if args.checkers
        else None
    )
    try:
        checkers.resolve(checker_names)
    except ValueError as e:
        print(f"[{STAGE}] {e}", file=sys.stderr)
        return 2  # 사용자 입력 오류다. errors.jsonl은 파이프라인 실패만 담는다.

    # 입력 검증
    findings_doc = io.read_json(args.findings)
    try:
        io.check_header(findings_doc, expected_stage="05_interpret")
        schema.validate(findings_doc, "findings")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())
    except io.HeaderError as e:
        log.abort(STAGE, "schema_violation", {"field": "<header>", "message": str(e)})

    try:
        records = load_records(args.parsed)
    except (DuplicateRefError, ValueError, NotADirectoryError) as e:
        log.abort(STAGE, "parse_error", {"message": str(e)})

    if not records:
        log.abort(
            STAGE,
            "empty_result",
            {"message": f"파싱 결과가 비어 있음: {args.parsed}. 04단계를 먼저 실행한다."},
        )

    verified = verify(
        findings_doc,
        records,
        checker_names=checker_names,
        tolerance_seconds=args.tolerance_seconds,
    )

    # 출력 검증
    try:
        schema.validate(verified, "verified")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())

    io.write_json(out_path, verified)

    stats = verified["stats"]
    print(
        f"{out_path}: passed {stats['passed']} / rejected {stats['rejected']} "
        f"/ unverifiable {stats['unverifiable']} "
        f"(환각률 {stats['hallucination_rate']:.1%})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
