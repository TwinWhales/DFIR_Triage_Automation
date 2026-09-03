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
from ..stage03_select import mapping_loader
from . import checkers

__all__ = ["verify", "load_records", "main"]

STAGE = "06_verify"
DEFAULT_TOLERANCE_SECONDS = 1.0

#: ``unverifiable``에 남기는 사유. 보고서가 이 문구로 미검증 항목을 구분한다.
UNVERIFIABLE_REASON = "claims 없음 (종합 판단 문장)"


#: 04단계 산출물 읽기는 05단계와 공유하므로 공용에 있다. 두 단계가
#: 다르게 읽으면 ``input_refs``와 검증 대상이 어긋난다.
DuplicateRefError = io.DuplicateRefError
load_records = io.read_parsed_records


def technique_artifacts(mappings_dir: "str | Path") -> dict[str, frozenset[str]]:
    """기법 → 그 기법의 근거로 매핑에 등재된 아티팩트 이름.

    ``mappings/*/T*.yaml`` 의 ``artifacts:`` 를 그대로 뒤집은 표입니다.
    **새 판단 기준을 만드는 것이 아닙니다** — 03단계가 이 표로 선별하고,
    06단계가 같은 표로 "그 증거로 그 기법을 말했는가"를 봅니다.

    **OS 를 가리지 않고 합집합으로 읽습니다.** 05단계 산출물에는 대상 OS 가
    없고(시나리오에 있습니다), 같은 기법 번호라도 OS 마다 근거 아티팩트가
    다릅니다. 합치면 판정이 느슨해지는 쪽인데, 이 자리에서는 그쪽이 안전한
    방향입니다 — 판정할 수 없는 것을 기각하면 환각률이 실제 환각이 아니라
    우리 설정을 셉니다(``benchmark/validator_check.py``).

    **못 읽으면 빈 표를 냅니다.** 그러면 ``technique_supported`` 가 아무것도
    기각하지 않습니다. 이 단계는 매핑이 없어도 돌아야 하는 결정론적 구간이라,
    표가 없다고 멈추면 04단계 산출물만으로 검증하던 경로가 막힙니다.
    """
    directory = Path(mappings_dir)
    if not directory.is_dir():
        return {}

    try:
        catalog = mapping_loader.load_catalog(directory)
    except (mapping_loader.MappingError, OSError):
        return {}

    table: dict[str, set[str]] = {}
    for os_dir in sorted(p.name for p in directory.iterdir() if p.is_dir()):
        try:
            loaded = mapping_loader.load_all(directory, os_dir, catalog)
        except (mapping_loader.MappingError, OSError):
            continue
        for technique, mapping in loaded.items():
            table.setdefault(technique, set()).update(
                request.artifact for request in mapping.requests
            )
    return {technique: frozenset(names) for technique, names in table.items()}


def verify(
    findings_doc: dict[str, Any],
    records: dict[str, dict[str, Any]],
    *,
    checker_names: "list[str] | None" = None,
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    supported_artifacts: "dict[str, frozenset[str]] | None" = None,
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
        technique_artifacts=supported_artifacts or {},
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
        "--mappings",
        default="mappings",
        help=(
            "매핑 디렉터리. 기법마다 어느 아티팩트가 근거인지 읽어 "
            "technique_supported 가 쓴다. 기본 %(default)s. "
            "없거나 못 읽으면 그 체커는 아무것도 기각하지 않는다"
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
    io.configure_console()
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

    supported = technique_artifacts(args.mappings)
    if not supported:
        # 조용히 넘어가면 technique_supported 가 아무것도 안 잡는데 통과율만
        # 올라가고, 그것을 성능으로 읽게 된다. 실패는 아니므로 멈추지는
        # 않지만 말은 한다.
        print(
            f"[{STAGE}] 경고: {args.mappings} 에서 기법-아티팩트 표를 읽지 못했습니다. "
            "technique_supported 가 아무것도 기각하지 않습니다.",
            file=sys.stderr,
        )

    verified = verify(
        findings_doc,
        records,
        checker_names=checker_names,
        tolerance_seconds=args.tolerance_seconds,
        supported_artifacts=supported,
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
