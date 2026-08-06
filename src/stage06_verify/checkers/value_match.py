"""값 일치 검증 — 근거 검증 2층위.

``claims``의 ``(ref, field, value)`` 삼중항을 파싱 결과와 대조한다.

``statement``는 자연어라 기계 검증이 불가능하다. 그래서 문장이 주장하는
사실만 구조화해 이 체커가 볼 수 있게 했다. 여기서 통과하는 것은
"문장이 인용한 값이 실제 레코드와 같다"까지이며, **문장의 해석이 타당한지는
검증 범위 밖이다**(3층위, 분석가 검토 영역).

부분 통과는 없다. 하나라도 틀리면 문장 전체를 기각한다.
"""

from __future__ import annotations

from typing import Any

from .. import comparators
from . import CheckContext, CheckResult, Rejection

__all__ = ["check"]


def check(finding: dict[str, Any], ctx: CheckContext) -> CheckResult:
    claims = finding.get("claims", [])
    passed = 0

    for claim in claims:
        ref, field, claimed = claim["ref"], claim["field"], claim["value"]
        record = ctx.records.get(ref)

        if record is None:
            # ref_exists를 끈 조합에서만 도달한다. 조용히 통과시키면
            # 검증 강도 실험의 결과가 거짓이 된다.
            return CheckResult(
                rejection=Rejection(
                    reason="ref_not_found",
                    detail={"ref": ref, "message": "파싱 결과에 존재하지 않는 레코드"},
                ),
                checks=len(claims),
                checks_passed=passed,
            )

        try:
            actual = comparators.get_field(record, field)
        except comparators.FieldMissing as missing:
            # 값을 틀리게 말한 것과 필드 자체를 지어낸 것을 구분한다.
            # 후자가 더 심각한 환각이므로 같은 통계에 섞지 않는다.
            return CheckResult(
                rejection=Rejection(
                    reason="field_not_found",
                    detail={
                        "ref": ref,
                        "field": field,
                        "message": f"레코드에 없는 필드 (끊긴 지점: {missing})",
                    },
                ),
                checks=len(claims),
                checks_passed=passed,
            )

        if not comparators.compare(
            field, claimed, actual, tolerance_seconds=ctx.tolerance_seconds
        ):
            return CheckResult(
                rejection=Rejection(
                    reason="value_mismatch",
                    detail={
                        "ref": ref,
                        "field": field,
                        "claimed": claimed,
                        "actual": actual,
                    },
                ),
                checks=len(claims),
                checks_passed=passed,
            )
        passed += 1

    return CheckResult(checks=len(claims), checks_passed=passed)
