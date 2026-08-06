"""참조 존재 검증 — 근거 검증 1층위.

``refs``와 ``claims[].ref``가 가리키는 레코드가 파싱 결과에 실재하는가.

가장 노골적인 환각을 잡는다. 모델이 그럴듯한 레코드 번호를 지어내는
경우다. 형식은 멀쩡하므로 스키마로는 걸리지 않는다.
"""

from __future__ import annotations

from typing import Any

from . import CheckContext, CheckResult, Rejection, cited_refs

__all__ = ["check"]


def check(finding: dict[str, Any], ctx: CheckContext) -> CheckResult:
    for ref in cited_refs(finding):
        if ref not in ctx.records:
            return CheckResult(
                rejection=Rejection(
                    reason="ref_not_found",
                    detail={"ref": ref, "message": "파싱 결과에 존재하지 않는 레코드"},
                )
            )
    return CheckResult()
