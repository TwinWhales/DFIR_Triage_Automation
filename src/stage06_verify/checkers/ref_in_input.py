"""input_refs 범위 검증 — LLM에 주지 않은 레코드를 참조했는가.

실무에서 가장 흔한 환각 유형이다. 레코드는 실재하므로 ``ref_exists``는
통과한다. 그런데 그 레코드는 LLM에 전달되지 않았다. 모델이 파일 이름이나
번호 패턴에서 추측해 낸 것이다.

이 검사가 성립하려면 05단계가 ``input_refs``를 정직하게 기록해야 한다.
전달한 레코드를 빠뜨리면 정상 문장이 기각되고, 전달하지 않은 것을 적으면
이 검사가 무력해진다.
"""

from __future__ import annotations

from typing import Any

from . import CheckContext, CheckResult, Rejection, cited_refs

__all__ = ["check"]


def check(finding: dict[str, Any], ctx: CheckContext) -> CheckResult:
    for ref in cited_refs(finding):
        if ref not in ctx.input_refs:
            return CheckResult(
                rejection=Rejection(
                    reason="ref_not_in_input",
                    detail={"ref": ref, "message": "LLM에 전달되지 않은 레코드를 참조"},
                )
            )
    return CheckResult()
