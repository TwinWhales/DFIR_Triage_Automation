"""검증 항목별 체커.

항목마다 파일을 나눈 것은 각각을 독립적으로 켜고 끌 수 있어야 하기
때문이다. 검증 강도별 실험에서 ``--checkers ref_exists,value_match`` 같은
조합으로 통과율 변화를 측정한다.

**실행 순서는 고정이다.** ``ref_exists`` → ``ref_in_input`` → ``value_match``.

파싱 결과에도 ``input_refs``에도 없는 레코드는 두 체커 모두에 걸리는데,
스펙은 이것을 ``ref_not_found``로 판정한다. 순서가 반대면 같은 상황이
``ref_not_in_input``으로 집계되어 환각 유형 분포가 왜곡된다.

체커를 끄면 그 항목의 위반이 다음 체커로 넘어간다는 점에 주의한다.
``ref_exists``를 끄면 존재하지 않는 레코드가 ``ref_not_in_input``으로
잡히므로, 조합별 실험 결과를 읽을 때 감안해야 한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = [
    "Rejection",
    "CheckContext",
    "CheckResult",
    "CHECKERS",
    "DEFAULT_ORDER",
    "resolve",
    "cited_refs",
]


def cited_refs(finding: dict[str, Any]) -> list[str]:
    """문장이 인용한 모든 ref를 등장 순서대로, 중복 없이.

    ``refs``만 보면 부족하다. ``claims``가 ``refs``에 없는 레코드를 가리키는
    경우가 실제로 나오는데, 그때 검증 없이 통과하면 안 된다.
    정렬하지 않는 것은 기각 사유에 먼저 등장한 ref가 담기게 하기 위함이다.
    """
    seen: dict[str, None] = {}
    for ref in finding.get("refs", []):
        seen.setdefault(ref, None)
    for claim in finding.get("claims", []):
        ref = claim.get("ref")
        if ref is not None:
            seen.setdefault(ref, None)
    return list(seen)


@dataclass(frozen=True)
class Rejection:
    """기각 사유 한 건. 그대로 ``06_verified.json``의 ``rejected``에 들어간다."""

    reason: str
    detail: dict[str, Any]


@dataclass(frozen=True)
class CheckContext:
    """체커가 판정에 쓰는 모든 것."""

    #: ref → 파싱된 레코드. ``04_parsed/*.jsonl`` 전체.
    records: dict[str, dict[str, Any]]
    #: LLM에 실제로 전달한 레코드 목록.
    input_refs: frozenset[str]
    #: 타임스탬프 비교 허용 오차(초).
    tolerance_seconds: float = 0.0


@dataclass
class CheckResult:
    """체커 하나의 실행 결과."""

    rejection: Rejection | None = None
    #: 수행한 **claims 대조** 횟수. ref 검사는 세지 않는다.
    #:
    #: ``06_verified.json``의 ``checks``가 claims 개수와 같아야 하기
    #: 때문이다. ref 검사는 문장 단위의 통과 조건이지 claims 대조가 아니다.
    #: ``value_match``를 끄면 0이 되는데, 그래야 조합별 실험에서
    #: "무엇을 실제로 대조했는가"가 결과에 드러난다.
    checks: int = 0
    checks_passed: int = 0
    #: 부수적으로 기록할 것 (현재는 미사용, 체커 추가 시 확장 지점)
    extra: dict[str, Any] = field(default_factory=dict)


#: 체커 함수 시그니처: ``(finding, ctx) -> CheckResult``
Checker = Callable[[dict[str, Any], CheckContext], CheckResult]

#: 기각 판정에서의 실행 순서. 위 docstring 참조.
DEFAULT_ORDER: tuple[str, ...] = ("ref_exists", "ref_in_input", "value_match")


def resolve(names: "list[str] | tuple[str, ...] | None") -> list[tuple[str, Checker]]:
    """이름 목록을 ``DEFAULT_ORDER`` 순서의 체커 목록으로 바꾼다.

    입력 순서는 무시한다. 사용자가 ``--checkers value_match,ref_exists``라고
    써도 실행 순서는 바뀌지 않아야 판정이 일관된다.
    """
    if names is None:
        selected = set(DEFAULT_ORDER)
    else:
        selected = set(names)
        unknown = selected - set(CHECKERS)
        if unknown:
            raise ValueError(
                f"알 수 없는 체커: {', '.join(sorted(unknown))} "
                f"(사용 가능: {', '.join(DEFAULT_ORDER)})"
            )
    return [(name, CHECKERS[name]) for name in DEFAULT_ORDER if name in selected]


# 순환 참조를 피하려고 아래에서 불러온다. 위의 정의가 끝난 뒤여야
# 각 체커 모듈이 CheckContext 등을 가져갈 수 있다.
from .ref_exists import check as _ref_exists  # noqa: E402
from .ref_in_input import check as _ref_in_input  # noqa: E402
from .value_match import check as _value_match  # noqa: E402

#: 이름 → 체커. ``--checkers``가 이 키를 받는다.
CHECKERS: dict[str, Checker] = {
    "ref_exists": _ref_exists,
    "ref_in_input": _ref_in_input,
    "value_match": _value_match,
}
