"""인용한 증거가 그 기법의 근거가 되는가.

다른 체커들이 **값**을 본다면 이 체커는 **함의**를 봅니다. "이 레코드의
`path`가 정말 저 값인가"가 아니라 "그 레코드로 이 기법을 말할 수 있는가"
입니다.

**왜 이 체커가 필요해졌나.** 05단계가 `claims`를 파이썬으로 조립하게 되면
`value_match`는 항등식이 됩니다 — 우리가 원본에서 복사한 값을 우리가 원본과
대조하는 것이라 언제나 통과합니다. `ref`는 이미 출력 문법의 `enum`이 막고
있어 지어낼 수 없습니다. 그러면 06단계가 실제로 판정하는 것이 하나도 남지
않고, 통과율 100%는 성과가 아니라 **측정의 소멸**입니다
(`docs/limitations.md` "환각률이 무엇을 재고 무엇을 안 재나").

모델에게 남은 자유도는 셋입니다 — 어느 레코드를 고르는가, 거기에 어떤
기법을 붙이는가, 문장을 뭐라고 쓰는가. 이 체커는 **둘째**를 봅니다.
나머지 둘은 여전히 못 잽니다.

**근거는 지어내지 않습니다.** `mappings/*/T*.yaml`의 `artifacts:`가 "이
기법은 이 아티팩트로 말한다"를 이미 적어 두었고, 03단계가 바로 그것으로
선별합니다. 같은 표를 05단계 산출물에 거꾸로 적용할 뿐이라, 새 판단 기준을
만드는 것이 아니라 **이미 선언된 것을 지키는지 보는 것**입니다.

## 판정하지 않는 경우

셋은 통과시킵니다. **판정할 수 없는 것을 기각하면 환각률이 실제 환각이
아니라 우리 무지를 셉니다**(`benchmark/validator_check.py`가 감시하는 방향).

- `technique`이 `null` — 종합 판단 문장입니다. 동결 스키마가 허용합니다.
- 그 기법의 매핑이 없음 — 03단계가 `empty_result`로 남기는 **매핑 결손**
  이지 05단계의 잘못이 아닙니다.
- 인용한 `ref`가 하나도 없음 — 볼 것이 없습니다.

## 기각은 두 가지 원인을 섞습니다

이 표는 03단계가 **"어디를 수집할까"**로 쓰는 목록이고, 여기서는 뒤집어
**"이 증거로 이 기법을 말할 수 있나"**로 씁니다. 방향이 다르므로 목록에
없다고 근거가 아닌 것은 아닙니다 — 파서가 있는 것만, 작성자가 생각한
것만 들어 있는 부분집합입니다.

그래서 기각 하나가 둘 중 어느 쪽인지 자동으로는 가릴 수 없습니다.

- **모델이 기법을 잘못 붙였다** — 잡아야 할 것
- **매핑에 그 아티팩트가 빠져 있다** — 우리 미비

느슨하게 만들 방법이 없습니다. "시나리오의 다른 기법이 그 아티팩트를
요청했으면 통과"로 완화하려 해도, **레코드가 05단계에 도달했다는 것 자체가
03단계가 그 아티팩트를 선별했다는 뜻**이라 그 조건은 언제나 참이고 검사가
사라집니다.

대신 **사람이 가를 수 있게** 합니다. 기각 사유에 ``also_supports`` 를 실어,
인용한 아티팩트를 근거로 인정하는 **다른 기법**을 함께 보여 줍니다. 프리패치
레코드로 T1505.003 을 말해 기각됐는데 ``also_supports`` 에 T1543.003 이
있으면, 그것은 "매핑을 넓힐 것인가 모델이 틀린 것인가"라는 **판정 가능한
질문**이 됩니다. 그 수치가 두 원인을 섞는다는 사실은
``docs/limitations.md`` 에 적혀 있습니다.

## 하나라도 맞으면 통과입니다

인용한 레코드 **전부**가 근거 아티팩트여야 한다고 하지 않습니다. 한 문장이
맥락으로 다른 아티팩트를 함께 인용하는 것은 정상이고, 그것까지 기각하면
과엄격 쪽으로 넘어갑니다. **한 건도 근거가 아닐 때만** 기각합니다.
"""

from __future__ import annotations

from typing import Any

from ...common.refs import parse_ref
from . import CheckContext, CheckResult, Rejection, cited_refs

__all__ = ["check"]


def _artifact_of(ref: str) -> "str | None":
    """``ref``가 가리키는 아티팩트 이름. 못 읽으면 ``None``.

    형식이 틀린 ``ref``는 여기서 판정하지 않습니다 — ``ref_exists``가
    앞에서 봅니다. 여기서 또 기각하면 같은 잘못이 두 유형으로 집계됩니다.
    """
    try:
        return parse_ref(ref).artifact
    except ValueError:
        return None


def check(finding: dict[str, Any], ctx: CheckContext) -> CheckResult:
    """이 문장의 기법이 인용한 증거로 뒷받침되는가.

    ``checks``는 올리지 않습니다. 그 수는 **claims 대조 횟수**여야 하고
    (``06_verified.json``의 ``checks``가 claims 개수와 같아야 한다),
    이것은 문장 단위의 통과 조건이지 claims 대조가 아닙니다.
    """
    technique = finding.get("technique")
    if not technique:
        return CheckResult()

    supported = ctx.technique_artifacts.get(technique)
    if not supported:
        return CheckResult()

    cited = [(ref, _artifact_of(ref)) for ref in cited_refs(finding)]
    artifacts = sorted({artifact for _ref, artifact in cited if artifact})
    if not artifacts:
        return CheckResult()

    if any(artifact in supported for artifact in artifacts):
        return CheckResult()

    # 인용한 아티팩트를 근거로 인정하는 **다른** 기법. 이 한 줄이 기각을
    # "판정 불가"에서 "사람이 가를 수 있는 질문"으로 바꾼다 — 위 설명 참조.
    cited = set(artifacts)
    also = sorted(
        other
        for other, names in ctx.technique_artifacts.items()
        if other != technique and cited & names
    )

    return CheckResult(
        rejection=Rejection(
            reason="technique_unsupported",
            detail={
                "technique": technique,
                "cited_artifacts": artifacts,
                "supported_artifacts": sorted(supported),
                "also_supports": also,
            },
        )
    )
