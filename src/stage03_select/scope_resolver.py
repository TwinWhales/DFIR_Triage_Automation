"""``scope_template``의 변수를 실제 값으로 바꾼다.

매핑은 ``{web_root}`` 같은 자리표시자를 쓴다. 기법 지식은 재사용 가능해야
하는데 웹루트 경로는 환경마다 다르기 때문이다.

값의 출처는 두 곳이고 우선순위가 있다.

1. **시나리오의 ``entities``** — 사용자가 실제로 언급한 값
2. **매핑의 ``defaults``** — 언급이 없을 때의 관례적 위치

시나리오를 우선하는 것에는 대가가 있다. 사용자가 웹루트가 아닌 경로를
언급하면 엉뚱한 곳을 보게 된다. 반대로 defaults만 쓰면 비표준 경로에
설치된 서버를 통째로 놓친다. **후자가 더 위험하다** — 잘못된 곳을 보면
결과가 비어 있어 알아채지만, 안 본 것은 드러나지 않는다.

이 선택이 재현율에 어떻게 나타나는지는 벤치마크에서 측정한다.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["UnresolvedVariable", "build_context", "resolve", "VARIABLE_PATTERN"]

VARIABLE_PATTERN = re.compile(r"\{([a-z_][a-z0-9_]*)\}")

#: 시나리오 ``entities``에서 끌어올 수 있는 변수. 값이 없으면 defaults로 넘어간다.
#:
#: ``paths``의 첫 항목을 ``web_root``로 보는 것은 강한 가정이다. 02단계가
#: 웹 침해 시나리오에서 웹루트를 첫 경로로 올린다는 관찰에 기댄 것이며,
#: 다른 종류의 시나리오에서는 성립하지 않을 수 있다.
ENTITY_VARIABLES: dict[str, str] = {
    "web_root": "paths",
    "host": "hosts",
    "account": "accounts",
    "process": "processes",
    "ip": "ips",
}


class UnresolvedVariable(KeyError):
    """치환할 값을 찾지 못했다."""


def build_context(scenario: dict[str, Any], defaults: dict[str, str]) -> dict[str, str]:
    """치환 컨텍스트를 만든다. 시나리오 값이 defaults를 덮어쓴다."""
    context = dict(defaults)
    entities = scenario.get("entities") or {}
    for variable, entity_key in ENTITY_VARIABLES.items():
        values = entities.get(entity_key) or []
        if values:
            context[variable] = str(values[0])
    return context


def resolve(
    scope_template: dict[str, Any],
    context: dict[str, str],
    time_range: dict[str, str] | None = None,
) -> dict[str, Any]:
    """자리표시자를 치환한 ``scope``를 만든다.

    ``time_range``는 항상 마지막에 붙는다. 모든 선별은 시간으로 좁혀지며,
    이것이 전수 파싱 대비 효율의 근거다.
    """
    scope: dict[str, Any] = {key: _substitute(value, context, key) for key, value in scope_template.items()}
    if time_range is not None:
        # basis는 추론 근거라 선별 범위에 넣지 않는다.
        scope["time_range"] = {"start": time_range["start"], "end": time_range["end"]}
    return scope


def _substitute(value: Any, context: dict[str, str], where: str) -> Any:
    if isinstance(value, str):
        return _substitute_string(value, context, where)
    if isinstance(value, list):
        return [_substitute(item, context, where) for item in value]
    if isinstance(value, dict):
        return {key: _substitute(item, context, f"{where}.{key}") for key, item in value.items()}
    return value


def _substitute_string(value: str, context: dict[str, str], where: str) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in context:
            # 치환 실패를 조용히 넘기면 "{web_root}" 라는 문자열이 그대로
            # 선별 결과에 실려 파서가 존재하지 않는 경로를 찾는다.
            known = ", ".join(sorted(context)) or "(없음)"
            raise UnresolvedVariable(
                f"{where}: 치환할 값이 없는 변수 {{{name}}} "
                f"(사용 가능: {known}). 매핑의 defaults에 추가하거나 "
                f"시나리오 entities에서 채워야 한다."
            )
        return context[name]

    return VARIABLE_PATTERN.sub(replace, value)
