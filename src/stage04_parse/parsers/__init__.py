"""파서 등록소.

``parse.py``가 아티팩트 이름으로 파서를 찾습니다. 파서를 구현하면
**아래 ``PARSERS``에 한 줄 추가**하면 끝입니다.

## 구현이 둘입니다

===========  ==========================================================
``native``   자체 구현. 발표의 차별점이자 학습 성과물
``reference``  오픈소스 기반 **임시** 구현 (``third_party/`` 참조)
===========  ==========================================================

참조 구현은 자체 파서가 완성될 때까지의 대체물이면서, 완성된 뒤에는
**대조군**이 됩니다. 두 구현의 출력을 맞춰 보면 MFTECmd 없이도
``pytest`` 안에서 정확도를 잴 수 있습니다.

등록되지 않은 아티팩트가 선별되면 ``parse.py``가 그 사실을
``errors.jsonl``에 남기고 건너뜁니다. 조용히 빈 결과를 내지 않습니다 —
"봤는데 없었다"와 "볼 줄 몰라 못 봤다"는 다릅니다.
"""

from __future__ import annotations

from .base import ParseError, Parser, Scope

__all__ = [
    "Parser",
    "Scope",
    "ParseError",
    "PARSERS",
    "REFERENCE_PARSERS",
    "IMPLEMENTATIONS",
    "get",
    "registered",
]


#: 자체 구현. 아티팩트 이름 → 파서 인스턴스.
#:
#: 이름은 ``mappings/_artifacts.yaml``과 정확히 같아야 합니다.
#:
#: 구현하면 주석을 풀고 등록하십시오::
#:
#:     from .mft import MftParser
#:     PARSERS["$MFT"] = MftParser()
PARSERS: dict[str, Parser] = {}


#: 참조 구현. **임시**이며 자체 파서가 완성되면 대조군으로만 남습니다.
REFERENCE_PARSERS: dict[str, Parser] = {}

try:
    from .reference_mft import ReferenceMftParser

    REFERENCE_PARSERS["$MFT"] = ReferenceMftParser()
except ImportError:  # pragma: no cover - vendored 코드가 없는 경우
    # third_party/ 를 지웠다면 참조 구현 없이 동작한다. 자체 파서만 쓴다.
    pass


IMPLEMENTATIONS = ("native", "reference")


def get(artifact: str, implementation: str = "native") -> Parser | None:
    """등록된 파서. 없으면 ``None``."""
    if implementation not in IMPLEMENTATIONS:
        raise ValueError(
            f"알 수 없는 구현: {implementation!r} (사용 가능: {', '.join(IMPLEMENTATIONS)})"
        )
    table = PARSERS if implementation == "native" else REFERENCE_PARSERS
    return table.get(artifact)


def registered(implementation: str = "native") -> list[str]:
    """구현된 아티팩트 목록."""
    table = PARSERS if implementation == "native" else REFERENCE_PARSERS
    return sorted(table)
