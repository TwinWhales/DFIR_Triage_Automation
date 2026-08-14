"""파서 등록소.

``parse.py``가 아티팩트 이름으로 파서를 찾습니다. 파서를 구현하면
**아래 ``PARSERS``에 한 줄 추가**하면 끝입니다. 그 외에 고칠 곳은 없습니다.

등록되지 않은 아티팩트가 선별되면 ``parse.py``가 그 사실을
``errors.jsonl``에 남기고 건너뜁니다. 조용히 빈 결과를 내지 않습니다 —
"봤는데 없었다"와 "볼 줄 몰라 못 봤다"는 다릅니다.
"""

from __future__ import annotations

from .base import ParseError, Parser, Scope

__all__ = ["Parser", "Scope", "ParseError", "PARSERS", "get", "registered"]


#: 아티팩트 이름 → 파서 인스턴스.
#:
#: 이름은 ``mappings/_artifacts.yaml``과 정확히 같아야 합니다.
#:
#: 구현하면 주석을 풀고 등록하십시오::
#:
#:     from .mft import MftParser
#:     PARSERS["$MFT"] = MftParser()
PARSERS: dict[str, Parser] = {}


def get(artifact: str) -> Parser | None:
    """등록된 파서. 없으면 ``None``."""
    return PARSERS.get(artifact)


def registered() -> list[str]:
    """구현된 아티팩트 목록."""
    return sorted(PARSERS)
