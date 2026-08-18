"""파서 등록소.

``parse.py``가 아티팩트 이름으로 파서를 찾습니다. 파서를 구현하면
**아래 ``PARSERS``에 한 줄 추가**하면 끝입니다.

## 파서 구현

``$MFT`` 메인 파서는 ``mft`` (analyzeMFT 기반, MIT) 입니다.
``parse.py``는 기본적으로 ``native`` 테이블을 쓰고 ``$MFT``는 이 파서로
해석됩니다. ``--parser reference``도 같은 파서를 가리킵니다.

다른 아티팩트($UsnJrnl, evtx 등) 파서를 추가하면 아래 ``PARSERS``에 한 줄
등록하면 됩니다.

등록되지 않은 아티팩트가 선별되면 ``parse.py``가 그 사실을
``errors.jsonl``에 남기고 건너뜁니다. 조용히 빈 결과를 내지 않습니다 —
"봤는데 없었다"와 "볼 줄 몰라 못 봤다"는 다릅니다.
"""

from __future__ import annotations

import logging

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

_log = logging.getLogger(__name__)


#: 메인 파서. 아티팩트 이름 → 파서 인스턴스.
#:
#: 이름은 ``mappings/_artifacts.yaml``과 정확히 같아야 합니다.
#: ``$MFT``는 아래 등록 블록에서 ``mft.MftParser``로 채워집니다.
PARSERS: dict[str, Parser] = {}


#: ``--parser reference`` 별칭 테이블. ``$MFT``는 메인 파서와 동일한
#: 인스턴스를 가리키므로 어느 쪽으로 불러도 결과가 같습니다.
REFERENCE_PARSERS: dict[str, Parser] = {}

try:
    from .mft import MftParser

    # $MFT 파서를 native / reference 양쪽에 같은 인스턴스로 등록한다.
    # 기본 파이프라인과 ``--parser reference`` 가 모두 이 파서를 쓴다.
    _mft_parser = MftParser()
    PARSERS["$MFT"] = _mft_parser
    REFERENCE_PARSERS["$MFT"] = _mft_parser
except ImportError as e:  # pragma: no cover - vendored 코드가 없는 경우
    # third_party/ 를 지웠다면 $MFT 파서 없이 동작한다. 그 경우만 봐준다.
    #
    # 예전에는 여기서 모든 ImportError 를 조용히 삼켰다. 파서 파일 이름이
    # 바뀌었을 때 등록소가 통째로 비었는데도 아무 소리가 나지 않았고,
    # 04단계가 그것을 "파서 미구현"으로 분류해 $MFT 없는 보고서를 정상
    # 종료로 냈다. 우리 쪽 오타는 소리를 내야 한다.
    if not (e.name or "").startswith("third_party"):
        raise
    _log.warning("$MFT 파서를 등록하지 못했습니다 (vendored 코드 없음): %s", e)


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
