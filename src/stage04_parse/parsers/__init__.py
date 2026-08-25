"""파서 등록소.

``parse.py``가 아티팩트 이름으로 파서를 찾습니다. 파서를 구현하면
**아래 ``PARSERS``에 한 줄 추가**하면 끝입니다.

## 파서 구현

``$MFT`` 메인 파서는 ``mft`` (analyzeMFT 기반, MIT) 입니다.
``$UsnJrnl`` 파서는 ``usnjrnl`` (전부 자체 구현) 입니다.
``evtx:Security`` / ``evtx:System`` 은 ``evtx`` (python-evtx 기반) 입니다.
``registry:SYSTEM`` / ``registry:SOFTWARE`` 는 ``registry`` (python-registry 기반) 입니다.
``prefetch`` 는 ``prefetch`` (온디스크 구조도 압축 해제도 전부 자체 구현) 입니다.
``parse.py``는 기본적으로 ``native`` 테이블을 쓰고, ``--parser reference``도
같은 인스턴스를 가리킵니다 — 아티팩트마다 구현이 하나씩뿐입니다.

다른 아티팩트(registry 등) 파서를 추가하면 아래 ``PARSERS``에 한 줄
등록하면 됩니다. **한 파서 클래스가 여러 아티팩트를 맡으면 인스턴스를
아티팩트마다 따로 만듭니다** — ``artifact``가 ``ref`` 접두어와 출력
파일명을 정하므로, 공유하면 한쪽 레코드가 다른 쪽 접두어로 나가고
06단계가 그것을 환각으로 집계합니다.

## 파일 하나짜리 아티팩트만 있는 것은 아니다

``prefetch``는 **폴더 하나가 아티팩트 하나**입니다. ``parse.py``가
``evidence.open_all``로 .pf 파일마다 ``parse()``를 부르므로, 그 파서는
호출 사이에 상태를 들고 있고 ``begin_artifact()``로 시작을 받습니다.
다른 파서에는 그 메서드가 없어도 됩니다 — ``parse.py``가 있는지 보고
부릅니다.

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


# $UsnJrnl 은 vendored 코드에 기대지 않는다. 전부 우리 구현이라
# import 가 실패하면 그건 우리 잘못이므로 감싸지 않는다.
from .usnjrnl import UsnJrnlParser  # noqa: E402 — $MFT 등록 블록 뒤라야 한다

# 구현이 하나뿐이므로 $MFT 와 같이 양쪽 테이블에 같은 인스턴스를 넣는다.
# reference 쪽을 비워 두면 ``--parser reference`` 로 돌렸을 때 USN 만
# 조용히 빠진 보고서가 나온다.
_usn_parser = UsnJrnlParser()
PARSERS["$UsnJrnl"] = _usn_parser
REFERENCE_PARSERS["$UsnJrnl"] = _usn_parser


# evtx 는 python-evtx 에 온디스크 계층을 맡긴다(work-guide.md 3.1). 라이브러리가
# 없으면 우리 잘못이 아니라 설치 문제이므로 $MFT 와 달리 감싸지 않는다 —
# requirements.txt 에 들어 있고, 조용히 빠지면 evtx 없는 보고서가 정상 종료로 나온다.
from .evtx import EvtxParser  # noqa: E402 — 등록 블록 순서를 유지한다

# **아티팩트마다 인스턴스를 따로 만든다.** artifact 가 ref 접두어와 출력
# 파일명을 정하므로, 공유하면 System 레코드가 EVTX-SEC# 으로 나가고
# 06단계가 그것을 환각으로 집계한다.
for _artifact in (
    "evtx:Security",
    "evtx:System",
    "evtx:Firewall",
    "evtx:BITS",
    "evtx:NetworkProfile",
):
    _evtx_parser = EvtxParser(_artifact)
    PARSERS[_artifact] = _evtx_parser
    REFERENCE_PARSERS[_artifact] = _evtx_parser


# 레지스트리도 온디스크 계층을 python-registry 에 맡긴다. evtx 와 근거는
# 다르다 — regf 는 어렵지 않지만 오프셋을 이미 주므로 직접 구현할 이유가
# 없다(parsers/registry.py 모듈 docstring). evtx 와 같이 감싸지 않는다.
from .registry import RegistryParser  # noqa: E402 — 등록 블록 순서를 유지한다

for _artifact in ("registry:SYSTEM", "registry:SOFTWARE", "registry:Amcache"):
    _registry_parser = RegistryParser(_artifact)
    PARSERS[_artifact] = _registry_parser
    REFERENCE_PARSERS[_artifact] = _registry_parser


# 프리패치는 유일한 **디렉터리 아티팩트**다. 폴더 안의 .pf 전부가
# 아티팩트 하나이며, 04단계가 파일마다 parse() 를 부른다
# (evidence.open_all). 온디스크 구조도 MAM 압축 해제도 전부 우리
# 구현이라 evtx·registry 와 달리 기댈 라이브러리가 없다.
from .prefetch import PrefetchParser  # noqa: E402 — 등록 블록 순서를 유지한다

_prefetch_parser = PrefetchParser()
PARSERS["prefetch"] = _prefetch_parser
REFERENCE_PARSERS["prefetch"] = _prefetch_parser


# RecentFileCache.bcf 는 Windows 7 전용이다. Win8 이상에는 아예 없고,
# 그 자리를 registry:Amcache 가 대신한다 — 어느 쪽을 읽을지는 osinfo 가
# 증거의 빌드 번호로 가른다. 여기 등록돼 있다고 해서 모든 이미지에서
# 불리는 것이 아니다.
from .recentfilecache import RecentFileCacheParser  # noqa: E402 — 등록 블록 순서

_rfc_parser = RecentFileCacheParser()
PARSERS["recentfilecache"] = _rfc_parser
REFERENCE_PARSERS["recentfilecache"] = _rfc_parser


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
