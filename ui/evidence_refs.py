"""Evidence Ref 접두어와 04단계 산출물 파일명의 연결.

**여기에 목록을 적지 않는다.** 두 원본에서 유도한다 —

- 어떤 접두어가 있고 그것이 어느 아티팩트인가 :
  ``src/common/refs.py`` (CLAUDE.md — ``ref`` 문자열은 이곳을 경유한다)
- 그 아티팩트가 ``04_parsed/`` 의 어느 파일로 떨어지는가 :
  ``src/stage04_parse/parse.OUTPUT_FILENAMES``

손으로 적으면 파서를 하나 늘릴 때 04단계는 파일을 만드는데 UI 만 조용히
그 ref 를 모르는 상태가 된다. 실제로 그랬다 — 접두어 28종 중 3종
(``USN``·``REG-SYS``·``MFT``)만 적혀 있어서, C-001 보고서에 있는 ref 3개
중 눌리는 것이 1개였고 ``EVTX-SEC#40912`` 는 400 을 받았다. 04단계는 그
레코드를 정상적으로 만들어 뒀는데도 그랬다.

키오스크 축이 특히 걸렸다 — 빠진 25종에 ``EVTX-AAOP``·``EVTX-AAADM``·
``EVTX-AABRK``·``EVTX-DRV``·``EVTX-RDPCM``, 즉 키오스크 채널 다섯이 전부
들어 있었다.
"""

from __future__ import annotations

from src.common.refs import PREFIX_ARTIFACT
from src.stage04_parse.parse import OUTPUT_FILENAMES


__all__ = ["EVIDENCE_FILES", "REF_PREFIXES"]


def _build() -> dict[str, str]:
    """접두어 → 파일명. 한쪽만 아는 아티팩트가 있으면 기동을 멈춘다."""

    mapped: dict[str, str] = {}
    unmapped: list[str] = []

    for prefix, artifact in PREFIX_ARTIFACT.items():
        filename = OUTPUT_FILENAMES.get(artifact)

        if filename is None:
            unmapped.append(f"{prefix} → {artifact}")
            continue

        mapped[prefix] = filename

    if unmapped:
        # 폴백을 만들지 않는다 (CLAUDE.md). 조용히 빼면 그 ref 만
        # 근거 추적이 안 되는 상태로 돌아가는데, 그게 지금 고치는 결함이다.
        raise RuntimeError(
            "refs.py 가 아는 아티팩트에 04단계 출력 파일명이 없다: "
            + ", ".join(unmapped)
            + ". src/stage04_parse/parse.py 의 OUTPUT_FILENAMES 를 맞춘다."
        )

    return mapped


#: Evidence Ref 접두어 → ``04_parsed/`` 안의 파일명.
EVIDENCE_FILES: dict[str, str] = _build()


#: 프론트엔드 정규식에 넘길 접두어. **긴 것부터** 준다.
#:
#: 교대(alternation)는 왼쪽부터 맞춰 보므로, 짧은 접두어가 긴 접두어의
#: 앞부분과 겹치면 짧은 쪽이 먼저 걸려 뒤가 잘린다. 지금 목록에는 그런
#: 짝이 없지만, 접두어가 늘 때 이 순서가 없으면 조용히 틀린다.
REF_PREFIXES: tuple[str, ...] = tuple(
    sorted(
        EVIDENCE_FILES,
        key=lambda prefix: (-len(prefix), prefix),
    )
)
