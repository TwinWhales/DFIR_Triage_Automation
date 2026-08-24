"""05단계 레코드 배분 — 아티팩트마다 몇 자리를 줄 것인가.

``record_filter``가 "이 레코드가 볼 만한가"를 판정한다면 이 모듈은 **"어느
아티팩트에 몇 자리를 줄 것인가"**를 정한다. 둘을 나눈 이유는 질문이
다르기 때문이다. 앞의 것은 룰의 문제이고 뒤의 것은 배분의 문제다.

**왜 배분이 필요한가.** 예전에는 신호를 전부 모아 앞에서 60개를 잘랐다.
자르는 기준이 파일명 알파벳순이라 어느 증거가 모델에 도달하는지가 파일
이름 철자에 달려 있었고, 무엇보다 **파이프라인에서 이 자르기만 시나리오의
영향을 받지 않았다.** 03단계가 "이 기법 때문에 이 아티팩트를 본다"고 정해
놓은 것을 05단계가 통째로 무시했다. 이 도구의 논지가 시나리오 기반 선별인데
마지막 관문이 시나리오와 무관했다(``docs/limitations.md`` 4-2, 4-2-1).

**2단 배분.**

.. code-block:: text

    매핑 priority   →  이 케이스에서 어느 아티팩트가 중요한가   [가중치]
    후보 수 상한    →  가진 것보다 많이 받지 않는다             [보정]
                              ↓
                    아티팩트별 자릿수 배분 (쿼터)
                              ↓
                    쿼터 안에서 레코드 선택 (신호 → 시간창 근접)

가중치만 있으면 시끄러운 아티팩트가 자리를 쓸어가고, 보정만 있으면 모든
아티팩트를 똑같이 취급한다. 둘 다 있어야 "웹셸 케이스에서 ``$MFT``를
우선하되, ``$UsnJrnl``이 30만 건이라고 ``$MFT``를 밀어내지는 못한다"가 된다.

**바닥 한 자리.** 후보가 있는 아티팩트는 가중치와 무관하게 최소 한 자리를
받는다. 03단계가 보라고 한 아티팩트가 보고서에서 통째로 사라지지 않는다는
보장이다. 레지스트리가 정확히 그 경우였다 — 파싱은 1,754건이 되는데 플래그가
0건이라 모델에 한 건도 가지 않았다(``docs/limitations.md`` 6-7).

**이 모듈이 풀지 못하는 것.** 쿼터 안에서 어느 레코드를 고를지는 여전히
시간창 근접성에 기댄다. ``$MFT``의 ``MISMATCH_PAIRS``처럼 물리적 근거가 있는
판별자를 찾기 전까지는 임시다(``docs/limitations.md`` 6-6).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
from typing import Any, Iterable, Sequence

from ..stage03_select.mapping_loader import (
    DEFAULT_PRIORITY,
    DEFAULT_SIGNAL_SOURCE,
    PRIORITIES,
)
from .record_filter import (
    DEFAULT_LIMIT,
    DEFAULT_WINDOW_SECONDS,
    NO_TIME,
    AnchorIndex,
    activity_times,
    is_signal,
)

__all__ = [
    "PRIORITY_WEIGHT",
    "Quota",
    "priorities_from_selection",
    "allocate_seats",
    "allocate_records",
]

#: ``priority`` → 자릿수 배분 가중치. priority는 작을수록 강하므로 뒤집는다.
#:
#: 한 눈금마다 두 배다. priority 1인 아티팩트는 3인 것의 네 배를 받는다.
#: 배수를 크게 잡지 않은 것은 **약한 아티팩트가 굶으면 안 되기 때문**이다 —
#: 자리를 적게 받는 것과 한 건도 못 받는 것은 보고서에서 전혀 다른 결과다.
PRIORITY_WEIGHT = {1: 4, 2: 2, 3: 1}

if set(PRIORITY_WEIGHT) != set(PRIORITIES):
    # 눈금을 늘리고 가중치를 안 채우면 배분이 KeyError 로 멈춘다. 임포트
    # 시점에 잡는다 — assert 로 두면 ``-O`` 에서 사라진다.
    raise RuntimeError(
        f"priority 눈금과 가중치가 어긋남: {sorted(PRIORITIES)} vs {sorted(PRIORITY_WEIGHT)}"
    )


@dataclass(frozen=True)
class Quota:
    """아티팩트 하나에 배분된 자리와 그 근거.

    ``interpret``이 이것을 그대로 찍는다. "왜 이 60건입니까"에 답하려면
    배분 결과가 사람이 읽을 수 있게 남아야 한다.
    """

    artifact: str
    priority: int
    candidates: int
    seats: int
    parsed: int

    @property
    def weight(self) -> int:
        return PRIORITY_WEIGHT[self.priority]


def priorities_from_selection(selection: dict[str, Any]) -> dict[str, int]:
    """``03_selection.json``에서 아티팩트별 priority를 뽑는다.

    한 아티팩트를 여러 기법이 요청할 수 있다(04단계가 ``scope``를 합치는
    이유와 같다). 그때는 **요청한 기법들 중 가장 강한 값**을 쓴다. 합치거나
    평균 내면 여러 기법이 스치듯 요청한 아티팩트가 한 기법이 강하게 요청한
    아티팩트를 이긴다.
    """
    strongest: dict[str, int] = {}
    for entry in selection.get("selected") or []:
        artifact = entry.get("artifact")
        if not artifact:
            continue
        # 값을 거르는 것은 스키마의 일이다(1~3 정수). 여기서 한 번 더 보는
        # 것은 손으로 만든 selection 이 들어왔을 때를 위한 것이며, bool 을
        # 먼저 막는다 — ``True in PRIORITY_WEIGHT`` 가 참이라 그냥 두면
        # 가장 강한 값인 1 이 된다.
        priority = entry.get("priority", DEFAULT_PRIORITY)
        if isinstance(priority, bool) or priority not in PRIORITY_WEIGHT:
            priority = DEFAULT_PRIORITY
        strongest[artifact] = min(strongest.get(artifact, DEFAULT_PRIORITY), priority)
    return strongest


def allocate_seats(
    candidates: dict[str, int], priorities: dict[str, int], limit: int
) -> dict[str, int]:
    """아티팩트별 자릿수를 정한다. 후보가 있는 곳은 최소 한 자리.

    바닥을 채우고 남은 자리는 동트(D'Hondt)식으로 하나씩 나눈다. 매번
    ``가중치 / (이미 받은 자리 + 1)``이 가장 큰 아티팩트가 다음 자리를
    가져간다. 최대잔여법과 달리 소수점 잔여를 들고 다니지 않아 배분 결과를
    손으로 따라갈 수 있고, 자리마다 누가 왜 가져갔는지 말할 수 있다.

    후보 수가 상한이다. 가진 것보다 많이 받지 않고, 남은 자리는 다른
    아티팩트로 돌아간다.
    """
    seats = {artifact: 0 for artifact in candidates}
    remaining = max(0, limit)

    def weight(artifact: str) -> int:
        return PRIORITY_WEIGHT[priorities.get(artifact, DEFAULT_PRIORITY)]

    # 바닥. 자리가 아티팩트 수보다 적으면 강한 쪽부터 받는다.
    for artifact in sorted(candidates, key=lambda a: (-weight(a), a)):
        if remaining <= 0:
            break
        if candidates[artifact] > 0:
            seats[artifact] = 1
            remaining -= 1

    while remaining > 0:
        open_artifacts = [a for a in candidates if seats[a] < candidates[a]]
        if not open_artifacts:
            break
        # 동점은 이름순으로 가른다. 근거가 있어서가 아니라 **같은 입력에
        # 같은 배분이 나와야** 재현율이 모델 성능의 지표가 되기 때문이다.
        winner = min(
            open_artifacts,
            key=lambda a: (-Fraction(weight(a), seats[a] + 1), a),
        )
        seats[winner] += 1
        remaining -= 1

    return seats


def allocate_records(
    records: Iterable[dict[str, Any]],
    *,
    priorities: dict[str, int] | None = None,
    signal_sources: dict[str, str] | None = None,
    limit: int = DEFAULT_LIMIT,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> tuple[list[dict[str, Any]], list[Quota]]:
    """전달할 레코드를 시간순으로, 배분 내역과 함께 돌려준다.

    ``priorities``가 비면 모든 아티팩트가 중립(``DEFAULT_PRIORITY``)이다.
    선별 결과 없이도 아티팩트별 배분은 그대로 작동한다 — 시나리오 반영만
    빠진다.
    """
    priorities = priorities or {}
    signal_sources = signal_sources or {}

    by_artifact: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_artifact.setdefault(record.get("artifact", ""), []).append(record)

    # 앵커는 **플래그가 붙은 레코드의 활동 시각**이다. 아티팩트를 가리지
    # 않으므로 evtx의 로그온 시각이 레지스트리 키를 끌어올 수 있다 —
    # 키오스크처럼 증거가 여러 계층에 흩어지는 사건에서 이 교차가 핵심이다.
    #
    # 시각을 못 읽는 신호는 앵커가 되지 못한다. "그 시각 주변"이라고 할
    # 시각이 없기 때문이다. 자기는 전달되되 창은 안 연다.
    anchors: list[datetime] = []
    for artifact_records in by_artifact.values():
        for record in artifact_records:
            if is_signal(record):
                anchors.extend(activity_times(record))

    # 앵커는 한 번만 정렬해 아티팩트마다 돌려 쓴다. 아티팩트마다 새로
    # 만들면 정렬 비용이 아티팩트 수만큼 붙는다.
    anchor_index = AnchorIndex(anchors)

    ranked = {
        artifact: _rank(
            artifact_records,
            anchor_index,
            window_seconds,
            signal_sources.get(artifact, DEFAULT_SIGNAL_SOURCE),
        )
        for artifact, artifact_records in by_artifact.items()
    }
    seats = allocate_seats(
        {artifact: len(entries) for artifact, entries in ranked.items()}, priorities, limit
    )

    chosen: list[tuple[datetime, dict[str, Any]]] = []
    quotas: list[Quota] = []
    for artifact in sorted(ranked):
        entries = ranked[artifact]
        given = seats[artifact]
        for _key, moment, record in entries[:given]:
            chosen.append((moment, record))
        quotas.append(
            Quota(
                artifact=artifact,
                priority=priorities.get(artifact, DEFAULT_PRIORITY),
                candidates=len(entries),
                seats=given,
                parsed=len(by_artifact[artifact]),
            )
        )

    chosen.sort(key=lambda item: item[0])
    return [record for _moment, record in chosen], quotas


def _rank(
    records: Sequence[dict[str, Any]],
    anchors: "AnchorIndex",
    window_seconds: float,
    signal_source: str,
) -> list[tuple[tuple[Any, ...], datetime, dict[str, Any]]]:
    """한 아티팩트 안에서 전달 순서를 매긴다. 앞에서부터 쿼터만큼 나간다.

    순위는 셋으로 나뉜다.

    0. **신호** — 룰이 볼 만하다고 판정했다. 가장 이른 활동 시각 순.
    1. **시간창 안의 주변 레코드** — 신호에 가까운 순. 의심스러운 사건
       하나만 보면 그것이 정상 작업인지 알 수 없다는 이유로 함께 넣는다.
    2. **선별이 골라 온 나머지** — ``signal_source: scope``인 아티팩트에만
       있다. 아래 설명 참조.

    ``signal_source``가 갈리는 지점이 2번이다. ``flags`` 아티팩트에서
    플래그도 없고 시간창에도 안 걸린 레코드는 볼 이유가 없으므로 후보에서
    빠진다. ``scope`` 아티팩트는 반대다 — 03단계의 ``path_prefix``가 이미
    신호 판정을 끝냈으므로 **모든 레코드가 후보**이고, 시간창으로 다시
    거르면 선별이 골라 온 것이 통째로 사라진다. 레지스트리의 LastWrite는
    대개 OS 설치 시각이라 사건 시간창에 걸리지 않는다.
    """
    entries: list[tuple[tuple[Any, ...], datetime, dict[str, Any]]] = []

    for index, record in enumerate(records):
        times = activity_times(record)
        ref = str(record.get("ref", ""))

        if is_signal(record):
            moment = min(times) if times else NO_TIME
            entries.append(((0, moment, ref), moment, record))
            continue

        found = anchors.nearest(times, window_seconds)
        if found is not None:
            distance, moment = found
            entries.append(((1, distance, moment, ref), moment, record))
            continue

        if signal_source == "scope":
            # 앵커에서 멀거나 앵커가 아예 없다. 그래도 선별이 골라 온
            # 것이므로 버리지 않고, 창 밖 거리로 줄을 세운다. 거리를 잴 수
            # 없으면 파일에 있던 순서를 쓴다 — 근거가 아니라 재현성을 위한
            # 것이며, 6-6이 말하는 "임시"가 바로 이 자리다.
            moment = min(times) if times else NO_TIME
            entries.append(((2, anchors.distance_to_any(times), index), moment, record))

    entries.sort(key=lambda item: item[0])
    return entries



