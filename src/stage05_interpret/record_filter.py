"""LLM에 전달할 레코드를 추린다.

선별(03단계)이 아티팩트 단위로 좁힌 뒤에도 레코드는 수천 건이 남는다.
소형 모델 컨텍스트에 다 넣을 수 없으므로 한 번 더 줄인다.

**규칙은 두 가지다.**

1. **신호 플래그가 붙은 레코드는 전부 넣는다.** 룰 기반으로 이미
   "볼 만하다"고 판정된 것들이다.
2. **신호 주변의 레코드를 함께 넣는다.** 플래그가 붙은 시각 ±``window``
   안에서 활동한 레코드다.

2번이 있는 이유는 분석가의 작업 방식이다. 의심스러운 사건 하나만 보면
그것이 정상 작업인지 알 수 없다. 같은 시각에 무슨 일이 있었는지를
함께 봐야 판단이 선다. 전부 주는 것과 신호만 주는 것 사이의 절충이다.

**여기서 빠진 레코드는 06단계가 환각으로 잡는다.** 모델이 전달받지
않은 레코드를 언급하면 ``ref_not_in_input``이다. 그래서 이 함수가
무엇을 넣고 뺐는지가 그대로 ``input_refs``가 되어야 하며, 모델이
보고하는 값을 믿어서는 안 된다.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from ..common.io import parse_timestamp

__all__ = [
    "DEFAULT_LIMIT",
    "DEFAULT_WINDOW_SECONDS",
    "NON_SIGNAL_FLAGS",
    "SI_TIME_FIELDS",
    "activity_times",
    "is_signal",
    "select_records",
]

#: 전달할 최대 레코드 수. 7B 모델 컨텍스트를 기준으로 잡은 값이다.
DEFAULT_LIMIT = 60

#: 신호 주변으로 함께 볼 시간 폭(초).
DEFAULT_WINDOW_SECONDS = 300

#: 플래그이긴 하나 "볼 만하다"는 신호가 아닌 것.
#:
#: ``outside_time_range``는 정보 표시일 뿐이다. 이것을 신호로 치면
#: 선별 범위 밖 레코드가 우선 전달되어, 시간 범위를 좁힌 의미가 사라진다.
NON_SIGNAL_FLAGS = frozenset({"outside_time_range"})

#: MFT 레코드에서 "활동 시각"으로 볼 필드.
#:
#: ``$FN``은 제외한다. $SI와 어긋나는 것이 타임스탬프 조작의 신호이지
#: 실제 활동 시각이 아니다. $FN을 섞으면 조작된 레코드가 엉뚱한 시점으로
#: 정렬되어 타임라인이 뒤틀린다.
SI_TIME_FIELDS = ("si_btime", "si_ctime", "si_mtime", "si_atime")


def is_signal(record: dict[str, Any]) -> bool:
    """볼 만하다고 룰이 판정한 레코드인가."""
    return bool(set(record.get("flags") or []) - NON_SIGNAL_FLAGS)


def activity_times(record: dict[str, Any]) -> list[datetime]:
    """이 레코드가 나타내는 활동 시각들."""
    if "timestamp" in record:  # EVTX
        parsed = parse_timestamp(record["timestamp"])
        return [parsed] if parsed else []

    times = []
    for field in SI_TIME_FIELDS:
        if field in record:
            parsed = parse_timestamp(record[field])
            if parsed:
                times.append(parsed)
    return times


def select_records(
    records: Iterable[dict[str, Any]],
    *,
    limit: int = DEFAULT_LIMIT,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> list[dict[str, Any]]:
    """전달할 레코드를 시간순으로 돌려준다.

    각 레코드는 "포함된 이유가 된 시각"을 기준으로 정렬된다. 플래그가
    붙은 레코드는 가장 이른 활동 시각, 주변 레코드는 신호에 가장 가까웠던
    활동 시각이 기준이다. 그래야 모델이 받는 순서가 사건 순서와 맞는다.
    """
    signals: list[tuple[datetime, dict[str, Any]]] = []
    others: list[dict[str, Any]] = []

    for record in records:
        times = activity_times(record)
        if is_signal(record):
            # 시각을 못 읽는 레코드도 신호라면 버리지 않는다.
            signals.append((min(times) if times else datetime.max.replace(tzinfo=None), record))
        else:
            others.append(record)

    anchors = [anchor for anchor, _ in signals if anchor.tzinfo is not None]

    context: list[tuple[float, datetime, dict[str, Any]]] = []
    for record in others:
        nearest = _nearest(activity_times(record), anchors, window_seconds)
        if nearest is not None:
            distance, moment = nearest
            context.append((distance, moment, record))

    # 신호가 자리를 먼저 차지하고, 남는 자리를 가까운 순으로 채운다.
    chosen: list[tuple[datetime, dict[str, Any]]] = [(t, r) for t, r in signals][:limit]
    context.sort(key=lambda item: item[0])
    for _distance, moment, record in context[: max(0, limit - len(chosen))]:
        chosen.append((moment, record))

    chosen.sort(key=lambda item: item[0])
    return [record for _moment, record in chosen]


def _nearest(
    times: list[datetime], anchors: list[datetime], window_seconds: float
) -> tuple[float, datetime] | None:
    """신호에 가장 가까웠던 활동 시각과 그 거리. 창 밖이면 ``None``."""
    best: tuple[float, datetime] | None = None
    for moment in times:
        if moment.tzinfo is None:
            continue
        for anchor in anchors:
            distance = abs((moment - anchor).total_seconds())
            if distance <= window_seconds and (best is None or distance < best[0]):
                best = (distance, moment)
    return best
