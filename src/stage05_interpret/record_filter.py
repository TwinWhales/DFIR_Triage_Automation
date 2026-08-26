"""레코드 하나가 볼 만한가 — 신호 판정과 활동 시각.

선별(03단계)이 아티팩트 단위로 좁힌 뒤에도 레코드는 수천 건이 남는다.
소형 모델 컨텍스트에 다 넣을 수 없으므로 한 번 더 줄인다. 그 줄이기가
두 가지 질문으로 나뉜다.

- **이 레코드가 볼 만한가** — 이 모듈. 신호 판정(``is_signal``)과
  활동 시각(``activity_times``), 신호까지의 거리(``nearest``).
- **어느 아티팩트에 몇 자리를 줄 것인가** — ``allocation``.

**규칙은 두 가지다.**

1. **신호 플래그가 붙은 레코드는 먼저 넣는다.** 룰 기반으로 이미
   "볼 만하다"고 판정된 것들이다.
2. **신호 주변의 레코드를 함께 넣는다.** 플래그가 붙은 시각 ±``window``
   안에서 활동한 레코드다.

2번이 있는 이유는 분석가의 작업 방식이다. 의심스러운 사건 하나만 보면
그것이 정상 작업인지 알 수 없다. 같은 시각에 무슨 일이 있었는지를
함께 봐야 판단이 선다. 전부 주는 것과 신호만 주는 것 사이의 절충이다.

**여기서 빠진 레코드는 06단계가 환각으로 잡는다.** 모델이 전달받지
않은 레코드를 언급하면 ``ref_not_in_input``이다. 그래서 배분이 무엇을
넣고 뺐는지가 그대로 ``input_refs``가 되어야 하며, 모델이 보고하는
값을 믿어서는 안 된다.
"""

from __future__ import annotations

from bisect import bisect_left
from datetime import datetime, timedelta, timezone
from typing import Any

from ..common.io import parse_timestamp

__all__ = [
    "DEFAULT_LIMIT",
    "DEFAULT_WINDOW_SECONDS",
    "NON_SIGNAL_FLAGS",
    "NO_TIME",
    "SI_TIME_FIELDS",
    "AnchorIndex",
    "activity_times",
    "is_signal",
    "nearest",
]

#: 전달할 최대 레코드 수.
#:
#: **상한이지 목표가 아니다.** 카탈로그가 11종이던 시절 7B 컨텍스트를 눈대중
#: 으로 잡은 값이고, 22종이 된 지금 60건이 무슨 크기가 되는지는 이 숫자가
#: 말해 주지 못한다 — 실측에서 71,476자였다가 100,068자였다. 창을 넘는지는
#: ``allocation``의 토큰 예산이 실제 글자 수로 판정한다.
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

#: 시각을 읽지 못한 신호 레코드가 앉을 정렬 자리. 맨 뒤로 보낸다.
#:
#: **tz-aware여야 한다.** 시각이 있는 신호와 같은 리스트에서 정렬되므로
#: naive를 쓰면 정렬이 ``can't compare offset-naive and offset-aware
#: datetimes``로 터지고 05단계가 통째로 멈춘다.
#:
#: 드문 경우가 아니다. ``$SI`` 타임스탬프가 전부 0인 레코드는
#: ``filetime_to_datetime``이 ``None``을 주고, 04단계가 거기에
#: ``zero_timestamp`` 플래그를 붙인다 — 즉 **시각이 없다는 사실 자체가
#: 그 레코드를 신호로 만든다.** 타임스탬프 조작 흔적이 있는 증거에서
#: 반드시 만나게 된다.
NO_TIME = datetime.max.replace(tzinfo=timezone.utc)


def is_signal(record: dict[str, Any]) -> bool:
    """볼 만하다고 룰이 판정한 레코드인가."""
    return bool(set(record.get("flags") or []) - NON_SIGNAL_FLAGS)


def activity_times(record: dict[str, Any]) -> list[datetime]:
    """이 레코드가 나타내는 활동 시각들."""
    # evtx·$UsnJrnl·레지스트리는 레코드마다 시각이 하나다. $MFT만 넷을
    # 들고 있어 아래에서 따로 모은다.
    if "timestamp" in record:
        parsed = parse_timestamp(record["timestamp"])
        return [parsed] if parsed else []

    times = []
    for field in SI_TIME_FIELDS:
        if field in record:
            parsed = parse_timestamp(record[field])
            if parsed:
                times.append(parsed)
    return times


#: 마이크로초 정수로 재기 위한 기준점과 눈금.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MICROSECOND = timedelta(microseconds=1)


def _microseconds(moment: datetime) -> int:
    """기준점부터의 마이크로초. ``timestamp()``와 달리 **정수라 오차가 없다.**

    ``float`` 초로 재면 2020년대 값(~1.8e9초)에서 마이크로초 자리가
    유효숫자 한계에 걸려 미세하게 어긋납니다. 실측에서 무차별 대입과
    1,200건 중 750건이 갈렸습니다 — 값 자체는 1µs 미만 차이지만
    거리로 줄을 세우는 자리라 순서가 뒤집힙니다.
    """
    return (moment - _EPOCH) // _MICROSECOND


class AnchorIndex:
    """앵커 시각을 **한 번만** 정렬해 두고 이분 탐색으로 최단 거리를 잰다.

    앵커마다 거리를 재면 ``비신호 레코드 × 앵커`` 곱이 그대로 연산량이
    됩니다. 실물 볼륨에서는 이 곱이 터집니다 — 사고 이미지 하나에서
    ``$MFT`` 신호 85,681건이 앵커 시각 337,264개를 만들었고, 비신호
    12,470건과 곱해 **3.4 × 10¹⁰ 회**가 됐습니다(약 56분). 목업
    데이터는 레코드가 수십 건이라 이 성질이 드러나지 않습니다.

    정렬은 한 번, 조회는 ``O(log n)``입니다. **고르는 값은 같습니다** —
    거리 최솟값과 그 활동 시각만 쓰고 어느 앵커였는지는 쓰지 않기
    때문입니다. 동점일 때 ``times`` 의 앞선 것이 이기는 성질도 그대로
    둡니다(호출 쪽 비교가 `<` 이므로).
    """

    __slots__ = ("_stamps",)

    def __init__(self, anchors: "list[datetime]") -> None:
        # 시각을 못 읽는 신호는 앵커가 되지 못한다. naive datetime 은
        # 뺄셈 자체가 안 되므로 여기서 거른다.
        self._stamps = sorted(
            _microseconds(anchor) for anchor in anchors if anchor.tzinfo is not None
        )

    def __len__(self) -> int:
        return len(self._stamps)

    def _closest(self, moment: datetime) -> float:
        """이 시각에서 가장 가까운 앵커까지의 초. 앵커가 없으면 무한대."""
        stamps = self._stamps
        if not stamps:
            return float("inf")
        target = _microseconds(moment)
        position = bisect_left(stamps, target)
        best = None
        if position < len(stamps):
            best = stamps[position] - target
        if position > 0:
            behind = target - stamps[position - 1]
            best = behind if best is None else min(best, behind)
        # ``timedelta.total_seconds()``가 하는 것과 같은 나눗셈이다.
        # 마이크로초를 정수로 재고 마지막에 한 번만 나누므로 원래
        # 무차별 대입과 **비트 단위로 같은 값**이 나온다.
        return abs(best) / 10**6

    def nearest(
        self, times: "list[datetime]", window_seconds: float
    ) -> "tuple[float, datetime] | None":
        """창 안에서 앵커에 가장 가까웠던 활동 시각과 그 거리."""
        best: tuple[float, datetime] | None = None
        for moment in times:
            if moment.tzinfo is None:
                continue
            distance = self._closest(moment)
            if distance <= window_seconds and (best is None or distance < best[0]):
                best = (distance, moment)
        return best

    def distance_to_any(self, times: "list[datetime]") -> float:
        """창을 무시한 최단 거리(초). 잴 수 없으면 무한대."""
        best = float("inf")
        for moment in times:
            if moment.tzinfo is None:
                continue
            best = min(best, self._closest(moment))
        return best


def nearest(
    times: list[datetime], anchors: list[datetime], window_seconds: float
) -> tuple[float, datetime] | None:
    """신호에 가장 가까웠던 활동 시각과 그 거리. 창 밖이면 ``None``.

    앵커를 여러 번 볼 곳에서는 ``AnchorIndex``를 만들어 재사용하십시오 —
    이 함수는 부를 때마다 정렬합니다.
    """
    return AnchorIndex(anchors).nearest(times, window_seconds)
