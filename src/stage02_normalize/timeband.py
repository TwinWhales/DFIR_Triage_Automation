"""한국어 서술의 벽시계 시각을 UTC 범위가 실제로 덮게 만든다.

스키마의 ``time_range`` 는 ``Z`` 로 고정돼 있고(`schemas/scenario.schema.json`),
04단계의 모든 타임스탬프도 UTC 다. 그런데 사람이 쓰는 서술은 벽시계다 —
``오전 11시경`` 은 KST 다. 소형 모델은 이 변환을 하지 않는다.

2026-09-07 `518_Test_0907` 실측이 그랬다. 입력의 ``2026년 9월 7일 오전
11시경`` 을 모델이 ``11:00:00Z`` 로 옮겼다. 실제 실행은 10:57 KST =
``01:57:30Z`` 였고, 아홉 시간 어긋난 범위 밖이라 그 프리패치 레코드는
``outside_time_range`` 로 밀려났다. **범위 하나가 정답 레코드를 걸렀다.**

## 무엇을 하고 무엇을 안 하나

**범위를 옮기지 않는다. 넓힌다.** 모델이 변환을 했는지 안 했는지 우리는
모른다 — 통째로 −9시간 옮겼다가 모델이 이미 옳게 변환했던 경우에는 멀쩡한
범위를 망친다. 그래서 두 읽기(벽시계를 UTC 로 읽은 것, KST 로 읽고 변환한
것)를 **둘 다 덮도록** 넓힌다. 넓히는 것은 이 프로젝트가 이미 택한 방향이다
— 프롬프트가 모델에게도 그렇게 말한다("범위가 좁으면 증거를 놓칩니다.
확신이 없으면 넓히십시오").

**이미 덮고 있으면 아무것도 안 한다.** 모델이 옳게 변환했거나 범위가 원래
넓었으면 이 모듈은 조용하다.

**표준시가 적혀 있으면 손대지 않는다.** 서술에 ``UTC``·``GMT``·``Z`` 가
있으면 쓴 사람이 표준시로 말한 것이므로 KST 로 가정할 근거가 없다.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

__all__ = [
    "DEFAULT_OFFSET_HOURS",
    "PAD",
    "Adjustment",
    "local_wall_clocks",
    "widen_for_local_time",
]

#: 한국 표준시. 서머타임이 없어 연중 고정이라 오프셋 하나로 끝난다.
DEFAULT_OFFSET_HOURS = 9

#: 서술이 시각 하나를 대면 그 **주변 이만큼까지** 범위가 덮어야 한다.
#:
#: 점 하나만 덮는지 보면 부족하다. ``11시경`` 의 ``경`` 은 정각이 아니라는
#: 뜻이고, 모델은 언급된 시각을 **범위의 경계에** 놓는 버릇이 있다 —
#: 2026-09-07 실측에서 모델이 변환은 옳게 해 놓고 ``02:00:00Z ~ 14:00:00Z``
#: 를 냈는데, 실제 실행은 ``01:57:30Z`` 로 시작 경계보다 2분 30초 빨랐다.
#: 정각만 봤다면 "이미 덮고 있다"고 판정하고 그 레코드를 놓쳤을 것이다.
PAD = timedelta(hours=2)

#: 이것이 있으면 쓴 사람이 **협정 세계시로** 말한 것이다. 가정하지 않는다.
#:
#: ``KST`` 는 여기 없다 — 그것이 적혀 있으면 오히려 변환해야 할 이유가
#: 뚜렷해진다. 막는 것은 "이미 UTC 로 적혀 있다"는 신호뿐이다.
_EXPLICIT_TZ = re.compile(r"\bUTC\b|\bGMT\b|\d\s*Z\b|협정\s*세계시", re.IGNORECASE)

#: 한글이 한 자라도 있는가. 한국어 서술일 때만 KST 를 가정한다.
_HANGUL = re.compile(r"[가-힣]")

#: ``2026년 9월 7일`` / ``9월 7일`` / ``2026-09-07`` / ``2026.09.07``
_DATE = re.compile(
    r"(?:(?P<y1>\d{4})\s*년\s*)?(?P<m1>\d{1,2})\s*월\s*(?P<d1>\d{1,2})\s*일"
    r"|(?P<y2>\d{4})[-/.](?P<m2>\d{1,2})[-/.](?P<d2>\d{1,2})"
)

#: 날짜 뒤에 이어지는 시각. ``오전 11시경`` / ``오후 3시 20분`` / ``11:00``
_TIME = re.compile(
    r"(?P<half>오전|오후|새벽|아침|저녁|밤)?\s*"
    r"(?:(?P<h1>\d{1,2})\s*시(?:\s*(?P<mi1>\d{1,2})\s*분)?"
    r"|(?P<h2>\d{1,2}):(?P<mi2>\d{2}))"
)

#: 날짜 뒤 어디까지를 "그 날짜의 시각"으로 볼 것인가(글자 수).
#: ``2026년 9월 7일 오전 11시경`` 이 넉넉히 들어가고, 다음 문장의 숫자까지
#: 끌어오지는 않는 길이다.
_TIME_WINDOW = 20


class Adjustment:
    """무엇을 왜 넓혔는지. ``basis`` 에 실릴 한 문장을 만든다."""

    def __init__(self, before: tuple[str, str], after: tuple[str, str], wall_clocks: list[str]):
        self.before = before
        self.after = after
        self.wall_clocks = wall_clocks

    def sentence(self, offset_hours: int = DEFAULT_OFFSET_HOURS) -> str:
        return (
            f"한국어 서술의 벽시계 시각({', '.join(self.wall_clocks)})을 "
            f"UTC+{offset_hours} 로 읽은 값까지 덮도록 범위를 넓혔다 "
            f"({self.before[0]}~{self.before[1]} → {self.after[0]}~{self.after[1]})."
        )

    def as_detail(self) -> dict[str, Any]:
        return {
            "field": "time_range",
            "wall_clocks": self.wall_clocks,
            "before": {"start": self.before[0], "end": self.before[1]},
            "after": {"start": self.after[0], "end": self.after[1]},
        }


def _to_utc(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str) -> datetime:
    return datetime.strptime(value.split(".")[0].rstrip("Z"), "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=timezone.utc
    )


def _hour_24(hour: int, half: str | None) -> int | None:
    """``오후 3시`` → 15. 범위를 벗어나면 ``None`` (그 시각은 버린다)."""
    if half in ("오후", "저녁", "밤") and hour < 12:
        hour += 12
    elif half in ("오전", "새벽", "아침") and hour == 12:
        hour = 0
    return hour if 0 <= hour <= 23 else None


def local_wall_clocks(raw: str) -> list[datetime]:
    """서술이 말한 벽시계 시각. 표준시 정보가 **없는** 순수한 연·월·일·시·분.

    날짜 하나에 시각이 붙어 있으면 그 한 점을, 시각이 없으면 그 날의
    처음과 끝(00:00, 23:59)을 낸다. 날짜가 없는 시각은 무시한다 — 어느
    날인지 모르면 UTC 로 옮길 수 없고, 모델의 범위에서 날짜를 빌려 오면
    그 범위가 틀렸을 때 같이 틀린다.

    돌려주는 값은 ``tzinfo`` 가 없는 naive datetime 이다. **어느 표준시로
    읽을지는 부르는 쪽이 정한다** — 그것이 이 모듈의 요점이다.
    """
    moments: list[datetime] = []
    for match in _DATE.finditer(raw):
        year = match.group("y1") or match.group("y2")
        month = match.group("m1") or match.group("m2")
        day = match.group("d1") or match.group("d2")
        if not (month and day):
            continue
        if not year:
            # 연도 없는 ``9월 7일``. 서술이 연도를 안 말했으면 우리도
            # 지어내지 않는다 — 날짜만으로는 UTC 를 만들 수 없다.
            continue

        tail = raw[match.end() : match.end() + _TIME_WINDOW]
        time_match = _TIME.search(tail)
        hour_text = None
        if time_match:
            hour_text = time_match.group("h1") or time_match.group("h2")

        try:
            if hour_text is None:
                base = datetime(int(year), int(month), int(day))
                moments += [base, base + timedelta(hours=23, minutes=59)]
                continue
            hour = _hour_24(int(hour_text), time_match.group("half"))
            if hour is None:
                continue
            minute = int(time_match.group("mi1") or time_match.group("mi2") or 0)
            if minute > 59:
                continue
            moments.append(datetime(int(year), int(month), int(day), hour, minute))
        except ValueError:
            # ``13월 40일`` 같은 것. 서술의 오타는 우리가 고칠 것이 아니다.
            continue
    return moments


def widen_for_local_time(
    time_range: dict[str, str], raw: str, *, offset_hours: int = DEFAULT_OFFSET_HOURS
) -> "Adjustment | None":
    """``time_range`` 를 제자리에서 넓힌다. 넓혔으면 무엇을 넓혔는지 돌려준다.

    안 넓히는 경우가 넷이다 — 한글이 없다, 표준시가 적혀 있다, 서술에서
    벽시계 시각을 못 찾았다, 그리고 **이미 `PAD` 만큼 덮고 있다.**
    """
    if not _HANGUL.search(raw) or _EXPLICIT_TZ.search(raw):
        return None

    wall_clocks = local_wall_clocks(raw)
    if not wall_clocks:
        return None

    start, end = _parse(time_range["start"]), _parse(time_range["end"])
    shift = timedelta(hours=offset_hours)
    #: 벽시계를 그 표준시로 읽었을 때 덮어야 하는 띠. 점이 아니라 띠인
    #: 이유는 `PAD` 에 적어 두었다.
    bands = [
        (moment.replace(tzinfo=timezone.utc) - shift - PAD,
         moment.replace(tzinfo=timezone.utc) - shift + PAD)
        for moment in wall_clocks
    ]

    uncovered = [(lo, hi) for lo, hi in bands if lo < start or hi > end]
    if not uncovered:
        return None

    before = (time_range["start"], time_range["end"])
    new_start = min([start] + [lo for lo, _ in uncovered])
    new_end = max([end] + [hi for _, hi in uncovered])
    time_range["start"], time_range["end"] = _to_utc(new_start), _to_utc(new_end)

    return Adjustment(
        before=before,
        after=(time_range["start"], time_range["end"]),
        wall_clocks=[moment.strftime("%Y-%m-%d %H:%M") for moment in wall_clocks],
    )
