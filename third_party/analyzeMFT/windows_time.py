# 우리가 고친 곳 — 2026-08-28
#
# **무엇을**: `dt`·`dtstr`·`unixtime` 을 생성자에서 계산하던 것을 property
# 로 늦췄다. 생성자는 이제 `low`/`high` 만 저장한다.
#
# **왜**: 이 파이프라인은 셋 중 어느 것도 읽지 않는다. 시각은
# `src/stage04_parse/parsers/mft.py` 의 `_times()` 가 `low`/`high` 에서
# **정수 연산으로 다시 계산한다** — `get_unix_time()` 의 float 나눗셈이
# 마이크로초를 틀어뜨리기 때문이고, 그 근거는 `docs/limitations.md` 에
# 있다. 즉 여기서 만든 값은 전량 폐기물이었다.
#
# 실측(2026-08-28, 98,151 레코드): 생성자 호출 4,034,184회 —
# 레코드당 41회다. `$MFT` 파서가 경로 재구성 때문에 두 번 도는데 1회차는
# 이름과 부모 번호만 쓰면서도 타임스탬프를 전부 변환하고 버렸다.
# `datetime.fromtimestamp` 2,463,625회 + `isoformat` 2,463,624회가
# 그 안에 있었다.
#
# **의미는 바꾸지 않았다.** 값과 예외 처리는 원본 그대로이고, 계산 시점만
# "생성할 때"에서 "처음 물을 때"로 옮겼다. 원본에서 `.dtstr` 을 읽는 곳은
# `mft_record.to_csv()` 하나이고 우리는 그것을 부르지 않는다.
from datetime import datetime, timezone
from typing import Optional

class WindowsTime:

    WINDOWS_EPOCH_DIFF: float = 11644473600.0  # Seconds between Windows and Unix epochs
    TICKS_PER_SECOND: float = 10000000.0       # 100-nanosecond intervals per second

    def __init__(self, low: int, high: int) -> None:
        self.low = int(low)
        self.high = int(high)
        self._resolved: bool = False
        self._dt: Optional[datetime] = None
        self._dtstr: str = "Not defined"
        self._unixtime: float = 0.0

    def _resolve(self) -> None:
        """처음 물을 때 한 번만 계산한다. 값은 원본 생성자와 같다."""
        if self._resolved:
            return
        self._resolved = True

        if (self.low == 0) and (self.high == 0):
            # 원본과 같다 — dt None / "Not defined" / 0.0 을 그대로 둔다.
            return

        unixtime = self.get_unix_time()

        try:
            if unixtime >= 0:
                self._dt = datetime.fromtimestamp(unixtime, tz=timezone.utc)
                self._dtstr = self._dt.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                self._unixtime = unixtime
            else:
                self._dtstr = "Invalid timestamp"
        except (OSError, OverflowError, ValueError):
            self._dt = None
            self._dtstr = "Invalid timestamp"
            self._unixtime = 0.0

    @property
    def dt(self) -> Optional[datetime]:
        self._resolve()
        return self._dt

    @property
    def dtstr(self) -> str:
        self._resolve()
        return self._dtstr

    @property
    def unixtime(self) -> float:
        self._resolve()
        return self._unixtime

    def get_unix_time(self) -> float:
        timestamp = (self.high << 32) | self.low
        return (timestamp / self.TICKS_PER_SECOND) - self.WINDOWS_EPOCH_DIFF

    def __str__(self) -> str:
        return self.dtstr

    def __repr__(self) -> str:
        return f"WindowsTime(low={self.low}, high={self.high}, unixtime={self.unixtime})"

    def is_valid(self) -> bool:
        return self.dt is not None and self.unixtime != 0.0
