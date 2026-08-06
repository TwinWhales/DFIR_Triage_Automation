"""필드 타입별 비교 규칙.

검증기가 지나치게 엄격해지면 정상 문장이 대량 기각되고, 환각률이 실제
환각이 아니라 표기 차이를 세게 된다. 이 모듈이 그 경계를 정한다.

세 가지를 관대하게 본다. 전부 "주장하는 사실은 같은데 표기가 다른" 경우다.

1. **타임스탬프** — ``03:14:22`` 대 ``03:14:22.1234567Z``. 완전 일치를 요구하면
   대량 오탐이 난다. 허용 오차는 호출자가 정한다.
2. **경로** — 대소문자 무시, 구분자 정규화. NTFS는 대소문자를 구별하지 않는다.
3. **타입** — 크기를 ``4821``로 쓰든 ``"4821"``로 쓰든 사실은 같다.

반대로 관대하게 보지 않는 것도 분명히 해 둔다. 부분 문자열 일치는 허용하지
않는다. ``"shell"``이 ``"shell.aspx"``에 들어 있다고 통과시키면, 경로를 대충
쓴 문장이 전부 통과해 검증이 무의미해진다.

`benchmark/validator_check.py`가 사람이 옳다고 판단한 문장 30건을 넣어
이 규칙이 과엄격하지 않은지 정기적으로 확인한다.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

__all__ = [
    "parse_timestamp",
    "normalize_path",
    "is_path_field",
    "compare",
    "get_field",
    "FieldMissing",
]


class FieldMissing(LookupError):
    """레코드에 해당 필드가 없다."""


#: 초 이하 자릿수를 제한하지 않는다. NTFS는 100ns 단위라 7자리가 오는데
#: ``datetime``은 마이크로초(6자리)까지만 담는다. 남는 자리는 버린다 —
#: 허용 오차가 초 단위이므로 100ns 손실은 판정에 영향이 없다.
_TIMESTAMP = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ]"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)

#: 경로로 취급할 필드. 이름으로 판단한다. 값의 생김새로 추측하면
#: ``C:\Users``처럼 보이는 계정명 같은 것에서 오작동한다.
PATH_FIELDS = frozenset({"path", "target_path", "source_path", "image_path"})


def parse_timestamp(value: Any) -> datetime | None:
    """ISO 8601 문자열을 UTC ``datetime``으로. 형식이 아니면 ``None``.

    타임존이 없으면 UTC로 간주한다. 파이프라인 전체가 UTC Z 표기로
    고정되어 있으므로(스키마가 강제한다) 이 가정은 안전하다.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    m = _TIMESTAMP.match(value.strip())
    if not m:
        return None

    frac = (m.group("frac") or "")[:6].ljust(6, "0")
    base = f"{m.group('date')}T{m.group('time')}.{frac}"
    dt = datetime.fromisoformat(base)

    tz = m.group("tz")
    if tz in (None, "Z"):
        return dt.replace(tzinfo=timezone.utc)
    sign = 1 if tz[0] == "+" else -1
    hh, mm = tz[1:].replace(":", "")[:2], tz[1:].replace(":", "")[2:4]
    return dt.replace(tzinfo=timezone(sign * timedelta(hours=int(hh), minutes=int(mm))))


def normalize_path(value: str) -> str:
    """대소문자와 구분자를 정규화한다.

    끝의 구분자도 떼어 ``C:\\dir``과 ``C:/dir/``를 같게 본다.
    """
    normalized = value.replace("\\", "/").lower()
    stripped = normalized.rstrip("/")
    # "/" 하나만 있던 경우까지 빈 문자열로 만들지는 않는다.
    return stripped or normalized


def is_path_field(field: str) -> bool:
    """경로 비교 규칙을 적용할 필드인가."""
    leaf = field.rsplit(".", 1)[-1].lower()
    return leaf in PATH_FIELDS or leaf.endswith("_path")


def get_field(record: dict[str, Any], field: str) -> Any:
    """점 표기로 레코드 안을 찾아 들어간다.

    ``fields.TargetUserName``처럼 EVTX 레코드의 중첩 값을 가리킬 때 쓴다.
    없으면 ``FieldMissing``. ``None``을 돌려주면 "값이 None인 필드"와
    구별할 수 없다.
    """
    current: Any = record
    walked: list[str] = []
    for part in field.split("."):
        walked.append(part)
        if not isinstance(current, dict) or part not in current:
            raise FieldMissing(".".join(walked))
        current = current[part]
    return current


def compare(field: str, claimed: Any, actual: Any, *, tolerance_seconds: float = 0.0) -> bool:
    """주장한 값이 실제 값과 같은가.

    ``actual``이 리스트면 원소 포함 여부를 본다. ``flags``가 그 경우다 —
    문장은 ``timestamp_mismatch`` 하나를 지목하는데 레코드는 플래그 배열을
    들고 있다.
    """
    if isinstance(actual, list):
        return any(
            compare(field, claimed, item, tolerance_seconds=tolerance_seconds) for item in actual
        )

    # 타임스탬프는 양쪽이 다 파싱되어야 시각 비교로 넘어간다. 한쪽만
    # 파싱되면 애초에 같은 종류의 값이 아니므로 불일치다.
    claimed_ts, actual_ts = parse_timestamp(claimed), parse_timestamp(actual)
    if claimed_ts is not None and actual_ts is not None:
        return abs((claimed_ts - actual_ts).total_seconds()) <= tolerance_seconds
    if (claimed_ts is None) != (actual_ts is None):
        return False

    if isinstance(claimed, str) and isinstance(actual, str) and is_path_field(field):
        return normalize_path(claimed) == normalize_path(actual)

    return _scalar_equal(claimed, actual)


def _scalar_equal(claimed: Any, actual: Any) -> bool:
    """표기 차이를 흡수한 스칼라 비교.

    bool을 먼저 처리한다. 파이썬에서 ``True == 1``이라 순서를 바꾸면
    ``allocated``가 ``1``이라는 주장이 통과한다.
    """
    if isinstance(claimed, bool) or isinstance(actual, bool):
        return _as_bool(claimed) is not None and _as_bool(claimed) == _as_bool(actual)

    if isinstance(claimed, (int, float)) or isinstance(actual, (int, float)):
        c, a = _as_number(claimed), _as_number(actual)
        if c is not None and a is not None:
            return c == a
        return False

    if isinstance(claimed, str) and isinstance(actual, str):
        return claimed.strip() == actual.strip()

    return claimed == actual


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None
