"""필드 타입별 비교 규칙.

검증기가 지나치게 엄격해지면 정상 문장이 대량 기각되고, 환각률이 실제
환각이 아니라 표기 차이를 세게 된다. 이 모듈이 그 경계를 정한다.

다섯 가지를 관대하게 본다. 전부 "주장하는 사실은 같은데 표기가 다른" 경우다.

1. **타임스탬프** — ``03:14:22`` 대 ``03:14:22.1234567Z``. 완전 일치를 요구하면
   대량 오탐이 난다. 허용 오차는 호출자가 정한다.
2. **경로** — 대소문자 무시, 구분자 정규화. NTFS는 대소문자를 구별하지 않는다.
3. **타입** — 크기를 ``4821``로 쓰든 ``"4821"``로 쓰든 사실은 같다.
4. **``fields.`` 접두어** — ``DisableRealtimeMonitoring`` 대
   ``fields.DisableRealtimeMonitoring``. 값이 최상위에 있는 아티팩트와
   ``fields`` 아래 있는 아티팩트가 섞여 있어 모델이 자주 틀리는 자리다
   (``get_field`` 참조).
5. **Windows Registry 간접 리소스 문자열** —
   ``@usb.inf,%usb\\composite.devicedesc%;USB Composite Device`` 대
   ``USB Composite Device``. ``DeviceDesc``처럼 Windows가 사용자 표시 문자열을
   리소스 참조와 함께 저장하는 필드에 한해서 같은 값으로 본다.

반대로 관대하게 보지 않는 것도 분명히 해 둔다. 부분 문자열 일치는 허용하지
않는다. ``"shell"``이 ``"shell.aspx"``에 들어 있다고 통과시키면, 경로를 대충
쓴 문장이 전부 통과해 검증이 무의미해진다.

Windows Registry 간접 리소스 문자열도 모든 문자열에 적용하지 않는다.
허용된 필드 이름에서만 정규화한다. 그렇지 않으면 세미콜론이 포함된 임의의
문자열이 의도치 않게 같은 값으로 처리될 수 있다.

`benchmark/validator_check.py`가 사람이 옳다고 판단한 문장을 넣어 이 규칙이
과엄격하지 않은지 정기적으로 확인한다. **경로 규칙과 Registry 문자열 규칙은
필드 이름으로 켜지므로, 아티팩트를 늘릴 때 이름을 같이 늘리지 않으면 조용히
정확 문자열 비교로 떨어진다** — 사례를 먼저 추가하고 고치는 것이 순서다.
"""

from __future__ import annotations

from typing import Any

from ..common.io import normalize_path, parse_timestamp

__all__ = [
    "parse_timestamp",
    "normalize_path",
    "is_path_field",
    "compare",
    "get_field",
    "FieldMissing",
    "PATH_FIELDS",
    "PATH_FIELD_SUFFIXES",
]


class FieldMissing(LookupError):
    """레코드에 요청한 필드가 없을 때 발생한다."""


#: 경로로 취급할 필드.
#:
#: 값의 생김새만 보고 경로라고 판단하지 않는다.
#: 예를 들어 ``C:\Users``처럼 보이는 문자열이라도 필드의 의미가 경로가
#: 아니라면 정확 문자열 비교를 유지한다.
PATH_FIELDS = frozenset(
    {
        # $MFT · USN · 파일시스템 계열
        "path",
        "target_path",
        "source_path",
        "image_path",

        # Sysmon 계열
        "image",
        "imagepath",
        "imageloaded",
        "parentimage",
        "sourceimage",
        "targetimage",
        "targetfilename",
        "originalfilename",
        "currentdirectory",

        # Security Event 계열
        "processname",
        "parentprocessname",
        "newprocessname",

        # Amcache
        "lowercaselongpath",
    }
)


#: 이름 끝으로도 경로 필드를 판정할 수 있는 접미어.
PATH_FIELD_SUFFIXES = ("_path", "filename")


#: Windows Registry 간접 리소스 문자열 정규화를 허용할 필드.
#:
#: 예:
#:   actual
#:   @usb.inf,%usb\composite.devicedesc%;USB Composite Device
#:
#:   claimed
#:   USB Composite Device
#:
#: 위 둘은 DeviceDesc 관점에서는 같은 사용자 표시 문자열이다.
#:
#: 단, 이 규칙을 모든 문자열에 적용하면 검증기가 지나치게 느슨해지므로
#: 명시된 필드에서만 사용한다.
WINDOWS_INDIRECT_STRING_FIELDS = frozenset(
    {
        "devicedesc",
    }
)


def is_path_field(field: str) -> bool:
    """경로 비교 규칙을 적용할 필드인지 판단한다."""
    leaf = field.rsplit(".", 1)[-1].lower()

    return (
        leaf in PATH_FIELDS
        or leaf.endswith(PATH_FIELD_SUFFIXES)
    )


def _walk(
    record: dict[str, Any],
    field: str,
) -> Any:
    """점 표기 필드를 따라 레코드 안의 값을 찾는다."""

    current: Any = record
    walked: list[str] = []

    for part in field.split("."):
        walked.append(part)

        if not isinstance(current, dict) or part not in current:
            raise FieldMissing(".".join(walked))

        current = current[part]

    return current


def _notation_alternatives(
    record: dict[str, Any],
    field: str,
) -> list[str]:
    """같은 필드를 가리킬 수 있는 다른 표기를 반환한다.

    예:

        DisableRealtimeMonitoring
        fields.DisableRealtimeMonitoring

    아티팩트마다 값이 최상위에 있거나 ``fields`` 아래에 있을 수 있으므로
    이 표기 차이만 허용한다.
    """

    if field.startswith("fields."):
        return [field[len("fields.") :]]

    if isinstance(record.get("fields"), dict):
        return [f"fields.{field}"]

    return []


def get_field(
    record: dict[str, Any],
    field: str,
) -> Any:
    """레코드에서 필드를 찾는다.

    먼저 모델이 지정한 표기를 그대로 시도하고, 실패하면
    ``fields.`` 접두어 차이만 보정한다.

    필드를 찾은 이후 실제 값이 같은지는 ``compare``가 판단한다.
    """

    try:
        return _walk(record, field)
    except FieldMissing as missing:
        original = missing

    for alternative in _notation_alternatives(record, field):
        try:
            return _walk(record, alternative)
        except FieldMissing:
            continue

    raise original


def compare(
    field: str,
    claimed: Any,
    actual: Any,
    *,
    tolerance_seconds: float = 0.0,
) -> bool:
    """주장한 값과 실제 파싱 값을 비교한다.

    비교 순서:

    1. 배열
    2. 타임스탬프
    3. 경로
    4. Windows Registry 간접 리소스 문자열
    5. 일반 스칼라 값

    임의의 부분 문자열 비교나 fuzzy matching은 수행하지 않는다.
    """

    # 실제 값이 배열이면 요소 중 하나와 정확한 의미 비교가 가능한지 본다.
    if isinstance(actual, list):
        return any(
            compare(
                field,
                claimed,
                item,
                tolerance_seconds=tolerance_seconds,
            )
            for item in actual
        )

    # 타임스탬프 비교
    claimed_ts = parse_timestamp(claimed)
    actual_ts = parse_timestamp(actual)

    if claimed_ts is not None and actual_ts is not None:
        difference = abs(
            (claimed_ts - actual_ts).total_seconds()
        )

        return difference <= tolerance_seconds

    # 한쪽만 타임스탬프로 해석되면 서로 다른 값이다.
    if (claimed_ts is None) != (actual_ts is None):
        return False

    # Windows 경로 비교
    if (
        isinstance(claimed, str)
        and isinstance(actual, str)
        and is_path_field(field)
    ):
        return (
            normalize_path(claimed)
            == normalize_path(actual)
        )

    # Windows Registry 간접 리소스 문자열 비교
    if (
        isinstance(claimed, str)
        and isinstance(actual, str)
        and _is_windows_indirect_string_field(field)
    ):
        return (
            _normalize_windows_indirect_string(claimed)
            == _normalize_windows_indirect_string(actual)
        )

    # 일반 값 비교
    return _scalar_equal(claimed, actual)


def _is_windows_indirect_string_field(
    field: str,
) -> bool:
    """Registry 간접 리소스 문자열 비교를 허용할 필드인지 판단한다."""

    leaf = field.rsplit(".", 1)[-1].lower()

    return leaf in WINDOWS_INDIRECT_STRING_FIELDS


def _normalize_windows_indirect_string(
    value: str,
) -> str:
    """Windows Registry 간접 리소스 문자열을 표시 문자열로 정규화한다.

    예:

        @usb.inf,%usb\\composite.devicedesc%;USB Composite Device

    는 다음과 같이 정규화된다.

        USB Composite Device

    ``@``로 시작하지 않거나 세미콜론이 없다면 일반 문자열 그대로 반환한다.
    """

    text = value.strip()

    if not text.startswith("@"):
        return text

    if ";" not in text:
        return text

    display_value = text.rsplit(";", 1)[1].strip()

    if not display_value:
        return text

    return display_value


def _scalar_equal(
    claimed: Any,
    actual: Any,
) -> bool:
    """표기 차이만 허용하는 일반 스칼라 비교."""

    # Python에서는 bool이 int의 하위 타입이므로 숫자보다 먼저 처리한다.
    if isinstance(claimed, bool) or isinstance(actual, bool):
        claimed_bool = _as_bool(claimed)
        actual_bool = _as_bool(actual)

        return (
            claimed_bool is not None
            and actual_bool is not None
            and claimed_bool == actual_bool
        )

    # 숫자와 숫자 문자열은 같은 값으로 볼 수 있다.
    if (
        isinstance(claimed, (int, float))
        or isinstance(actual, (int, float))
    ):
        claimed_number = _as_number(claimed)
        actual_number = _as_number(actual)

        if (
            claimed_number is not None
            and actual_number is not None
        ):
            return claimed_number == actual_number

        return False

    # 일반 문자열은 앞뒤 공백만 제거하고 정확히 비교한다.
    # 부분 문자열 비교는 절대 하지 않는다.
    if isinstance(claimed, str) and isinstance(actual, str):
        return claimed.strip() == actual.strip()

    return claimed == actual


def _as_bool(
    value: Any,
) -> bool | None:
    """bool 또는 true/false 문자열을 bool로 변환한다."""

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in ("true", "false"):
            return normalized == "true"

    return None


def _as_number(
    value: Any,
) -> float | None:
    """숫자 또는 숫자 문자열을 비교 가능한 숫자로 변환한다."""

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