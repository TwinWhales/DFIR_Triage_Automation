"""필드 타입별 비교 규칙.

검증기가 지나치게 엄격해지면 정상 문장이 대량 기각되고, 환각률이 실제
환각이 아니라 표기 차이를 세게 된다. 이 모듈이 그 경계를 정한다.

네 가지를 관대하게 본다. 전부 "주장하는 사실은 같은데 표기가 다른" 경우다.

1. **타임스탬프** — ``03:14:22`` 대 ``03:14:22.1234567Z``. 완전 일치를 요구하면
   대량 오탐이 난다. 허용 오차는 호출자가 정한다.
2. **경로** — 대소문자 무시, 구분자 정규화. NTFS는 대소문자를 구별하지 않는다.
3. **타입** — 크기를 ``4821``로 쓰든 ``"4821"``로 쓰든 사실은 같다.
4. **``fields.`` 접두어** — ``DisableRealtimeMonitoring`` 대
   ``fields.DisableRealtimeMonitoring``. 값이 최상위에 있는 아티팩트와
   ``fields`` 아래 있는 아티팩트가 섞여 있어 모델이 자주 틀리는 자리다
   (``get_field`` 참조).

반대로 관대하게 보지 않는 것도 분명히 해 둔다. 부분 문자열 일치는 허용하지
않는다. ``"shell"``이 ``"shell.aspx"``에 들어 있다고 통과시키면, 경로를 대충
쓴 문장이 전부 통과해 검증이 무의미해진다.

`benchmark/validator_check.py`가 사람이 옳다고 판단한 문장을 넣어 이 규칙이
과엄격하지 않은지 정기적으로 확인한다. **경로 규칙은 필드 이름으로 켜지므로,
아티팩트를 늘릴 때 이름을 같이 늘리지 않으면 조용히 정확 문자열 비교로
떨어진다** — 사례를 먼저 추가하고 고치는 것이 순서다.
"""

from __future__ import annotations

from datetime import datetime, timezone
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
    "is_date_field",
    "DATE_FIELDS",
    "DATE_FIELD_FORMATS",
]


class FieldMissing(LookupError):
    """레코드에 해당 필드가 없다."""


#: 경로로 취급할 필드. **이름으로 판단한다.** 값의 생김새로 추측하면
#: ``C:\Users``처럼 보이는 계정명 같은 것에서 오작동한다.
#:
#: 이름 목록이라 **아티팩트를 늘릴 때마다 같이 늘려야 한다.** 안 늘리면
#: 조용히 정확 문자열 비교로 떨어져 대소문자 하나로 정상 문장이 기각된다.
#: 2026-08-26 실측에서 실제로 그랬다 — `docs/limitations.md` "검증기가
#: 경로 표기 차이를 환각으로 센다".
PATH_FIELDS = frozenset(
    {
        # $MFT·USN·프리패치 등 최상위 경로
        "path",
        "target_path",
        "source_path",
        "image_path",
        # Sysmon — K-001 Stage 2·3 이 여기 기댄다
        "image",
        "imagepath",
        "imageloaded",
        "parentimage",
        "sourceimage",
        "targetimage",
        "targetfilename",
        "originalfilename",
        "currentdirectory",
        # Security 4688·4624 계열
        "processname",
        "parentprocessname",
        "newprocessname",
        # Amcache — 값이 **전부 소문자로 저장된다**(`c:\program files\...`).
        # 모델은 `C:\Program Files\...` 라고 쓰므로, 여기 없으면 정확 문자열
        # 비교로 떨어져 Amcache 를 인용한 정상 문장이 **전량** 기각된다.
        # Root\File 의 숫자 이름을 이 이름으로 바꾸는 것은 04단계다
        # (`parsers/registry.AMCACHE_FILE_VALUE_NAMES`).
        "lowercaselongpath",
    }
)

#: 이름 끝으로도 받는다. 새 채널이 같은 관례를 따르면 목록을 안 고쳐도 된다.
PATH_FIELD_SUFFIXES = ("_path", "filename")

#: **레지스트리가 시각을 문자열로 적어 둔 자리.** 값이 ``RegSZ`` 라
#: 04단계가 원본 그대로 냅니다 — ``'03/20/2017 03:53:52'``.
#:
#: 이 프로젝트의 다른 시각은 전부 ISO 8601 이고 모델도 그렇게 씁니다.
#: 그러면 ``parse_timestamp`` 가 모델 쪽만 파싱하고 레코드 쪽은 못 해
#: "같은 종류의 값이 아니다"로 떨어집니다. **사실은 같은데 표기가 다른
#: 경우**라 모듈 첫머리의 네 가지와 같은 부류입니다. 실측 이미지의
#: ``InventoryApplication`` 78건이 전부 이 표기입니다.
#:
#: **경로와 같이 이름으로 켭니다.** 아무 문자열에나 이 형식을 시도하면
#: 값의 생김새로 판단하는 것이 되고, 이 모듈이 처음부터 거부한 방식입니다.
#: 04단계에서 값을 바꾸지 않는 이유도 같습니다 — 산출물은 하이브에 적힌
#: 것에 충실해야 하고, 표기를 흡수하는 것은 비교기의 일입니다.
DATE_FIELDS = frozenset({"installdate"})

#: ``DATE_FIELDS`` 에서만 추가로 시도하는 형식. 레지스트리가 쓰는 미국식
#: 표기이고 타임존이 없습니다 — ``parse_timestamp`` 와 같이 UTC 로 봅니다.
DATE_FIELD_FORMATS = ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y")

#: **`CommandLine` 은 일부러 뺐다.** 앞머리는 경로지만 뒤는 인자다.
#: 경로 규칙으로 대소문자를 지우면 인자의 실제 차이(`-EncodedCommand` 의
#: base64 등)까지 같이 지워져 검증이 물러진다.

# normalize_path와 parse_timestamp는 common에서 가져다 쓴다. 04단계의 범위
# 매칭이 같은 함수를 쓰기 때문이다. NTFS 대소문자 무시는 검증 정책이 아니라
# 파일시스템의 사실이므로 두 단계가 갈라지면 안 된다.
#
# 여기서 다시 정의하지 않는다. 한때 같은 이름의 사본이 아래에 있었는데,
# 본문이 같아 아무도 눈치채지 못하는 채로 import를 가리고 있었다. 한쪽만
# 고치는 순간 04와 06이 다른 규칙으로 경로를 비교하게 된다 — 이 주석이
# 막으려던 바로 그 상황이다.


def is_path_field(field: str) -> bool:
    """경로 비교 규칙을 적용할 필드인가."""
    leaf = field.rsplit(".", 1)[-1].lower()
    return leaf in PATH_FIELDS or leaf.endswith(PATH_FIELD_SUFFIXES)


def is_date_field(field: str) -> bool:
    """ISO 8601 밖의 날짜 표기를 흡수할 필드인가."""
    return field.rsplit(".", 1)[-1].lower() in DATE_FIELDS


def _as_datetime(field: str, value: Any) -> "datetime | None":
    """``parse_timestamp`` 에 ``DATE_FIELDS`` 용 형식을 더한 것.

    ISO 8601 이 먼저다. 그쪽이 파이프라인의 규약이고, 실패했을 때만
    이름이 허락한 형식을 시도한다.
    """
    parsed = parse_timestamp(value)
    if parsed is not None or not isinstance(value, str) or not is_date_field(field):
        return parsed
    for fmt in DATE_FIELD_FORMATS:
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _walk(record: dict[str, Any], field: str) -> Any:
    """점 표기를 그대로 따라 들어간다. 없으면 끊긴 지점을 담아 올린다."""
    current: Any = record
    walked: list[str] = []
    for part in field.split("."):
        walked.append(part)
        if not isinstance(current, dict) or part not in current:
            raise FieldMissing(".".join(walked))
        current = current[part]
    return current


def _notation_alternatives(record: dict[str, Any], field: str) -> "list[str]":
    """같은 필드를 가리키는 다른 표기.

    레코드마다 값이 어디 있는지가 다르다. ``$MFT``는 ``path``를 최상위에
    두고, evtx·레지스트리·프리패치는 ``fields`` 아래 둔다. 모델은 이 차이를
    자주 틀린다 — 둘 다 실제로 겪었다.

    **모호해질 수 없다.** 원래 표기가 먼저 시도되고 성공하면 여기까지 오지
    않으므로, 최상위와 ``fields``에 같은 이름이 있어도 최상위가 이긴다.
    """
    if field.startswith("fields."):
        return [field[len("fields.") :]]
    if isinstance(record.get("fields"), dict):
        return [f"fields.{field}"]
    return []


def get_field(record: dict[str, Any], field: str) -> Any:
    """점 표기로 레코드 안을 찾아 들어간다.

    ``fields.TargetUserName``처럼 EVTX 레코드의 중첩 값을 가리킬 때 쓴다.
    없으면 ``FieldMissing``. ``None``을 돌려주면 "값이 None인 필드"와
    구별할 수 없다.

    **``fields.`` 접두어의 유무는 흡수한다.** 모듈 첫머리의 세 가지와 같은
    부류의 네 번째다 — 주장하는 사실은 같은데 표기가 다른 경우다. 실측에서
    모델이 ``fields.DisableRealtimeMonitoring``을 ``DisableRealtimeMonitoring``
    으로 썼는데, ref 도 필드명도 값도 맞는 문장이 ``field_not_found``로
    기각돼 **환각률 100%**로 집계됐다(2026-08-24).

    흡수해도 검증이 무르지 않는 이유는 **찾은 뒤에 값을 여전히 대조하기
    때문**이다. 이 함수가 하는 일은 "모델이 가리킨 필드를 찾아 주는 것"까지고,
    값이 틀리면 ``compare``가 ``value_mismatch``로 기각한다. 없는 필드를
    지어낸 경우는 대안 표기로도 못 찾으므로 그대로 ``FieldMissing``이다.
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
    # 끊긴 지점은 **모델이 쓴 표기 기준**으로 남긴다. 대안 표기의 끊긴
    # 지점을 보고하면 기각 사유가 모델이 쓰지도 않은 경로를 가리킨다.
    raise original


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
    claimed_ts = _as_datetime(field, claimed)
    actual_ts = _as_datetime(field, actual)
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
