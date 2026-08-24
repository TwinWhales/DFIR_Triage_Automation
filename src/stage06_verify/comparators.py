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

`benchmark/validator_check.py`가 사람이 옳다고 판단한 문장 30건을 넣어
이 규칙이 과엄격하지 않은지 정기적으로 확인한다.
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
]


class FieldMissing(LookupError):
    """레코드에 해당 필드가 없다."""


#: 경로로 취급할 필드. 이름으로 판단한다. 값의 생김새로 추측하면
#: ``C:\Users``처럼 보이는 계정명 같은 것에서 오작동한다.
PATH_FIELDS = frozenset({"path", "target_path", "source_path", "image_path"})

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
    return leaf in PATH_FIELDS or leaf.endswith("_path")


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
