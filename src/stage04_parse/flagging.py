"""``flags`` 어휘 룰 적용.

파서는 레코드를 만들기만 하고 플래그는 여기서 일괄로 붙입니다. 룰이
파서마다 흩어지면 어휘가 갈라지고, 그러면 05단계의 레코드 추림이
레코드를 놓칩니다. 놓친 결과는 "선별 재현율 저하"로 잘못 집계됩니다.

플래그는 **LLM에 전달할 레코드를 추리는 필터**입니다. 수천 건에서 수십
건으로 줄이는 기준이므로, 여기서 안 붙으면 그 레코드는 사실상 없는 것이
됩니다. 반대로 남발하면 필터가 일을 안 하게 됩니다.

어휘는 ``mappings/_flags.yaml``과 ``schemas/parsed_record.schema.json``
양쪽에 적혀 있고 테스트가 일치를 확인합니다. **여기서 새 이름을 만들지
마십시오.**
"""

from __future__ import annotations

import functools
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

import yaml

from ..common.io import parse_timestamp

__all__ = [
    "FLAGS",
    "DEFAULT_PRIVILEGED_GROUPS",
    "SI_FIELDS",
    "FN_FIELDS",
    "mappings_dir",
    "privileged_groups",
    "apply",
    "apply_all",
]

#: 고정 어휘. schemas/parsed_record.schema.json의 enum과 같아야 한다.
FLAGS = (
    "timestamp_mismatch",
    "deleted",
    "zero_timestamp",
    "file_created",
    "account_created",
    "privileged_group_add",
    "service_installed",
    "outside_time_range",
)

#: ``$STANDARD_INFORMATION`` / ``$FILE_NAME``의 대응하는 타임스탬프 쌍.
#: 순서가 서로 맞아야 한다. ``zero_timestamp``와 시간 범위 판정에 쓴다.
SI_FIELDS = ("si_btime", "si_ctime", "si_mtime")
FN_FIELDS = ("fn_btime", "fn_ctime", "fn_mtime")

#: ``timestamp_mismatch`` 판정에 쓰는 쌍. **생성 시각만 본다.**
#:
#: 처음에는 세 쌍을 모두 봤는데 실제 이미지에서 154건 중 91건(59%)이
#: 걸렸다. 전부 오탐이었다.
#:
#: 원인: 파일을 복사하면 ``$SI``의 ctime·mtime은 원본에서 보존되고
#: ``$FN``은 새 디렉터리 항목이 만들어진 시각으로 설정된다. 그래서
#: ``si_ctime < fn_ctime``이 **정상적으로** 성립한다.
#:
#: "파일이 자기 이름 항목보다 먼저 존재할 수 없다"는 논리는 **생성
#: 시각에만** 적용된다. 같은 이미지에서 생성 시각 비교는 0건이 걸렸다.
#: 측정 기록은 ``docs/artifact-notes.md`` 참조.
MISMATCH_PAIRS = (("si_btime", "fn_btime"),)

#: ``_flags.yaml``을 읽지 못했을 때 쓰는 값.
DEFAULT_PRIVILEGED_GROUPS = frozenset(
    {
        "administrators",
        "domain admins",
        "enterprise admins",
        "backup operators",
        "remote desktop users",
    }
)

#: FILETIME 0은 1601-01-01. 이보다 이르거나 같으면 값이 없는 것이다.
_FILETIME_EPOCH = datetime(1601, 1, 2, tzinfo=timezone.utc)

_ACCOUNT_CREATED_EVENTS = frozenset({4720})
_GROUP_ADD_EVENTS = frozenset({4728, 4732})
_SERVICE_INSTALL_EVENTS = frozenset({7045})


def mappings_dir() -> Path:
    """``mappings/`` 위치. ``src/stage04_parse/flagging.py`` 기준."""
    return Path(__file__).resolve().parents[2] / "mappings"


@functools.lru_cache(maxsize=None)
def privileged_groups(directory: str | None = None) -> frozenset[str]:
    """특권 그룹 이름 집합(소문자). ``_flags.yaml``에서 읽는다.

    파일이 없거나 항목이 비면 기본값을 씁니다. 플래그가 조용히 안 붙는
    것보다 기본값으로라도 붙는 편이 낫습니다.
    """
    path = Path(directory or mappings_dir()) / "_flags.yaml"
    if not path.is_file():
        return DEFAULT_PRIVILEGED_GROUPS
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    names = data.get("privileged_groups") or []
    return frozenset(str(n).strip().lower() for n in names) or DEFAULT_PRIVILEGED_GROUPS


def apply(
    record: dict[str, Any],
    scope: Any = None,
    *,
    groups: frozenset[str] | None = None,
) -> dict[str, Any]:
    """레코드 하나에 플래그를 붙여 새 dict를 돌려준다.

    ``flags``를 **맨 뒤에** 놓습니다. 사람이 JSONL을 눈으로 훑을 때
    줄 끝에 플래그가 오면 읽기 쉽습니다.

    ``scope``는 ``parsers.base.Scope``입니다. 주면 ``outside_time_range``를
    판정하고, 없으면 그 플래그는 붙지 않습니다.
    """
    groups = privileged_groups() if groups is None else groups

    found: list[str] = []
    artifact = record.get("artifact", "")

    if artifact == "$MFT":
        found.extend(_mft_flags(record))
    if artifact == "$UsnJrnl":
        found.extend(_usn_flags(record))
    if artifact.startswith("evtx:"):
        found.extend(_evtx_flags(record, groups))
    if scope is not None and _outside_time_range(record, scope):
        found.append("outside_time_range")

    # 파서가 이미 붙인 것이 있으면 합친다. 순서는 FLAGS 기준으로 고정해
    # 같은 레코드가 항상 같은 JSON을 내게 한다.
    existing = record.get("flags") or []
    merged = {f for f in list(existing) + found if f in FLAGS}

    unknown = {f for f in list(existing) + found} - set(FLAGS)
    if unknown:
        raise ValueError(
            f"{record.get('ref')}: 미등록 플래그 {sorted(unknown)}. "
            f"어휘는 mappings/_flags.yaml 과 parsed_record 스키마에 고정되어 있다."
        )

    out = {key: value for key, value in record.items() if key != "flags"}
    out["flags"] = [f for f in FLAGS if f in merged]
    return out


def apply_all(
    records: Iterable[dict[str, Any]],
    scope: Any = None,
    *,
    groups: frozenset[str] | None = None,
) -> Iterator[dict[str, Any]]:
    """레코드를 흘려보내며 플래그를 붙인다."""
    resolved = privileged_groups() if groups is None else groups
    for record in records:
        yield apply(record, scope, groups=resolved)


# ------------------------------------------------------------------ $MFT


def _mft_flags(record: dict[str, Any]) -> list[str]:
    found: list[str] = []

    if record.get("allocated") is False:
        found.append("deleted")

    times = {
        field: parse_timestamp(record.get(field))
        for field in SI_FIELDS + FN_FIELDS + ("si_atime", "fn_atime")
        if field in record
    }

    if _has_zero_timestamp(record, times):
        found.append("zero_timestamp")

    if _timestamp_mismatch(times):
        found.append("timestamp_mismatch")

    return found


def _has_zero_timestamp(record: dict[str, Any], times: dict[str, datetime | None]) -> bool:
    """값이 없거나 FILETIME 0에 해당하는 타임스탬프가 있는가.

    이런 레코드를 버리지 않고 표시하는 이유는, 그 이상함 자체가 증거인
    경우가 있기 때문입니다. 조작 도구가 타임스탬프를 0으로 밀어 버립니다.
    """
    for field in SI_FIELDS + FN_FIELDS:
        if field not in record:
            continue
        moment = times.get(field)
        if moment is None or moment < _FILETIME_EPOCH:
            return True
    return False


def _timestamp_mismatch(times: dict[str, datetime | None]) -> bool:
    """``$SI`` 생성 시각이 ``$FN``보다 이른가.

    **방향과 대상이 모두 중요합니다.**

    방향 — 단순 불일치로 잡으면 이름이 바뀐 파일이 전부 걸립니다.
    ``$FN``은 rename 시점에 갱신되므로 정상적으로도 달라집니다. 반대로
    ``$SI``가 더 이른 것은 파일이 자기 이름 항목보다 먼저 존재했다는
    뜻이라 자연적으로 생기기 어렵습니다.

    대상 — **생성 시각만** 봅니다. ctime·mtime까지 보면 파일 복사가 전부
    걸립니다(실측 59%). ``MISMATCH_PAIRS``의 주석에 근거가 있습니다.

    타임스탬프 조작 도구는 대개 ``$SI``만 과거로 되돌리는데, ``$FN``은
    커널이 갱신해 일반 도구로 바꾸기 어렵습니다. 그 비대칭이 이 판정의
    근거입니다.
    """
    for si_field, fn_field in MISMATCH_PAIRS:
        si, fn = times.get(si_field), times.get(fn_field)
        if si is not None and fn is not None and si < fn:
            return True
    return False


# -------------------------------------------------------------- $UsnJrnl


#: USN 변경 사유 → 플래그. 사유 이름은 ``structs/usn_record.py``의
#: ``UsnReason`` 소문자 이름과 같아야 한다.
USN_REASON_FLAGS = {
    "file_delete": "deleted",
    "file_create": "file_created",
}


def _usn_flags(record: dict[str, Any]) -> list[str]:
    """변경 사유에서 플래그를 뽑는다.

    한 레코드가 여러 사유를 동시에 들 수 있습니다. 파일을 만들고 바로
    지우면 ``file_create``와 ``file_delete``가 같은 레코드에 함께 옵니다
    (드물지만 임시 파일에서 실제로 나옵니다). 둘 다 붙입니다 — 하나를
    골라 버리면 그 순간을 되짚을 수 없습니다.

    ``zero_timestamp``는 붙이지 않습니다. USN 파서는 시각을 읽지 못하면
    ``timestamp`` 키 자체를 빼므로, ``$MFT``처럼 "0이 들어 있다"를
    판정할 대상이 없습니다.
    """
    reasons = record.get("reason") or []
    if not isinstance(reasons, list):
        return []
    return [flag for reason, flag in USN_REASON_FLAGS.items() if reason in reasons]


# ------------------------------------------------------------------ EVTX


def _evtx_flags(record: dict[str, Any], groups: frozenset[str]) -> list[str]:
    event_id = record.get("event_id")
    if not isinstance(event_id, int):
        return []

    found: list[str] = []
    if event_id in _ACCOUNT_CREATED_EVENTS:
        found.append("account_created")

    if event_id in _GROUP_ADD_EVENTS:
        # 4728/4732에서 TargetUserName은 **그룹 이름**이다. 계정 이름이
        # 아니다. 이걸 헷갈리면 특권 그룹 추가를 전부 놓친다.
        target = str((record.get("fields") or {}).get("TargetUserName", "")).strip().lower()
        if target in groups:
            found.append("privileged_group_add")

    if event_id in _SERVICE_INSTALL_EVENTS:
        found.append("service_installed")

    return found


# ----------------------------------------------------------- 시간 범위


def _outside_time_range(record: dict[str, Any], scope: Any) -> bool:
    """레코드의 어떤 시각도 선별 범위 안에 들지 않는가."""
    moments: list[datetime | None] = []
    if "timestamp" in record:
        moments.append(parse_timestamp(record["timestamp"]))
    for field in SI_FIELDS + ("si_atime",):
        if field in record:
            moments.append(parse_timestamp(record[field]))

    usable = [m for m in moments if m is not None]
    if not usable:
        return False  # 시각을 모르면 범위 밖이라고 단정할 수 없다
    return not any(scope.matches_time(m) for m in usable)
