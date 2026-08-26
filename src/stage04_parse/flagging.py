"""``flags`` 어휘 룰 적용.

파서는 레코드를 만들기만 하고 플래그는 여기서 일괄로 붙입니다. 룰이
파서마다 흩어지면 어휘가 갈라지고, 그러면 05단계의 레코드 추림이
레코드를 놓칩니다. 놓친 결과는 "선별 재현율 저하"로 잘못 집계됩니다.

플래그는 **LLM에 전달할 레코드를 추리는 필터**입니다. 수천 건에서 수십
건으로 줄이는 기준이므로, 여기서 안 붙으면 그 레코드는 사실상 없는 것이
됩니다. 반대로 남발하면 필터가 일을 안 하게 됩니다.

## 어휘와 룰은 ``mappings/_flags.yaml`` 에 있습니다

예전에는 어휘 목록이 이 파일의 튜플과 스키마 enum과 YAML 세 곳에
중복돼 있었고, 주석이 사람에게 "셋을 같이 고쳐 달라"고 부탁하고
테스트가 그 부탁을 감시했습니다. 지금은 YAML 하나가 원본입니다.

- ``FLAGS`` 와 판정 룰 — 이 모듈이 YAML에서 읽습니다
- 스키마 enum — ``tools/sync_flag_enum.py`` 가 YAML에서 생성합니다

**event_id·USN 사유·필드값 비교로 표현되는 룰은 YAML만 고치면 됩니다.**
새 파이썬 코드가 필요한 것은 ``HANDLERS`` 에 등록된 판정뿐입니다 —
타임스탬프 비교처럼 근거가 코드 주석에 붙어 있어야 하는 것들입니다.

**여기서 새 플래그 이름을 만들지 마십시오.** YAML에 없는 이름은 거부됩니다.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import yaml

from ..common.io import parse_timestamp

__all__ = [
    "FLAGS",
    "HANDLERS",
    "MATCHERS",
    "DEFAULT_PRIVILEGED_GROUPS",
    "SI_FIELDS",
    "FN_FIELDS",
    "MISMATCH_PAIRS",
    "VocabularyError",
    "Clause",
    "FlagRule",
    "Vocabulary",
    "Context",
    "mappings_dir",
    "load_vocabulary",
    "privileged_groups",
    "apply",
    "apply_all",
]

class VocabularyError(ValueError):
    """``_flags.yaml`` 의 어휘 또는 룰 정의 오류."""

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
#:
#: 이 근거가 코드 주석에 붙어 있어야 해서 선언형 룰로 내리지 않았다.
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

def mappings_dir() -> Path:
    """``mappings/`` 위치. ``src/stage04_parse/flagging.py`` 기준."""
    return Path(__file__).resolve().parents[2] / "mappings"


# ============================================================== 룰 정의


@dataclass(frozen=True)
class Clause:
    """``when`` 의 절 하나. 어떤 레코드를 대상으로 하는가."""

    artifact: str
    match: str | None = None
    field: str | None = None
    values: tuple[Any, ...] = ()
    #: 이 절이 볼 EventID. 비면 제한 없음. ``artifact`` 와 같은 자리에
    #: 있습니다 — 둘 다 **대상을 좁히고**(AND), 그다음 ``match`` 가 판정합니다.
    #:
    #: 채널 하나가 여러 뜻의 이벤트를 담을 때 필요합니다. Sysmon 이 그렇습니다:
    #: 같은 ``fields.Image`` 가 EID 1(생성)에도 5(종료)에도 실려 있어, 이름만
    #: 보는 룰은 한 프로세스를 두 번 셉니다. 종료 레코드에는 ``ParentImage``
    #: 도 ``CommandLine`` 도 없으므로 **자리는 먹고 정보는 더 적습니다.**
    #:
    #: ``match: event_id`` 와 다릅니다. 그쪽은 "이 EventID 라는 사실 자체가
    #: 신호"이고(예: Sysmon 3·22 = network_connection), 이쪽은 다른 판정을
    #: 걸기 전에 대상을 좁히는 것입니다. 그래서 함께 쓰지 못하게 막습니다.
    event_ids: tuple[int, ...] = ()

    def matches(self, record: dict[str, Any]) -> bool:
        if not _artifact_matches(str(record.get("artifact", "")), self.artifact):
            return False
        if self.event_ids and record.get("event_id") not in self.event_ids:
            return False
        if self.match is None:
            return True
        return MATCHERS[self.match](record, self)


@dataclass(frozen=True)
class FlagRule:
    """플래그 하나의 판정 조건.

    ``when`` 은 **하나라도 맞으면** 통과입니다(OR). 절이 여럿인 것은 같은
    뜻이 아티팩트마다 다르게 나타나기 때문입니다 — ``deleted`` 를 보십시오.

    ``handler`` 가 함께 있으면 **둘 다** 만족해야 합니다. ``when`` 이
    대상을 좁히고 ``handler`` 가 판정합니다.
    """

    name: str
    clauses: tuple[Clause, ...]
    handler: str | None = None

    def matches(self, record: dict[str, Any], ctx: "Context") -> bool:
        if self.clauses and not any(clause.matches(record) for clause in self.clauses):
            return False
        if self.handler is not None and not HANDLERS[self.handler](record, ctx):
            return False
        return True


@dataclass(frozen=True)
class Vocabulary:
    """``_flags.yaml`` 이 정의한 어휘 전부."""

    names: tuple[str, ...]
    rules: tuple[FlagRule, ...]


@dataclass(frozen=True)
class Context:
    """판정에 필요한 주변 정보. handler 만 씁니다."""

    groups: frozenset[str]
    scope: Any = None


def _artifact_matches(artifact: str, pattern: str) -> bool:
    """``$MFT`` 정확 일치, ``evtx:*`` 접두어 일치, ``*`` 전부."""
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return artifact.startswith(pattern[:-1])
    return artifact == pattern


# ============================================================ 선언형 매처


def _match_event_id(record: dict[str, Any], clause: Clause) -> bool:
    event_id = record.get("event_id")
    # 문자열로 들어온 event_id 를 통과시키면 파서 회귀가 조용히 숨는다.
    return isinstance(event_id, int) and event_id in clause.values


def _match_list_contains(record: dict[str, Any], clause: Clause) -> bool:
    """리스트 필드가 ``values`` 와 겹치는가.

    한 레코드가 여러 사유를 동시에 들 수 있습니다. 파일을 만들고 바로
    지우면 ``file_create``와 ``file_delete``가 같은 레코드에 함께 옵니다
    (드물지만 임시 파일에서 실제로 나옵니다). 둘 다 붙습니다 — 하나를
    골라 버리면 그 순간을 되짚을 수 없습니다.
    """
    actual = record.get(clause.field)
    if not isinstance(actual, list):
        return False
    return any(value in actual for value in clause.values)


def _match_field_equals(record: dict[str, Any], clause: Clause) -> bool:
    # 키가 없는 것과 값이 다른 것을 구별한다. allocated 가 없는 레코드를
    # "미할당"으로 읽으면 전 레코드에 deleted 가 붙는다.
    if clause.field not in record:
        return False
    return record[clause.field] == clause.values[0]


def _dotted(record: dict[str, Any], field: str) -> Any:
    """``fields.Image`` 처럼 점 표기로 레코드 안을 찾아 들어간다.

    evtx 레코드의 값은 전부 ``fields`` 안에 있어서, 최상위 키만 보는
    ``field_equals`` 로는 가리킬 수 없습니다.

    06단계에도 같은 일을 하는 함수가 있습니다(``comparators.get_field``).
    가져다 쓰지 않는 이유는 **단계 간 import 를 만들지 않기 위해서**입니다 —
    지금 이 프로젝트에 단계끼리 참조하는 곳이 한 군데도 없고, 저쪽은
    표기 흡수·예외 처리까지 하는 훨씬 큰 함수라 여기서 필요한 것과
    다릅니다. 없으면 ``None`` 입니다 — 04단계는 "값이 None 인 필드"와
    "없는 필드"를 가릴 일이 없습니다.
    """
    current: Any = record
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _match_field_endswith(record: dict[str, Any], clause: Clause) -> bool:
    """``field`` 의 값이 ``values`` 중 하나로 **끝나는가**. 대소문자 무시.

    실행 파일 경로를 이름으로 가릴 때 씁니다. Sysmon 의 ``fields.Image``는
    ``C:\\Windows\\System32\\cmd.exe`` 처럼 전체 경로라 정확히 일치시킬 수
    없고, 경로가 어디든 ``cmd.exe`` 면 같은 프로그램입니다.

    **값에 구분자를 포함시키십시오** — ``\\cmd.exe`` 처럼. ``cmd.exe`` 만
    쓰면 ``evilcmd.exe`` 가 함께 걸립니다. 그 판단을 매처가 대신하지
    않는 것은, YAML 만 읽고도 무엇이 걸리는지 보여야 하기 때문입니다.
    """
    actual = _dotted(record, str(clause.field))
    if not isinstance(actual, str):
        return False
    lowered = actual.lower()
    return any(lowered.endswith(str(value).lower()) for value in clause.values)


def _match_field_startswith(record: dict[str, Any], clause: Clause) -> bool:
    r"""``field`` 의 값이 ``values`` 중 하나로 **시작하는가**. 대소문자 무시.

    실행 파일이 어느 볼륨에 있는지를 가릴 때 씁니다.

    **"C: 가 아니면"으로 쓰고 싶은 유혹을 참으십시오.** 부정으로 쓰면 형식
    가정이 틀렸을 때 **전량이 걸립니다** — Sysmon 설정에 따라 ``Image`` 가
    ``\Device\HarddiskVolume2\...`` 로 올 수 있고, 그러면 정상 프로세스
    생성이 모두 신호가 되어 05단계 쿼터를 통째로 태웁니다. 긍정으로 열거하면
    형식이 다를 때 아무것도 안 걸립니다 — 그것도 문제지만 조용히 넘어가는
    쪽이지 필터를 죽이지는 않습니다.

    실물 Sysmon 로그를 아직 한 번도 파싱해 본 적이 없어서 내린 판단입니다.
    """
    actual = _dotted(record, str(clause.field))
    if not isinstance(actual, str):
        return False
    lowered = actual.lower()
    return any(lowered.startswith(str(value).lower()) for value in clause.values)


def _match_field_contains(record: dict[str, Any], clause: Clause) -> bool:
    r"""``field`` 의 값이 ``values`` 중 하나를 **포함하는가**. 대소문자 무시.

    경로의 중간 조각을 가릴 때 씁니다. ``C:\Users\kiosk\AppData\Local\Temp\x.exe``
    처럼 사용자 이름이 가운데 끼는 경로는 접두어로도 접미어로도 못 잡습니다.

    **접두어·접미어로 되는 것을 이걸로 쓰지 마십시오.** 포함 검사는 가장
    헐거워서, 값이 짧으면 엉뚱한 데서 걸립니다. 경로를 가릴 때는 앞뒤에
    구분자를 붙이십시오 — ``\temp\`` 가 아니라 ``temp`` 로 쓰면
    ``C:\Program Files\Tempo\app.exe`` 가 걸립니다.
    """
    actual = _dotted(record, str(clause.field))
    if not isinstance(actual, str):
        return False
    lowered = actual.lower()
    return any(str(value).lower() in lowered for value in clause.values)


#: ``match:`` 에 쓸 수 있는 이름. YAML 이 목록 밖을 부르면 로드가 실패한다.
MATCHERS: dict[str, Callable[[dict[str, Any], Clause], bool]] = {
    "event_id": _match_event_id,
    "list_contains": _match_list_contains,
    "field_equals": _match_field_equals,
    "field_endswith": _match_field_endswith,
    "field_contains": _match_field_contains,
    "field_startswith": _match_field_startswith,
}

#: ``match`` 별 필수 항목. 빠뜨리면 조건이 조용히 헐거워진다.
_MATCH_REQUIRES: dict[str, tuple[str, ...]] = {
    "event_id": ("values",),
    "list_contains": ("field", "values"),
    "field_equals": ("field", "value"),
    "field_endswith": ("field", "values"),
    "field_contains": ("field", "values"),
    "field_startswith": ("field", "values"),
}


# ================================================================ handler


def _si_earlier_than_fn(record: dict[str, Any], ctx: Context) -> bool:
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
        si = parse_timestamp(record.get(si_field))
        fn = parse_timestamp(record.get(fn_field))
        if si is not None and fn is not None and si < fn:
            return True
    return False


def _si_subsecond_zeroed(record: dict[str, Any], ctx: Context) -> bool:
    """``$SI`` 타임스탬프의 100ns 자리가 **전부** 0인가.

    NTFS는 FILETIME을 100ns 단위로 기록하므로, 정상적으로 만들어진 파일의
    서브초 자리는 사실상 난수입니다. 타임스탬프 조작 도구 대부분은 초
    단위로 시각을 써 넣어 이 자리가 0으로 정렬됩니다.

    ``si_earlier_than_fn``이 못 잡는 경우를 겨냥합니다 — ``$SI``와 ``$FN``을
    **함께** 조작하면 방향 비교가 통과합니다. 그때도 서브초는 대개 0으로
    남습니다. 시나리오 설계서(K-001) Stage 5의 탐지 포인트가 두 신호를
    나란히 적은 이유가 이것입니다.

    ## 왜 "하나라도"가 아니라 "전부"인가

    타임스탬프 하나가 우연히 ``.0000000``일 확률은 1/10^7 이지만, 레코드가
    수십만 건이면 우연히 걸리는 것이 반드시 나옵니다. 그리고 그 자체로는
    조작의 증거가 아닙니다.

    반대로 조작 도구는 값을 **한꺼번에** 써 넣으므로 있는 것이 다 정렬됩니다.
    그래서 "존재하는 ``$SI`` 시각이 둘 이상이고, 그것이 전부 서브초 0"을
    조건으로 합니다. 실측 오탐률은 ``docs/artifact-notes.md`` 참조.

    값이 없는 필드는 세지 않습니다. FILETIME 0이면 파서가 키를 빼고 내는데
    (``parsers/mft.py``), 그것을 "서브초가 0"으로 읽으면 접근 시각 갱신을
    꺼 둔 시스템의 파일이 전부 걸립니다.

    **소수부가 아예 없는 표기도 세지 않습니다.** ``2026-07-24T00:28:07Z``는
    "서브초가 0"이 아니라 "서브초를 모른다"입니다. 우리 ``$MFT`` 파서는
    항상 100ns 일곱 자리를 쓰므로(``parsers/mft.py``) 실제 산출물에는 늘
    소수부가 있고, 없는 것은 다른 데서 온 레코드입니다. 없는 것을 0으로
    읽으면 그런 레코드가 전부 걸립니다 — 실제로 테스트 픽스처가 그 표기를
    쓰고 있어 처음 구현에서 오탐이 났습니다.
    """
    aligned = 0
    for field in SI_FIELDS:
        raw = record.get(field)
        if not isinstance(raw, str):
            continue
        moment = parse_timestamp(raw)
        if moment is None or moment <= _FILETIME_EPOCH:
            continue
        # 문자열의 소수부를 본다. parse_timestamp 가 마이크로초까지만
        # 들고 있어서 100ns 자리가 파싱에서 사라진다 — 원본 표기를 봐야
        # ".0000000" 과 ".0000001" 이 구별된다.
        fraction = raw.partition(".")[2].rstrip("Zz")
        if not fraction:
            continue
        if set(fraction) != {"0"}:
            return False
        aligned += 1
    return aligned >= 2


def _has_zero_timestamp(record: dict[str, Any], ctx: Context) -> bool:
    """값이 없거나 FILETIME 0에 해당하는 타임스탬프가 있는가.

    이런 레코드를 버리지 않고 표시하는 이유는, 그 이상함 자체가 증거인
    경우가 있기 때문입니다. 조작 도구가 타임스탬프를 0으로 밀어 버립니다.

    **키가 아예 없는 것도 이 조건에 든다.** ``$MFT`` 레코드는 언제나
    여덟 개의 시각을 갖는 구조라, 파서가 그중 하나를 못 읽어 키를 뺐다는
    것 자체가 "0/판독 불가"였다는 뜻입니다(``mft.py`` — FILETIME이 0이면
    null을 스키마가 막으므로 키를 뺀다). ``record.get()``을 쓰는 이유가
    이것입니다 — 값이 ``None``인 것과 키가 없는 것을 같게 다룹니다.
    """
    for field in SI_FIELDS + FN_FIELDS:
        moment = parse_timestamp(record.get(field))
        if moment is None or moment < _FILETIME_EPOCH:
            return True
    return False


def _target_is_privileged_group(record: dict[str, Any], ctx: Context) -> bool:
    """4728/4732의 대상이 특권 그룹인가.

    **TargetUserName은 그룹 이름입니다.** 계정 이름이 아닙니다. 이걸
    헷갈리면 특권 그룹 추가를 전부 놓칩니다. 목록은 ``_flags.yaml``의
    ``privileged_groups`` 에서 옵니다 — 그래서 이름 추가는 YAML만으로
    반영됩니다.
    """
    target = str((record.get("fields") or {}).get("TargetUserName", "")).strip().lower()
    return target in ctx.groups


def _outside_selected_time_range(record: dict[str, Any], ctx: Context) -> bool:
    """레코드의 어떤 시각도 선별 범위 안에 들지 않는가.

    ``scope`` 가 없으면 붙이지 않습니다 — 범위를 모르는데 범위 밖이라고
    할 수 없습니다.
    """
    if ctx.scope is None:
        return False

    moments: list[datetime | None] = []
    if "timestamp" in record:
        moments.append(parse_timestamp(record["timestamp"]))
    for field in SI_FIELDS + ("si_atime",):
        if field in record:
            moments.append(parse_timestamp(record[field]))

    usable = [m for m in moments if m is not None]
    if not usable:
        return False  # 시각을 모르면 범위 밖이라고 단정할 수 없다
    return not any(ctx.scope.matches_time(m) for m in usable)


#: ``handler:`` 에 쓸 수 있는 이름. YAML 이 목록 밖을 부르면 로드가 실패한다.
#:
#: **선언으로 되는 것을 여기 넣지 마십시오.** handler 로 내려가는 순간
#: ``_flags.yaml`` 만 읽어서는 무슨 조건인지 알 수 없게 됩니다.
HANDLERS: dict[str, Callable[[dict[str, Any], Context], bool]] = {
    "si_earlier_than_fn": _si_earlier_than_fn,
    "si_subsecond_zeroed": _si_subsecond_zeroed,
    "has_zero_timestamp": _has_zero_timestamp,
    "target_is_privileged_group": _target_is_privileged_group,
    "outside_selected_time_range": _outside_selected_time_range,
}


# =================================================================== 로드


def _build_clause(raw: Any, *, flag: str, where: str) -> Clause:
    if not isinstance(raw, dict):
        raise VocabularyError(f"{where}: {flag}.rule.when 의 절이 매핑이 아님 — {raw!r}")
    if "artifact" not in raw:
        raise VocabularyError(f"{where}: {flag}.rule.when 의 절에 artifact 없음")

    event_ids = _clause_event_ids(raw, flag=flag, where=where)

    match = raw.get("match")
    if match is None:
        return Clause(artifact=str(raw["artifact"]), event_ids=event_ids)
    if match not in MATCHERS:
        known = ", ".join(sorted(MATCHERS))
        raise VocabularyError(
            f"{where}: {flag} 의 알 수 없는 match — {match!r} (쓸 수 있는 값: {known})"
        )

    for required in _MATCH_REQUIRES[str(match)]:
        if required not in raw:
            raise VocabularyError(f"{where}: {flag} 의 match {match} 에는 {required} 가 필요함")

    values = (raw["value"],) if match == "field_equals" else tuple(raw["values"])
    if not values:
        raise VocabularyError(f"{where}: {flag} 의 values 가 비어 있음")

    if match == "event_id" and event_ids:
        raise VocabularyError(
            f"{where}: {flag} 의 절이 match: event_id 와 event_ids 를 함께 씀. "
            "둘은 뜻이 다르다 — match 는 EventID 자체가 신호일 때, event_ids 는 "
            "다른 판정의 대상을 좁힐 때 쓴다. 하나만 남긴다."
        )

    return Clause(
        artifact=str(raw["artifact"]),
        match=str(match),
        field=str(raw["field"]) if "field" in raw else None,
        values=values,
        event_ids=event_ids,
    )


def _clause_event_ids(raw: dict[str, Any], *, flag: str, where: str) -> tuple[int, ...]:
    """절의 ``event_ids`` 를 읽는다. 없으면 빈 튜플(제한 없음)."""
    if "event_ids" not in raw:
        return ()
    listed = raw["event_ids"]
    if not isinstance(listed, list) or not listed:
        raise VocabularyError(
            f"{where}: {flag} 의 event_ids 는 비지 않은 목록이어야 함 — {listed!r}"
        )
    try:
        return tuple(int(e) for e in listed)
    except (TypeError, ValueError) as e:
        raise VocabularyError(f"{where}: {flag} 의 event_ids 에 정수가 아닌 값 — {listed!r}") from e


def _build_rule(flag: str, spec: Any, *, where: str) -> FlagRule:
    if not isinstance(spec, dict):
        raise VocabularyError(f"{where}: {flag} 의 정의가 매핑이 아님")

    rule = spec.get("rule")
    if not isinstance(rule, dict):
        # 룰 없는 어휘를 허용하면 "등록은 됐는데 아무 레코드에도 안 붙는"
        # 플래그가 생긴다. 그 상태는 파서 버그와 구별되지 않는다.
        raise VocabularyError(f"{where}: {flag} 에 rule 블록이 없음")

    handler = rule.get("handler")
    if handler is not None and handler not in HANDLERS:
        known = ", ".join(sorted(HANDLERS))
        raise VocabularyError(
            f"{where}: {flag} 의 알 수 없는 handler — {handler!r} (등록된 값: {known}). "
            "선언으로 표현되는 조건이면 handler 대신 when 을 쓴다."
        )

    clauses = tuple(_build_clause(c, flag=flag, where=where) for c in (rule.get("when") or []))
    if not clauses and handler is None:
        raise VocabularyError(f"{where}: {flag} 의 rule 이 비어 있음 (when 또는 handler 필요)")

    return FlagRule(name=flag, clauses=clauses, handler=str(handler) if handler else None)


@functools.lru_cache(maxsize=None)
def load_vocabulary(directory: str | None = None) -> Vocabulary:
    """``_flags.yaml`` 에서 어휘와 룰을 읽는다.

    **폴백이 없습니다.** 파일이 없거나 정의가 틀리면 ``VocabularyError``로
    멈춥니다. 어휘가 조용히 비면 04단계가 플래그를 하나도 안 붙이고,
    그러면 05단계에 레코드가 한 건도 가지 않는데 아무 데도 기록이
    남지 않습니다.
    """
    path = Path(directory or mappings_dir()) / "_flags.yaml"
    if not path.is_file():
        raise VocabularyError(f"flags 어휘 파일 없음: {path}")

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise VocabularyError(f"{path}: 최상위가 매핑이 아님")

    flags = data.get("flags")
    if not isinstance(flags, dict) or not flags:
        raise VocabularyError(f"{path}: flags 가 비어 있음")

    rules = tuple(_build_rule(name, spec, where=str(path)) for name, spec in flags.items())
    return Vocabulary(names=tuple(flags), rules=rules)


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


#: 고정 어휘. ``mappings/_flags.yaml`` 이 원본이고, 스키마 enum 은
#: ``tools/sync_flag_enum.py`` 가 여기서 생성한다.
FLAGS: tuple[str, ...] = load_vocabulary().names


# =================================================================== 적용


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
    ctx = Context(groups=privileged_groups() if groups is None else groups, scope=scope)
    vocabulary = load_vocabulary()

    found = [rule.name for rule in vocabulary.rules if rule.matches(record, ctx)]

    # 파서가 이미 붙인 것이 있으면 합친다. 순서는 어휘 정의 순서로 고정해
    # 같은 레코드가 항상 같은 JSON을 내게 한다.
    existing = list(record.get("flags") or [])
    known = set(vocabulary.names)
    merged = {f for f in existing + found if f in known}

    unknown = set(existing + found) - known
    if unknown:
        raise ValueError(
            f"{record.get('ref')}: 미등록 플래그 {sorted(unknown)}. "
            f"어휘는 mappings/_flags.yaml 에 정의되어 있다."
        )

    out = {key: value for key, value in record.items() if key != "flags"}
    out["flags"] = [f for f in vocabulary.names if f in merged]
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
