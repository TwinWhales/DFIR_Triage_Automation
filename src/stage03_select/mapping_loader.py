"""``mappings/`` YAML 로드 및 병합.

매핑은 코드가 아니라 데이터다. 여러 명이 동시에 채울 수 있고, 개수를 셀 수
있고, 파이썬을 몰라도 작성할 수 있어야 한다. 그래서 로더의 일은 읽는 것보다
**틀리게 쓴 것을 잡아내는 것**에 가깝다.

YAML 오타는 조용히 흘러간다. 아티팩트 이름을 ``evtx:security``라고 쓰면
선별에서 그냥 빠지고, 나중에 재현율이 낮게 나왔을 때 원인이 모델인지 매핑인지
구분되지 않는다. 그래서 카탈로그에 없는 이름은 로드 시점에 거부한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..common import attack

__all__ = [
    "MappingError",
    "SIGNAL_SOURCES",
    "DEFAULT_SIGNAL_SOURCE",
    "PRIORITIES",
    "DEFAULT_PRIORITY",
    "ArtifactSpec",
    "Catalog",
    "ArtifactRequest",
    "Mapping",
    "load_catalog",
    "load_mapping",
    "load_all",
]


class MappingError(ValueError):
    """매핑 파일 또는 카탈로그의 정의 오류."""


#: 아티팩트의 신호가 어디서 나오는가. 05단계 배분이 이 값을 본다.
#:
#: - ``flags`` — 04단계가 전부 훑고 재미있는 것에 플래그를 붙인다.
#:   플래그 없는 레코드는 볼 이유가 없으므로 버린다. `$MFT`·`$UsnJrnl`·evtx.
#: - ``scope`` — 가치가 레코드가 아니라 **경로**에 있다. 03단계의
#:   ``path_prefix``가 이미 신호 판정을 끝냈으므로 04단계가 붙일 플래그가
#:   없고, 플래그로 거르면 선별이 정확히 골라 온 것이 전부 사라진다.
#:   레지스트리가 그 경우다(`docs/limitations.md` 6-7).
SIGNAL_SOURCES = ("flags", "scope")

#: 적지 않은 아티팩트의 기본값. 기존 파서 셋이 전부 이쪽이다.
DEFAULT_SIGNAL_SOURCE = "flags"


@dataclass(frozen=True)
class ArtifactSpec:
    """카탈로그 한 항목."""

    name: str
    parser: str | None
    os: tuple[str, ...]
    supported: bool
    exclude_reason: str | None = None
    description: str = ""
    signal_source: str = DEFAULT_SIGNAL_SOURCE

    def unusable_reason(self, target_os: str) -> str | None:
        """이 아티팩트를 읽을 수 없는 이유. 읽을 수 있으면 ``None``."""
        if not self.supported:
            return self.exclude_reason or "본 버전 미지원"
        if target_os not in self.os:
            return f"대상 OS({target_os})에 해당 없음"
        return None


@dataclass(frozen=True)
class Catalog:
    """이 도구가 아는 아티팩트의 전부."""

    mapping_table_version: str
    artifacts: dict[str, ArtifactSpec]

    def __contains__(self, name: object) -> bool:
        return name in self.artifacts

    def __getitem__(self, name: str) -> ArtifactSpec:
        try:
            return self.artifacts[name]
        except KeyError:
            known = ", ".join(self.artifacts)
            raise MappingError(f"카탈로그에 없는 아티팩트: {name!r} (등록된 값: {known})") from None


#: (기법, 아티팩트) 쌍의 조사 비중. **작을수록 강하다** — ``tier``와 같은 방향이다.
#:
#: - ``1`` 판정의 근거 그 자체. 이것이 없으면 그 기법을 말할 수 없다.
#: - ``2`` 보조. 다른 아티팩트의 판정을 뒷받침한다. **적지 않으면 이 값.**
#: - ``3`` 배경. 있으면 맥락이 넓어지지만 없어도 판정은 선다.
#:
#: 눈금을 셋으로 좁힌 것은 이 값이 **사람이 채우는 값**이기 때문이다
#: (`docs/limitations.md` 6-5). 열 단계를 주면 채우는 사람마다 기준이
#: 달라지고, 검토하는 사람이 3과 4의 차이를 따질 수 없다.
#:
#: 기법의 속성이 아니라 (기법, 아티팩트) 쌍의 속성이다. 같은 `$MFT`라도
#: ``T1070.006``(Timestomp)에서는 1이고 ``T1053.005``에서는 2다.
PRIORITIES = (1, 2, 3)

#: 적지 않은 요청의 기본값. 중립 — 아직 사람이 판단하지 않았다는 뜻이다.
DEFAULT_PRIORITY = 2


#: 매핑 YAML 이 쓸 수 있는 키. **여기 없는 키는 로드 시점에 거부한다.**
#:
#: 예전에는 모르는 키를 조용히 버렸고, 그래서 두 번 물렸다(2026-08-31·09-01).
#:
#: - ``T1059.001``·``T1105`` 가 ``scope_template`` 대신 ``scope:`` 를 썼다.
#:   적어 둔 ``event_ids`` 가 통째로 사라져 ``evtx:Sysmon`` 이 **채널 전량
#:   요청**이 됐다 — 좁히려고 적은 것이 넓히는 결과가 됐다.
#: - ``T1105`` 의 ``name_pattern`` 은 ``Scope`` 에도 ``merge_scopes`` 에도
#:   없어 프리패치를 좁히지 못했다.
#:
#: 매핑은 데이터라 오타가 조용히 흘러간다. 문법 오류가 아니라 **의미가
#: 없는 키**이므로 YAML 파서도 스키마도 잡지 못한다. 여기서 잡는다.
MAPPING_KEYS = frozenset(
    {"technique", "name", "os", "artifacts", "defaults", "followups", "corroborates"}
)

#: ``artifacts[]`` 의 키. ``followups[]`` 는 여기에 ``technique``·``artifact``
#: 를 더한다(그쪽은 어느 기법의 무엇인지를 직접 적는다).
REQUEST_KEYS = frozenset({"name", "tier", "priority", "rationale", "scope_template", "trigger"})
FOLLOWUP_KEYS = REQUEST_KEYS | {"technique", "artifact"}

#: ``scope_template`` 의 키. ``Scope.from_selection`` 이 읽는 것과 같아야 한다.
#:
#: **``time_range`` 는 여기 없다.** 적어도 무시되는 것이 아니라
#: ``scope_resolver.resolve`` 가 시나리오의 값으로 **항상 덮어쓴다** — 적으면
#: 뜻이 있는 것처럼 보이는데 아무 일도 하지 않는다. 시간 범위는 매핑이
#: 정하는 것이 아니라 02단계가 정한다.
SCOPE_KEYS = frozenset({"path_prefix", "extensions", "event_ids"})


#: ``path_prefix`` 가 쓸 수 있는 유일한 와일드카드는 ``*`` 하나이고,
#: **세그먼트 하나 안에서만** 확장된다(``parsers.base.path_in_prefix``).
#:
#: 나머지 glob 문법을 여기서 막는 이유는 04단계가 그것을 **글자 그대로**
#: 취급하기 때문이다. ``?`` 를 적으면 물음표라는 문자가 든 경로만 찾게
#: 되는데 그런 경로는 없으므로 결과는 조용한 0건이다. 매핑을 쓴 사람은
#: "그 범위에 흔적이 없었다"고 읽는다 — 증거를 놓친 것과 구별이 안 된다.
#:
#: 선례: ``T1105`` 의 ``$MFT`` 요청이 ``C:\Users\*\AppData\Local\Temp`` 로
#: 적혀 있었는데 04단계에 ``*`` 확장이 없어 **영구 0건**이었다
#: (2026-09-04 실측, ``K-LIVE-0902-wide``). ``*`` 는 지원하게 고쳤고,
#: 지원하지 않는 문법은 여기서 멈춘다.
UNSUPPORTED_GLOB = {
    "?": "한 글자 와일드카드",
    "[": "문자 클래스",
    "]": "문자 클래스",
}

#: 구분자를 넘는 재귀 glob. ``*`` 두 개는 04단계에서 ``*`` 하나와 똑같이
#: 동작하므로, 적은 사람의 뜻(하위 전부)과 조용히 어긋난다.
RECURSIVE_GLOB = "**"


def _reject_unsupported_glob(path_prefix: Any, where: str) -> None:
    """``path_prefix`` 에 04단계가 못 읽는 문법이 있으면 멈춘다."""
    if not isinstance(path_prefix, list):
        return
    for value in path_prefix:
        if not isinstance(value, str):
            continue
        if RECURSIVE_GLOB in value:
            raise MappingError(
                f"{where}: path_prefix 에 {RECURSIVE_GLOB!r} — 구분자를 넘는 재귀 glob 은 "
                f"지원하지 않습니다. ``*`` 는 세그먼트 하나만 채웁니다 ({value!r})"
            )
        for char, label in UNSUPPORTED_GLOB.items():
            if char in value:
                raise MappingError(
                    f"{where}: path_prefix 에 {char!r}({label}) — 쓸 수 있는 와일드카드는 "
                    f"``*`` 하나뿐입니다. 04단계는 나머지를 글자 그대로 읽어 "
                    f"조용히 0건이 됩니다 ({value!r})"
                )


def _reject_unknown_keys(entry: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    """모르는 키가 있으면 멈춘다. 무엇을 쓸 수 있는지 함께 말한다."""
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise MappingError(
            f"{where}: 모르는 키 {', '.join(repr(k) for k in unknown)} — "
            f"쓸 수 있는 것: {', '.join(sorted(allowed))}"
        )


@dataclass(frozen=True)
class ArtifactRequest:
    """매핑이 요청한 아티팩트 하나."""

    artifact: str
    tier: int
    technique: str
    rationale: str
    scope_template: dict[str, Any] = field(default_factory=dict)
    trigger: str | None = None
    priority: int = DEFAULT_PRIORITY


@dataclass(frozen=True)
class Mapping:
    """기법 하나의 매핑 테이블."""

    technique: str
    name: str
    os: str
    requests: tuple[ArtifactRequest, ...]
    defaults: dict[str, str] = field(default_factory=dict)
    #: 06단계가 근거로 **추가로** 인정하는 아티팩트. 03단계는 보지 않는다.
    corroborates: frozenset[str] = frozenset()


def _require(data: dict[str, Any], key: str, where: str) -> Any:
    if key not in data:
        raise MappingError(f"{where}: 필수 항목 없음 — {key}")
    return data[key]


def load_catalog(mappings_dir: str | Path) -> Catalog:
    """``mappings/_artifacts.yaml``을 읽는다."""
    path = Path(mappings_dir) / "_artifacts.yaml"
    if not path.is_file():
        raise MappingError(f"아티팩트 카탈로그 없음: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    version = _require(data, "mapping_table_version", str(path))
    entries = _require(data, "artifacts", str(path))
    if not isinstance(entries, dict) or not entries:
        raise MappingError(f"{path}: artifacts가 비어 있음")

    artifacts: dict[str, ArtifactSpec] = {}
    for name, spec in entries.items():
        spec = spec or {}
        supported = bool(spec.get("supported", False))
        exclude_reason = spec.get("exclude_reason")
        if not supported and not exclude_reason:
            # 제외 사유가 최종 보고서까지 전달되므로 비워 둘 수 없다.
            raise MappingError(f"{path}: {name}은 supported: false 인데 exclude_reason이 없음")
        signal_source = str(spec.get("signal_source", DEFAULT_SIGNAL_SOURCE))
        if signal_source not in SIGNAL_SOURCES:
            raise MappingError(
                f"{path}: {name}의 signal_source는 "
                f"{' 또는 '.join(SIGNAL_SOURCES)}여야 함 (현재 {signal_source!r})"
            )

        artifacts[name] = ArtifactSpec(
            name=name,
            parser=spec.get("parser"),
            os=tuple(spec.get("os", ())),
            supported=supported,
            exclude_reason=exclude_reason,
            description=spec.get("description", ""),
            signal_source=signal_source,
        )
    return Catalog(mapping_table_version=str(version), artifacts=artifacts)


def _load_corroborates(data: dict[str, Any], catalog: Catalog, where: str) -> frozenset[str]:
    """``corroborates:`` — **06단계만** 쓰는 목록.

    `artifacts:` 와 축이 다르다. 저쪽은 03단계가 **"어디를 수집할까"** 로
    읽고, 좁고 날카로워야 한다 — 다 담으면 04 파싱 시간과 05 토큰 예산이
    터진다. 이쪽은 06단계가 **"이 증거로 이 기법을 말할 수 있나"** 로 읽고,
    직접 흔적뿐 아니라 그 행위에서 파생된 것까지 넓게 인정해야 한다.

    한 목록을 양쪽에 쓰면 둘 중 하나가 진다. 넓히면 03 이 다 읽어야 하고,
    좁히면 06 이 정탐을 기각한다(`work.md` 10번).

    **비워 두는 것이 기본이고, 그것이 옳은 상태다.** 06 은
    ``artifacts:`` ∪ ``corroborates:`` 를 보므로 안 적으면 지금과 똑같이
    동작한다. 넓히는 것은 **기각 기록을 보고** 하는 일이다 —
    ``technique_unsupported`` 기각 사유에 실리는 ``also_supports`` 가 그
    근거다. 실측 없이 채우면 06 에서 **유일하게 실제로 판정하는 체커**를
    가설로 무르게 만드는 것이 된다(`technique_supported` 의 설명 참조).

    2026-09-04 기준 실측: 지금까지 나온 소견의 (기법, 인용 아티팩트) 쌍
    여섯 중 기각은 하나이고, 그 하나는 **정탐이었다** — `T1091`(USB) 이
    Wazuh 에이전트 재시작 레코드를 인용했다. 그래서 아직 아무 매핑도 이
    키를 쓰지 않는다.
    """
    names = data.get("corroborates") or []
    if not isinstance(names, list):
        raise MappingError(f"{where}: corroborates 는 아티팩트 이름의 목록이어야 함")
    for name in names:
        catalog[str(name)]  # 카탈로그에 없으면 여기서 MappingError
    return frozenset(str(name) for name in names)


def load_mapping(path: str | Path, catalog: Catalog) -> Mapping:
    """매핑 파일 하나를 읽고 검증한다."""
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    where = str(path)

    _reject_unknown_keys(data, MAPPING_KEYS, where)

    technique = str(_require(data, "technique", where))
    if not attack.is_valid_format(technique):
        raise MappingError(f"{where}: ATT&CK ID 형식 위반 — {technique!r}")
    if technique != path.stem:
        # 파일명이 곧 기법 ID다. 어긋나면 attack.mapped_techniques()가
        # 실제와 다른 목록을 내고, 매핑 결손 집계가 틀어진다.
        raise MappingError(f"{where}: 파일명과 technique 불일치 ({path.stem} vs {technique})")

    defaults = {str(k): str(v) for k, v in (data.get("defaults") or {}).items()}
    requests: list[ArtifactRequest] = []

    for entry in data.get("artifacts") or []:
        requests.append(
            _build_request(entry, technique=technique, catalog=catalog, where=where, kind="artifacts")
        )
    for entry in data.get("followups") or []:
        _reject_unknown_keys(entry, FOLLOWUP_KEYS, f"{where} followups")
        followup_technique = str(_require(entry, "technique", f"{where} followups"))
        if not attack.is_valid_format(followup_technique):
            raise MappingError(f"{where}: followups의 ATT&CK ID 형식 위반 — {followup_technique!r}")
        requests.append(
            _build_request(
                {**entry, "name": _require(entry, "artifact", f"{where} followups")},
                technique=followup_technique,
                catalog=catalog,
                where=where,
                kind="followups",
            )
        )

    if not requests:
        raise MappingError(f"{where}: 요청하는 아티팩트가 하나도 없음")

    return Mapping(
        technique=technique,
        name=str(data.get("name", "")),
        os=str(data.get("os", "windows")),
        requests=tuple(requests),
        defaults=defaults,
        corroborates=_load_corroborates(data, catalog, where),
    )


def _build_request(
    entry: dict[str, Any], *, technique: str, catalog: Catalog, where: str, kind: str
) -> ArtifactRequest:
    if kind == "artifacts":
        # followups 는 위에서 자기 어휘로 이미 봤다. 여기서 다시 보면
        # technique·artifact 가 모르는 키로 걸린다.
        _reject_unknown_keys(entry, REQUEST_KEYS, f"{where} {kind}")

    name = str(_require(entry, "name", f"{where} {kind}"))
    catalog[name]  # 카탈로그에 없으면 여기서 MappingError

    scope_template = entry.get("scope_template") or {}
    _reject_unknown_keys(scope_template, SCOPE_KEYS, f"{where} {kind}[{name}].scope_template")
    _reject_unsupported_glob(
        scope_template.get("path_prefix"), f"{where} {kind}[{name}].scope_template"
    )

    tier = _require(entry, "tier", f"{where} {kind}[{name}]")
    if tier not in (1, 2):
        raise MappingError(f"{where}: {name}의 tier는 1 또는 2여야 함 (현재 {tier!r})")

    trigger = entry.get("trigger")
    if tier == 2 and not trigger:
        # Tier 2는 "언제 보게 되는가"가 핵심이다. 조건 없는 유예는
        # 보고서에서 "왜 안 봤는지" 설명할 수 없다.
        raise MappingError(f"{where}: {name}은 tier 2인데 trigger가 없음")
    if tier == 1 and trigger:
        raise MappingError(f"{where}: {name}은 tier 1인데 trigger가 있음")

    # 없으면 기본값으로 넘어가지만, 적었는데 눈금 밖이면 멈춘다. 오타
    # (``priority: 0``)가 조용히 흘러가면 그 아티팩트가 왜 자리를 적게
    # 받았는지 나중에 되짚을 방법이 없다.
    # bool 을 먼저 막는다. YAML 의 ``priority: yes`` 는 True 로 읽히고
    # ``True in (1, 2, 3)`` 이 참이라 조용히 priority 1 이 된다 — 가장 강한
    # 값이다. 2.0 같은 실수도 같은 이유로 막는다.
    priority = entry.get("priority", DEFAULT_PRIORITY)
    if isinstance(priority, bool) or not isinstance(priority, int) or priority not in PRIORITIES:
        raise MappingError(
            f"{where}: {name}의 priority는 {PRIORITIES} 중 하나여야 함 (현재 {priority!r})"
        )

    return ArtifactRequest(
        artifact=name,
        tier=int(tier),
        technique=technique,
        rationale=str(_require(entry, "rationale", f"{where} {kind}[{name}]")),
        scope_template=dict(scope_template),
        trigger=str(trigger) if trigger else None,
        priority=int(priority),
    )


def load_all(mappings_dir: str | Path, target_os: str, catalog: Catalog) -> dict[str, Mapping]:
    """``mappings/<os>/*.yaml``을 전부 읽어 기법 ID로 색인한다."""
    directory = Path(mappings_dir) / target_os
    if not directory.is_dir():
        raise MappingError(f"매핑 디렉터리 없음: {directory}")

    mappings: dict[str, Mapping] = {}
    for path in sorted(directory.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        mapping = load_mapping(path, catalog)
        if mapping.technique in mappings:
            raise MappingError(f"기법 중복: {mapping.technique}")
        mappings[mapping.technique] = mapping
    return mappings
