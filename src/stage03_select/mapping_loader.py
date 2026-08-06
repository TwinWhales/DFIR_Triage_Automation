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


@dataclass(frozen=True)
class ArtifactSpec:
    """카탈로그 한 항목."""

    name: str
    parser: str | None
    os: tuple[str, ...]
    supported: bool
    exclude_reason: str | None = None
    description: str = ""

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


@dataclass(frozen=True)
class ArtifactRequest:
    """매핑이 요청한 아티팩트 하나."""

    artifact: str
    tier: int
    technique: str
    rationale: str
    scope_template: dict[str, Any] = field(default_factory=dict)
    trigger: str | None = None


@dataclass(frozen=True)
class Mapping:
    """기법 하나의 매핑 테이블."""

    technique: str
    name: str
    os: str
    requests: tuple[ArtifactRequest, ...]
    defaults: dict[str, str] = field(default_factory=dict)


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
        artifacts[name] = ArtifactSpec(
            name=name,
            parser=spec.get("parser"),
            os=tuple(spec.get("os", ())),
            supported=supported,
            exclude_reason=exclude_reason,
            description=spec.get("description", ""),
        )
    return Catalog(mapping_table_version=str(version), artifacts=artifacts)


def load_mapping(path: str | Path, catalog: Catalog) -> Mapping:
    """매핑 파일 하나를 읽고 검증한다."""
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    where = str(path)

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
    )


def _build_request(
    entry: dict[str, Any], *, technique: str, catalog: Catalog, where: str, kind: str
) -> ArtifactRequest:
    name = str(_require(entry, "name", f"{where} {kind}"))
    catalog[name]  # 카탈로그에 없으면 여기서 MappingError

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

    return ArtifactRequest(
        artifact=name,
        tier=int(tier),
        technique=technique,
        rationale=str(_require(entry, "rationale", f"{where} {kind}[{name}]")),
        scope_template=dict(entry.get("scope_template") or {}),
        trigger=str(trigger) if trigger else None,
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
