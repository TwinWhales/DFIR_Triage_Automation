"""03단계 강제 선별 — 사람이 지정한 아티팩트가 기법 매핑을 이기는가.

`--artifacts` 는 여태 02단계 프롬프트에 실리는 힌트일 뿐이었다. 그래서
02가 기법 하나를 잘못 고르면 사람이 "이건 꼭 봐라"고 적어 준 것이 통째로
빠졌다 — 2026-09-07 `518_Test_0907` 의 실패다. 여기서 확인하는 것은
**그 경로가 닫혔는가**와, 지정하지 않았을 때 예전과 똑같이 도는가다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.common import schema
from src.stage03_select import mapping_loader
from src.stage03_select import select as select_mod

MAPPINGS = Path(__file__).resolve().parents[1] / "mappings"


@pytest.fixture(scope="module")
def catalog():
    return mapping_loader.load_catalog(MAPPINGS)


@pytest.fixture(scope="module")
def mappings(catalog):
    return mapping_loader.load_all(MAPPINGS, "windows", catalog)


def _scenario(*technique_ids: str) -> dict:
    """기법만 갈아 끼우는 최소 시나리오. `T1059.003` 이 기본값인 이유는
    그것이 실제로 실패했던 조합이기 때문이다 — 그 매핑은 ``prefetch`` 를
    Tier 2 로 두고 ``$MFT``·``$UsnJrnl`` 은 아예 요청하지 않는다."""
    return {
        "case_id": "T-FORCE",
        "target_os": "windows",
        "techniques": [
            {"id": tid, "name": tid, "confidence": 0.7 - i * 0.1, "evidence_text": ""}
            for i, tid in enumerate(technique_ids or ("T1059.003",))
        ],
        "time_range": {
            "start": "2026-09-07T00:00:00Z",
            "end": "2026-09-07T12:00:00Z",
            "basis": "테스트",
        },
        "entities": {"hosts": [], "paths": [], "processes": [], "accounts": [], "ips": []},
        "unmapped_text": [],
    }


def _by_artifact(document: dict) -> dict[str, dict]:
    return {entry["artifact"]: entry for entry in document["selected"]}


# ============================================== 지정하지 않으면 예전 그대로


def test_without_force_the_selection_is_unchanged(catalog, mappings):
    plain, _ = select_mod.select(_scenario(), catalog, mappings)
    same, _ = select_mod.select(_scenario(), catalog, mappings, force=())
    assert plain["selected"] == same["selected"]
    assert plain["deferred"] == same["deferred"]


def test_the_518_combination_really_did_lose_prefetch(catalog, mappings):
    # 회귀 테스트의 전제. 이것이 깨지면(=매핑이 바뀌어 prefetch 가 Tier 1
    # 이 되면) 아래 테스트들은 아무것도 증명하지 않는다.
    document, _ = select_mod.select(_scenario("T1059.003"), catalog, mappings)
    assert "prefetch" not in _by_artifact(document)
    assert "prefetch" in {entry["artifact"] for entry in document["deferred"]}


# ==================================================== 세 갈래가 다 돌아야 한다


def test_a_deferred_artifact_is_promoted_to_tier_1(catalog, mappings):
    document, _ = select_mod.select(
        _scenario("T1059.003"), catalog, mappings, force=["prefetch"]
    )
    entry = _by_artifact(document)["prefetch"]
    assert entry["tier"] == 1
    assert entry["priority"] == select_mod.FORCE_PRIORITY
    # 승격됐으면 유예 목록에 남으면 안 된다 — 07단계가 같은 아티팩트를
    # "봤다"와 "안 봤다" 양쪽에 인쇄한다.
    assert "prefetch" not in {e["artifact"] for e in document["deferred"]}


def test_a_promoted_artifact_keeps_the_mappings_own_reason(catalog, mappings):
    # 유예했다고 해서 "왜 보는가"에 대한 판단까지 틀린 것은 아니다.
    document, _ = select_mod.select(
        _scenario("T1059.003"), catalog, mappings, force=["prefetch"]
    )
    reason = _by_artifact(document)["prefetch"]["reason"]
    assert reason["technique"] == "T1059.003"
    assert reason["rationale"].startswith(select_mod.FORCE_RATIONALE)
    assert "셸" in reason["rationale"]  # 매핑이 적어 둔 사유가 이어져 있다


def test_an_artifact_no_technique_asked_for_is_added(catalog, mappings):
    document, _ = select_mod.select(
        _scenario("T1059.003"), catalog, mappings, force=["$MFT"]
    )
    entry = _by_artifact(document)["$MFT"]
    assert entry["tier"] == 1
    # 좁힐 근거가 없으므로 시간 범위만 걸린다.
    assert entry["scope"] == {"time_range": {"start": "2026-09-07T00:00:00Z", "end": "2026-09-07T12:00:00Z"}}
    assert entry["reason"]["technique"] == "T1059.003"


def test_the_added_entry_borrows_the_most_confident_technique(catalog, mappings):
    # 스키마가 technique 을 요구하는데 강제 선별은 정의상 기법이 고른 것이
    # 아니다. 07단계가 이 값에서 "선별을 유발한 기법"을 뽑으므로
    # (report._techniques) 시나리오에 있는 ID 여야 한다.
    # 둘 다 $UsnJrnl 을 요청하지 않는 기법이라 승격이 아니라 추가 경로다.
    document, _ = select_mod.select(
        _scenario("T1219", "T1016"), catalog, mappings, force=["$UsnJrnl"]
    )
    assert _by_artifact(document)["$UsnJrnl"]["reason"]["technique"] == "T1219"


def test_an_artifact_already_tier_1_is_left_alone(catalog, mappings):
    # 매핑이 적어 둔 범위가 사람이 지정한 것보다 구체적이다. 덮어쓰면
    # 확장자 필터가 사라져 볼륨 전체를 파게 된다.
    plain, _ = select_mod.select(_scenario("T1204.002"), catalog, mappings)
    forced, _ = select_mod.select(
        _scenario("T1204.002"), catalog, mappings, force=["$MFT", "prefetch"]
    )
    assert _by_artifact(forced)["$MFT"] == _by_artifact(plain)["$MFT"]


def test_a_forced_artifact_leaves_the_excluded_list(catalog, mappings):
    # "이 도구가 볼 줄 아는데 이번엔 안 봤다"가 excluded 의 뜻이다. 봤으면
    # 거기 있으면 안 된다.
    document, _ = select_mod.select(
        _scenario("T1059.003"), catalog, mappings, force=["$MFT"]
    )
    assert "$MFT" not in {entry["artifact"] for entry in document["excluded"]}


def test_the_result_still_satisfies_the_frozen_schema(catalog, mappings):
    document, _ = select_mod.select(
        _scenario("T1059.003"),
        catalog,
        mappings,
        force=["$MFT", "$UsnJrnl", "prefetch"],
    )
    schema.validate(document, "selection")


# ======================================================== 이름을 펴는 규칙


def test_an_exact_name_resolves_to_itself(catalog):
    assert select_mod.resolve_force_names(["$MFT", "prefetch"], catalog) == ["$MFT", "prefetch"]


def test_a_prefix_opens_the_whole_group(catalog):
    resolved = select_mod.resolve_force_names(["evtx"], catalog)
    assert "evtx:Security" in resolved and "evtx:Sysmon" in resolved
    assert all(name.startswith("evtx:") for name in resolved)


def test_a_group_and_one_of_its_members_do_not_double_up(catalog):
    resolved = select_mod.resolve_force_names(["evtx:Security", "evtx"], catalog)
    assert resolved.count("evtx:Security") == 1


def test_a_name_the_catalog_does_not_know_stops_the_run(catalog):
    # 조용히 버리면 오타 하나로 강제 선별이 통째로 사라지는데, 산출물만
    # 봐서는 그것이 오타인지 원래 선별될 이유가 없었는지 구별되지 않는다.
    with pytest.raises(mapping_loader.MappingError, match="prefetches"):
        select_mod.resolve_force_names(["prefetches"], catalog)


def test_an_artifact_this_os_cannot_read_is_not_forced_up(catalog, mappings):
    # 파서 없이 강제로 올려 봐야 04단계가 멈춘다. 그 자리는 excluded 가
    # 사유와 함께 받는다.
    unsupported = next(
        name for name, spec in catalog.artifacts.items() if not spec.supported
    )
    document, _ = select_mod.select(
        _scenario("T1204.002"), catalog, mappings, force=[unsupported]
    )
    assert unsupported not in _by_artifact(document)
    assert unsupported in {entry["artifact"] for entry in document["excluded"]}


def test_registry_group_uses_incident_critical_subkeys(catalog, mappings):
    forced = select_mod.resolve_force_names(["registry"], catalog)
    scopes = select_mod.resolve_force_scopes(["registry"], catalog)
    document, _ = select_mod.select(
        _scenario("T1059.003"),
        catalog,
        mappings,
        force=forced,
        force_scopes=scopes,
    )
    selected = _by_artifact(document)

    software_paths = selected["registry:SOFTWARE"]["scope"]["path_prefix"]
    assert any("Schedule\\TaskCache" in path for path in software_paths)
    assert any(path.endswith("\\Run") for path in software_paths)
    assert selected["registry:SYSTEM"]["scope"]["path_prefix"] == [
        r"SYSTEM\CurrentControlSet\Services",
        r"SYSTEM\CurrentControlSet\Control\Session Manager",
    ]
    assert selected["registry:Amcache"]["scope"]["path_prefix"]


def test_exact_registry_name_still_means_the_whole_hive(catalog, mappings):
    forced = select_mod.resolve_force_names(["registry:SOFTWARE"], catalog)
    scopes = select_mod.resolve_force_scopes(["registry:SOFTWARE"], catalog)
    document, _ = select_mod.select(
        _scenario("T1059.003"),
        catalog,
        mappings,
        force=forced,
        force_scopes=scopes,
    )

    assert scopes == {}
    assert _by_artifact(document)["registry:SOFTWARE"]["scope"] == {
        "time_range": {
            "start": "2026-09-07T00:00:00Z",
            "end": "2026-09-07T12:00:00Z",
        }
    }


def test_exact_registry_member_overrides_the_group_default(catalog):
    scopes = select_mod.resolve_force_scopes(
        ["registry", "registry:SOFTWARE"], catalog
    )

    assert "registry:SOFTWARE" not in scopes
    assert "registry:SYSTEM" in scopes
