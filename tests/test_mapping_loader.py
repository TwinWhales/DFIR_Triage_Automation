"""03단계 선별과 매핑 로더 테스트.

매핑은 데이터라서 오타가 조용히 흘러간다. 아티팩트 이름을 한 글자
틀리면 선별에서 그냥 빠지고, 나중에 재현율이 낮게 나왔을 때 원인이
모델인지 매핑인지 구분되지 않는다. 로더가 로드 시점에 거부하는지를
집중적으로 확인한다.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from src.common import io, schema
from src.stage03_select import mapping_loader, scope_resolver
from src.stage03_select import select as select_mod
from src.stage03_select.select import select

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = REPO_ROOT / "mappings"
MOCK = REPO_ROOT / "benchmark/datasets/C-001-webshell/mock"


@pytest.fixture(scope="module")
def catalog():
    return mapping_loader.load_catalog(MAPPINGS)


@pytest.fixture(scope="module")
def mappings(catalog):
    return mapping_loader.load_all(MAPPINGS, "windows", catalog)


@pytest.fixture
def scenario():
    return copy.deepcopy(io.read_json(MOCK / "02_scenario.json"))


def _write_mapping(tmp_path: Path, body: dict, name: str) -> Path:
    directory = tmp_path / "windows"
    directory.mkdir(exist_ok=True)
    path = directory / name
    path.write_text(yaml.safe_dump(body, allow_unicode=True), encoding="utf-8")
    return path


# ============================================================== 카탈로그


def test_catalog_loads_every_artifact(catalog):
    assert set(catalog.artifacts) == {
        "$MFT",
        "$UsnJrnl",
        "evtx:Security",
        "evtx:System",
        "registry:SYSTEM",
        "registry:SOFTWARE",
        "prefetch",
        "$LogFile",
    }
    # 목록이 바뀌면 이 값도 올린다. 03_selection.json 에 실려 나가므로
    # 산출물만 보고 어느 카탈로그로 돌렸는지 되짚을 수 있어야 한다.
    assert catalog.mapping_table_version == "0.5"


def test_unsupported_artifacts_carry_a_reason(catalog):
    assert catalog["prefetch"].unusable_reason("windows")
    assert catalog["$LogFile"].unusable_reason("windows")
    assert catalog["$MFT"].unusable_reason("windows") is None


def test_windows_artifacts_are_unusable_on_linux(catalog):
    assert "linux" in catalog["$MFT"].unusable_reason("linux")


def test_unknown_artifact_lookup_lists_the_known_ones(catalog):
    with pytest.raises(mapping_loader.MappingError, match=r"\$MFT"):
        catalog["evtx:security"]  # 소문자 오타


def test_unsupported_without_a_reason_is_refused(tmp_path):
    # 제외 사유가 보고서까지 전달되므로 비워 둘 수 없다.
    (tmp_path / "_artifacts.yaml").write_text(
        yaml.safe_dump(
            {"mapping_table_version": "0.1", "artifacts": {"prefetch": {"supported": False}}}
        ),
        encoding="utf-8",
    )
    with pytest.raises(mapping_loader.MappingError, match="exclude_reason"):
        mapping_loader.load_catalog(tmp_path)


# ========================================================== 매핑 유효성


def test_all_shipped_mappings_load(mappings):
    assert set(mappings) == {
        "T1505.003", "T1136.001", "T1543.003", "T1053.005", "T1070.004", "T1070.006",
        "T1547.001", "T1091", "T1200",
    }


def test_every_mapping_requests_at_least_one_artifact(mappings):
    for technique, mapping in mappings.items():
        assert mapping.requests, technique


def test_tier2_requests_all_declare_a_trigger(mappings):
    # Tier 2는 "언제 보게 되는가"가 핵심이다. 조건 없는 유예는
    # 보고서에서 왜 안 봤는지 설명할 수 없다.
    for mapping in mappings.values():
        for request in mapping.requests:
            if request.tier == 2:
                assert request.trigger, f"{mapping.technique}/{request.artifact}"


def test_every_scope_template_variable_has_a_default(mappings):
    # 시나리오에 entities가 비어 있어도 치환이 되어야 한다.
    for mapping in mappings.values():
        for request in mapping.requests:
            rendered = json.dumps(request.scope_template, ensure_ascii=False)
            for variable in scope_resolver.VARIABLE_PATTERN.findall(rendered):
                assert variable in mapping.defaults or variable in scope_resolver.ENTITY_VARIABLES, (
                    f"{mapping.technique}: {{{variable}}} 의 기본값이 없다"
                )


def test_unknown_artifact_name_is_refused_at_load_time(tmp_path, catalog):
    path = _write_mapping(
        tmp_path,
        {
            "technique": "T1505.003",
            "artifacts": [{"name": "evtx:security", "tier": 1, "rationale": "x"}],
        },
        "T1505.003.yaml",
    )
    with pytest.raises(mapping_loader.MappingError, match="카탈로그에 없는"):
        mapping_loader.load_mapping(path, catalog)


def test_filename_must_match_the_technique_id(tmp_path, catalog):
    # 파일명이 곧 기법 ID다. 어긋나면 매핑 결손 집계가 틀어진다.
    path = _write_mapping(
        tmp_path,
        {"technique": "T1136.001", "artifacts": [{"name": "$MFT", "tier": 1, "rationale": "x"}]},
        "T1505.003.yaml",
    )
    with pytest.raises(mapping_loader.MappingError, match="파일명과 technique 불일치"):
        mapping_loader.load_mapping(path, catalog)


def test_tier2_without_a_trigger_is_refused(tmp_path, catalog):
    path = _write_mapping(
        tmp_path,
        {"technique": "T1505.003", "artifacts": [{"name": "$MFT", "tier": 2, "rationale": "x"}]},
        "T1505.003.yaml",
    )
    with pytest.raises(mapping_loader.MappingError, match="trigger가 없음"):
        mapping_loader.load_mapping(path, catalog)


def test_tier1_with_a_trigger_is_refused(tmp_path, catalog):
    path = _write_mapping(
        tmp_path,
        {
            "technique": "T1505.003",
            "artifacts": [{"name": "$MFT", "tier": 1, "rationale": "x", "trigger": "언젠가"}],
        },
        "T1505.003.yaml",
    )
    with pytest.raises(mapping_loader.MappingError, match="tier 1인데 trigger"):
        mapping_loader.load_mapping(path, catalog)


@pytest.mark.parametrize("tier", [0, 3, "1"])
def test_invalid_tier_is_refused(tmp_path, catalog, tier):
    path = _write_mapping(
        tmp_path,
        {"technique": "T1505.003", "artifacts": [{"name": "$MFT", "tier": tier, "rationale": "x"}]},
        "T1505.003.yaml",
    )
    with pytest.raises(mapping_loader.MappingError, match="tier는 1 또는 2"):
        mapping_loader.load_mapping(path, catalog)


def test_missing_rationale_is_refused(tmp_path, catalog):
    # rationale이 없으면 보고서가 "왜 이걸 봤는지" 설명하지 못한다.
    path = _write_mapping(
        tmp_path,
        {"technique": "T1505.003", "artifacts": [{"name": "$MFT", "tier": 1}]},
        "T1505.003.yaml",
    )
    with pytest.raises(mapping_loader.MappingError, match="rationale"):
        mapping_loader.load_mapping(path, catalog)


def test_followups_are_attributed_to_their_own_technique(mappings):
    webshell = mappings["T1505.003"]
    followup = next(r for r in webshell.requests if r.artifact == "evtx:System")
    assert followup.technique == "T1543.003"
    assert followup.tier == 2


# ================================================ flags 어휘 이중 관리 방지


def test_flags_yaml_matches_the_parsed_record_schema():
    # 두 곳에 적힌 어휘가 갈라지면 파서가 만든 flag를 스키마가 거부하거나,
    # 반대로 오타 flag가 통과한다. YAML 이 원본이고 스키마 enum 은
    # tools/sync_flag_enum.py 가 거기서 생성한다 — flagging 을 import 하지
    # 않고 두 파일만 대조하는 것은, 생성기가 빠뜨려도 여기서 잡히게 하려는 것이다.
    declared = set(
        yaml.safe_load((MAPPINGS / "_flags.yaml").read_text(encoding="utf-8"))["flags"]
    )
    in_schema = set(schema.load_schema("parsed_record")["properties"]["flags"]["items"]["enum"])
    assert declared == in_schema, (
        "스키마 enum 이 어휘와 어긋났다. tools/sync_flag_enum.py 를 돌린다."
    )


def test_flags_reference_only_catalogued_artifacts(catalog):
    flags = yaml.safe_load((MAPPINGS / "_flags.yaml").read_text(encoding="utf-8"))["flags"]
    for name, spec in flags.items():
        for artifact in spec.get("artifacts", []):
            assert artifact in catalog, f"{name}: {artifact}"


# ========================================================= scope_resolver


def test_scenario_entities_override_mapping_defaults(scenario):
    context = scope_resolver.build_context(scenario, {"web_root": 'C:\\default'})
    assert context["web_root"] == "C:\\inetpub\\wwwroot"


def test_defaults_apply_when_the_scenario_says_nothing(scenario):
    scenario["entities"]["paths"] = []
    context = scope_resolver.build_context(scenario, {"web_root": "C:\\default"})
    assert context["web_root"] == "C:\\default"


def test_substitution_reaches_inside_lists():
    scope = scope_resolver.resolve({"path_prefix": ["{web_root}"]}, {"web_root": "C:\\web"})
    assert scope == {"path_prefix": ["C:\\web"]}


def test_an_unresolvable_variable_is_an_error_not_a_literal():
    # 조용히 넘기면 "{web_root}" 라는 문자열이 선별 결과에 실려
    # 파서가 존재하지 않는 경로를 찾는다.
    with pytest.raises(scope_resolver.UnresolvedVariable, match="web_root"):
        scope_resolver.resolve({"path_prefix": ["{web_root}"]}, {})


def test_time_range_is_appended_without_the_basis(scenario):
    scope = scope_resolver.resolve({}, {}, scenario["time_range"])
    assert scope == {
        "time_range": {"start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z"}
    }


# ================================================== 선별 결과 픽스처 재현


def test_reproduces_the_selection_fixture_exactly(scenario, catalog, mappings):
    expected = io.read_json(MOCK / "03_selection.json")
    got, unmapped = select(scenario, catalog, mappings)
    assert unmapped == []
    got.pop("generated_at")
    expected.pop("generated_at")
    assert got == expected


def test_output_validates_against_its_schema(scenario, catalog, mappings):
    got, _ = select(scenario, catalog, mappings)
    schema.validate(got, "selection")


# ------------------------------------------------------------ 선별 규칙


def test_an_artifact_already_selected_is_not_also_deferred(scenario, catalog, mappings):
    # T1136.001은 $MFT를 tier 2로 요청하지만 T1505.003이 tier 1로 읽는다.
    # 보고서에 "안 봤다"고 적히면 사실과 다르다.
    got, _ = select(scenario, catalog, mappings)
    assert "$MFT" in {e["artifact"] for e in got["selected"]}
    assert "$MFT" not in {e["artifact"] for e in got["deferred"]}


def test_the_same_request_is_deferred_when_nothing_selects_it(scenario, catalog, mappings):
    scenario["techniques"] = [t for t in scenario["techniques"] if t["id"] == "T1136.001"]
    got, _ = select(scenario, catalog, mappings)
    assert {e["artifact"] for e in got["selected"]} == {"evtx:Security"}
    assert "$MFT" in {e["artifact"] for e in got["deferred"]}


def test_unsupported_artifacts_are_always_excluded(scenario, catalog, mappings):
    got, _ = select(scenario, catalog, mappings)
    excluded = {e["artifact"]: e["reason"] for e in got["excluded"]}
    assert "미지원" in excluded["prefetch"]
    assert "미지원" in excluded["$LogFile"]


def test_exclusion_reasons_hold_regardless_of_windows_variant(catalog):
    # 제외 사유는 보고서에 그대로 실린다. "Windows Server 기본 비활성화"라고
    # 적었더니 Windows 10 케이스 보고서에 그대로 나가 사실과 달라졌다.
    # 1차 사유는 OS 변종과 무관해야 한다.
    for name, spec in catalog.artifacts.items():
        reason = spec.unusable_reason("windows")
        if reason is not None and not spec.supported:
            assert "미지원" in reason, f"{name}: {reason}"


def test_artifacts_nobody_asked_for_are_still_reported(scenario, catalog, mappings):
    # "볼 줄 아는데 이번엔 안 봤다"와 "애초에 볼 줄 모른다"를 구별해야 한다.
    scenario["techniques"] = [t for t in scenario["techniques"] if t["id"] == "T1136.001"]
    got, _ = select(scenario, catalog, mappings)
    excluded = {e["artifact"]: e["reason"] for e in got["excluded"]}
    assert excluded["$UsnJrnl"] == select_mod.NOT_REQUESTED_REASON


def test_every_artifact_is_accounted_for_exactly_once(scenario, catalog, mappings):
    got, _ = select(scenario, catalog, mappings)
    seen = (
        {e["artifact"] for e in got["selected"]}
        | {e["artifact"] for e in got["deferred"]}
        | {e["artifact"] for e in got["excluded"]}
    )
    assert seen == set(catalog.artifacts)


def test_stats_agree_with_the_lists(scenario, catalog, mappings):
    got, _ = select(scenario, catalog, mappings)
    assert got["stats"] == {
        "selected_count": len(got["selected"]),
        "deferred_count": len(got["deferred"]),
        "excluded_count": len(got["excluded"]),
    }


def test_a_technique_without_a_mapping_is_reported_not_silently_dropped(
    scenario, catalog, mappings
):
    # 재현율이 낮을 때 원인이 모델인지 매핑 결손인지 가르는 데이터다.
    scenario["techniques"].append(
        {"id": "T1486", "name": "Data Encrypted for Impact", "confidence": 0.6, "evidence_text": "x"}
    )
    _got, unmapped = select(scenario, catalog, mappings)
    assert unmapped == ["T1486"]


def test_selection_is_deterministic(scenario, catalog, mappings):
    # 같은 시나리오에 같은 선별이 나와야 재현율이 모델 성능의 지표가 된다.
    first, _ = select(scenario, catalog, mappings)
    second, _ = select(scenario, catalog, mappings)
    first.pop("generated_at")
    second.pop("generated_at")
    assert first == second


# ================================================================== CLI


def test_cli_reproduces_the_fixture(tmp_path):
    out = tmp_path / "03_selection.json"
    assert (
        select_mod.main(
            ["--in", str(MOCK / "02_scenario.json"), "--out", str(out), "--mappings", str(MAPPINGS)]
        )
        == 0
    )
    got, expected = io.read_json(out), io.read_json(MOCK / "03_selection.json")
    got.pop("generated_at")
    expected.pop("generated_at")
    assert got == expected
    assert b"\r\n" not in out.read_bytes()


def test_cli_logs_unmapped_techniques_as_skipped(tmp_path):
    scenario = io.read_json(MOCK / "02_scenario.json")
    scenario["techniques"].append(
        {"id": "T1486", "name": "Data Encrypted for Impact", "confidence": 0.6, "evidence_text": "x"}
    )
    src = tmp_path / "02_scenario.json"
    io.write_json(src, scenario)

    select_mod.main(
        ["--in", str(src), "--out", str(tmp_path / "03_selection.json"), "--mappings", str(MAPPINGS)]
    )
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["type"] == "empty_result"
    assert logged[0]["action"] == "skip"
    assert logged[0]["detail"]["value"] == "T1486"


def test_cli_aborts_when_nothing_can_be_selected(tmp_path):
    scenario = io.read_json(MOCK / "02_scenario.json")
    scenario["target_os"] = "linux"  # mappings/linux/ 는 비어 있다
    src = tmp_path / "02_scenario.json"
    io.write_json(src, scenario)

    with pytest.raises(SystemExit) as e:
        select_mod.main(
            ["--in", str(src), "--out", str(tmp_path / "03_selection.json"), "--mappings", str(MAPPINGS)]
        )
    assert e.value.code == 1
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[-1]["type"] == "empty_result"
    assert logged[-1]["action"] == "abort"


def test_cli_aborts_on_a_schema_violating_scenario(tmp_path):
    scenario = io.read_json(MOCK / "02_scenario.json")
    scenario["techniques"] = []  # 스펙의 명시적 위반
    src = tmp_path / "02_scenario.json"
    io.write_json(src, scenario)

    with pytest.raises(SystemExit):
        select_mod.main(
            ["--in", str(src), "--out", str(tmp_path / "03_selection.json"), "--mappings", str(MAPPINGS)]
        )
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["type"] == "schema_violation"
    assert logged[0]["detail"]["field"] == "techniques"
