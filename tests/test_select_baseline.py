"""기법과 무관하게 여는 상관분석 바탕.

03단계는 02단계가 고른 기법의 매핑만 읽는다. 그래서 기법 하나가 어긋나면 그
축의 아티팩트가 통째로 빠진다. 실측에서 그것이 **프로세스 생성**에서 일어났고,
보고서에는 "그런 실행이 없었다"로 보였다.
"""

import copy

import pytest

from src.stage03_select import mapping_loader, select as select_mod


MAPPINGS = "mappings"


@pytest.fixture(scope="module")
def loaded():
    catalog = mapping_loader.load_catalog(MAPPINGS)
    return (
        catalog,
        mapping_loader.load_all(MAPPINGS, "windows", catalog),
        mapping_loader.load_baseline(MAPPINGS),
    )


def _scenario(*technique_ids: str) -> dict:
    return {
        "case_id": "T",
        "stage": "02_normalize",
        "schema_version": "1.0",
        "target_os": "windows",
        "techniques": [
            {"id": tid, "name": "x", "confidence": 0.8, "evidence_text": "근거"}
            for tid in technique_ids
        ],
        "time_range": {
            "start": "2026-09-07T00:00:00Z",
            "end": "2026-09-07T23:59:59Z",
            "basis": "고정",
        },
        "entities": {"hosts": [], "paths": [], "processes": [], "accounts": [], "ips": []},
        "overall_confidence": 0.8,
        "unmapped_text": [],
    }


def _sysmon(doc: dict):
    found = [e for e in doc["selected"] if e["artifact"] == "evtx:Sysmon"]
    return found[0] if found else None


def _select(loaded, scenario, *, with_baseline=True):
    catalog, mappings, baseline = loaded
    doc, _ = select_mod.select(
        copy.deepcopy(scenario), catalog, mappings,
        baseline=baseline if with_baseline else (),
    )
    return doc


# ── 바탕이 메우는 자리 ─────────────────────────────────────────────────


@pytest.mark.parametrize("technique", ["T1091", "T1200", "T1112", "T1197", "T1547.001"])
def test_a_technique_that_never_asks_for_sysmon_still_gets_the_baseline_channels(loaded, technique):
    """41개 매핑 중 13개가 Sysmon 을 아예 요청하지 않는다.

    ``T1091``(USB)·``T1200``(하드웨어)처럼 키오스크 조사에서 자주 걸리는
    것들이 거기 있다. 02가 그 기법 하나만 고르면 `cmd`·`certutil`·
    `powershell` 의 실행 흔적(EID 1)도, **누구에게 연결했는가(EID 3)** 도
    04단계에서 한 건도 나오지 않는다.

    실측(`K-2LINE-KIOSK`, 2026-09-09): 두 줄짜리 질문에 02가
    ``T1091``·``T1078.003`` 둘만 골랐고 EID 3 이 0건이라, 옆 노드로 나간
    연결 60건이 통째로 사라졌다. 그 60건은 08단계가 노드를 잇는 유일한
    직접 증거다.
    """
    scenario = _scenario(technique)

    assert _sysmon(_select(loaded, scenario, with_baseline=False)) is None
    assert _sysmon(_select(loaded, scenario))["scope"]["event_ids"] == [1, 3]


def test_exfiltration_scopes_gain_process_creation_without_losing_their_own(loaded):
    """``T1041``·``T1048`` 은 [3, 22] 만 열어 EID 1 을 닫는다.

    **덮어쓰지 않고 더한다.** [3, 22] 는 그 기법에 맞는 판단이고, 바탕은
    거기에 없는 것(1)만 더할 뿐이다 — 3 은 이미 있으므로 손대지 않는다.
    """
    doc = _select(loaded, _scenario("T1048"))

    assert _sysmon(doc)["scope"]["event_ids"] == [1, 3, 22]


def test_the_reason_says_the_baseline_added_it(loaded):
    """보고서까지 그대로 가므로, 기법이 고른 것과 구별돼야 한다."""
    doc = _select(loaded, _scenario("T1091"))

    assert select_mod.BASELINE_RATIONALE in _sysmon(doc)["reason"]["rationale"]


def test_a_merged_scope_records_what_the_baseline_added(loaded):
    doc = _select(loaded, _scenario("T1048"))

    assert "바탕으로 1 추가" in _sysmon(doc)["reason"]["rationale"]


# ── 바탕이 건드리지 않는 자리 ──────────────────────────────────────────


def test_a_scope_that_already_has_the_baseline_channels_is_untouched(loaded):
    """``T1018`` 은 [1, 3] 을 스스로 연다. 바탕이 더할 것이 없다."""
    before = _sysmon(_select(loaded, _scenario("T1018"), with_baseline=False))
    after = _sysmon(_select(loaded, _scenario("T1018")))

    assert before["scope"]["event_ids"] == after["scope"]["event_ids"] == [1, 3]
    assert before["reason"]["rationale"] == after["reason"]["rationale"]


def test_the_rationale_names_only_what_the_baseline_actually_added(loaded):
    """``T1204.002`` 는 [1, 5] 를 연다 — 바탕이 실제로 더하는 것은 3 뿐이다.

    바탕 전체를 적으면 기법이 이미 열어 둔 1 까지 바탕이 연 것처럼 보인다.
    이 문장은 07 보고서에 그대로 실리므로 "누가 무엇을 열었나"가 어긋난다.
    """
    after = _sysmon(_select(loaded, _scenario("T1204.002")))

    assert after["scope"]["event_ids"] == [1, 3, 5]
    assert "바탕으로 3 추가" in after["reason"]["rationale"]


def test_the_baseline_does_not_outrank_a_technique_request(loaded):
    """바탕은 조사의 초점이 아니라 바탕이다.

    05단계가 이 값으로 자리를 배분하므로, 기법이 지목한 아티팩트를 밀어내면
    안 된다.
    """
    doc = _select(loaded, _scenario("T1091"))
    sysmon = _sysmon(doc)
    others = [e["priority"] for e in doc["selected"] if e["artifact"] != "evtx:Sysmon"]

    assert others, "비교할 기법 요청이 없다"
    assert sysmon["priority"] >= max(others)


def test_removing_the_file_restores_the_old_behaviour(loaded, tmp_path):
    """파일 하나로 분리해 둔 이유 — 그 차이를 잴 수 있어야 한다."""
    assert mapping_loader.load_baseline(tmp_path) == ()
    assert _sysmon(_select(loaded, _scenario("T1091"), with_baseline=False)) is None


# ── 파일 자체 ──────────────────────────────────────────────────────────


def test_the_baseline_only_holds_cheap_correlation_channels(loaded):
    """바탕에 아무거나 넣지 않는다.

    ``$MFT`` 처럼 볼륨 전체를 뜨는 것을 넣으면 **모든 실행이** 비싸진다.
    그런 것은 기법이 요청할 때만 연다.
    """
    _, _, baseline = loaded
    expensive = {"$MFT", "$UsnJrnl"}

    assert {request.artifact for request in baseline}.isdisjoint(expensive)


def test_an_unknown_artifact_in_the_baseline_is_rejected(loaded, tmp_path):
    (tmp_path / mapping_loader.BASELINE_FILE).write_text(
        "baseline:\n  - name: evtx:NotARealChannel\n    event_ids: [1]\n", encoding="utf-8"
    )
    catalog, mappings, _ = loaded
    bad = mapping_loader.load_baseline(tmp_path)

    with pytest.raises(mapping_loader.MappingError, match="카탈로그에 없는"):
        select_mod.select(_scenario("T1091"), catalog, mappings, baseline=bad)
