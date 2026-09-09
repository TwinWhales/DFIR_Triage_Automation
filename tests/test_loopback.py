"""05단계 추가 조사 요청 → 02단계 확장 (`src/stage02_normalize/expand.py`).

여기서 지키는 것은 **하나가 다른 모든 것보다 크다** — 2차 시나리오는 1차의
상위집합이어야 한다. 넓히러 간 단계가 좁혀 오면 루프백은 증거를 더 보는
장치가 아니라 1차 결과를 잃는 장치가 된다.

나머지는 "지어낸 요청이 뒤 단계의 선별 기준이 되지 않는가"다. 요청 가능한
``ref``·기법·아티팩트가 전부 열거형이므로 실제 실행에서 이 기각들은 거의
걸리지 않아야 하고, 걸린다면 열거형이 새는 것이다.

설계는 ``docs/proposals/stage05-investigation-loopback.md``.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.common import errors as errlog
from src.common import io, schema
from src.stage02_normalize import expand as expand_mod
from src.stage03_select import mapping_loader
from casepaths import FIXTURES

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = REPO_ROOT / "mappings"

#: 픽스처의 1차 전달 레코드. 요청의 근거는 이 안에서만 나올 수 있다.
INPUT_REFS = {"MFT#12345", "MFT#12346", "EVTX-SEC#40912", "EVTX-SEC#40915"}


@pytest.fixture(scope="module")
def catalog():
    return mapping_loader.load_catalog(MAPPINGS)


@pytest.fixture(scope="module")
def mapped():
    from src.common import attack

    return attack.mapped_techniques(MAPPINGS)


@pytest.fixture
def scenario():
    return io.read_json(FIXTURES / "02_scenario.json")


def request_time(pivot="2026-07-16T00:00:00Z", hours=2, ref="MFT#12345"):
    return {
        "type": "expand_time_range",
        "based_on_ref": ref,
        "rationale": "웹셸 생성 직전 유입 경로를 못 봤다",
        "pivot_time": pivot,
        "window_hours": hours,
    }


def request_technique(technique_id="T1041", ref="EVTX-SEC#40912"):
    return {
        "type": "request_technique",
        "based_on_ref": ref,
        "rationale": "외부로 나간 데이터가 있는지 확인 필요",
        "technique_id": technique_id,
    }


def request_artifact(artifact="prefetch", ref="MFT#12345"):
    return {
        "type": "request_artifact",
        "based_on_ref": ref,
        "rationale": "실행 흔적을 프리패치로 교차 확인",
        "artifact": artifact,
    }


def run(scenario, requests, *, catalog, mapped, selected=(), collected_at=None):
    return expand_mod.expand(
        scenario,
        requests,
        input_refs=INPUT_REFS,
        already_selected=set(selected),
        catalog=catalog,
        mapped=mapped,
        collected_at=collected_at,
    )


def verdicts(outcome):
    return [r["disposition"]["verdict"] for r in outcome.requests]


def reasons(outcome):
    return [r["disposition"]["reason"] for r in outcome.requests]


# ==================================================== 상위집합 불변식


def test_the_second_round_never_loses_what_the_first_round_had(scenario, catalog, mapped):
    """**이 시험이 이 파일의 이유다.**

    기법·시간 범위·엔티티 어느 것도 잃지 않는다. 하나라도 잃으면 2차가
    1차보다 얇아질 수 있고, 그것은 루프백의 실패다.
    """
    before = copy.deepcopy(scenario)
    outcome = run(
        scenario,
        [request_time(), request_technique(), request_artifact()],
        catalog=catalog,
        mapped=mapped,
    )
    after = outcome.scenario

    was = {t["id"] for t in before["techniques"]}
    assert was <= {t["id"] for t in after["techniques"]}
    assert after["time_range"]["start"] <= before["time_range"]["start"]
    assert after["time_range"]["end"] >= before["time_range"]["end"]
    assert after["entities"] == before["entities"]
    assert after["target_os"] == before["target_os"]


def test_the_first_round_document_is_not_touched(scenario, catalog, mapped):
    """1차 문서를 제자리에서 고치면 ``.round1`` 보존이 뜻을 잃는다."""
    before = copy.deepcopy(scenario)
    run(scenario, [request_time(), request_technique()], catalog=catalog, mapped=mapped)
    assert scenario == before


def test_the_expanded_scenario_still_validates(scenario, catalog, mapped):
    """우리가 넣은 값도 같은 관문을 지난다 (``normalize`` 와 같은 규약)."""
    outcome = run(
        scenario,
        [request_time(), request_technique(), request_artifact()],
        catalog=catalog,
        mapped=mapped,
    )
    schema.validate(outcome.scenario, "scenario")
    assert outcome.scenario["stage"] == "02_normalize"


def test_the_generator_keeps_the_model_that_wrote_the_first_round(scenario, catalog, mapped):
    """어느 모델이 1차를 썼는가는 2차 문서에서도 복원할 수 있어야 한다.

    ``tools/live_check.py`` 의 결산이 이 값에서 "목업이 섞이지 않았는가"를
    본다 — 지우면 그 판정이 2차 실행에서 의미를 잃는다.
    """
    outcome = run(scenario, [request_time()], catalog=catalog, mapped=mapped)
    assert scenario["generator"] in outcome.scenario["generator"]
    assert "expand.py" in outcome.scenario["generator"]


# ==================================================== 시간 범위


def test_a_pivot_outside_the_window_widens_it(scenario, catalog, mapped):
    outcome = run(
        scenario,
        [request_time(pivot="2026-07-17T12:00:00Z", hours=6)],
        catalog=catalog,
        mapped=mapped,
    )
    assert outcome.time_range_widened
    assert outcome.scenario["time_range"]["start"] == "2026-07-17T06:00:00Z"
    # 끝은 1차 그대로다. 합집합이지 이동이 아니다.
    assert outcome.scenario["time_range"]["end"] == "2026-07-22T23:59:59Z"


def test_a_pivot_already_covered_is_rejected(scenario, catalog, mapped):
    """이미 덮고 있으면 2차를 돌릴 이유가 없다 — 4~5분짜리 재파싱이 헛돈다."""
    outcome = run(
        scenario,
        [request_time(pivot="2026-07-20T03:00:00Z", hours=1)],
        catalog=catalog,
        mapped=mapped,
    )
    assert reasons(outcome) == ["no_widening"]
    assert not outcome.accepted


def test_the_collection_time_is_the_ceiling(scenario, catalog, mapped):
    """수집 시각 뒤로는 증거가 없다. 그쪽으로는 넓히지 않는다."""
    collected = expand_mod._parse_utc("2026-07-23T00:00:00Z")
    outcome = run(
        scenario,
        [request_time(pivot="2026-07-25T00:00:00Z", hours=3)],
        catalog=catalog,
        mapped=mapped,
        collected_at=collected,
    )
    assert reasons(outcome) == ["out_of_evidence"]
    assert outcome.scenario["time_range"]["end"] == "2026-07-22T23:59:59Z"


def test_the_ceiling_never_shrinks_the_first_round_range(scenario, catalog, mapped):
    """수집 시각이 1차의 끝보다 **앞서도** 1차를 잘라 내지 않는다.

    상한을 그대로 걸면 2차가 1차보다 좁아진다. 상위집합 불변식이 클램프보다
    위에 있다 — 1차 범위는 이미 그 판단을 지나온 값이다.
    """
    collected = expand_mod._parse_utc("2026-07-19T00:00:00Z")
    outcome = run(
        scenario,
        [request_time(pivot="2026-07-16T00:00:00Z", hours=4)],
        catalog=catalog,
        mapped=mapped,
        collected_at=collected,
    )
    assert outcome.time_range_widened
    assert outcome.scenario["time_range"]["start"] == "2026-07-15T20:00:00Z"
    assert outcome.scenario["time_range"]["end"] == "2026-07-22T23:59:59Z"


def test_the_basis_keeps_the_first_round_reason(scenario, catalog, mapped):
    """``basis`` 는 "범위가 틀렸을 때 원인이 드러난다"는 자리다(스키마).

    우리가 넓힌 것도 그 원인의 일부이므로 1차의 근거를 지우지 않고 잇는다.
    """
    original = scenario["time_range"]["basis"]
    outcome = run(
        scenario,
        [request_time(pivot="2026-07-16T00:00:00Z", hours=2)],
        catalog=catalog,
        mapped=mapped,
    )
    basis = outcome.scenario["time_range"]["basis"]
    assert original in basis
    assert "2차 조사 요청" in basis


# ==================================================== 기법


def test_a_mapped_technique_is_added_with_a_traceable_evidence_text(scenario, catalog, mapped):
    """추가된 기법의 ``evidence_text`` 는 **입력 원문에서 온 값이 아니다.**

    07단계 보고서의 "식별된 기법" 표에 그대로 실리므로, 출처를 감추면
    보고서가 1차 분류와 2차 가설을 같은 말로 인쇄한다.
    """
    outcome = run(scenario, [request_technique("T1041")], catalog=catalog, mapped=mapped)
    added = [t for t in outcome.scenario["techniques"] if t["id"] == "T1041"]
    assert len(added) == 1
    assert "2차 조사 요청" in added[0]["evidence_text"]
    assert "EVTX-SEC#40912" in added[0]["evidence_text"]
    assert outcome.techniques == ["T1041"]


def test_a_requested_technique_never_becomes_the_leading_one(scenario, catalog, mapped):
    """03단계는 confidence 최대값으로 대표 기법을 고른다(``_leading_technique``).

    2차 가설이 그 자리를 뺏으면 강제 선별의 사유 딱지가 가설로 바뀐다.
    """
    outcome = run(scenario, [request_technique("T1041")], catalog=catalog, mapped=mapped)
    top = max(outcome.scenario["techniques"], key=lambda t: t["confidence"])
    assert top["id"] != "T1041"


def test_an_invented_technique_id_is_rejected(scenario, catalog, mapped):
    outcome = run(scenario, [request_technique("T9999")], catalog=catalog, mapped=mapped)
    assert reasons(outcome) == ["unknown_technique"]
    assert len(outcome.scenario["techniques"]) == len(scenario["techniques"])


def test_a_real_but_unmapped_technique_is_rejected_separately(scenario, catalog, mapped):
    """**두 기각을 나눈다.** 지어낸 ID 는 프롬프트를 고칠 일이고, 매핑이 없는
    것은 매핑을 넓힐 일이다(``benchmark/rejections.yaml``).

    ``T1486``(Data Encrypted for Impact)은 ``KNOWN_TECHNIQUES``에 있지만
    ``mappings/windows/`` 에 파일이 없다.
    """
    assert "T1486" not in mapped, "매핑이 생겼다면 이 시험의 예시를 바꾼다"
    outcome = run(scenario, [request_technique("T1486")], catalog=catalog, mapped=mapped)
    assert reasons(outcome) == ["unmapped_technique"]


def test_a_technique_already_in_the_scenario_is_rejected(scenario, catalog, mapped):
    outcome = run(scenario, [request_technique("T1505.003")], catalog=catalog, mapped=mapped)
    assert reasons(outcome) == ["already_selected"]


# ==================================================== 아티팩트


def test_a_deferred_artifact_can_be_woken(scenario, catalog, mapped):
    """Tier 2 로 유예된 것을 2차에 여는 것이 이 과제의 출발점이다."""
    outcome = run(scenario, [request_artifact("prefetch")], catalog=catalog, mapped=mapped)
    assert verdicts(outcome) == ["accepted"]
    assert outcome.artifacts == ["prefetch"]


def test_an_artifact_without_a_parser_is_rejected(scenario, catalog, mapped):
    """``psreadline_history`` 는 ``parser: null`` 이다.

    요청해도 03단계 ``_force_select`` 가 ``unusable_reason`` 을 보고 올리지
    않으므로, 통과시키면 2차가 아무것도 못 가져오면서 재파싱 시간만 쓴다.
    """
    assert catalog["psreadline_history"].supported is False
    outcome = run(scenario, [request_artifact("psreadline_history")], catalog=catalog, mapped=mapped)
    assert reasons(outcome) == ["unsupported_artifact"]
    assert outcome.artifacts == []


def test_an_artifact_outside_the_catalog_is_rejected(scenario, catalog, mapped):
    outcome = run(scenario, [request_artifact("$LogFile2")], catalog=catalog, mapped=mapped)
    assert reasons(outcome) == ["unsupported_artifact"]


def test_an_artifact_already_read_is_rejected(scenario, catalog, mapped):
    outcome = run(
        scenario,
        [request_artifact("$MFT")],
        catalog=catalog,
        mapped=mapped,
        selected=["$MFT", "evtx:Security"],
    )
    assert reasons(outcome) == ["already_selected"]


# ==================================================== 근거


def test_a_request_grounded_on_a_record_we_never_sent_is_rejected(scenario, catalog, mapped):
    """가장 중요한 기각이다. 모델이 못 본 것을 근거로 삼으면 요청에 근거가 없다.

    열거형으로 막아 두었으므로 실제 실행에서 여기 걸리면 제약이 새는 것이다.
    """
    outcome = run(
        scenario,
        [request_technique("T1041", ref="MFT#99999")],
        catalog=catalog,
        mapped=mapped,
    )
    assert reasons(outcome) == ["ungrounded_ref"]
    assert not outcome.accepted


def test_the_ungrounded_check_comes_before_everything_else(scenario, catalog, mapped):
    """근거가 없으면 내용은 보지 않는다. 내용이 옳아도 근거 없는 요청이다."""
    outcome = run(
        scenario,
        [request_artifact("prefetch", ref="EVTX-SYS#1")],
        catalog=catalog,
        mapped=mapped,
    )
    assert reasons(outcome) == ["ungrounded_ref"]


# ==================================================== 가드레일 G3 · CLI


def test_nothing_accepted_means_no_second_round(scenario, catalog, mapped):
    outcome = run(
        scenario,
        [request_technique("T9999"), request_artifact("psreadline_history")],
        catalog=catalog,
        mapped=mapped,
    )
    assert not outcome.accepted
    assert verdicts(outcome) == ["rejected", "rejected"]


def _case(tmp_path: Path, requests: list) -> Path:
    """확장을 CLI 로 돌릴 수 있는 최소 케이스."""
    case = tmp_path / "C-001"
    case.mkdir()
    for name in ("02_scenario.json", "05_findings.json"):
        (case / name).write_text(
            (FIXTURES / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    io.write_json(
        case / "03_selection.json",
        io.read_json(FIXTURES.parent.parent / "golden" / "C-001-webshell" / "03_selection.json"),
    )
    io.write_json(
        case / "05_requests.json",
        io.new_document(
            "C-001",
            "05_investigate",
            "interpret.py / stub(05_selection.json)",
            round=1,
            requests=requests,
        ),
    )
    return case


def _run_cli(case: Path) -> int:
    return expand_mod.main(
        [
            "--scenario", str(case / "02_scenario.json"),
            "--requests", str(case / "05_requests.json"),
            "--findings", str(case / "05_findings.json"),
            "--selection", str(case / "03_selection.json"),
            "--out", str(case / "02_scenario.round2.json"),
            "--mappings", str(MAPPINGS),
        ]
    )


def test_the_cli_writes_the_second_scenario_and_the_dispositions(tmp_path):
    case = _case(tmp_path, [request_time(pivot="2026-07-16T00:00:00Z", hours=2), request_artifact()])
    assert _run_cli(case) == 0

    written = io.read_json(case / "02_scenario.round2.json")
    schema.validate(written, "scenario")

    requests_doc = io.read_json(case / "05_requests.json")
    schema.validate(requests_doc, "investigation")
    assert [r["disposition"]["verdict"] for r in requests_doc["requests"]] == ["accepted", "accepted"]
    # 아티팩트는 시나리오에 담을 자리가 없다. 오케스트레이터가 여기서 읽어
    # 03단계에 --force-artifacts 로 넘긴다.
    assert requests_doc["applied"]["artifacts"] == ["prefetch"]
    assert requests_doc["applied"]["time_range"] == {
        "start": written["time_range"]["start"],
        "end": written["time_range"]["end"],
    }


def test_the_cli_leaves_no_second_scenario_when_nothing_is_accepted(tmp_path, capsys):
    """가드레일 G3 — 헛도는 2차를 만들지 않는다.

    종료 코드가 0도 1도 아닌 것은 오케스트레이터가 "돌릴 이유가 없다"와
    "실패했다"를 갈라야 하기 때문이다.
    """
    case = _case(tmp_path, [request_technique("T9999")])
    assert _run_cli(case) == expand_mod.EXIT_NOTHING_TO_DO
    assert not (case / "02_scenario.round2.json").exists()
    assert "2차를 돌리지 않는다" in capsys.readouterr().out


def test_the_cli_finds_the_collection_time_through_the_input_document(tmp_path):
    """``--input`` 이 상한을 실제로 걸어야 한다.

    수집 시각은 ``01_input.json`` 의 ``evidence.root`` 아래 KAPE CopyLog 에서
    나온다(``timeband.collection_time``). 이 배선이 끊기면 조용히 상한이
    사라지고, 2차가 증거 없는 구간까지 넓어져도 아무도 모른다.
    """
    collected = tmp_path / "KIOSK_snapshotA"
    (collected / "C").mkdir(parents=True)
    (collected / "2026-07-19T00_00_00_0000000_CopyLog.csv").write_text(
        "SourceFile\n", encoding="utf-8"
    )

    case = _case(tmp_path, [request_time(pivot="2026-07-25T00:00:00Z", hours=3)])
    io.write_json(
        case / "01_input.json",
        {
            **io.read_json(FIXTURES / "01_input.json"),
            "evidence": {"root": str(collected / "C"), "os_hint": "windows_server_2019"},
        },
    )

    code = expand_mod.main(
        [
            "--scenario", str(case / "02_scenario.json"),
            "--requests", str(case / "05_requests.json"),
            "--findings", str(case / "05_findings.json"),
            "--selection", str(case / "03_selection.json"),
            "--input", str(case / "01_input.json"),
            "--out", str(case / "02_scenario.round2.json"),
            "--mappings", str(MAPPINGS),
        ]
    )

    assert code == expand_mod.EXIT_NOTHING_TO_DO
    requests_doc = io.read_json(case / "05_requests.json")
    assert requests_doc["requests"][0]["disposition"]["reason"] == "out_of_evidence"


def test_rejections_are_counted_as_measurements_not_failures(tmp_path):
    """``errors.jsonl`` 에 남되 **흐름을 바꾸지 않았다**는 뜻의 ``record`` 다.

    ``retry`` 로 적으면 부르지도 않은 호출이 재시도 횟수에 잡히고,
    ``skip`` 으로 적으면 읽지 못한 아티팩트 수에 섞인다.
    """
    case = _case(tmp_path, [request_technique("T9999")])
    _run_cli(case)

    entries = [json.loads(line) for line in (case / "errors.jsonl").read_text(encoding="utf-8").splitlines()]
    rejected = [e for e in entries if e["type"] == "investigation_rejected"]
    assert len(rejected) == 1
    assert rejected[0]["action"] == "record"
    # 발견하는 코드는 02단계에 있지만 틀린 것은 05단계의 산출물이다.
    assert rejected[0]["stage"] == "05_interpret"
    assert rejected[0]["detail"]["value"] == "unknown_technique"
    assert rejected[0]["type"] in errlog.ERROR_TYPES


# ==================================================== 한 묶음 안의 중복
#
# 두 결함이 서로를 가리고 있던 자리입니다. `_add_artifact` 가 1차 선별만
# 보느라 같은 아티팩트를 두 번 수용했고, 저장 전 검증이 없어 `uniqueItems` 를
# 어긴 문서가 조용히 쓰였습니다.


def test_the_same_artifact_asked_twice_is_accepted_once(scenario, catalog, mapped):
    outcome = run(
        scenario,
        [request_artifact("prefetch"), request_artifact("prefetch")],
        catalog=catalog,
        mapped=mapped,
    )

    assert verdicts(outcome) == ["accepted", "rejected"]
    assert reasons(outcome) == ["applied", "already_selected"]
    assert outcome.artifacts == ["prefetch"]
    # 어휘는 1차 중복과 같고 문장이 다르다 — 무엇 때문에 기각인지는 detail 이 말한다.
    assert "이 요청 묶음" in outcome.requests[1]["disposition"]["detail"]


def test_the_same_technique_asked_twice_is_added_once(scenario, catalog, mapped):
    """기법 쪽은 원래 안전하다 — 시나리오의 목록을 직접 보기 때문이다.

    그 성질에 기대고 있으므로 시험으로 못 박는다.
    """
    outcome = run(
        scenario,
        [request_technique("T1041"), request_technique("T1041")],
        catalog=catalog,
        mapped=mapped,
    )

    assert reasons(outcome) == ["applied", "already_selected"]
    assert outcome.techniques == ["T1041"]
    assert [t["id"] for t in outcome.scenario["techniques"]].count("T1041") == 1


def test_applied_never_repeats_an_artifact(scenario, catalog, mapped):
    """``applied.artifacts`` 는 03단계에 ``--force-artifacts`` 로 그대로 나간다.

    중복이 남으면 같은 이름이 두 번 넘어가고, 스키마의 ``uniqueItems`` 도
    어겨 문서가 무효가 된다.
    """
    outcome = run(
        scenario,
        [request_artifact("prefetch"), request_artifact("prefetch")],
        catalog=catalog,
        mapped=mapped,
    )
    applied = outcome.applied()
    assert applied["artifacts"] == ["prefetch"]
    assert len(applied["artifacts"]) == len(set(applied["artifacts"]))


def test_the_cli_writes_a_document_that_validates_after_duplicates(tmp_path):
    """저장된 파일이 스키마를 만족해야 한다. 뒤 단계가 그것을 읽는다."""
    case = _case(tmp_path, [request_artifact("prefetch"), request_artifact("prefetch")])
    assert _run_cli(case) == 0

    document = io.read_json(case / "05_requests.json")
    schema.validate(document, "investigation")
    assert document["applied"]["artifacts"] == ["prefetch"]


def test_an_invalid_request_document_is_never_written(tmp_path, monkeypatch):
    """쓰기 전 검증이 실제로 막는가.

    우리 손질이 스키마를 깨는 상황을 억지로 만든다. 무효한 파일을 남기면
    07 보고서와 관문이 한참 뒤에 그것을 발견하고, 그때는 원인에서 멀다.
    **우리 결함이므로 멈춘다** — errors.jsonl 에 사유가 남는다.
    """
    case = _case(tmp_path, [request_artifact("prefetch")])
    original = expand_mod.expand

    def duplicated(*args, **kwargs):
        outcome = original(*args, **kwargs)
        outcome.artifacts.append("prefetch")  # uniqueItems 위반
        return outcome

    monkeypatch.setattr(expand_mod, "expand", duplicated)

    with pytest.raises(SystemExit) as stop:
        _run_cli(case)
    assert stop.value.code == 1

    # 파일은 1차가 낸 그대로다 — disposition 도 applied 도 없다.
    assert "applied" not in io.read_json(case / "05_requests.json")
    logged = [json.loads(line) for line in (case / "errors.jsonl").read_text(encoding="utf-8").splitlines()]
    assert logged[-1]["type"] == "schema_violation"
    assert logged[-1]["action"] == "abort"
