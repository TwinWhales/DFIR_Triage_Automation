"""02단계 정규화와 LLM 전송 계층 테스트."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.common import errors as errlog
from src.common import io, llm, schema
from src.stage02_normalize import alert_adapter
from src.stage02_normalize import normalize as normalize_mod
from src.stage02_normalize.llm_client import NormalizeClient
from src.stage02_normalize.normalize import build_scenario, check_attack_ids, normalize

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK = REPO_ROOT / "benchmark/datasets/C-001-webshell/mock"


class FakeBackend:
    """정해진 순서로 응답을 돌려주는 백엔드. 재시도 경로를 시험한다."""

    def __init__(self, *responses: str | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []
        self.name = "fake"

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        response = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture
def scenario_body():
    body = copy.deepcopy(io.read_json(MOCK / "02_scenario.json"))
    for key in ("case_id", "stage", "schema_version", "generated_at", "generator"):
        body.pop(key)
    return body


# ==================================================== 응답에서 JSON 꺼내기


def test_plain_json_parses():
    assert llm.extract_json('{"a": 1}') == {"a": 1}


def test_code_fence_is_stripped():
    # 소형 모델은 JSON만 내라고 해도 코드펜스를 두른다. 이것을 파싱
    # 실패로 처리하면 내용은 맞게 냈는데도 실패로 집계된다.
    assert llm.extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert llm.extract_json('```\n{"a": 1}\n```') == {"a": 1}


def test_surrounding_prose_is_discarded():
    text = '분석 결과입니다:\n{"a": 1}\n도움이 되었길 바랍니다.'
    assert llm.extract_json(text) == {"a": 1}


def test_braces_inside_strings_do_not_confuse_the_scanner():
    text = 'note:\n{"path": "C:\\\\dir{0}", "b": {"c": 2}}\nend'
    assert llm.extract_json(text) == {"path": "C:\\dir{0}", "b": {"c": 2}}


@pytest.mark.parametrize("text", ["", "   ", "설명만 있고 JSON은 없습니다", "[1, 2, 3]"])
def test_unusable_responses_raise_malformed_output(text):
    with pytest.raises(llm.MalformedOutput):
        llm.extract_json(text)


def test_stub_backend_needs_an_existing_fixture(tmp_path):
    with pytest.raises(llm.LLMError, match="스텁 응답 파일 없음"):
        llm.build_backend("stub", fixture=tmp_path / "nope.json")


def test_unknown_backend_is_refused():
    with pytest.raises(llm.LLMError, match="알 수 없는 백엔드"):
        llm.build_backend("gpt")


# ============================================================ 문서 조립


def test_header_is_added_by_the_script_not_the_model(scenario_body):
    # 모델이 case_id나 generated_at을 만들게 하면 지어내고, 그것이
    # 스키마 위반으로 집계되어 통계를 오염시킨다.
    doc = build_scenario(scenario_body, "C-001", "normalize.py / test")
    assert doc["case_id"] == "C-001"
    assert doc["stage"] == "02_normalize"
    assert doc["generator"] == "normalize.py / test"
    schema.validate(doc, "scenario")


def test_missing_body_field_is_a_schema_violation(scenario_body):
    del scenario_body["entities"]
    with pytest.raises(schema.SchemaViolation, match="entities"):
        build_scenario(scenario_body, "C-001", "test")


def test_format_valid_but_nonexistent_attack_id_is_caught(scenario_body):
    # 스키마는 T9999를 통과시킨다. 형식이 맞기 때문이다.
    scenario_body["techniques"][0]["id"] = "T9999"
    doc = build_scenario(scenario_body, "C-001", "test")
    schema.validate(doc, "scenario")
    with pytest.raises(schema.SchemaViolation) as e:
        check_attack_ids(doc)
    assert e.value.field == "techniques[0].id"
    assert e.value.value == "T9999"


# ================================================================ 재시도


def test_a_bad_first_response_is_retried_and_logged(tmp_path, scenario_body):
    log = errlog.ErrorLog.for_case(tmp_path)
    good = json.dumps(scenario_body, ensure_ascii=False)
    client = NormalizeClient(FakeBackend("설명만 있고 JSON은 없음", good), few_shot=False)

    doc = normalize({"case_id": "C-001", "raw": "x", "evidence": {}}, client, log)
    schema.validate(doc, "scenario")

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert [(e["type"], e["action"], e["attempt"]) for e in logged] == [
        ("malformed_output", "retry", 1)
    ]


def test_the_violation_is_fed_back_into_the_next_prompt(tmp_path, scenario_body):
    log = errlog.ErrorLog.for_case(tmp_path)
    broken = copy.deepcopy(scenario_body)
    broken["techniques"][0]["confidence"] = 1.5
    backend = FakeBackend(
        json.dumps(broken, ensure_ascii=False), json.dumps(scenario_body, ensure_ascii=False)
    )
    client = NormalizeClient(backend, few_shot=False)

    normalize({"case_id": "C-001", "raw": "x", "evidence": {}}, client, log)

    # 지적은 한 번에 하나만. 여러 건을 주면 소형 모델은 대개 더 나빠진다.
    second_prompt = backend.calls[1][1]
    assert "techniques[0].confidence" in second_prompt


def test_exhausting_retries_aborts_with_the_reason_recorded(tmp_path, scenario_body):
    log = errlog.ErrorLog.for_case(tmp_path)
    scenario_body["target_os"] = "macos"
    client = NormalizeClient(
        FakeBackend(json.dumps(scenario_body, ensure_ascii=False)), few_shot=False
    )

    with pytest.raises(SystemExit) as e:
        normalize({"case_id": "C-001", "raw": "x", "evidence": {}}, client, log, max_attempts=2)
    assert e.value.code == 1

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert [entry["action"] for entry in logged] == ["retry", "retry", "abort"]
    assert all(entry["detail"].get("field") == "target_os" for entry in logged[:2])


def test_timeout_is_recorded_under_its_own_type(tmp_path, scenario_body):
    log = errlog.ErrorLog.for_case(tmp_path)
    backend = FakeBackend(
        llm.LLMTimeout("120초 내 응답 없음"), json.dumps(scenario_body, ensure_ascii=False)
    )
    normalize({"case_id": "C-001", "raw": "x", "evidence": {}}, NormalizeClient(backend, few_shot=False), log)

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["type"] == "timeout"


def test_the_prompt_carries_the_allowed_technique_ids():
    # 목록을 주지 않으면 모델이 그럴듯한 ID를 지어낸다.
    client = NormalizeClient(FakeBackend("{}"), few_shot=False)
    assert "T1505.003" in client.system_prompt()
    assert "T1136.001" in client.system_prompt()


# ========================================================= alert_adapter


@pytest.fixture
def alert():
    return {
        "alert_id": "EDR-99213",
        "rule_name": "Suspicious child process from web server",
        "severity": "high",
        "detected_at": "2026-07-20T03:16:40Z",
        "host": "WEB01",
        "process": {"name": "cmd.exe", "parent": "w3wp.exe", "cmdline": "cmd.exe /c whoami"},
        "mitre": ["T1505.003"],
    }


def test_alert_converts_without_any_model(alert):
    body = alert_adapter.convert(alert, {"os_hint": "windows_server_2019"})
    doc = build_scenario(body, "C-002", "alert_adapter.py")
    schema.validate(doc, "scenario")
    check_attack_ids(doc)
    assert [t["id"] for t in doc["techniques"]] == ["T1505.003"]


def test_alert_output_has_the_same_shape_as_the_llm_path(alert, scenario_body):
    body = alert_adapter.convert(alert, {"os_hint": "windows_server_2019"})
    assert set(body) == set(scenario_body)


def test_detection_time_is_widened_backwards(alert):
    # 탐지는 침해의 시작이 아니라 발각이다. 앞쪽을 넓게 본다.
    body = alert_adapter.convert(alert, {})
    assert body["time_range"]["start"] == "2026-07-17T03:16:40Z"
    assert body["time_range"]["end"] == "2026-07-22T03:16:40Z"


def test_severity_maps_to_confidence(alert):
    alert["severity"] = "low"
    assert alert_adapter.convert(alert, {})["overall_confidence"] == 0.5
    alert["severity"] = "made-up"
    assert alert_adapter.convert(alert, {})["overall_confidence"] == 0.7


def test_entities_come_only_from_the_alert(alert):
    entities = alert_adapter.convert(alert, {})["entities"]
    assert entities["hosts"] == ["WEB01"]
    assert entities["processes"] == ["cmd.exe", "w3wp.exe"]
    assert entities["paths"] == [] and entities["accounts"] == []


def test_command_line_is_kept_as_unmapped_text(alert):
    assert alert_adapter.convert(alert, {})["unmapped_text"] == ["실행 명령: cmd.exe /c whoami"]


def test_malformed_technique_ids_from_the_edr_are_dropped(alert):
    alert["mitre"] = ["T1505.003", "웹셸", "TA0001"]
    body = alert_adapter.convert(alert, {})
    assert [t["id"] for t in body["techniques"]] == ["T1505.003"]


def test_an_alert_without_techniques_fails_loudly(alert):
    # 조용히 빈 배열을 내면 03단계가 아무것도 못 하고 원인이 드러나지 않는다.
    alert["mitre"] = []
    with pytest.raises(alert_adapter.AlertAdapterError, match="ATT&CK 기법이 없다"):
        alert_adapter.convert(alert, {})


def test_an_alert_without_a_timestamp_fails_loudly(alert):
    del alert["detected_at"]
    with pytest.raises(alert_adapter.AlertAdapterError, match="detected_at"):
        alert_adapter.convert(alert, {})


def test_linux_os_hint_is_honoured(alert):
    assert alert_adapter.convert(alert, {"os_hint": "ubuntu_22"})["target_os"] == "linux"


# ================================================================== CLI


def test_cli_stub_run_produces_a_valid_scenario(tmp_path):
    out = tmp_path / "02_scenario.json"
    code = normalize_mod.main(
        [
            "--in", str(MOCK / "01_input.json"),
            "--out", str(out),
            "--llm", "stub",
            "--replay", str(MOCK / "02_scenario.json"),
        ]
    )
    assert code == 0
    doc = io.read_json(out)
    schema.validate(doc, "scenario")
    # 실험 조건이 결과 파일만으로 복원되어야 한다.
    assert doc["generator"] == "normalize.py / stub(02_scenario.json)"


def test_cli_refuses_stub_without_a_replay_file(tmp_path):
    code = normalize_mod.main(
        ["--in", str(MOCK / "01_input.json"), "--out", str(tmp_path / "o.json"), "--llm", "stub"]
    )
    assert code == 2
    assert not (tmp_path / "errors.jsonl").exists()


def test_cli_takes_the_adapter_path_for_edr_alerts(tmp_path):
    alert_input = {
        "case_id": "C-002",
        "stage": "01_input",
        "schema_version": "1.0",
        "generated_at": "2026-08-06T04:10:00Z",
        "source_type": "edr_alert",
        "raw": {
            "alert_id": "EDR-99213",
            "rule_name": "Suspicious child process from web server",
            "severity": "high",
            "detected_at": "2026-07-20T03:16:40Z",
            "host": "WEB01",
            "process": {"name": "cmd.exe", "parent": "w3wp.exe", "cmdline": "cmd.exe /c whoami"},
            "mitre": ["T1505.003"],
        },
        "evidence": {
            "root": "/mnt/evidence/WEB01",
            "os_hint": "windows_server_2019",
            "artifacts_available": ["$MFT", "evtx"],
        },
    }
    src = tmp_path / "01_input.json"
    io.write_json(src, alert_input)
    out = tmp_path / "02_scenario.json"

    # --replay 없이도 동작해야 한다. LLM이 준비되지 않은 상태에서
    # 03단계 이후를 개발할 수 있는 이유다.
    assert normalize_mod.main(["--in", str(src), "--out", str(out)]) == 0
    assert io.read_json(out)["generator"] == "alert_adapter.py"
