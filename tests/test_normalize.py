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
from src.stage02_normalize.llm_client import DEFAULT_NUM_PREDICT, NormalizeClient
from src.stage02_normalize.normalize import build_scenario, check_attack_ids, normalize

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK = REPO_ROOT / "benchmark/datasets/C-001-webshell/mock"


class FakeBackend:
    """정해진 순서로 응답을 돌려주는 백엔드. 재시도 경로를 시험한다."""

    def __init__(self, *responses: str | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []
        #: 호출마다 받은 ``fmt``. 제약을 실제로 걸었는지 시험이 볼 수 있어야
        #: 한다 — 응답만 보면 스텁이 무엇을 받았든 같은 값이 돌아온다.
        self.formats: list[dict | None] = []
        self.name = "fake"

    def complete(self, system: str, user: str, *, fmt: dict | None = None) -> str:
        self.calls.append((system, user))
        self.formats.append(fmt)
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


def test_a_cut_off_response_is_named_as_cut_not_as_a_format_violation():
    # 프롬프트를 고쳐야 할 일(형식 위반)과 상한을 올려야 할 일(잘림)은
    # 대응이 정반대다. errors.jsonl 에서 같은 문구로 보이면 가릴 수 없다.
    with pytest.raises(llm.MalformedOutput, match="중간에 잘림"):
        llm.extract_json('{"findings": [{"id": "F1", "statement": "웹셸이 생성')


def test_prose_without_any_brace_keeps_the_generic_message():
    with pytest.raises(llm.MalformedOutput, match="찾지 못함"):
        llm.extract_json("JSON 없이 설명만 했습니다")


# ============================================================ 출력 상한


def test_the_output_cap_reaches_the_request_body():
    body = llm.build_backend("ollama", model="m", num_predict=2048).payload("s", "u")
    assert body["options"]["num_predict"] == 2048


def test_no_cap_is_sent_when_the_stage_did_not_ask_for_one():
    # 값은 단계가 정한다. 전송 계층이 임의로 채우면 단계별 실험이 섞인다.
    body = llm.OllamaBackend("m").payload("s", "u")
    assert "num_predict" not in body["options"]
    # 상한을 얹어도 나머지는 그대로여야 한다. 제약을 켠 실행과 끈 실행이
    # 둘 다 이 상한을 지고 가야 둘의 차이가 format 하나로 남는다.
    capped = llm.OllamaBackend("m", num_predict=512).payload("s", "u", fmt={"type": "object"})
    assert capped["options"]["num_ctx"] == llm.DEFAULT_NUM_CTX
    assert capped["format"] == {"type": "object"}


def test_cli_hands_the_output_cap_to_the_backend(monkeypatch, tmp_path):
    """CLI에서 백엔드까지 상한이 실제로 도달하는가.

    이 배선이 없어서 05단계가 실물 실행에서 타임아웃 3회로 죽었다. 상수가
    있는 것과 그 상수가 요청에 실리는 것은 다른 이야기다.
    """
    captured: dict = {}

    def fake_build_backend(kind, **kwargs):
        captured.update(kwargs)
        return FakeBackend((MOCK / "02_scenario.json").read_text(encoding="utf-8"))

    monkeypatch.setattr(llm, "build_backend", fake_build_backend)
    code = normalize_mod.main(
        [
            "--in", str(MOCK / "01_input.json"),
            "--out", str(tmp_path / "02_scenario.json"),
            "--llm", "ollama", "--model", "m", "--num-predict", "1234",
        ]
    )
    assert code == 0
    assert captured["num_predict"] == 1234


def test_the_default_cap_is_the_stage_constant(monkeypatch, tmp_path):
    captured: dict = {}

    def fake_build_backend(kind, **kwargs):
        captured.update(kwargs)
        return FakeBackend((MOCK / "02_scenario.json").read_text(encoding="utf-8"))

    monkeypatch.setattr(llm, "build_backend", fake_build_backend)
    normalize_mod.main(
        [
            "--in", str(MOCK / "01_input.json"),
            "--out", str(tmp_path / "02_scenario.json"),
            "--llm", "ollama", "--model", "m",
        ]
    )
    assert captured["num_predict"] == DEFAULT_NUM_PREDICT


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


def test_a_call_failure_that_is_not_a_timeout_aborts_without_retrying(tmp_path, scenario_body):
    """모델명 오타·서버 미기동은 **세 번 불러도 같은 답이다.**

    실제 모델 테스트에서 드러난 자리입니다(`tests/test_llm_live.py`). 예전에는
    이 예외를 아무도 잡지 않아 파이썬 트레이스백이 그대로 올라왔고,
    `errors.jsonl` 에 남지 않아 07단계가 볼 수 없었습니다.
    """
    log = errlog.ErrorLog.for_case(tmp_path)
    backend = FakeBackend(
        llm.LLMError("존재하지-않는-모델:v0: HTTP 400 — invalid model name"),
        json.dumps(scenario_body, ensure_ascii=False),
    )
    with pytest.raises(SystemExit):
        normalize(
            {"case_id": "C-001", "raw": "x", "evidence": {}},
            NormalizeClient(backend, few_shot=False),
            log,
        )

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert [(e["type"], e["action"]) for e in logged] == [("llm_error", "abort")]
    # 두 번째 응답까지 갔다면 재시도한 것이다. 한 번에 멈춰야 한다.
    assert len(backend.calls) == 1


def test_timeout_is_recorded_under_its_own_type(tmp_path, scenario_body):
    log = errlog.ErrorLog.for_case(tmp_path)
    backend = FakeBackend(
        llm.LLMTimeout("120초 내 응답 없음"), json.dumps(scenario_body, ensure_ascii=False)
    )
    normalize({"case_id": "C-001", "raw": "x", "evidence": {}}, NormalizeClient(backend, few_shot=False), log)

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["type"] == "timeout"


def test_the_failed_response_is_kept_verbatim(tmp_path, scenario_body):
    log = errlog.ErrorLog.for_case(tmp_path)
    client = NormalizeClient(
        FakeBackend("설명만 있고 JSON은 없음", json.dumps(scenario_body, ensure_ascii=False)),
        few_shot=False,
    )
    normalize({"case_id": "C-001", "raw": "x", "evidence": {}}, client, log)

    dumped = tmp_path / "02_normalize_raw_attempt1.txt"
    assert dumped.read_text(encoding="utf-8") == "설명만 있고 JSON은 없음"

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["detail"]["raw"] == dumped.name


def test_a_timeout_leaves_no_file(tmp_path, scenario_body):
    # 응답이 아예 없었다. 직전 시도의 원문을 떨구면 이번 실패의 것으로 읽힌다.
    log = errlog.ErrorLog.for_case(tmp_path)
    backend = FakeBackend(
        llm.LLMTimeout("120초 내 응답 없음"), json.dumps(scenario_body, ensure_ascii=False)
    )
    normalize(
        {"case_id": "C-001", "raw": "x", "evidence": {}},
        NormalizeClient(backend, few_shot=False),
        log,
    )

    assert not (tmp_path / "02_normalize_raw_attempt1.txt").exists()
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert "raw" not in logged[0]["detail"]


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
