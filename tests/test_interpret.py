"""05단계 해석과 레코드 추림 테스트."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.common import errors as errlog
from src.common import io, schema
from src.stage05_interpret import interpret as interpret_mod
from src.stage05_interpret import record_filter
from src.stage05_interpret.interpret import build_findings, interpret
from src.stage05_interpret.llm_client import InterpretClient

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK = REPO_ROOT / "benchmark/datasets/C-001-webshell/mock"
PARSED = MOCK / "04_parsed"


class FakeBackend:
    def __init__(self, *responses: str) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []
        self.name = "fake"

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]


@pytest.fixture(scope="module")
def records():
    return io.read_parsed_records(PARSED)


@pytest.fixture
def scenario():
    return copy.deepcopy(io.read_json(MOCK / "02_scenario.json"))


def _mft(ref, **fields):
    record = {
        "ref": ref,
        "artifact": "$MFT",
        "record_num": int(ref.split("#")[1]),
        "offset": "0x1000",
        "path": "C:\\x.aspx",
        "flags": [],
    }
    record.update(fields)
    return record


# ========================================================= record_filter


def test_reproduces_the_mock_input_refs(records):
    # 목업의 input_refs가 곧 이 함수의 기대 출력이다. MFT#12400은
    # 파싱은 됐으나 전달되지 않은 레코드로 일부러 넣어 둔 것이다.
    selected = record_filter.select_records(records.values())
    assert [r["ref"] for r in selected] == io.read_json(MOCK / "05_findings.json")["input_refs"]


def test_flagged_records_are_always_included():
    flagged = _mft("MFT#1", si_ctime="2020-01-01T00:00:00Z", flags=["timestamp_mismatch"])
    assert record_filter.select_records([flagged]) == [flagged]


def test_outside_time_range_is_not_treated_as_a_signal():
    # 이것을 신호로 치면 선별 범위 밖 레코드가 우선 전달되어
    # 시간 범위를 좁힌 의미가 사라진다.
    record = _mft("MFT#1", si_ctime="2020-01-01T00:00:00Z", flags=["outside_time_range"])
    assert not record_filter.is_signal(record)
    assert record_filter.select_records([record]) == []


def test_unflagged_records_near_a_signal_come_along():
    signal = _mft("MFT#1", si_ctime="2026-07-20T03:14:22Z", flags=["timestamp_mismatch"])
    near = _mft("MFT#2", si_ctime="2026-07-20T03:15:01Z")
    far = _mft("MFT#3", si_ctime="2026-07-19T11:40:05Z")

    refs = [r["ref"] for r in record_filter.select_records([signal, near, far])]
    assert refs == ["MFT#1", "MFT#2"]


def test_the_context_window_is_configurable():
    signal = _mft("MFT#1", si_ctime="2026-07-20T03:14:22Z", flags=["deleted"])
    far = _mft("MFT#2", si_ctime="2026-07-20T04:00:00Z")
    assert len(record_filter.select_records([signal, far], window_seconds=60)) == 1
    assert len(record_filter.select_records([signal, far], window_seconds=3600)) == 2


def test_fn_timestamps_do_not_drive_ordering():
    # $FN이 $SI와 어긋나는 것은 조작의 신호이지 활동 시각이 아니다.
    # 섞으면 조작된 레코드가 엉뚱한 시점으로 정렬되어 타임라인이 뒤틀린다.
    record = _mft(
        "MFT#1",
        si_ctime="2026-07-20T03:14:22Z",
        fn_ctime="2030-01-01T00:00:00Z",
        flags=["timestamp_mismatch"],
    )
    times = record_filter.activity_times(record)
    assert all(moment.year == 2026 for moment in times)


def test_the_limit_caps_the_payload():
    signals = [
        _mft(f"MFT#{i}", si_ctime=f"2026-07-20T03:{i:02d}:00Z", flags=["deleted"])
        for i in range(10)
    ]
    assert len(record_filter.select_records(signals, limit=3)) == 3


def test_signals_win_the_available_slots():
    signal = _mft("MFT#1", si_ctime="2026-07-20T03:14:22Z", flags=["deleted"])
    near = _mft("MFT#2", si_ctime="2026-07-20T03:14:30Z")
    assert [r["ref"] for r in record_filter.select_records([near, signal], limit=1)] == ["MFT#1"]


def test_no_signals_means_nothing_to_send():
    assert record_filter.select_records([_mft("MFT#1", si_ctime="2026-07-20T03:14:22Z")]) == []


# ============================================================ 문서 조립


def test_input_refs_come_from_us_not_from_the_model():
    # 모델이 보고하게 하면 받지 않은 레코드를 목록에 넣어
    # ref_not_in_input 검사를 무력화할 수 있다.
    body = {"findings": [], "timeline": [], "input_refs": ["MFT#99999"]}
    doc = build_findings(body, "C-001", "test", ["MFT#12345"])
    assert doc["input_refs"] == ["MFT#12345"]


def test_output_matches_the_findings_schema(records, scenario, tmp_path):
    selected = record_filter.select_records(records.values())
    client = InterpretClient(
        FakeBackend((MOCK / "05_findings.json").read_text(encoding="utf-8"))
    )
    doc = interpret(scenario, selected, client, errlog.ErrorLog.for_case(tmp_path))
    schema.validate(doc, "findings")


def test_reproduces_the_findings_fixture(records, scenario, tmp_path):
    expected = io.read_json(MOCK / "05_findings.json")
    selected = record_filter.select_records(records.values())
    client = InterpretClient(
        FakeBackend((MOCK / "05_findings.json").read_text(encoding="utf-8"))
    )
    got = interpret(scenario, selected, client, errlog.ErrorLog.for_case(tmp_path))

    for doc in (got, expected):
        doc.pop("generated_at")
        doc.pop("generator")
    assert got == expected


def test_the_prompt_tells_the_model_which_refs_exist(records, scenario, tmp_path):
    selected = record_filter.select_records(records.values())
    backend = FakeBackend((MOCK / "05_findings.json").read_text(encoding="utf-8"))
    interpret(scenario, selected, InterpretClient(backend), errlog.ErrorLog.for_case(tmp_path))

    prompt = backend.calls[0][1]
    assert "MFT#12345" in prompt
    assert "MFT#12400" not in prompt  # 전달하지 않은 레코드는 프롬프트에도 없어야 한다


def test_a_schema_violation_is_retried(records, scenario, tmp_path):
    log = errlog.ErrorLog.for_case(tmp_path)
    broken = copy.deepcopy(io.read_json(MOCK / "05_findings.json"))
    broken["findings"][0]["severity"] = "catastrophic"
    backend = FakeBackend(
        json.dumps(broken, ensure_ascii=False),
        (MOCK / "05_findings.json").read_text(encoding="utf-8"),
    )
    selected = record_filter.select_records(records.values())
    interpret(scenario, selected, InterpretClient(backend), log)

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["detail"]["field"] == "findings[0].severity"
    assert logged[0]["action"] == "retry"


# ================================================================== CLI


def test_cli_stub_run(tmp_path):
    out = tmp_path / "05_findings.json"
    code = interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(MOCK / "02_scenario.json"),
            "--out", str(out),
            "--llm", "stub",
            "--replay", str(MOCK / "05_findings.json"),
        ]
    )
    assert code == 0
    doc = io.read_json(out)
    schema.validate(doc, "findings")
    assert doc["input_refs"] == ["MFT#12345", "MFT#12346", "EVTX-SEC#40912", "EVTX-SEC#40915"]
    assert doc["generator"] == "interpret.py / stub(05_findings.json)"


def test_cli_aborts_when_no_record_carries_a_signal(tmp_path):
    parsed = tmp_path / "04_parsed"
    parsed.mkdir()
    io.write_jsonl(parsed / "mft.jsonl", [_mft("MFT#1", si_ctime="2026-07-20T03:14:22Z")])

    with pytest.raises(SystemExit):
        interpret_mod.main(
            [
                "--in", str(parsed),
                "--scenario", str(MOCK / "02_scenario.json"),
                "--out", str(tmp_path / "05_findings.json"),
                "--llm", "stub",
                "--replay", str(MOCK / "05_findings.json"),
            ]
        )
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[-1]["type"] == "empty_result"
