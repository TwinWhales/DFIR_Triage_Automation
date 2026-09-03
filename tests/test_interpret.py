"""05단계 해석과 레코드 추림 테스트."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.common import errors as errlog
from src.common import io, schema
from src.stage05_interpret import allocation
from src.stage05_interpret import interpret as interpret_mod
from src.stage05_interpret import record_filter
from src.stage05_interpret.interpret import build_findings, interpret
from src.stage05_interpret.llm_client import InterpretClient
from casepaths import FIXTURES

PARSED = FIXTURES / "04_parsed"


class FakeBackend:
    def __init__(self, *responses: "str | Exception") -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []
        #: 호출마다 받은 ``fmt`` (``test_normalize.py`` 와 같은 규약).
        self.formats: list["dict | None"] = []
        self.name = "fake"
        #: 모델이 실제로 평가한 프롬프트 토큰 수. 테스트가 값을 꽂아
        #: "추정 대 실측"을 재현한다(``Backend`` 프로토콜).
        self.last_prompt_tokens: "int | None" = None

    def complete(self, system: str, user: str, *, fmt: "dict | None" = None) -> str:
        self.calls.append((system, user))
        self.formats.append(fmt)
        response = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        # 예외를 그대로 두면 호출 실패가 아니라 이상한 응답이 된다
        # (test_normalize.py 의 FakeBackend 와 같은 규약).
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture(scope="module")
def records():
    return io.read_parsed_records(PARSED)


@pytest.fixture
def scenario():
    return copy.deepcopy(io.read_json(FIXTURES / "02_scenario.json"))


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


def _selected(records, **kwargs):
    """배분 결과에서 레코드만. 이 블록의 관심사는 자릿수가 아니라 판정이다."""
    return allocation.allocate_records(records, **kwargs)[0]


# ========================================================= record_filter


def test_reproduces_the_mock_input_refs(records):
    # 목업의 input_refs가 곧 이 함수의 기대 출력이다. MFT#12400은
    # 파싱은 됐으나 전달되지 않은 레코드로 일부러 넣어 둔 것이다.
    selected = _selected(records.values())
    assert [r["ref"] for r in selected] == io.read_json(FIXTURES / "05_findings.json")["input_refs"]


def test_flagged_records_are_always_included():
    flagged = _mft("MFT#1", si_ctime="2020-01-01T00:00:00Z", flags=["timestamp_mismatch"])
    assert _selected([flagged]) == [flagged]


def test_outside_time_range_is_not_treated_as_a_signal():
    # 이것을 신호로 치면 선별 범위 밖 레코드가 우선 전달되어
    # 시간 범위를 좁힌 의미가 사라진다.
    record = _mft("MFT#1", si_ctime="2020-01-01T00:00:00Z", flags=["outside_time_range"])
    assert not record_filter.is_signal(record)
    assert _selected([record]) == []


def test_unflagged_records_near_a_signal_come_along():
    signal = _mft("MFT#1", si_ctime="2026-07-20T03:14:22Z", flags=["timestamp_mismatch"])
    near = _mft("MFT#2", si_ctime="2026-07-20T03:15:01Z")
    far = _mft("MFT#3", si_ctime="2026-07-19T11:40:05Z")

    refs = [r["ref"] for r in _selected([signal, near, far])]
    assert refs == ["MFT#1", "MFT#2"]


def test_the_context_window_is_configurable():
    signal = _mft("MFT#1", si_ctime="2026-07-20T03:14:22Z", flags=["deleted"])
    far = _mft("MFT#2", si_ctime="2026-07-20T04:00:00Z")
    assert len(_selected([signal, far], window_seconds=60)) == 1
    assert len(_selected([signal, far], window_seconds=3600)) == 2


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
    assert len(_selected(signals, limit=3)) == 3


def test_signals_win_the_available_slots():
    signal = _mft("MFT#1", si_ctime="2026-07-20T03:14:22Z", flags=["deleted"])
    near = _mft("MFT#2", si_ctime="2026-07-20T03:14:30Z")
    assert [r["ref"] for r in _selected([near, signal], limit=1)] == ["MFT#1"]


def test_no_signals_means_nothing_to_send():
    assert _selected([_mft("MFT#1", si_ctime="2026-07-20T03:14:22Z")]) == []


def test_a_signal_without_a_readable_time_sorts_last_instead_of_crashing():
    """``zero_timestamp`` 레코드는 시각이 없다 — 그게 신호가 된 이유다.

    04단계는 ``$SI``가 전부 0이면 타임스탬프를 ``None``으로 내고
    ``zero_timestamp``를 붙인다. 시각 있는 신호와 같이 정렬될 때 naive를
    섞으면 05단계가 ``TypeError``로 통째로 멈춘다.
    """
    timed = _mft("MFT#1", si_ctime="2026-07-20T03:14:22Z", flags=["deleted"])
    untimed = _mft("MFT#2", si_btime=None, si_ctime=None, flags=["zero_timestamp"])

    selected = _selected([timed, untimed])

    # 버려지지 않고, 시각을 아는 것 뒤에 온다.
    assert [r["ref"] for r in selected] == ["MFT#1", "MFT#2"]


def test_a_timeless_signal_does_not_open_a_context_window():
    """앵커가 될 시각이 없으므로 주변 레코드를 끌어오지 않는다."""
    untimed = _mft("MFT#1", si_ctime=None, flags=["zero_timestamp"])
    other = _mft("MFT#2", si_ctime="2026-07-20T03:14:30Z")

    assert [r["ref"] for r in _selected([untimed, other])] == ["MFT#1"]


# ============================================================ 문서 조립


def test_input_refs_come_from_us_not_from_the_model():
    # 모델이 보고하게 하면 받지 않은 레코드를 목록에 넣어
    # ref_not_in_input 검사를 무력화할 수 있다.
    body = {"findings": [], "timeline": [], "input_refs": ["MFT#99999"]}
    doc = build_findings(body, "C-001", "test", ["MFT#12345"])
    assert doc["input_refs"] == ["MFT#12345"]


def test_a_call_failure_that_is_not_a_timeout_aborts_without_retrying(
    records, scenario, tmp_path
):
    """02단계와 같은 규약이다. 두 단계가 갈리면 어느 쪽이 맞는지 알 수 없다."""
    from src.common import llm

    selected = _selected(records.values())
    backend = FakeBackend(
        llm.LLMError("존재하지-않는-모델:v0: HTTP 400 — invalid model name"),
        (FIXTURES / "05_findings.json").read_text(encoding="utf-8"),
    )
    log = errlog.ErrorLog.for_case(tmp_path)
    with pytest.raises(SystemExit):
        interpret(scenario, selected, InterpretClient(backend), log)

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert [(e["type"], e["action"]) for e in logged] == [("llm_error", "abort")]
    assert len(backend.calls) == 1


def test_output_matches_the_findings_schema(records, scenario, tmp_path):
    selected = _selected(records.values())
    client = InterpretClient(
        FakeBackend((FIXTURES / "05_findings.json").read_text(encoding="utf-8"))
    )
    doc = interpret(scenario, selected, client, errlog.ErrorLog.for_case(tmp_path))
    schema.validate(doc, "findings")


def test_reproduces_the_findings_fixture(records, scenario, tmp_path):
    expected = io.read_json(FIXTURES / "05_findings.json")
    selected = _selected(records.values())
    client = InterpretClient(
        FakeBackend((FIXTURES / "05_findings.json").read_text(encoding="utf-8"))
    )
    got = interpret(scenario, selected, client, errlog.ErrorLog.for_case(tmp_path))

    for doc in (got, expected):
        doc.pop("generated_at")
        doc.pop("generator")
    assert got == expected


def test_the_prompt_tells_the_model_which_refs_exist(records, scenario, tmp_path):
    selected = _selected(records.values())
    backend = FakeBackend((FIXTURES / "05_findings.json").read_text(encoding="utf-8"))
    interpret(scenario, selected, InterpretClient(backend), errlog.ErrorLog.for_case(tmp_path))

    prompt = backend.calls[0][1]
    assert "MFT#12345" in prompt
    assert "MFT#12400" not in prompt  # 전달하지 않은 레코드는 프롬프트에도 없어야 한다


def test_a_schema_violation_is_retried(records, scenario, tmp_path):
    log = errlog.ErrorLog.for_case(tmp_path)
    broken = copy.deepcopy(io.read_json(FIXTURES / "05_findings.json"))
    broken["findings"][0]["severity"] = "catastrophic"
    backend = FakeBackend(
        json.dumps(broken, ensure_ascii=False),
        (FIXTURES / "05_findings.json").read_text(encoding="utf-8"),
    )
    selected = _selected(records.values())
    interpret(scenario, selected, InterpretClient(backend), log)

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["detail"]["field"] == "findings[0].severity"
    assert logged[0]["action"] == "retry"


def test_the_failed_response_is_kept_verbatim(records, scenario, tmp_path):
    # 원문이 없으면 프롬프트가 잘린 것인지 모델이 형식을 어긴 것인지
    # 가릴 수 없다. 2026-08-26 실측에서 실제로 추측으로 진단했다.
    log = errlog.ErrorLog.for_case(tmp_path)
    backend = FakeBackend(
        "여기서 잘렸습니다 {\"findings\": [",
        (FIXTURES / "05_findings.json").read_text(encoding="utf-8"),
    )
    selected = _selected(records.values())
    interpret(scenario, selected, InterpretClient(backend), log)

    dumped = tmp_path / "05_interpret_raw_attempt1.txt"
    assert dumped.read_text(encoding="utf-8") == "여기서 잘렸습니다 {\"findings\": ["

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["type"] == "malformed_output"
    assert logged[0]["detail"]["raw"] == dumped.name


def test_a_schema_violation_keeps_the_response_too(records, scenario, tmp_path):
    # JSON 이긴 한데 스키마를 어긴 경우가 실측에서 더 잦았다.
    log = errlog.ErrorLog.for_case(tmp_path)
    broken = copy.deepcopy(io.read_json(FIXTURES / "05_findings.json"))
    broken["findings"][0]["severity"] = "catastrophic"
    backend = FakeBackend(
        json.dumps(broken, ensure_ascii=False),
        (FIXTURES / "05_findings.json").read_text(encoding="utf-8"),
    )
    interpret(scenario, _selected(records.values()), InterpretClient(backend), log)

    dumped = tmp_path / "05_interpret_raw_attempt1.txt"
    assert "catastrophic" in dumped.read_text(encoding="utf-8")


def test_each_attempt_gets_its_own_file(records, scenario, tmp_path):
    # 한 파일에 덮어쓰면 마지막 시도만 남아, 모델이 지적을 받고 어떻게
    # 달라졌는지(또는 달라지지 않았는지)를 볼 수 없다.
    log = errlog.ErrorLog.for_case(tmp_path)
    backend = FakeBackend("첫째 쓰레기", "둘째 쓰레기")
    with pytest.raises(SystemExit):
        interpret(
            scenario, _selected(records.values()), InterpretClient(backend), log, max_attempts=2
        )

    assert (tmp_path / "05_interpret_raw_attempt1.txt").read_text(encoding="utf-8") == "첫째 쓰레기"
    assert (tmp_path / "05_interpret_raw_attempt2.txt").read_text(encoding="utf-8") == "둘째 쓰레기"


# ================================================================== CLI


def test_cli_stub_run(tmp_path):
    out = tmp_path / "05_findings.json"
    code = interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(out),
            "--llm", "stub",
            "--replay", str(FIXTURES / "05_findings.json"),
        ]
    )
    assert code == 0
    doc = io.read_json(out)
    schema.validate(doc, "findings")
    assert doc["input_refs"] == ["MFT#12345", "MFT#12346", "EVTX-SEC#40912", "EVTX-SEC#40915"]
    assert doc["generator"] == "interpret.py / stub(05_findings.json)"


@pytest.mark.parametrize("reserve", [None, 1024])
def test_cli_ties_the_output_cap_to_the_reserved_budget(monkeypatch, tmp_path, reserve):
    """예산에서 답을 쓰라고 비워 둔 양이 그대로 출력 상한으로 나가는가.

    둘이 갈라지면 "비워 둔 자리"와 "실제로 쓸 수 있는 양"이 달라지고, 어느
    쪽이 맞는지 확인할 방법이 없다. 상한이 아예 없던 동안에는 모델이 JSON을
    닫지 못할 때 컨텍스트가 찰 때까지 써서 타임아웃으로만 끝났다.
    """
    captured: dict = {}

    def fake_build_backend(kind, **kwargs):
        captured.update(kwargs)
        return FakeBackend((FIXTURES / "05_findings.json").read_text(encoding="utf-8"))

    monkeypatch.setattr(interpret_mod.llm, "build_backend", fake_build_backend)
    argv = [
        "--in", str(PARSED),
        "--scenario", str(FIXTURES / "02_scenario.json"),
        "--out", str(tmp_path / "05_findings.json"),
        "--llm", "ollama", "--model", "m",
    ]
    if reserve is not None:
        argv += ["--reserve-output-tokens", str(reserve)]

    assert interpret_mod.main(argv) == 0
    assert captured["num_predict"] == (reserve or allocation.RESERVE_FINDINGS_TOKENS)


def _run_with_tokens(monkeypatch, tmp_path, prompt_tokens):
    """실측 토큰 수를 꽂은 백엔드로 05를 한 번 돌리고 출력을 돌려준다."""
    backend = FakeBackend((FIXTURES / "05_findings.json").read_text(encoding="utf-8"))
    backend.last_prompt_tokens = prompt_tokens
    monkeypatch.setattr(interpret_mod.llm, "build_backend", lambda kind, **kw: backend)
    assert (
        interpret_mod.main(
            [
                "--in", str(PARSED),
                "--scenario", str(FIXTURES / "02_scenario.json"),
                "--out", str(tmp_path / "05_findings.json"),
                "--llm", "ollama", "--model", "m",
            ]
        )
        == 0
    )


def test_cli_puts_the_measured_token_count_next_to_the_estimate(
    monkeypatch, tmp_path, capsys
):
    # 추정 옆에 실측이 없으면 상수가 어긋난 것이 실행 중에 보이지 않는다.
    # 프롬프트가 창을 넘고 있다는 사실을 사람이 따로 재서야 찾아냈다.
    _run_with_tokens(monkeypatch, tmp_path, 2000)

    printed = capsys.readouterr()
    assert "프롬프트 실측 2,000토큰" in printed.out
    assert "경고" not in printed.err


def test_cli_warns_when_the_ratio_says_the_prompt_was_cut(monkeypatch, tmp_path, capsys):
    """자·토큰 비가 예산의 가정보다 훨씬 크면 앞이 잘렸을 수 있다.

    잘림은 이 수로 직접 볼 수 없다 — Ollama 가 자른 뒤의 수를 돌려주기
    때문이다. 절반이 잘리면 비가 두 배가 되고, 그것이 유일한 단서다.
    """
    # 레코드 넷의 프롬프트를 터무니없이 적은 토큰으로 평가했다고 말한다.
    _run_with_tokens(monkeypatch, tmp_path, 50)

    printed = capsys.readouterr()
    assert "경고" in printed.err
    assert "잘렸을 수 있습니다" in printed.err
    # 중단하지는 않는다 — 비율이 벗어나는 데는 잘림 말고 다른 이유도 있다.
    assert (tmp_path / "05_findings.json").is_file()


def test_the_stub_backend_measures_nothing(tmp_path, capsys):
    # 0 이 아니라 None 이라야 "0토큰이었다"와 "재지 않았다"가 갈린다.
    interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(tmp_path / "05_findings.json"),
            "--llm", "stub",
            "--replay", str(FIXTURES / "05_findings.json"),
        ]
    )
    assert "프롬프트 실측" not in capsys.readouterr().out


def test_cli_aborts_when_no_record_carries_a_signal(tmp_path):
    parsed = tmp_path / "04_parsed"
    parsed.mkdir()
    io.write_jsonl(parsed / "mft.jsonl", [_mft("MFT#1", si_ctime="2026-07-20T03:14:22Z")])

    with pytest.raises(SystemExit):
        interpret_mod.main(
            [
                "--in", str(parsed),
                "--scenario", str(FIXTURES / "02_scenario.json"),
                "--out", str(tmp_path / "05_findings.json"),
                "--llm", "stub",
                "--replay", str(FIXTURES / "05_findings.json"),
            ]
        )
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[-1]["type"] == "empty_result"


def test_cli_aborts_when_the_budget_admits_nothing(tmp_path, capsys):
    """예산이 한 건도 못 들여보내면 사유를 구분해 말한다.

    flags 룰을 들여다봐야 풀리는 문제가 아니다 — 창을 키우거나 모델을
    바꿔야 한다. 두 경우가 같은 메시지로 나오면 엉뚱한 데를 파게 된다.
    """
    with pytest.raises(SystemExit):
        interpret_mod.main(
            [
                "--in", str(PARSED),
                "--scenario", str(FIXTURES / "02_scenario.json"),
                "--out", str(tmp_path / "05_findings.json"),
                "--llm", "stub",
                "--replay", str(FIXTURES / "05_findings.json"),
                # 출력 자리로 창을 통째로 떼어 레코드에 남는 예산을 0으로.
                "--num-ctx", "4096",
                "--reserve-output-tokens", "4096",
            ]
        )
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[-1]["type"] == "empty_result"
    assert "예산" in logged[-1]["detail"]["message"]
    assert "num-ctx" in logged[-1]["detail"]["message"]


def test_cli_says_so_when_the_budget_trims_seats(tmp_path, capsys):
    # 넘는데도 조용히 도는 것이 이 자리에서 가장 나쁜 성질이다.
    out = tmp_path / "05_findings.json"
    code = interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(out),
            "--llm", "stub",
            "--replay", str(FIXTURES / "05_findings.json"),
            # 레코드 넷 중 둘만 들어갈 만큼만 연다. 창에서 출력 예약을 빼고
            # 남은 것이 1,056자다 — CHARS_PER_TOKEN 을 실측값으로 낮추면서
            # 같은 예산이 나오도록 창을 함께 옮겼다(2026-09-03).
            "--num-ctx", "5600",
            "--reserve-output-tokens", "4096",
        ]
    )
    assert code == 0
    printed = capsys.readouterr().out
    assert "토큰 예산" in printed

    # 전달된 것만 input_refs 에 남는다. 모델이 못 받은 것을 목록에 넣으면
    # ref_not_in_input 검사가 무력해진다.
    doc = io.read_json(out)
    assert len(doc["input_refs"]) < 4


def test_a_roomy_context_says_nothing_about_the_budget(tmp_path, capsys):
    interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(tmp_path / "05_findings.json"),
            "--llm", "stub",
            "--replay", str(FIXTURES / "05_findings.json"),
        ]
    )
    assert "토큰 예산" not in capsys.readouterr().out
