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
from src.stage05_interpret.llm_client import InterpretClient, MalformedOutput, connection_schema
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
            "--mode", "model",
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
        # 이 백엔드가 돌려주는 것이 findings 문서라 예전 경로 시험이다.
        "--mode", "model",
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
                # 이 백엔드가 돌려주는 것이 findings 문서라 예전 경로 시험이다.
                "--mode", "model",
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
    assert "프롬프트 실측 최대 2,000토큰" in printed.out
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
            "--mode", "model",
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
                "--mode", "model",
            "--mode", "model",
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
                "--mode", "model",
            "--mode", "model",
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
    #
    # **골든 픽스처를 그대로 재생하지 않는다.** 리플레이 파일은 어떤
    # 프롬프트에 대한 응답의 기록이다. 이 테스트는 일부러 레코드를 잘라
    # 프롬프트를 바꾸므로, 자르기 전 프롬프트로 녹음한 골든을 재생하면
    # 모델이 받은 적 없는 EVTX-SEC#40915 를 인용하게 된다. 그것은 05단계
    # claim 관문이 잡으라고 있는 것이라 통과시키면 안 되고, 여기서 볼
    # 것도 아니다. 잘린 프롬프트에 맞는 기록을 따로 준다.
    replay = tmp_path / "05_trimmed_reply.json"
    replay.write_text(
        json.dumps(
            {
                # 살아남는 둘은 MFT#12345 · EVTX-SEC#40912 다. F1 은 앞의
                # 것만 인용하므로 잘라도 성립한다. F2 는 EVTX-SEC#40915 를
                # 함께 인용해야 말이 되는 문장이라 통째로 뺀다.
                "findings": [
                    finding
                    for finding in io.read_json(FIXTURES / "05_findings.json")["findings"]
                    if finding["id"] in ("F1", "F3")
                ],
                "timeline": [
                    {
                        "ts": "2026-07-20T03:14:22Z",
                        "event": "shell.aspx 생성",
                        "refs": ["MFT#12345"],
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    out = tmp_path / "05_findings.json"
    code = interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(out),
            "--llm", "stub",
            "--replay", str(replay),
            "--mode", "model",
            # 레코드 넷 중 둘만 들어갈 만큼만 연다. 창에서 출력 예약을 빼고
            # 남은 것이 1,055자다 — CHARS_PER_TOKEN 을 실측값으로 낮추면서
            # 같은 예산이 나오도록 창을 함께 옮겼고(2026-09-03), 기법 라벨
            # 목록이 프롬프트에 들어오며 고정분이 2,034 → 3,853자가 되어
            # 5600 → 6550 으로 다시 옮겼고, 누락 기법 5종을 등재해 라벨이
            # 41 → 46개가 되며 6550 → 6660 으로 또 옮겼다(둘 다 2026-09-10).
            "--num-ctx", "6660",
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

    # 자리가 줄어도 살아남은 레코드를 인용한 문장은 그대로 나온다. 잘림이
    # 문장을 통째로 삼키면 예산 축소가 조용한 누락이 된다.
    assert [finding["id"] for finding in doc["findings"]] == ["F1", "F3"]


def test_replaying_a_reply_that_cites_a_trimmed_record_is_refused(tmp_path, capsys):
    """자르기 전에 녹음한 응답을 자른 프롬프트에 재생하면 중단한다.

    관문이 실제로 켜져 있는지 보는 자리다. 위 테스트가 기록을 맞춰 주고
    지나가므로, 맞추지 않았을 때 조용히 통과하지 않는다는 것을 여기서
    따로 못 박는다. 재생된 F2 는 잘려 나간 EVTX-SEC#40915 를 인용한다.
    """
    with pytest.raises(SystemExit):
        interpret_mod.main(
            [
                "--in", str(PARSED),
                "--scenario", str(FIXTURES / "02_scenario.json"),
                "--out", str(tmp_path / "05_findings.json"),
                "--llm", "stub",
                "--replay", str(FIXTURES / "05_findings.json"),
                "--mode", "model",
            "--mode", "model",
                # 위 테스트와 같은 창이어야 같은 자르기가 일어난다.
                # CHARS_PER_TOKEN 을 실측값으로 낮추면서 5300 → 5600
                # (2026-09-03), 기법 라벨 목록이 들어오며 5600 → 6550,
                # 누락 기법 5종 등재로 6550 → 6660 (2026-09-10). 예전 값으로 두면 예산이 한 건도 못 들여보내
                # empty_result 로 죽고, 이 테스트가 보려던 claim_validation
                # 관문에는 닿지도 못한다.
                "--num-ctx", "6660",
                "--reserve-output-tokens", "4096",
            ]
        )

    recorded = [
        json.loads(line)
        for line in (tmp_path / "errors.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert recorded[0]["type"] == "claim_validation"
    assert "EVTX-SEC#40915" in recorded[0]["detail"]["message"]


def test_a_roomy_context_says_nothing_about_the_budget(tmp_path, capsys):
    interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(tmp_path / "05_findings.json"),
            "--llm", "stub",
            "--replay", str(FIXTURES / "05_findings.json"),
            "--mode", "model",
        ]
    )
    assert "토큰 예산" not in capsys.readouterr().out


# ================================================ --mode assemble · 실패 처리


def _selection(*items):
    """선별 질의의 응답 원문."""
    return json.dumps({"suspicious_records": list(items)}, ensure_ascii=False)


def _pick(ref, **overrides):
    base = {
        "ref": ref,
        "technique": None,
        "reason": "의심 정황",
        "severity": "medium",
        "evidence_fields": ["path"],
    }
    base.update(overrides)
    return base


def _run_assembled(monkeypatch, tmp_path, backend, extra=()):
    monkeypatch.setattr(interpret_mod.llm, "build_backend", lambda kind, **kw: backend)
    return interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(tmp_path / "05_findings.json"),
            "--llm", "ollama", "--model", "m",
            "--mode", "assemble",
            *extra,
        ]
    )


def _errors(tmp_path):
    path = tmp_path / "errors.jsonl"
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_assemble_mode_builds_the_document_from_what_the_model_chose(
    monkeypatch, tmp_path
):
    """모델은 고르고 파이썬이 옮긴다. 문장 하나만 모델의 것이다."""
    backend = FakeBackend(_selection(_pick("MFT#12345")))

    assert _run_assembled(monkeypatch, tmp_path, backend) == 0

    doc = io.read_json(tmp_path / "05_findings.json")
    schema.validate(doc, "findings")
    finding = doc["findings"][0]
    assert finding["statement"] == "의심 정황"
    assert [c["field"] for c in finding["claims"]] == ["path"]
    # 값은 모델이 아니라 원본에서 왔다.
    assert finding["claims"][0]["value"].endswith("shell.aspx")


def test_a_field_the_record_lacks_is_retried_with_feedback(monkeypatch, tmp_path):
    """**모델 잘못이라 다시 물어보면 고쳐질 수 있다.**

    조립 경로에서 살아남은 유일한 모델 오류 채널이다.
    """
    backend = FakeBackend(
        _selection(_pick("MFT#12345", evidence_fields=["fields.CommandLine"])),
        _selection(_pick("MFT#12345")),
    )

    assert _run_assembled(monkeypatch, tmp_path, backend) == 0

    recorded = _errors(tmp_path)
    assert [(e["type"], e["action"]) for e in recorded] == [("claim_validation", "retry")]
    assert len(backend.calls) == 2  # 다시 물어봤고 두 번째가 통과했다
    # 지적이 프롬프트에 실려 나갔는가. 안 실리면 재시도가 같은 답을 부른다.
    assert "evidence_fields" in backend.calls[1][1]


def test_a_reason_that_only_lists_flags_is_retried(monkeypatch, tmp_path):
    """**실측 회귀 (`K-LIVE-0907-wide`, 2026-09-07).**

    소견 18건 중 13건의 문장이 ``"file_created, outside_time_range"`` 처럼
    그 레코드의 플래그를 그대로 옮긴 것이었고, **13건 전부 06단계를
    통과해** 보고서의 "확인된 사항 15건"에 들어갔다. 글자는 있는데 사실이
    없으므로 빈 문장과 성질이 같다.

    막는 자리를 05 로 둔 것은, 06 에서 강등하면 수치는 정직해지지만 소견이
    남지 않기 때문이다. 모델에게 다시 쓰게 하는 것이 답이다.
    """
    backend = FakeBackend(
        _selection(_pick("MFT#12345", reason="file_created, outside_time_range")),
        _selection(_pick("MFT#12345", reason="webshell.aspx 가 웹 루트에 생성됐다")),
    )

    assert _run_assembled(monkeypatch, tmp_path, backend) == 0

    recorded = _errors(tmp_path)
    assert [(e["type"], e["action"]) for e in recorded] == [("claim_validation", "retry")]
    assert len(backend.calls) == 2

    # **무엇을 고쳐야 하는지가 실려 나가는가.** 필드가 틀렸다고 말하면 모델은
    # 문장을 그대로 두고 필드만 만진다.
    followup = backend.calls[1][1]
    assert "flags" in followup and "한 문장" in followup
    assert "evidence_fields" not in followup, "이 실패는 필드 문제가 아니다"


def test_a_reason_that_mentions_a_flag_but_says_more_is_kept(monkeypatch, tmp_path):
    """**판정은 좁게 한다.** 정상 문장을 기각하는 쪽이 더 나쁘다.

    낱말 하나라도 어휘 밖이면 통과시킨다 — 무내용을 놓치면 06 이 한 번 더
    보지만, 정상 문장을 기각하면 증거가 사라진다.
    """
    backend = FakeBackend(
        _selection(
            _pick("MFT#12345", reason="outside_time_range 이지만 webshell.aspx 가 생성됐다")
        )
    )

    assert _run_assembled(monkeypatch, tmp_path, backend) == 0
    assert _errors(tmp_path) == []
    assert len(backend.calls) == 1


def test_our_own_bug_stops_at_once_instead_of_burning_three_calls(
    monkeypatch, tmp_path
):
    """**조립기 오류는 재시도해도 같은 답이 나온다.**

    같은 코드가 같은 입력으로 같은 답을 낸다. 재시도하면 모델을 세 번 더
    부르고 똑같이 죽으며, 그 실패가 claim_validation 으로 쌓여 "모델이
    틀렸다"와 "우리가 틀렸다"를 한 통계에 섞는다.
    """
    # 보내지 않은 ref 를 골랐다고 하면 조립기가 짝을 못 짓는다.
    backend = FakeBackend(_selection(_pick("MFT#99999")))

    with pytest.raises(SystemExit):
        _run_assembled(monkeypatch, tmp_path, backend)

    recorded = _errors(tmp_path)
    assert [(e["type"], e["action"]) for e in recorded] == [("assembly_error", "abort")]
    assert len(backend.calls) == 1  # 한 번만 부르고 멈췄다


def test_the_two_failures_do_not_share_a_name(monkeypatch, tmp_path):
    """한 이름으로 세면 어느 쪽이 몇 건이었는지 나중에 못 가른다."""
    assert "assembly_error" in errlog.ERROR_TYPES
    assert "claim_validation" in errlog.ERROR_TYPES


@pytest.mark.parametrize(
    "mode, expected",
    [("model", allocation.RESERVE_FINDINGS_TOKENS), ("assemble", allocation.RESERVE_SELECTION_TOKENS)],
)
def test_the_output_reserve_follows_the_query_kind(monkeypatch, tmp_path, mode, expected):
    """선별 질의는 답 쓸 자리가 소견 질의의 4분의 1이다.

    큰 쪽에 맞춰 두면 작은 질의가 쓰지도 않을 자리를 창에서 떼어 간다.
    """
    captured: dict = {}

    def fake_build_backend(kind, **kwargs):
        captured.update(kwargs)
        body = (
            _selection(_pick("MFT#12345"))
            if mode == "assemble"
            else (FIXTURES / "05_findings.json").read_text(encoding="utf-8")
        )
        return FakeBackend(body)

    monkeypatch.setattr(interpret_mod.llm, "build_backend", fake_build_backend)
    interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(tmp_path / "05_findings.json"),
            "--llm", "ollama", "--model", "m",
            "--mode", mode,
        ]
    )

    assert captured["num_predict"] == expected


def test_an_explicit_reserve_wins_over_the_mode_default(monkeypatch, tmp_path):
    captured: dict = {}

    def fake_build_backend(kind, **kwargs):
        captured.update(kwargs)
        return FakeBackend(_selection(_pick("MFT#12345")))

    monkeypatch.setattr(interpret_mod.llm, "build_backend", fake_build_backend)
    interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(tmp_path / "05_findings.json"),
            "--llm", "ollama", "--model", "m",
            "--mode", "assemble",
            "--reserve-output-tokens", "2048",
        ]
    )

    assert captured["num_predict"] == 2048


def test_a_chunk_failure_stops_instead_of_finishing_with_the_rest(monkeypatch, tmp_path):
    """**남은 조각으로 완주하면 그것이 폴백이다.**

    증거의 일부만 본 보고서가 전부를 본 것처럼 나가고, 그 사실은 산출물
    어디에도 없다. 이 프로젝트에서 가장 나쁜 성질이다.
    """
    # 세 번 다 JSON 이 아니다 — 한 조각이 재시도를 다 쓴다.
    backend = FakeBackend("설명만 하고 JSON 을 안 냈다", "또 안 냈다", "여전히 안 냈다")

    with pytest.raises(SystemExit):
        _run_assembled(monkeypatch, tmp_path, backend)

    recorded = _errors(tmp_path)
    assert [e["action"] for e in recorded] == ["retry", "retry", "retry", "abort"]
    assert recorded[-1]["type"] == "malformed_output"
    assert "일부만 본 보고서" in recorded[-1]["detail"]["message"]


def test_each_chunk_is_asked_separately(monkeypatch, tmp_path):
    """조각마다 자기 질의를 받아야, 어느 조각이 틀렸는지 그 자리에서 안다."""
    backend = FakeBackend(
        _selection(_pick("MFT#12345")),
        _selection(_pick("MFT#12346")),
        _selection(),
        _selection(),
        _selection(),
    )

    # 레코드 하나가 겨우 들어갈 만큼만 열어 조각을 강제한다. 배분 예산은
    # --max-chunks 배라 레코드는 전부 골라지고, 질의만 나뉜다.
    #
    # **이 숫자는 프롬프트 고정분을 따라간다.** 창에서 출력 예약과 고정분을
    # 뺀 나머지가 예산이므로, select_system.txt 가 길어지면 같은 창에서
    # 예산이 0 이 되고 이 시험은 "조각이 나뉘는가"가 아니라 "예산이 남는가"
    # 를 재게 된다. 2026-09-07 에 flags 지침을 넣으며 고정분이 2,194 →
    # 2,633자가 되어 5400 → 5620 으로 옮겼다(예산 414 → 415자로 같다).
    # 2026-09-08 typed assertion 원자화 지침 뒤 6000, packet/Story 지침 뒤
    # 6200으로 재보정했다. 2026-09-10 기법 라벨 목록(41건, 1,819자)이
    # 프롬프트에 들어오며 고정분이 3,830 → 5,649자가 되어 7130 으로 옮겼다
    # (예산 419자로 거의 같다). 같은 날 누락 기법 5종을 등재해 라벨이
    # 41 → 46개가 되며 7130 → 7240 으로 또 옮겼다(예산 415자).
    # 프롬프트를 또 고치면 여기도 같이 본다.
    code = _run_assembled(
        monkeypatch,
        tmp_path,
        backend,
        extra=["--num-ctx", "7240", "--reserve-output-tokens", "4096"],
    )

    assert code == 0
    assert len(backend.calls) > 1  # 한 번에 다 묻지 않았다
    doc = io.read_json(tmp_path / "05_findings.json")
    # 조각들에서 나온 선별이 하나의 문서로 합쳐진다.
    assert {f["refs"][0] for f in doc["findings"]} == {"MFT#12345", "MFT#12346"}


def test_the_reduce_query_ties_records_across_artifacts(monkeypatch, tmp_path):
    """**이것이 Map-Reduce 의 Reduce 다.**

    없으면 조각마다 따로 판정만 하고 파이썬이 append 할 뿐이라, 조각을 넘는
    연결은 아무도 말한 적이 없다.
    """
    backend = FakeBackend(
        _selection(_pick("MFT#12345"), _pick("EVTX-SEC#40912", evidence_fields=["event_id"])),
        json.dumps(
            {
                "connections": [
                    {
                        "refs": ["MFT#12345", "EVTX-SEC#40912"],
                        "technique": None,
                        "reason": "파일이 떨어진 직후 계정이 생겼다",
                        "severity": "high",
                    }
                ]
            },
            ensure_ascii=False,
        ),
    )

    assert _run_assembled(monkeypatch, tmp_path, backend) == 0

    doc = io.read_json(tmp_path / "05_findings.json")
    schema.validate(doc, "findings")
    assert len(doc["findings"]) == 1
    assert doc["findings"][0]["refs"] == ["MFT#12345", "EVTX-SEC#40912"]
    # 각 레코드의 근거는 Map 이 골라 둔 것이다.
    assert {c["field"] for c in doc["findings"][0]["claims"]} == {"path", "event_id"}


def test_a_failed_reduce_skips_instead_of_stopping(monkeypatch, tmp_path):
    """**조각 실패와 다르다.** 여기서 잃는 것은 종합이지 증거가 아니다.

    고른 항목은 전부 단독 소견으로 실리므로 산출물이 부분이 되지 않는다.
    그래서 abort 가 아니라 skip 이다. 다만 조용히 넘어가지는 않는다.
    """
    backend = FakeBackend(
        _selection(_pick("MFT#12345"), _pick("EVTX-SEC#40912", evidence_fields=["event_id"])),
        "종합은 못 하겠고 설명만 하겠다",
    )

    assert _run_assembled(monkeypatch, tmp_path, backend) == 0

    recorded = _errors(tmp_path)
    assert [(e["type"], e["action"]) for e in recorded] == [
        ("malformed_output", "retry"),
        ("malformed_output", "retry"),
        ("malformed_output", "skip"),
    ]
    doc = io.read_json(tmp_path / "05_findings.json")
    # 증거는 다 실렸다 — 묶이지 않았을 뿐이다.
    assert {f["refs"][0] for f in doc["findings"]} == {"MFT#12345", "EVTX-SEC#40912"}


def test_reduce_builds_one_incident_story_and_runs_one_batched_critic(monkeypatch, tmp_path):
    story = {
        "summary": "파일 생성과 후속 계정 이벤트가 하나의 사건으로 이어진다.",
        "sentences": [
            {"id": "N1", "text": "파일이 생성됐다.", "kind": "observed_fact", "refs": ["MFT#12345"]},
            {"id": "N2", "text": "후속 행위의 의도는 미확인이다.", "kind": "unknown", "refs": ["EVTX-SEC#40912"]},
        ],
        "critical_threat": "후속 계정 행위",
    }
    backend = FakeBackend(
        _selection(_pick("MFT#12345"), _pick("EVTX-SEC#40912", evidence_fields=["event_id"])),
        json.dumps({
            "connections": [{
                "refs": ["MFT#12345", "EVTX-SEC#40912"], "technique": None,
                "reason": "파일 생성 뒤 계정 이벤트가 이어졌다", "severity": "high",
                "assertions": [{
                    "predicate": "contains", "subject": {"ref": "MFT#12345", "field": "path"},
                    "object": ".aspx",
                }],
            }],
            "incident_story": story,
        }, ensure_ascii=False),
        json.dumps({"story_critic": [
            {"sentence_id": "N1", "verdict": "supported", "reason": "MFT 근거가 있다"},
            {"sentence_id": "N2", "verdict": "insufficient", "reason": "의도 근거가 없다"},
        ]}, ensure_ascii=False),
    )

    assert _run_assembled(monkeypatch, tmp_path, backend) == 0
    doc = io.read_json(tmp_path / "05_findings.json")
    assert doc["incident_story"] == story
    assert len(doc["story_critic"]) == 2
    assert len(backend.calls) == 3
    assert doc["findings"][0]["assertions"][0]["predicate"] == "contains"


def test_signal_dispositions_accumulate_across_map_chunks(tmp_path):
    records = [
        {"ref": "SYSMON#1", "fields": {"Image": "a.exe"}, "attention_signals": ["a"]},
        {"ref": "SYSMON#2", "fields": {"Image": "b.exe"}, "attention_signals": ["b"]},
    ]
    responses = []
    for ref, signal in (("SYSMON#1", "a"), ("SYSMON#2", "b")):
        responses.append(json.dumps({
            "suspicious_records": [],
            "signal_dispositions": {f"{ref}:{signal}": {
                "disposition": "dismissed", "reason": "검토함", "evidence_fields": ["fields.Image"],
            }},
        }, ensure_ascii=False))
    client = InterpretClient(FakeBackend(*responses))
    accumulated = {}
    log = errlog.ErrorLog(tmp_path / "errors.jsonl")
    for index, record in enumerate(records, 1):
        interpret_mod._select_chunk(
            {"case_id": "C", "techniques": []}, [record], client, log, index, 2,
            dispositions=accumulated,
        )
    assert set(accumulated) == {"SYSMON#1:a", "SYSMON#2:b"}


def test_reduce_schema_allows_relation_ids_not_authored_endpoints():
    fmt = connection_schema(
        {"techniques": []},
        [_pick("SYSMON#1"), _pick("MFT#1")],
        [{"id": "R1"}],
    )
    connection = fmt["properties"]["connections"]["items"]
    assert "assertion_ids" in connection["properties"]
    assert "assertions" not in connection["properties"]
    assert connection["properties"]["assertion_ids"]["items"]["enum"] == ["R1"]


def test_reduce_schema_requires_each_must_review_ref_in_story():
    picked = [
        {**_pick("SYSMON#1"), "attention_signals": ["credential_export_option_observed"]},
        _pick("MFT#1"),
    ]
    fmt = connection_schema({"techniques": []}, picked, [])
    sentences = fmt["properties"]["incident_story"]["properties"]["sentences"]
    required_ref = sentences["allOf"][0]["contains"]["properties"]["refs"]["contains"]["const"]
    assert required_ref == "SYSMON#1"


def test_reduce_rejects_story_that_drops_a_must_review_ref():
    picked = [
        {**_pick("SYSMON#1"), "attention_signals": ["credential_export_option_observed"]},
        _pick("MFT#1"),
    ]
    response = json.dumps({
        "connections": [],
        "incident_story": {
            "summary": "요약", "critical_threat": "위협",
            "sentences": [{
                "id": "N1", "text": "다른 증거만 기술", "kind": "observed_fact",
                "refs": ["MFT#1"],
            }],
        },
    }, ensure_ascii=False)
    client = InterpretClient(FakeBackend(response))

    with pytest.raises(MalformedOutput, match="must_review"):
        client.propose_connections({"techniques": []}, picked, [])


def test_reduce_accepts_a_paraphrase_that_cites_the_must_review_ref():
    """**어휘 전사를 요구하지 않는다.**

    시그널 어휘(`key=clear`)가 문장에 문자 그대로 있는지까지 보면, 뜻을 옳게
    옮긴 문장이 단어가 다르다는 이유로 기각된다. 그것은 의미 검사가 아니라
    받아쓰기 강요다. 여기서 보장할 것은 그 증거가 서사에서 다뤄졌는가까지고,
    잘 다뤘는지는 Critic 이 판정한다.
    """
    picked = [{
        **_pick("SYSMON#1"),
        "attention_signals": ["credential_export_option_observed"],
        "attention_requirements": {
            "credential_export_option_observed": {"all": ["netsh", "wlan", "key=clear"]}
        },
    }, _pick("MFT#1")]
    response = json.dumps({
        "connections": [],
        "incident_story": {
            "summary": "요약", "critical_threat": "위협",
            "sentences": [{
                "id": "N1",
                "text": "무선 프로파일을 평문으로 내보내는 명령이 실행됐다",
                "kind": "observed_fact", "refs": ["SYSMON#1"],
            }],
        },
    }, ensure_ascii=False)
    client = InterpretClient(FakeBackend(response))

    client.propose_connections({"techniques": []}, picked, [])

    assert client.last_incident_story["sentences"][0]["refs"] == ["SYSMON#1"]


def test_reduce_completes_catalogued_relation_endpoints_without_inference():
    picked = [_pick("SYSMON#1"), _pick("MFT#1"), _pick("SYSMON#2")]
    response = json.dumps({
        "connections": [{
            "refs": ["SYSMON#1", "MFT#1"], "technique": None,
            "reason": "관계", "severity": "high", "assertion_ids": ["R1"],
        }],
        "incident_story": {
            "summary": "요약", "critical_threat": "위협",
            "sentences": [{
                "id": "N1", "text": "관계", "kind": "analytical_assessment",
                "refs": ["SYSMON#1", "MFT#1"],
            }],
        },
    }, ensure_ascii=False)
    relation = [{
        "id": "R1", "predicate": "spawned",
        "subject": {"ref": "SYSMON#1", "field": "incident_packet.process.child_refs"},
        "object": "SYSMON#2", "refs": ["SYSMON#1", "SYSMON#2"],
    }]
    client = InterpretClient(FakeBackend(response))

    connections = client.propose_connections({"techniques": []}, picked, relation)
    assert connections[0]["refs"] == ["SYSMON#1", "MFT#1", "SYSMON#2"]


def test_python_never_ghostwrites_a_missing_review_sentence():
    """서사를 만드는 것은 sLLM 의 일이다.

    못 채우면 기각하고 재시도한다. 파이썬이 대신 문장을 써 넣으면 그것이
    Critic 심사와 story_review 를 거쳐 **모델이 판단한 것처럼 보인다.**
    """
    picked = [
        {
            **_pick("SYSMON#1"),
            "attention_signals": ["credential_export_option_observed"],
            "attention_context": {
                "credential_export_option_observed": ["netsh wlan export profile key=clear"]
            },
        },
        _pick("MFT#1"),
    ]
    response = json.dumps({
        "connections": [],
        "incident_story": {
            "summary": "요약", "critical_threat": "위협",
            "sentences": [{
                "id": "N1", "text": "다른 사실", "kind": "observed_fact", "refs": ["MFT#1"],
            }],
        },
    }, ensure_ascii=False)
    client = InterpretClient(FakeBackend(response))

    with pytest.raises(MalformedOutput, match="SYSMON#1"):
        client.propose_connections({"techniques": []}, picked, [])

    assert client.last_incident_story is None


def test_one_pick_needs_no_reduce_query(monkeypatch, tmp_path):
    """묶을 것이 둘 미만이면 물어볼 것이 없다."""
    backend = FakeBackend(_selection(_pick("MFT#12345")))

    assert _run_assembled(monkeypatch, tmp_path, backend) == 0

    assert len(backend.calls) == 1  # 종합 질의를 안 보냈다


@pytest.mark.parametrize(
    "mode, expected",
    [
        ("model", interpret_mod.DEFAULT_NUM_CTX),
        ("assemble", interpret_mod.ASSEMBLE_NUM_CTX),
    ],
)
def test_the_window_follows_the_query_kind(monkeypatch, tmp_path, mode, expected):
    """단일 질의는 창이 곧 커버리지라 넓어야 하고, 분할 질의는 여러 번
    보내므로 좁혀도 커버리지를 잃지 않는다.

    한 값으로 두면 한쪽이 반드시 손해다 — 넓으면 GPU 에서 흘러넘치고,
    좁으면 단일 질의가 54건에서 열 건 남짓이 된다.
    """
    captured: dict = {}

    def fake_build_backend(kind, **kwargs):
        captured.update(kwargs)
        body = (
            _selection(_pick("MFT#12345"))
            if mode == "assemble"
            else (FIXTURES / "05_findings.json").read_text(encoding="utf-8")
        )
        return FakeBackend(body)

    monkeypatch.setattr(interpret_mod.llm, "build_backend", fake_build_backend)
    interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(tmp_path / "05_findings.json"),
            "--llm", "ollama", "--model", "m",
            "--mode", mode,
        ]
    )

    assert captured["num_ctx"] == expected


def test_an_explicit_window_wins_over_the_mode_default(monkeypatch, tmp_path):
    captured: dict = {}

    def fake_build_backend(kind, **kwargs):
        captured.update(kwargs)
        return FakeBackend(_selection(_pick("MFT#12345")))

    monkeypatch.setattr(interpret_mod.llm, "build_backend", fake_build_backend)
    interpret_mod.main(
        [
            "--in", str(PARSED),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(tmp_path / "05_findings.json"),
            "--llm", "ollama", "--model", "m",
            "--mode", "assemble",
            "--num-ctx", "16384",
        ]
    )

    assert captured["num_ctx"] == 16384



# ============================================ 프롬프트 예시가 새지 않는가


def test_prompt_examples_are_templates_not_sentences():
    """`좋음:` 예시는 **빈칸이 있는 형태**여야 한다.

    완성된 서술문을 예시로 두면 모델이 그대로 옮겨 적는다. 실측:
    `reduce_system.txt` 의 "임시 폴더에 떨어진 실행 파일이 3분 뒤 실행되고
    외부로 접속했다" 가 K-LIVE-0902-wide(USB 시나리오)의 소견 F4 에 거의
    글자 그대로 실렸다 — 06단계는 claims 만 대조하므로 잡지 못한다.
    """
    from src.stage05_interpret.llm_client import PROMPT_DIR

    for prompt in sorted(PROMPT_DIR.glob("*.txt")):
        for number, line in enumerate(prompt.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith("- 좋음:"):
                continue
            assert "<" in stripped and ">" in stripped, (
                f"{prompt.name}:{number} 의 좋음 예시에 빈칸(<...>)이 없다 — "
                f"완성된 문장은 소견으로 새어 나간다: {stripped}"
            )
