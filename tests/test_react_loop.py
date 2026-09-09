"""05→02 루프백 오케스트레이터 (`tools/react_loop.py`).

여기서 지키는 것은 **케이스 디렉터리가 어떤 상태로 끝나는가**다. 06·07은
루프가 돌았는지 모르고 정규 이름을 읽으므로, 그 이름이 무엇을 가리키는지가
곧 최종 보고서의 내용이다.

- 2차가 돌면 정규 이름은 **2차**, 1차는 ``.round1``
- 돌 이유가 없으면 정규 이름은 **1차 그대로**이고 ``.round1``은 남지 않는다
  (남으면 "2차가 돌았다"로 읽힌다)

가드레일 G1(2차에 재요청 없음)도 여기서 본다 — 카운터가 아니라 구조로 걸어
두었으므로, 구조가 그대로인지는 실행해 봐야 안다.

설계는 ``docs/proposals/stage05-investigation-loopback.md``.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from src.common import io
from casepaths import FIXTURES, GOLDEN

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import react_loop  # noqa: E402

REPLAY = FIXTURES / "05_selection.json"


def _requests(*items):
    return io.new_document(
        "C-001",
        "05_investigate",
        "interpret.py / stub(05_selection.json)",
        round=1,
        requests=list(items),
    )


@pytest.fixture
def case(tmp_path):
    """1차가 끝난 케이스. 04_parsed 는 픽스처 그대로다."""
    case_dir = tmp_path / "C-001"
    case_dir.mkdir()
    shutil.copy(FIXTURES / "01_input.json", case_dir / "01_input.json")
    shutil.copy(FIXTURES / "02_scenario.json", case_dir / "02_scenario.json")
    shutil.copy(FIXTURES / "05_findings.json", case_dir / "05_findings.json")
    shutil.copy(GOLDEN / "03_selection.json", case_dir / "03_selection.json")
    shutil.copytree(FIXTURES / "04_parsed", case_dir / "04_parsed")
    (tmp_path / "evidence").mkdir()
    return case_dir


def run(case: Path, *extra: str) -> int:
    return react_loop.main(
        [
            "--case", str(case),
            "--evidence", str(case.parent / "evidence"),
            "--replay", str(REPLAY),
            "--python", sys.executable,
            "--quiet",
            *extra,
        ]
    )


def technique_request(technique_id="T1041"):
    return {
        "type": "request_technique",
        "based_on_ref": "EVTX-SEC#40912",
        "rationale": "유출 여부를 봐야 한다",
        "technique_id": technique_id,
    }


# ==================================================== 돌았을 때


def test_the_second_round_takes_the_canonical_names(case):
    """06·07은 루프가 돌았는지 모른다. 정규 이름이 최종을 가리켜야 한다."""
    io.write_json(case / "05_requests.json", _requests(technique_request()))
    before = (case / "02_scenario.json").read_text(encoding="utf-8")

    assert run(case) == 0

    # 1차는 .round1 에 온전히 남는다.
    assert (case / "02_scenario.round1.json").read_text(encoding="utf-8") == before
    for name in react_loop.PRESERVED:
        assert (case / react_loop.round1_name(name)).is_file()

    # 정규 이름은 2차다 — 요청한 기법이 들어가 있어야 한다.
    second = io.read_json(case / "02_scenario.json")
    assert "T1041" in {t["id"] for t in second["techniques"]}
    assert "expand.py" in second["generator"]


def test_the_second_round_never_asks_again(case):
    """가드레일 G1 — 카운터가 아니라 구조로 건다.

    2차 05에 ``--investigate`` 를 주지 않으므로 3차 요청이 생길 자리가 없다.
    요청 파일이 1차의 것 그대로여야 한다(``round`` 가 1).
    """
    io.write_json(case / "05_requests.json", _requests(technique_request()))
    assert run(case) == 0

    document = io.read_json(case / "05_requests.json")
    assert document["round"] == 1
    # 2차 질의 내역에 조사 요청 질의가 없어야 한다.
    round2 = sorted(p.name for p in (case / "05_llm_queries_round2").glob("*.txt"))
    assert round2 and not any("investigation" in name for name in round2)


def test_the_accepted_artifacts_reach_the_second_selection(case):
    """아티팩트는 시나리오에 담을 자리가 없다(동결 스키마).

    확장이 ``applied.artifacts`` 에 남기고 오케스트레이터가 03단계에
    ``--force-artifacts`` 로 넘긴다. 그 배선이 끊기면 요청은 수용됐는데
    아무것도 안 열린다.
    """
    io.write_json(
        case / "05_requests.json",
        _requests(
            {
                "type": "request_artifact",
                "based_on_ref": "MFT#12345",
                "rationale": "실행 흔적을 교차 확인",
                "artifact": "prefetch",
            }
        ),
    )
    assert run(case) == 0

    selected = io.read_json(case / "03_selection.json")["selected"]
    prefetch = [entry for entry in selected if entry["artifact"] == "prefetch"]
    assert prefetch and prefetch[0]["tier"] == 1
    assert "--force-artifacts" in prefetch[0]["reason"]["rationale"]


def test_the_first_round_citations_are_pinned(case, capsys):
    """2차는 레코드가 늘어난 상태에서 같은 예산으로 다시 배분한다.

    1차가 인용한 레코드가 자리를 잃으면 최종 보고서가 1차보다 얇아진다.
    """
    io.write_json(case / "05_requests.json", _requests(technique_request()))
    assert run(case) == 0

    first = set(io.read_json(case / "05_findings.round1.json")["input_refs"])
    second = set(io.read_json(case / "05_findings.json")["input_refs"])
    cited = {
        ref
        for finding in io.read_json(case / "05_findings.round1.json")["findings"]
        for ref in finding["refs"]
    }
    assert cited <= second, "1차가 인용한 레코드가 2차 전달 목록에 없다"
    assert first <= second


# ==================================================== 돌지 않을 때


def test_without_a_request_file_nothing_happens(case):
    """05를 ``--investigate`` 없이 돌렸거나 질의가 실패한 경우다."""
    assert run(case) == react_loop.EXIT_NOTHING_TO_DO
    assert not (case / "05_findings.round1.json").exists()


def test_a_fully_rejected_request_leaves_no_round1_files(case):
    """가드레일 G3.

    ``.round1`` 이 남아 있으면 사람도 도구도 "2차가 돌았다"로 읽는다.
    돌지 않았으면 흔적도 없어야 한다.
    """
    io.write_json(case / "05_requests.json", _requests(technique_request("T9999")))
    before = (case / "02_scenario.json").read_text(encoding="utf-8")

    assert run(case) == react_loop.EXIT_NOTHING_TO_DO

    for name in react_loop.PRESERVED:
        assert not (case / react_loop.round1_name(name)).exists()
    assert (case / "02_scenario.json").read_text(encoding="utf-8") == before


def test_an_unchanged_selection_puts_the_first_round_back(case, monkeypatch):
    """가드레일 G4 — 시나리오는 넓어졌는데 볼 것이 그대로인 경우.

    04·05를 돌려 봐야 같은 결과가 나오므로 멈추고 1차를 정규 이름으로
    되돌린다. **되돌리지 않으면 정규 이름이 2차 시나리오를 가리킨 채로
    끝나고**, 07 보고서가 있지도 않은 2차 근거로 기법을 싣는다.
    """
    io.write_json(case / "05_requests.json", _requests(technique_request()))
    before = (case / "02_scenario.json").read_text(encoding="utf-8")
    monkeypatch.setattr(react_loop, "selection_changed", lambda first, second: False)

    assert run(case) == react_loop.EXIT_NOTHING_TO_DO

    assert (case / "02_scenario.json").read_text(encoding="utf-8") == before
    for name in react_loop.PRESERVED:
        assert not (case / react_loop.round1_name(name)).exists()


def test_selection_changed_ignores_the_order_of_values(tmp_path):
    """04단계의 재사용 판정과 **같은 기준**이어야 한다.

    여기서 "달라졌다"고 본 것이 저기서 다시 읽히지 않으면, 2차가 넓힌
    범위를 반영하지 않은 산출물로 돈다.
    """
    def selection(scope):
        document = io.new_document(
            "C-001", "03_select", "select.py",
            mapping_table_version="1.0",
            selected=[{
                "artifact": "$MFT", "tier": 1, "priority": 1, "scope": scope,
                "reason": {"technique": "T1505.003", "rationale": "테스트"},
            }],
            deferred=[], excluded=[],
            stats={"selected_count": 1, "deferred_count": 0, "excluded_count": 0},
        )
        path = tmp_path / f"{abs(hash(str(scope)))}.json"
        io.write_json(path, document)
        return path

    same_a = selection({"extensions": [".aspx", ".asp"]})
    same_b = selection({"extensions": [".asp", ".aspx"]})
    wider = selection({"extensions": [".asp", ".aspx", ".php"]})

    assert not react_loop.selection_changed(same_a, same_b)
    assert react_loop.selection_changed(same_a, wider)


# ==================================================== CLI 계약


def test_a_real_run_needs_a_model(case, capsys):
    """단계에 기본 모델이 있지만 여기서는 받지 않는다.

    산출물의 ``generator`` 가 실행한 사람의 기계 사정에 좌우되면 모델별
    비교가 성립하지 않는다 (``run_pipeline.sh`` 의 MODEL 과 같은 규약).
    """
    with pytest.raises(SystemExit):
        react_loop.main(["--case", str(case), "--evidence", str(case.parent / "evidence")])
    assert "--model 이 필요하다" in capsys.readouterr().err


# ==================================================== 관문 (tools/live_check.py)
#
# live_check 는 실물 증거와 실제 모델로만 도는 도구라 여기서 돌릴 수 없습니다.
# 그래도 **배선**은 볼 수 있고, 이 둘은 틀리면 5분짜리 실물 실행 중간에야
# 드러나는 종류입니다.


def test_every_live_check_step_has_a_handler():
    """단계 하나가 ``getattr(self, f"do_{key}")`` 로 불린다.

    키 오타는 import 에서도 문법 검사에서도 안 걸리고, 그 단계 차례가 와야
    AttributeError 로 터진다.
    """
    import live_check

    keys = [plan.key for plan in live_check.PLAN] + [live_check.LOOPBACK_PLAN.key]
    missing = [key for key in keys if not hasattr(live_check.Runner, f"do_{key}")]
    assert missing == []


def test_the_loopback_gate_sits_between_05_and_06(tmp_path):
    """자리가 곧 계약이다.

    06·07은 정규 이름을 읽으므로, 루프백이 그 앞에서 끝나 있어야 06이
    2차 결과를 검증한다. 뒤에 두면 06이 1차를 검증하고 07이 2차를 싣는다.
    """
    from types import SimpleNamespace

    import live_check

    runner = live_check.Runner(
        SimpleNamespace(cases_dir=str(tmp_path), case_id="C-001", loop=True)
    )
    keys = [plan.key for plan in runner.plan]
    assert keys.index("loopback") == keys.index("stage05") + 1
    assert keys.index("loopback") == keys.index("stage06") - 1


def test_without_the_flag_the_gate_is_not_in_the_table(tmp_path):
    """"이 표가 곧 화면 출력이다. 여기 없는 판정은 하지 않는다"(live_check)."""
    from types import SimpleNamespace

    import live_check

    runner = live_check.Runner(
        SimpleNamespace(cases_dir=str(tmp_path), case_id="C-001", loop=False)
    )
    assert "loopback" not in [plan.key for plan in runner.plan]
