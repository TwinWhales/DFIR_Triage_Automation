"""02단계가 근거 없이 고른 세부 기법을 떨구고, 흘린 파일명을 되돌려 놓는가.

`test_coverage.py` 와 같은 성질을 먼저 요구한다 — **사람이 제대로 쓴 것에는
조용해야 한다.** 늑대를 외치면 아무도 안 읽고, 그러면 정작 02가 엉뚱한
기법을 골랐을 때도 묻힌다.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.common import io
from src.stage02_normalize import grounding
from casepaths import FIXTURES

PROMPTS = Path(__file__).resolve().parents[1] / "src" / "stage02_normalize" / "prompts"

#: 2026-09-07 `518_Test_0907` 의 입력 서술. 이 파일의 거의 모든 판정이
#: 여기서 나왔다.
RAW_518 = (
    "2026년 9월 7일 오전 11시경 실행 파일 518.exe가 실행된 정황이 있습니다. "
    "실행 주체와 실행 방법은 아직 확인되지 않았습니다. 해당 파일의 실행 흔적과 "
    "프로세스 생성 기록, 파일 시스템 변경 기록을 조사해야 합니다."
)


def _scenario(*technique_ids: str, processes: "list[str] | None" = None) -> dict:
    return {
        "techniques": [
            {"id": tid, "name": tid, "confidence": 0.7, "evidence_text": ""}
            for tid in technique_ids
        ],
        "entities": {
            "hosts": [], "paths": [], "processes": list(processes or []),
            "accounts": [], "ips": [],
        },
    }


# ============================================ 사람이 쓴 것에는 조용해야 한다


def test_the_hand_written_fixture_raises_nothing():
    scenario = io.read_json(FIXTURES / "02_scenario.json")
    raw = io.read_json(FIXTURES / "01_input.json")["raw"]
    assert grounding.ungrounded_techniques(scenario, raw) == []


def test_the_few_shot_examples_obey_their_own_rules():
    # 예시가 규칙을 어기면 모델은 규칙이 아니라 예시를 배운다. 실측이
    # 그랬다 — 앞의 둘만 있을 때 모델이 "unmapped_text 는 늘 빈 배열"로
    # 배웠다(normalize_fewshot.json 의 note).
    examples = json.loads((PROMPTS / "normalize_fewshot.json").read_text(encoding="utf-8"))
    for example in examples["examples"]:
        assert grounding.ungrounded_techniques(example["output"], example["input"]) == []


def test_a_technique_outside_the_cue_table_is_never_touched():
    # 이 검사는 분류기가 아니다. MECHANISM_CUES 에 없는 기법은 근거를
    # 따지지 않는다 — 목록을 안 넓히면 조용하다.
    assert "T1204.002" not in grounding.MECHANISM_CUES
    assert grounding.ungrounded_techniques(_scenario("T1204.002"), RAW_518) == []


def test_the_tool_being_named_is_enough():
    raw = "단말에서 cmd.exe 가 떴습니다"
    assert grounding.ungrounded_techniques(_scenario("T1059.003"), raw) == []


def test_a_korean_cue_counts_too():
    raw = "키오스크에서 명령 프롬프트가 열린 흔적이 있습니다"
    assert grounding.ungrounded_techniques(_scenario("T1059.003"), raw) == []


# ================================================ 근거 없는 세부 기법은 잡는다


def test_the_518_run_would_have_been_caught():
    # 실제 실패다. 입력이 "실행 방법은 아직 확인되지 않았습니다" 라고
    # 명시했는데 모델이 T1059.003 을 골랐고, 그 매핑이 prefetch 를 Tier 2
    # 로 두는 바람에 518.EXE-71CD1C31.pf 가 영구 미수집이 됐다.
    found = grounding.ungrounded_techniques(_scenario("T1059.003", "T1204.002"), RAW_518)
    assert [entry["technique"] for entry in found] == ["T1059.003"]


def test_the_report_says_what_would_have_counted_as_evidence():
    # 무엇이 있었어야 하는지를 함께 내야 매핑·프롬프트 중 어느 쪽을
    # 고칠지 판단할 수 있다.
    (entry,) = grounding.ungrounded_techniques(_scenario("T1059.001"), RAW_518)
    assert "powershell" in entry["expected_any_of"]


def test_a_quote_that_the_model_trimmed_does_not_rescue_the_technique():
    # evidence_text 만 보면 안 되는 이유. 모델은 인용을 다듬으므로
    # (coverage.nonverbatim_quotes 의 실측) 원문 전체를 본다.
    scenario = _scenario("T1218.011")
    scenario["techniques"][0]["evidence_text"] = "rundll32 로 실행됐습니다"
    assert len(grounding.ungrounded_techniques(scenario, RAW_518)) == 1


# ==================================================== 파일명은 되돌려 놓는다


def test_the_named_executable_is_restored():
    scenario = _scenario("T1204.002")
    assert grounding.restore_named_processes(scenario, RAW_518) == ["518.exe"]
    assert scenario["entities"]["processes"] == ["518.exe"]


def test_what_the_model_already_had_keeps_its_place():
    # processes[0] 은 scope_resolver 가 {process} 로 쓴다. 모델이 골라 둔
    # 순서를 우리가 뒤집지 않는다.
    scenario = _scenario("T1204.002", processes=["explorer.exe"])
    assert grounding.restore_named_processes(scenario, RAW_518) == ["518.exe"]
    assert scenario["entities"]["processes"] == ["explorer.exe", "518.exe"]


def test_a_name_the_model_already_wrote_is_not_doubled():
    scenario = _scenario("T1204.002", processes=["518.EXE"])
    assert grounding.restore_named_processes(scenario, RAW_518) == []


def test_only_things_that_execute_are_restored():
    raw = "보고서 report.docx 와 로그 setup.log 를 첨부합니다. install.exe 도 있습니다"
    assert grounding.named_processes(raw) == ["install.exe"]


def test_a_path_yields_the_file_name_not_the_path():
    # 경로는 entities.paths 의 몫이고, 그쪽 첫 항목은 매핑의 web_root 를
    # 덮는다(scope_resolver.ENTITY_VARIABLES). 여기서 건드리지 않는다.
    raw = "C:\\Users\\Public\\Documents\\518.exe 가 실행됐습니다"
    assert grounding.named_processes(raw) == ["518.exe"]


def test_the_restored_name_survives_the_ungrounded_entity_check():
    # 우리가 넣은 값도 같은 관문을 지나야 한다. 원문에서 잘라 온 것이라
    # 통과하는 것이 당연하지만, 그 당연함이 깨지면 03단계가 받는 entities
    # 가 조용히 비어 버린다.
    from src.stage02_normalize import coverage

    scenario = _scenario("T1204.002")
    grounding.restore_named_processes(scenario, RAW_518)
    assert coverage.ungrounded_entities(scenario, RAW_518) == {}


def test_restore_transit_techniques_detects_lateral_movement_cues():
    raw = "2026년 9월 10일, 키오스크에 USB가 꽂힌 뒤 포스기를 지나 관리서버까지 공격이 진행되었습니다."
    scenario = _scenario("T1091")
    restored = grounding.restore_transit_techniques(scenario, raw)
    assert restored == ["T1210"]
    tech_ids = [t["id"] for t in scenario["techniques"]]
    assert "T1210" in tech_ids
    assert "T1091" in tech_ids


def test_restore_transit_techniques_does_not_duplicate_if_already_present():
    raw = "포스기를 지나 관리서버까지 공격이 진행되었습니다."
    scenario = _scenario("T1210")
    assert grounding.restore_transit_techniques(scenario, raw) == []

