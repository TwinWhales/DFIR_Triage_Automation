"""02단계가 입력 서술을 얼마나 옮겼는지 세는 검사.

**이 검사의 가장 중요한 성질은 "조용한 것"이다.** 사람이 제대로 쓴
시나리오에서 경고가 나오면 아무도 읽지 않게 되고, 그러면 정작 축이
빠졌을 때도 묻힌다. 그래서 골든 픽스처가 0건인지를 먼저 본다.
"""

from __future__ import annotations

import json

from src.common import io
from src.stage02_normalize import coverage
from casepaths import FIXTURES


def _fixture_raw() -> str:
    return io.read_json(FIXTURES / "01_input.json")["raw"]


# ============================================ 사람이 쓴 것에는 조용해야 한다


def test_the_hand_written_fixture_raises_nothing():
    # 늑대를 외치면 검사가 죽는다. `benchmark/fixtures/` 는 사람이 쓴 것이라
    # (`tests/casepaths.py`) 여기서 걸리는 것은 검사가 과한 것이다.
    scenario = io.read_json(FIXTURES / "02_scenario.json")
    raw = _fixture_raw()
    assert coverage.nonverbatim_quotes(scenario, raw) == []
    assert coverage.uncovered_spans(scenario, raw) == []


def test_a_host_name_is_covered_by_entities():
    # 호스트 이름은 techniques 가 아니라 entities 가 받는 몫이다. 기법만
    # 보면 `웹서버 WEB01에서` 가 "안 옮긴 서술"이 된다.
    raw = "웹서버 WEB01에서 이상한 파일이 발견됐습니다"
    scenario = {
        "techniques": [{"id": "T1505.003", "evidence_text": "이상한 파일이 발견됐습니다"}],
        "entities": {"hosts": ["WEB01"]},
    }
    assert coverage.uncovered_spans(scenario, raw) == []


def test_a_date_is_covered_by_the_time_range_basis():
    raw = "이상한 파일이 발견됐습니다. 7월 20일 전후로 보입니다"
    scenario = {
        "techniques": [{"id": "T1505.003", "evidence_text": "이상한 파일이 발견됐습니다"}],
        "time_range": {"basis": "사용자가 7월 20일 전후로 언급, ±2일 확장"},
    }
    assert coverage.uncovered_spans(scenario, raw) == []


# ================================================ 통째로 빠진 축은 잡아야 한다


def test_a_dropped_clause_is_reported():
    # 2026-09-04 `K-LIVE-0902-wide` 1차 실행의 실제 실패다. 모델이 인용을
    # 다듬으며 `계정 관련 변경` 을 지웠고, 계정 기법이 하나도 나오지 않아
    # evtx:Security 가 선별되지 않았다.
    raw = "재부팅 뒤에도 남는 자동 실행 등록과 계정 관련 변경이 있었는지도 확인해야 합니다."
    scenario = {
        "techniques": [
            {"id": "T1547.001", "evidence_text": "재부팅 뒤에도 남는 자동 실행 등록이 있었는지도 확인해야 합니다"}
        ],
        "unmapped_text": [],
    }
    spans = coverage.uncovered_spans(scenario, raw)
    assert spans, "통째로 빠진 절을 놓쳤다"
    assert any("계정" in span for span in spans)


def test_a_paraphrased_quote_is_reported():
    raw = "실행 파일이 실행됐고, 이후 명령 셸이 사용된 정황이 있습니다"
    scenario = {"techniques": [{"id": "T1059", "evidence_text": "실행 파일이 실행됐습니다"}]}
    reported = coverage.nonverbatim_quotes(scenario, raw)
    assert [r["technique"] for r in reported] == ["T1059"]


def test_a_verbatim_quote_is_not_reported():
    raw = "실행 파일이 실행됐고, 이후 명령 셸이 사용된 정황이 있습니다"
    scenario = {"techniques": [{"id": "T1059", "evidence_text": "실행 파일이 실행됐고"}]}
    assert coverage.nonverbatim_quotes(scenario, raw) == []


# ================================================================ 알려진 한계


def test_a_clause_mapped_to_the_wrong_technique_is_not_caught():
    """**못 잡는 것을 못 잡는다고 굳혀 둔다.**

    절이 인용되기만 하면 덮인 것으로 보이므로, 엉뚱한 기법에 붙은 것은
    이 검사로 드러나지 않는다. 실측(`K-LIVE-0902-wide` 3차)에서
    `계정 관련 변경이` 가 `T1543.003`(Windows Service)에 붙었다.

    이 테스트가 깨진다면 검사가 세졌다는 뜻이므로, 그때는 오탐이 늘지
    않았는지 위의 골든 픽스처 테스트와 함께 본다.
    """
    raw = "자동 실행 등록과 계정 관련 변경이 있었는지도 확인해야 합니다."
    scenario = {
        "techniques": [
            {"id": "T1547.001", "evidence_text": "자동 실행 등록과"},
            {"id": "T1543.003", "evidence_text": "계정 관련 변경이 있었는지도 확인해야 합니다"},
        ]
    }
    assert coverage.uncovered_spans(scenario, raw) == []


# ============================================================ 어휘가 등록됐는가


def test_the_error_types_are_registered():
    # 미등록 유형은 쓰는 시점에 ValueError 다. 어휘를 되돌리면 02단계가
    # 통째로 죽으므로, 이 둘이 사라지지 않게 붙들어 둔다.
    from src.common import errors as errlog

    assert {"uncovered_input", "nonverbatim_evidence"} <= errlog.ERROR_TYPES
    assert "record" in errlog.ACTIONS
