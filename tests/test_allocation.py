"""05단계 레코드 배분 테스트.

배분이 없던 시절의 실패는 조용했습니다. 신호를 전부 모아 앞에서 60개를
잘랐고, 자르는 기준이 파일명 알파벳순이었습니다. 시끄러운 아티팩트가 자리를
쓸어가고 조용한 아티팩트는 한 건도 못 갔는데, 모델이 없는 것을 지어낸 게
아니라 **있는 것을 못 받은 것**이라 06단계가 잡지 못했습니다. 결과는
"sLLM이 탐지에 실패했다"로 집계됩니다(``docs/limitations.md`` 4-2).

그래서 여기서 보는 것은 셋입니다.

1. **선별이 보라고 한 아티팩트가 사라지지 않는가** — 바닥 한 자리.
   레지스트리가 정확히 그 경우였습니다(6-7). 플래그가 0건이라 1,754건이
   통째로 탈락했습니다.
2. **시나리오가 자릿수에 반영되는가** — 매핑 ``priority``. 파이프라인에서
   이 자르기만 시나리오와 무관했던 것이 원래 문제였습니다.
3. **같은 입력에 같은 배분이 나오는가** — 재현율이 모델 성능의 지표가
   되려면 배분이 흔들리면 안 됩니다.

개별 레코드가 신호인지는 ``test_interpret.py``가 봅니다.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.stage03_select.mapping_loader import DEFAULT_PRIORITY
from src.stage04_parse import flagging
from src.stage05_interpret import allocation, record_filter

INCIDENT = datetime(2026, 8, 20, 9, 17, 3, tzinfo=timezone.utc)

SCOPE_SOURCES = {"registry:SYSTEM": "scope"}


def _at(seconds: float = 0, days: float = 0) -> str:
    moment = INCIDENT + timedelta(seconds=seconds, days=days)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _evtx(num, seconds=0, flags=("account_created",)):
    return {
        "ref": f"EVTX-SEC#{num}",
        "artifact": "evtx:Security",
        "event_id": 4720,
        "flags": list(flags),
        "timestamp": _at(seconds=seconds),
    }


def _usn(num, seconds=0, flags=("deleted",)):
    return {
        "ref": f"USN#{num}",
        "artifact": "$UsnJrnl",
        "name": f"f{num}.exe",
        "flags": list(flags),
        "timestamp": _at(seconds=seconds),
    }


def _reg(num, days=-400, seconds=0):
    """레지스트리 키. **플래그가 없다** — 04단계가 붙일 룰이 없다.

    기본값을 사건에서 400일 떨어뜨린 것은 실물을 닮게 하기 위해서다.
    ``Services`` 하위 키의 LastWrite는 대개 OS 설치 시각이라 사건
    시간창에 걸리지 않는다.
    """
    return {
        "ref": f"REG-SYS#{num}",
        "artifact": "registry:SYSTEM",
        "path": rf"SYSTEM\ControlSet001\Services\svc{num}",
        "name": f"svc{num}",
        "flags": [],
        "timestamp": _at(seconds=seconds, days=days),
    }


# ============================================================ 자릿수 배분


def test_every_artifact_with_candidates_gets_at_least_one_seat():
    # 바닥 한 자리. 03단계가 보라고 한 아티팩트가 보고서에서 통째로
    # 사라지지 않는다는 보장이며, 이 배분의 존재 이유다.
    seats = allocation.allocate_seats({"a": 500, "b": 1, "c": 3}, {}, limit=10)
    assert all(seats[name] >= 1 for name in "abc")


def test_an_artifact_with_no_candidates_gets_no_seat():
    seats = allocation.allocate_seats({"a": 5, "b": 0}, {}, limit=10)
    assert seats["b"] == 0


def test_a_stronger_priority_gets_more_seats():
    seats = allocation.allocate_seats(
        {"strong": 100, "weak": 100}, {"strong": 1, "weak": 3}, limit=60
    )
    # 가중치 4 대 1.
    assert seats["strong"] > seats["weak"]
    assert seats["strong"] + seats["weak"] == 60


def test_a_weak_artifact_is_never_starved():
    # 자리를 적게 받는 것과 한 건도 못 받는 것은 보고서에서 전혀 다른
    # 결과다. 배수를 크게 잡지 않은 이유가 이것이다.
    seats = allocation.allocate_seats(
        {"strong": 100, "weak": 100}, {"strong": 1, "weak": 3}, limit=60
    )
    assert seats["weak"] > 0


def test_candidates_cap_the_seats_and_the_surplus_goes_elsewhere():
    # 가진 것보다 많이 받지 않는다. 남는 자리가 증발하면 모델이 받을 수
    # 있었던 증거가 그냥 사라진다.
    seats = allocation.allocate_seats({"small": 2, "big": 500}, {}, limit=60)
    assert seats["small"] == 2
    assert seats["big"] == 58


def test_a_noisy_artifact_cannot_sweep_the_seats():
    """4-2가 지적한 바로 그 상황 — ``$UsnJrnl`` 30만 건이 ``$MFT``를 밀어낸다."""
    seats = allocation.allocate_seats({"$UsnJrnl": 300_000, "$MFT": 150}, {}, limit=60)
    assert seats["$MFT"] == 30
    assert seats["$UsnJrnl"] == 30


def test_when_seats_run_out_the_strong_get_the_floor():
    seats = allocation.allocate_seats(
        {"a": 5, "b": 5, "c": 5}, {"a": 3, "b": 1, "c": 2}, limit=2
    )
    assert seats == {"a": 0, "b": 1, "c": 1}


def test_the_allocation_does_not_depend_on_insertion_order():
    # 같은 입력에 같은 배분이 나와야 재현율이 모델 성능의 지표가 된다.
    forward = allocation.allocate_seats({"a": 50, "b": 50, "c": 50}, {"b": 1}, limit=37)
    backward = allocation.allocate_seats({"c": 50, "b": 50, "a": 50}, {"b": 1}, limit=37)
    assert forward == backward


def test_seats_never_exceed_the_limit():
    seats = allocation.allocate_seats({"a": 1000, "b": 1000}, {"a": 1}, limit=7)
    assert sum(seats.values()) == 7


# ==================================== 선별이 골라 온 것은 플래그 없이도 간다


def test_a_scope_artifact_reaches_the_model_without_any_flag():
    """6-7 회귀 — 레지스트리 1,754건(플래그 0건)이 통째로 탈락하던 문제.

    선별이 ``path_prefix``로 이미 골라 온 것을 05단계가 다시 플래그로
    거르면, 정확히 골라 온 것이 한 건도 모델에 가지 않는다.
    """
    records = [_reg(i) for i in range(1754)] + [_evtx(1)]

    chosen, quotas, _budget = allocation.allocate_records(
        records, signal_sources=SCOPE_SOURCES, limit=60
    )

    registry = [r for r in chosen if r["artifact"] == "registry:SYSTEM"]
    assert registry, "선별이 골라 온 레지스트리 키가 한 건도 전달되지 않았다"
    by_artifact = {q.artifact: q for q in quotas}
    assert by_artifact["registry:SYSTEM"].parsed == 1754
    assert by_artifact["registry:SYSTEM"].candidates == 1754


def test_a_flags_artifact_still_drops_records_with_nothing_to_say():
    # scope 아티팩트의 예외가 다른 아티팩트로 새면 안 된다. 플래그도 없고
    # 시간창에도 안 걸린 $UsnJrnl 레코드는 볼 이유가 없다.
    quiet = _usn(1, seconds=0, flags=())
    chosen, _quotas, _budget = allocation.allocate_records([quiet], signal_sources=SCOPE_SOURCES, limit=60)
    assert chosen == []


def test_within_a_scope_artifact_the_keys_nearest_the_incident_come_first():
    # 쿼터가 후보보다 작을 때 무엇을 넣을지 가르는 것이 이 순서다.
    near = [_reg(i, days=0, seconds=i) for i in range(3)]
    far = [_reg(100 + i, days=-400) for i in range(50)]

    chosen, _quotas, _budget = allocation.allocate_records(
        [*far, *near, _evtx(1)], signal_sources=SCOPE_SOURCES, limit=6
    )

    refs = {r["ref"] for r in chosen}
    assert {"REG-SYS#0", "REG-SYS#1", "REG-SYS#2"} <= refs


def test_an_anchor_from_one_artifact_pulls_in_another():
    """앵커는 아티팩트를 가리지 않는다.

    evtx의 로그온 시각이 레지스트리 키를 끌어온다. 증거가 여러 계층에
    흩어지는 사건에서 이 교차가 상관분석의 실질이다.
    """
    logon = _evtx(1, seconds=0)
    same_minute = _reg(1, days=0, seconds=20)
    much_later = _reg(2, days=0, seconds=99_999)

    chosen, _quotas, _budget = allocation.allocate_records(
        [logon, same_minute, much_later], signal_sources=SCOPE_SOURCES, limit=2
    )

    assert [r["ref"] for r in chosen] == ["EVTX-SEC#1", "REG-SYS#1"]


# ============================================================ 시나리오 반영


def test_the_strongest_requesting_technique_sets_the_priority():
    # 한 아티팩트를 여러 기법이 요청한다. 합치거나 평균 내면 스치듯
    # 요청한 기법 여럿이 강하게 요청한 기법 하나를 이긴다.
    selection = {
        "selected": [
            {"artifact": "$MFT", "priority": 3, "reason": {"technique": "T1053.005"}},
            {"artifact": "$MFT", "priority": 1, "reason": {"technique": "T1070.006"}},
            {"artifact": "$MFT", "priority": 3, "reason": {"technique": "T1136.001"}},
        ]
    }
    assert allocation.priorities_from_selection(selection) == {"$MFT": 1}


def test_a_selection_without_priority_reads_as_neutral():
    # 사람이 아직 판단하지 않은 매핑이 있다(6-5). 그때는 중립이지
    # 배분에서 빠지는 것이 아니다.
    selection = {"selected": [{"artifact": "$MFT", "reason": {"technique": "T1505.003"}}]}
    assert allocation.priorities_from_selection(selection) == {"$MFT": DEFAULT_PRIORITY}


def test_the_scenario_changes_which_evidence_reaches_the_model():
    """이 배분의 논지 — 03단계의 판단이 마지막 관문까지 간다."""
    records = [_reg(i, days=0, seconds=i) for i in range(100)]
    records += [_usn(i, seconds=i) for i in range(100)]

    def registry_seats(priorities):
        _chosen, quotas, _budget = allocation.allocate_records(
            records, priorities=priorities, signal_sources=SCOPE_SOURCES, limit=60
        )
        return next(q.seats for q in quotas if q.artifact == "registry:SYSTEM")

    usb_case = registry_seats({"registry:SYSTEM": 1, "$UsnJrnl": 3})
    deletion_case = registry_seats({"registry:SYSTEM": 3, "$UsnJrnl": 1})

    assert usb_case > deletion_case


# ================================================================ 배분 내역


def test_the_quota_report_covers_every_parsed_artifact():
    # "왜 이 60건입니까"에 답하려면 배분 결과가 사람이 읽을 수 있게
    # 남아야 한다. 후보를 다 못 넣은 아티팩트는 여기서만 보인다.
    records = [_reg(i) for i in range(10)] + [_evtx(1)] + [_usn(1)]

    _chosen, quotas, _budget = allocation.allocate_records(
        records, signal_sources=SCOPE_SOURCES, limit=5
    )

    assert {q.artifact for q in quotas} == {"registry:SYSTEM", "evtx:Security", "$UsnJrnl"}
    assert sum(q.seats for q in quotas) == 5


def test_the_quota_reports_the_weight_behind_the_seats():
    quota = allocation.Quota(
        artifact="$MFT", priority=1, candidates=10, seats=4, parsed=100
    )
    assert quota.weight == allocation.PRIORITY_WEIGHT[1]


@pytest.mark.parametrize("priority", sorted(allocation.PRIORITY_WEIGHT))
def test_every_priority_has_a_weight(priority):
    # 눈금이 늘었는데 가중치를 안 채우면 배분이 KeyError 로 멈춘다.
    assert allocation.PRIORITY_WEIGHT[priority] > 0


# ==================================================== AnchorIndex (성능·동치)
#
# 실물 이미지에서 처음 드러난 자리입니다. 앵커마다 거리를 재던 구현이
# $MFT 98,151건에서 3.4 × 10^10 회 비교로 불어나 05단계가 사실상 멈췄습니다.
# 정렬 + 이분 탐색으로 바꿨고, **값이 같은지**를 여기서 못 박습니다.


def _brute_nearest(times, anchors, window):
    """바꾸기 전 구현. 이것과 값이 갈리면 최적화가 아니라 변경이다."""
    best = None
    for moment in times:
        if moment.tzinfo is None:
            continue
        for anchor in anchors:
            distance = abs((moment - anchor).total_seconds())
            if distance <= window and (best is None or distance < best[0]):
                best = (distance, moment)
    return best


def _brute_distance_to_any(times, anchors):
    best = float("inf")
    for moment in times:
        if moment.tzinfo is None:
            continue
        for anchor in anchors:
            best = min(best, abs((moment - anchor).total_seconds()))
    return best


def _spread(count, *, start=datetime(2026, 8, 24, 6, 55, 9, tzinfo=timezone.utc)):
    """마이크로초 자리까지 흩어진 시각들. float 오차가 드러나는 자리다."""
    return [start + timedelta(seconds=i * 7, microseconds=(i * 137) % 1_000_000)
            for i in range(count)]


def test_anchor_index_matches_the_brute_force_it_replaced():
    anchors = _spread(400)
    times = _spread(60, start=datetime(2026, 8, 24, 6, 54, 0, tzinfo=timezone.utc))
    index = record_filter.AnchorIndex(anchors)

    for window in (0.0, 1.0, 60.0, 300.0, 86400.0):
        for moment in times:
            assert index.nearest([moment], window) == _brute_nearest([moment], anchors, window)
        assert index.nearest(times, window) == _brute_nearest(times, anchors, window)


def test_anchor_index_distance_to_any_matches_too():
    anchors = _spread(400)
    times = _spread(60, start=datetime(2026, 8, 24, 6, 54, 0, tzinfo=timezone.utc))
    index = record_filter.AnchorIndex(anchors)

    assert index.distance_to_any(times) == _brute_distance_to_any(times, anchors)
    for moment in times:
        assert index.distance_to_any([moment]) == _brute_distance_to_any([moment], anchors)


def test_microsecond_distances_survive_the_index():
    """float 초로 재면 여기서 어긋난다. 정수 마이크로초라 어긋나지 않는다."""
    anchor = datetime(2026, 8, 24, 6, 55, 9, 123456, tzinfo=timezone.utc)
    index = record_filter.AnchorIndex([anchor])

    moment = anchor + timedelta(microseconds=1)
    found = index.nearest([moment], 300.0)
    assert found is not None and found[0] == 1e-06


def test_an_index_without_anchors_finds_nothing():
    index = record_filter.AnchorIndex([])

    assert index.nearest(_spread(3), 300.0) is None
    assert index.distance_to_any(_spread(3)) == float("inf")


def test_naive_anchors_are_dropped_not_crashed():
    """시각을 못 읽는 신호는 앵커가 되지 못한다 — 창을 열 시각이 없다."""
    index = record_filter.AnchorIndex([datetime(2026, 8, 24, 6, 55, 9)])

    assert len(index) == 0


# ============================================================== 토큰 예산
#
# 자릿수만으로는 컨텍스트 창을 넘는지 알 수 없습니다. 레코드 하나의 크기가
# 아티팩트마다 열 배씩 차이 나기 때문입니다. 2026-08-26 K-ALERT 실측에서
# 60건이 71,476자가 되어 32,768 창을 넘겼고 05단계가 3회 재시도 끝에
# 중단됐습니다. 같은 날 win10_sysmon_testimage 로 다시 재니 60건이
# 100,068자였습니다 — 자릿수는 그대로인데 크기는 40% 더 컸습니다.


def _fat(num, size, seconds=0):
    """덩치가 큰 레코드. 프리패치의 loaded_files 자리를 흉내 낸다."""
    return {
        "ref": f"PF#{num}",
        "artifact": "prefetch",
        "flags": ["execution_from_unusual_path"],
        "timestamp": _at(seconds=seconds),
        "fields": {"loaded_files": ["C:/W/" + "x" * 40] * size},
    }


def test_record_chars_measures_what_the_prompt_actually_sends():
    """다르게 재면 예산이 맞아도 프롬프트가 넘친다.

    ``llm_client.user_prompt`` 은 레코드를 줄당 하나의 JSONL 로 내보낸다.
    여기서 재는 것이 그 문자열과 같아야 한다.
    """
    from src.common import llm
    from src.stage05_interpret.llm_client import InterpretClient

    records = [_evtx(1), _reg(2), _fat(3, 5)]
    client = InterpretClient(llm.StubBackend.__new__(llm.StubBackend))
    scenario = {"target_os": "windows_10", "techniques": [], "time_range": {}}

    overhead = len(client.system_prompt()) + len(client.user_prompt(scenario, []))
    whole = len(client.system_prompt()) + len(client.user_prompt(scenario, records))
    measured = sum(allocation.record_chars(r) for r in records)

    # 머리말의 "N건" 이 자릿수만큼 늘어나는 것까지 정확히 맞출 수는 없다.
    # 재는 쪽이 **더 크게** 나오는 것이 안전한 방향이다.
    assert measured >= whole - overhead
    assert measured - (whole - overhead) < 10


def test_the_budget_takes_the_output_seat_first():
    # 프롬프트가 창을 꽉 채우면 응답이 잘려 malformed_output 으로 온다.
    full = allocation.char_budget(32768, 0, reserve_output_tokens=0)
    reserved = allocation.char_budget(32768, 0, reserve_output_tokens=4096)

    assert reserved < full
    assert full - reserved == int(4096 * allocation.CHARS_PER_TOKEN)


def test_the_token_budget_is_the_window_minus_the_output_seat():
    # 질의를 쪼갤지 정하는 임계값이 이 함수여야 한다. 따로 적어 둔 수는
    # 창이나 예약이 바뀔 때 옛날 값으로 남고, 그 어긋남은 조용하다.
    assert allocation.prompt_token_budget(8192, reserve_output_tokens=1024) == 7168
    assert allocation.prompt_token_budget(4096, reserve_output_tokens=4096) == 0
    # 예약이 창보다 크면 음수가 아니라 0 이다 — 음수 예산은 아래 글자
    # 환산에서 부호가 뒤집혀 "무제한"처럼 보인다.
    assert allocation.prompt_token_budget(2048, reserve_output_tokens=4096) == 0


def test_the_char_budget_agrees_with_the_token_budget():
    # 둘이 갈라지면 분기는 들어간다고 보는데 실을 자리는 없는 상태가 된다.
    tokens = allocation.prompt_token_budget(16384, reserve_output_tokens=2048)
    chars = allocation.char_budget(16384, 0, reserve_output_tokens=2048)

    assert chars == int(tokens * allocation.CHARS_PER_TOKEN)


def test_the_estimate_does_not_claim_more_room_than_the_model_gives():
    # 2026-09-03 실측(`qwen2.5:7b`, prompt_eval_count): 55건 62,713자가
    # 29,910토큰이었다 — 2.10자/토큰. 상수가 이보다 크면 같은 글자를 더 적은
    # 토큰으로 세어 예산이 헐거워지고, 프롬프트가 창을 넘는다. 넘은 것은
    # 거부되지 않고 앞이 잘리므로 실행은 조용히 성공한다.
    assert allocation.CHARS_PER_TOKEN <= 62_713 / 29_910

    measured_chars, measured_tokens = 62_713, 29_910
    assert measured_chars / allocation.CHARS_PER_TOKEN >= measured_tokens


def test_a_long_system_prompt_shrinks_the_budget():
    assert allocation.char_budget(32768, 2000) == allocation.char_budget(32768, 0) - 2000


def test_a_budget_smaller_than_the_prompt_is_zero_not_negative():
    assert allocation.char_budget(1024, 999_999) == 0


def test_seats_shrink_until_the_records_fit():
    records = [_fat(i, 20, seconds=i) for i in range(30)]
    one = allocation.record_chars(records[0])

    _chosen, _quotas, budget = allocation.allocate_records(
        records, limit=30, char_budget=one * 7
    )

    assert budget.trimmed
    assert budget.effective_limit == 7
    assert budget.used_chars <= one * 7


def test_the_largest_fitting_limit_is_chosen():
    # 예산이 남는데 더 줄이면 근거를 버리는 것이다. 이분 탐색이 가장 큰
    # 값을 고르는지 본다 — 딱 맞는 자리에서 한 칸씩 어긋나기 쉽다.
    # 한 아티팩트뿐이고 전부 신호라 전달 순서가 곧 시각순 = 목록 순서다.
    records = [_fat(i, 20, seconds=i) for i in range(30)]

    for want in range(1, 12):
        exact = sum(allocation.record_chars(r) for r in records[:want])

        _c, _q, budget = allocation.allocate_records(records, limit=30, char_budget=exact)
        assert budget.effective_limit == want, want

        # 한 글자만 모자라면 한 자리가 줄어야 한다.
        _c, _q, tight = allocation.allocate_records(records, limit=30, char_budget=exact - 1)
        assert tight.effective_limit == want - 1, want


def test_a_budget_that_fits_leaves_the_seats_alone():
    records = [_evtx(i, seconds=i) for i in range(10)]

    _chosen, _quotas, budget = allocation.allocate_records(
        records, limit=10, char_budget=1_000_000
    )

    assert not budget.trimmed
    assert budget.effective_limit == 10


def test_without_a_budget_nothing_is_measured():
    records = [_fat(i, 50, seconds=i) for i in range(20)]

    chosen, _quotas, budget = allocation.allocate_records(records, limit=20)

    assert len(chosen) == 20
    assert not budget.enforced
    assert not budget.trimmed
    # used_chars 는 참고값으로 채운다. 예산을 안 쟀다고 크기를 모르는 것은 아니다.
    assert budget.used_chars > 0


def test_a_budget_too_small_for_one_record_gives_nothing():
    # 조용히 잘린 레코드를 보내는 것보다 낫다. interpret 이 여기서 사유를
    # 구분해 중단한다.
    records = [_fat(i, 20, seconds=i) for i in range(5)]

    chosen, _quotas, budget = allocation.allocate_records(records, limit=5, char_budget=10)

    assert chosen == []
    assert budget.effective_limit == 0
    assert budget.trimmed


def test_trimming_keeps_the_scenario_weighting():
    # 꼬리를 자르면 시간순 마지막 아티팩트가 통째로 사라져 4-2-1 이 고친
    # 문제가 되살아난다. 자릿수를 낮춰 다시 배분하므로 priority 는 살아 있다.
    records = [_evtx(i, seconds=i) for i in range(20)] + [_usn(i, seconds=i) for i in range(20)]
    priorities = {"evtx:Security": 1, "$UsnJrnl": 3}

    _chosen, quotas, budget = allocation.allocate_records(
        records, limit=20, priorities=priorities, char_budget=2_000
    )
    seats = {q.artifact: q.seats for q in quotas}

    assert budget.trimmed
    # 둘 다 살아 있고(바닥 한 자리), 강한 쪽이 더 많이 받는다.
    assert seats["$UsnJrnl"] >= 1
    assert seats["evtx:Security"] > seats["$UsnJrnl"]


def test_the_budget_reports_what_would_have_gone_without_it():
    # 후보가 4건인데 "60 → 2 자리로 줄임" 이라고 하면 58건을 버린 것처럼
    # 읽힌다. 사람에게 뜻이 있는 것은 실제 건수다.
    records = [_fat(i, 20, seconds=i) for i in range(4)]
    exact = sum(allocation.record_chars(r) for r in records[:2])

    _c, _q, budget = allocation.allocate_records(records, limit=60, char_budget=exact)

    assert budget.requested_limit == 60
    assert budget.natural_records == 4
    assert budget.effective_limit == 2


# ========================================================== 레코드 다이어트


def test_a_long_list_inside_fields_is_capped():
    record = _fat(1, 100)

    trimmed = allocation.for_prompt(record, 20)

    assert len(trimmed["fields"]["loaded_files"]) == 20
    # 원본은 안 건드린다. 06단계 검증은 04_parsed/ 의 원본을 읽는다.
    assert len(record["fields"]["loaded_files"]) == 100


def test_a_short_list_is_left_alone_and_the_record_is_not_copied():
    record = _fat(1, 5)
    assert allocation.for_prompt(record, 20) is record


def test_top_level_lists_are_never_capped():
    """``flags`` 가 최상위에 있다. 신호 판정 자체를 자르면 안 된다."""
    record = dict(_evtx(1), flags=[f"f{i}" for i in range(30)])

    trimmed = allocation.for_prompt(record, 3)

    assert len(trimmed["flags"]) == 30


def test_capping_can_be_turned_off():
    record = _fat(1, 100)
    assert allocation.for_prompt(record, None) is record


def test_a_record_without_fields_survives():
    assert allocation.for_prompt(_reg(1), 20) == _reg(1)


def test_the_budget_measures_the_trimmed_size_not_the_original():
    # 어긋나면 예산이 맞아도 프롬프트가 넘친다. 실제로 터진 자리다.
    record = _fat(1, 100)

    assert allocation.record_chars(record, 20) < allocation.record_chars(record, None)
    assert allocation.record_chars(record, 20) == allocation.record_chars(
        allocation.for_prompt(record, 20), None
    )


def test_the_prompt_and_the_budget_measure_the_same_string():
    """둘이 어긋나면 조용히 창을 넘는다. 같은 for_prompt 을 쓰는지 본다."""
    from src.common import llm
    from src.stage05_interpret.llm_client import InterpretClient

    records = [_fat(i, 100, seconds=i) for i in range(3)]
    client = InterpretClient(llm.StubBackend.__new__(llm.StubBackend), max_list_items=20)
    scenario = {"target_os": "windows_10", "techniques": [], "time_range": {}}

    body = client.user_prompt(scenario, records)

    # 레코드 3건 × 20개만 실린다. 원본은 3건 × 100개다.
    assert body.count(json.dumps("C:/W/" + "x" * 40, ensure_ascii=False)) == 3 * 20
    assert all(len(r["fields"]["loaded_files"]) == 100 for r in records)

    measured = sum(allocation.record_chars(r, 20) for r in records)
    overhead = len(client.user_prompt(scenario, []))
    assert measured >= len(body) - overhead


def test_the_prompt_says_the_lists_were_cut():
    """말하지 않으면 모델이 "적재 파일은 20개였다"고 쓴다 — 우리가 유발한 환각이다."""
    from src.common import llm
    from src.stage05_interpret.llm_client import InterpretClient

    scenario = {"target_os": "windows_10", "techniques": [], "time_range": {}}

    cut = InterpretClient(llm.StubBackend.__new__(llm.StubBackend), max_list_items=20)
    assert "20개까지만" in cut.user_prompt(scenario, [_fat(1, 100)])

    whole = InterpretClient(llm.StubBackend.__new__(llm.StubBackend), max_list_items=None)
    assert "까지만" not in whole.user_prompt(scenario, [_fat(1, 100)])


# ================================================ 무엇을 남길 것인가 (keep)


KEEP = flagging.KeepPaths(max_items=3, contains=("\\users\\", "\\windows\\temp\\"))


def _listed(paths):
    return {"ref": "PF#1", "artifact": "prefetch", "fields": {"loaded_files": list(paths)}}


def test_a_hit_at_the_tail_still_makes_it_in():
    # 이 작업의 논지다. 앞에서만 자르면 뒤쪽의 드롭 자리 DLL 이 통째로
    # 사라진다 — 사이드로딩은 거기서 보인다.
    paths = [f"C:\\Windows\\System32\\{i}.dll" for i in range(30)]
    paths[27] = "C:\\Users\\kisec\\AppData\\Local\\Temp\\evil.dll"

    trimmed = allocation.for_prompt(_listed(paths), 5, KEEP)["fields"]["loaded_files"]

    assert "C:\\Users\\kisec\\AppData\\Local\\Temp\\evil.dll" in trimmed
    assert len(trimmed) == 5


def test_the_order_of_the_original_list_is_kept():
    # 부분집합이지 재정렬이 아니다. 순서를 흔들면 적재 순서가 담고 있는
    # 정보(실행 파일이 대개 첫 항목)가 사라진다.
    paths = [f"C:\\Windows\\System32\\{i}.dll" for i in range(10)]
    paths[8] = "C:\\Users\\kisec\\a.dll"

    trimmed = allocation.for_prompt(_listed(paths), 4, KEEP)["fields"]["loaded_files"]

    assert trimmed == [paths[0], paths[1], paths[2], paths[8]]


def test_the_keep_list_cannot_take_every_seat():
    # 상한이 없으면 적중이 많은 레코드가 앞머리 몫을 통째로 먹는다.
    # 실측에서 한 레코드가 143건 적중했다.
    paths = ["C:\\Users\\kisec\\%d.dll" % i for i in range(20)]
    paths[0] = "C:\\Windows\\System32\\ntdll.dll"

    trimmed = allocation.for_prompt(_listed(paths), 5, KEEP)["fields"]["loaded_files"]

    # keep 상한 3 + 앞에서 채운 2. 첫 항목이 살아 있다.
    assert trimmed[0] == "C:\\Windows\\System32\\ntdll.dll"
    assert len(trimmed) == 5


def test_without_a_keep_list_it_is_the_head_as_before():
    paths = [f"C:\\Windows\\System32\\{i}.dll" for i in range(30)]
    paths[27] = "C:\\Users\\kisec\\AppData\\Local\\Temp\\evil.dll"

    trimmed = allocation.for_prompt(_listed(paths), 5, flagging.NO_KEEP_PATHS)

    assert trimmed["fields"]["loaded_files"] == paths[:5]


def test_a_list_of_non_strings_is_still_the_head():
    # keep 어휘는 경로용이다. 숫자 목록에서는 아무것도 걸리지 않는다.
    record = {"ref": "X#1", "artifact": "prefetch", "fields": {"n": list(range(30))}}

    trimmed = allocation.for_prompt(record, 4, KEEP)

    assert trimmed["fields"]["n"] == [0, 1, 2, 3]


def test_the_shipped_vocabulary_is_actually_loaded():
    """어휘가 조용히 비면 이 기능이 있으나 마나가 된다."""
    keep = flagging.prompt_keep_paths()

    assert keep.max_items > 0
    assert keep.matches("C:\\Users\\kisec\\AppData\\Local\\Temp\\a.dll")
    assert not keep.matches("C:\\Windows\\System32\\ntdll.dll")


DROP = frozenset({"hashes", "processguid"})


def test_dropped_fields_do_not_reach_the_prompt():
    record = {
        "ref": "SYSMON#1",
        "artifact": "evtx:Sysmon",
        "flags": ["suspicious_process"],
        "fields": {"Image": r"C:\x.exe", "Hashes": "SHA256=ab", "ProcessGuid": "{1}"},
    }

    slim = allocation.for_prompt(record, allocation.MAX_LIST_ITEMS, drop=DROP)

    assert slim["fields"] == {"Image": r"C:\x.exe"}
    # 04_parsed/ 의 원본은 안 건드린다. 06단계 검증이 그 원본을 읽는다.
    assert set(record["fields"]) == {"Image", "Hashes", "ProcessGuid"}


def test_dropping_ignores_case():
    record = {"ref": "SYSMON#1", "artifact": "evtx:Sysmon", "flags": [],
              "fields": {"HASHES": "ab", "Image": "x"}}

    assert allocation.for_prompt(record, None, drop=DROP)["fields"] == {"Image": "x"}


def test_dropping_happens_before_the_lists_are_trimmed():
    """뺄 필드의 목록을 자르느라 keep 어휘를 헛돌리지 않는다."""
    record = {"ref": "SYSMON#1", "artifact": "evtx:Sysmon", "flags": [],
              "fields": {"Hashes": list(range(100)), "keep": [1, 2, 3]}}

    slim = allocation.for_prompt(record, 2, KEEP, drop=DROP)

    assert "Hashes" not in slim["fields"]


def test_the_budget_measures_what_the_prompt_will_actually_carry():
    # 재는 쪽과 싣는 쪽이 갈라지면 예산이 맞아도 프롬프트가 넘친다.
    record = {"ref": "SYSMON#1", "artifact": "evtx:Sysmon", "flags": [],
              "fields": {"Image": r"C:\x.exe", "Hashes": "SHA256=" + "a" * 500}}

    measured = allocation.record_chars(record, allocation.MAX_LIST_ITEMS, drop=DROP)
    shipped = allocation.for_prompt(record, allocation.MAX_LIST_ITEMS, drop=DROP)

    assert measured == len(json.dumps(shipped, ensure_ascii=False)) + 1
    assert measured < 200


def test_the_shipped_drop_vocabulary_is_actually_loaded():
    """어휘가 조용히 비면 이 기능이 있으나 마나가 된다."""
    drop = flagging.prompt_drop_fields()

    assert "hashes" in drop
    assert "processguid" in drop
    # 판단에 쓰는 필드는 빠지지 않았는가. 이것이 빠지면 05가 볼 것을 잃는다.
    assert "commandline" not in drop
    assert "targetfilename" not in drop
    assert "reason" not in drop


def test_trimming_lets_more_records_through_the_same_budget():
    # 이 작업의 논지다. 한 아티팩트의 목록 때문에 다른 아티팩트가 자리를
    # 잃는 것은 증거의 폭으로 보아 손해다.
    records = [_fat(i, 200, seconds=i) for i in range(10)]
    budget = 20_000

    _c, _q, fat = allocation.allocate_records(
        records, limit=10, char_budget=budget, max_list_items=None
    )
    _c, _q, lean = allocation.allocate_records(
        records, limit=10, char_budget=budget, max_list_items=20
    )

    assert lean.effective_limit > fat.effective_limit
