"""한국어 벽시계 시각을 UTC 범위가 실제로 덮는가.

가장 중요한 성질은 **이미 덮고 있으면 아무 일도 안 하는 것**이다. 범위를
매번 넓히면 04단계가 시간으로 잘라 내는 몫이 사라지고, 05단계 후보가
쓸데없이 불어난다.
"""

from __future__ import annotations

from datetime import datetime

from src.stage02_normalize import timeband

RAW_518 = (
    "2026년 9월 7일 오전 11시경 실행 파일 518.exe가 실행된 정황이 있습니다. "
    "실행 주체와 실행 방법은 아직 확인되지 않았습니다."
)

#: `518_Test_0907` 프리패치의 최근 실행 시각. 이 한 점이 범위 안에
#: 들어오는지가 이 모듈이 존재하는 이유다.
ACTUAL_RUN = "2026-09-07T01:57:30Z"


def _range(start: str, end: str) -> dict[str, str]:
    return {"start": start, "end": end, "basis": "모델이 적은 근거"}


# ======================================================= 벽시계를 읽어 낸다


def test_a_korean_date_and_hour_is_read_as_a_wall_clock():
    assert timeband.local_wall_clocks(RAW_518) == [datetime(2026, 9, 7, 11, 0)]


def test_the_afternoon_marker_moves_the_hour():
    assert timeband.local_wall_clocks("2026년 8월 3일 오후 2시 20분에") == [
        datetime(2026, 8, 3, 14, 20)
    ]


def test_midnight_is_not_pushed_to_noon():
    assert timeband.local_wall_clocks("2026년 8월 3일 오전 12시에") == [
        datetime(2026, 8, 3, 0, 0)
    ]


def test_an_iso_date_and_colon_time_works_too():
    assert timeband.local_wall_clocks("2026-09-07 11:00 에 실행됨") == [
        datetime(2026, 9, 7, 11, 0)
    ]


def test_a_date_without_a_time_spans_the_local_day():
    assert timeband.local_wall_clocks("2026년 9월 7일에 무슨 일이 있었습니다") == [
        datetime(2026, 9, 7, 0, 0),
        datetime(2026, 9, 7, 23, 59),
    ]


def test_a_year_we_were_not_told_is_not_invented():
    # 연도 없는 `9월 7일` 로는 UTC 를 만들 수 없다. 모델의 범위에서
    # 빌려 오면 그 범위가 틀렸을 때 같이 틀린다.
    assert timeband.local_wall_clocks("9월 7일 오전 11시경") == []


def test_an_impossible_date_is_left_alone():
    assert timeband.local_wall_clocks("2026년 13월 40일 오전 11시") == []


# ==================================================== 넓히는 경우와 아닌 경우


def test_the_518_range_is_widened_to_cover_the_real_record():
    # 실제 실패다. 모델이 `오전 11시경` 을 11:00:00Z 로 옮겼고, 실제
    # 실행(01:57:30Z)은 아홉 시간 어긋난 범위 밖이었다.
    time_range = _range("2026-09-07T10:00:00Z", "2026-09-07T12:00:00Z")
    adjustment = timeband.widen_for_local_time(time_range, RAW_518)

    assert adjustment is not None
    assert time_range["start"] <= ACTUAL_RUN <= time_range["end"]


def test_the_models_own_range_is_not_thrown_away():
    # 옮기지 않고 넓힌다 — 모델이 옳게 변환했을 수도 있으므로 두 읽기를
    # 다 덮는다.
    time_range = _range("2026-09-07T10:00:00Z", "2026-09-07T12:00:00Z")
    timeband.widen_for_local_time(time_range, RAW_518)
    assert time_range["end"] == "2026-09-07T12:00:00Z"


def test_the_mentioned_instant_sitting_on_the_boundary_is_not_enough():
    # 2026-09-07 `K-TEST-518-VERIFY` 1차 실행의 실제 실패다. 모델이 변환은
    # 옳게 해 놓고(02:00Z) 그 시각을 **범위의 시작 경계에** 놓았는데,
    # 실제 실행은 01:57:30Z 로 2분 30초 빨랐다. 점만 봤다면 "이미 덮고
    # 있다"고 판정하고 정답 레코드를 놓쳤을 것이다.
    time_range = _range("2026-09-07T02:00:00Z", "2026-09-07T14:00:00Z")
    assert timeband.widen_for_local_time(time_range, RAW_518) is not None
    assert time_range["start"] < ACTUAL_RUN
    assert time_range["end"] == "2026-09-07T14:00:00Z"


def test_a_range_that_already_covers_it_is_left_alone():
    time_range = _range("2026-09-07T00:00:00Z", "2026-09-07T23:59:59Z")
    before = dict(time_range)
    assert timeband.widen_for_local_time(time_range, RAW_518) is None
    assert time_range == before


def test_an_explicit_utc_is_taken_at_its_word():
    """적힌 표준시대로 읽는다 — **다만 손을 떼지는 않는다.**

    2026-09-08 에 계약이 바뀌었다. 예전에는 ``UTC`` 가 보이면 아무 일도 하지
    않았다. 그런데 "우리가 옮길 일이 없다"와 "모델이 그 시각을 범위에
    넣었는가"는 다른 문제다 — 실측에서 모델은 ``13:37 UTC`` 를 받고
    ``02:37Z ~ 07:37Z`` 를 냈고, 정작 그 사건의 레코드가 전부 범위 밖이었다.
    지금은 UTC 로 읽고 그 점을 덮는지만 본다.
    """
    raw = "2026년 9월 7일 11:00 UTC 에 실행됐습니다"
    time_range = _range("2026-09-07T10:00:00Z", "2026-09-07T12:00:00Z")

    assert timeband.widen_for_local_time(time_range, raw) is not None
    # 11:00Z 를 중심으로 PAD 만큼. KST 로 오해했다면 02:00Z 로 내려갔을 것이다.
    assert time_range["start"] == "2026-09-07T09:00:00Z"
    assert time_range["end"] == "2026-09-07T13:00:00Z"


def test_an_explicit_utc_already_covered_is_left_alone():
    raw = "2026년 9월 7일 11:00 UTC 에 실행됐습니다"
    time_range = _range("2026-09-07T00:00:00Z", "2026-09-07T23:59:59Z")
    before = dict(time_range)

    assert timeband.widen_for_local_time(time_range, raw) is None
    assert time_range == before


def test_english_input_is_not_assumed_to_be_korean_time():
    raw = "An executable ran around 11:00 on 2026-09-07."
    time_range = _range("2026-09-07T10:00:00Z", "2026-09-07T12:00:00Z")
    assert timeband.widen_for_local_time(time_range, raw) is None


def test_a_description_without_a_clock_is_left_alone():
    raw = "실행 파일이 실행된 정황이 있습니다. 언제인지는 모르겠습니다"
    time_range = _range("2026-06-01T00:00:00Z", "2026-09-07T23:59:59Z")
    assert timeband.widen_for_local_time(time_range, raw) is None


def test_the_adjustment_says_what_it_did():
    # basis 는 "범위가 틀렸을 때 원인이 드러난다"는 자리다. 우리가 넓힌
    # 것도 그 원인의 일부다.
    time_range = _range("2026-09-07T10:00:00Z", "2026-09-07T12:00:00Z")
    adjustment = timeband.widen_for_local_time(time_range, RAW_518)
    sentence = adjustment.sentence()
    assert "2026-09-07 11:00" in sentence
    assert "UTC+9" in sentence
    assert adjustment.as_detail()["before"]["start"] == "2026-09-07T10:00:00Z"
