"""수집 시각 상한과 명시 표준시 보정.

둘 다 "모델이 낸 `time_range` 를 파이썬이 고친다"는 같은 자리이고, 고치는
방향이 서로 반대라 함께 고정해 둔다 — 하나는 넓히고 하나는 당긴다.
"""

from datetime import datetime, timezone

import pytest

from src.stage02_normalize import timeband


COLLECTED = datetime(2026, 9, 8, 3, 26, 57, tzinfo=timezone.utc)


# ── 명시 표준시: 손을 떼지 않는다 ──────────────────────────────────────


def test_explicit_utc_still_gets_its_instant_covered():
    """`UTC` 가 적혀 있어도 모델이 그 시각을 범위에 넣었는지는 따로 본다.

    실측에서 모델은 `13:37 UTC` 를 받고 `02:37Z ~ 07:37Z` 를 냈다 — 말한
    시각이 범위 밖이라 정작 그 사건의 레코드가 전부 `outside_time_range` 가
    된다.
    """
    time_range = {"start": "2026-09-07T02:37:00Z", "end": "2026-09-07T07:37:00Z"}
    raw = "2026-09-07 13:37 UTC 에 키오스크에서 cmd 셸이 실행됐습니다."

    adjustment = timeband.widen_for_local_time(time_range, raw)

    assert adjustment is not None
    assert time_range["start"] <= "2026-09-07T13:37:00Z" <= time_range["end"]


def test_explicit_utc_is_read_as_utc_not_shifted_nine_hours():
    """적혀 있는 대로 읽는다. KST 로 오해하면 9시간 어긋난 자리를 덮는다.

    ``13:37 UTC`` 를 KST 로 읽으면 덮어야 할 곳이 ``04:37Z`` 가 된다. 넓힌
    범위가 거기까지 내려가면 표준시를 잘못 가정한 것이다.
    """
    time_range = {"start": "2026-09-07T13:00:00Z", "end": "2026-09-07T14:00:00Z"}
    raw = "2026-09-07 13:37 UTC 에 실행됐습니다."

    timeband.widen_for_local_time(time_range, raw)

    # PAD(2시간)만큼만 넓어진다 — 13:37Z 를 중심으로 11:37Z~15:37Z.
    assert time_range["start"] == "2026-09-07T11:37:00Z"
    assert time_range["end"] == "2026-09-07T15:37:00Z"
    # KST 로 오해했다면 04:37Z 까지 내려갔을 것이다.
    assert time_range["start"] > "2026-09-07T04:37:00Z"


def test_explicit_utc_already_covered_is_left_alone():
    """이미 덮고 있으면 아무 일도 하지 않는다."""
    time_range = {"start": "2026-09-07T00:00:00Z", "end": "2026-09-07T23:00:00Z"}

    assert timeband.widen_for_local_time(time_range, "2026-09-07 13:37 UTC 에 실행됐습니다.") is None


def test_text_without_hangul_or_timezone_is_left_alone():
    """어느 표준시인지 알 길이 없으면 가정하지 않는다."""
    time_range = {"start": "2026-09-07T02:00:00Z", "end": "2026-09-07T03:00:00Z"}

    assert timeband.widen_for_local_time(time_range, "shell spawned on 2026-09-07 13:37") is None


# ── 수집 시각 상한 ─────────────────────────────────────────────────────


def test_invented_past_window_is_extended_to_the_collection_time():
    """실측(2026-09-08, K-LIVE-KIOSK-0908)에서 보고서 15건 중 8건을 만든 자리.

    02단계가 "시간 단서 없음, 최근 2개월로 넓게 설정" 이라며 07-01~08-31 을
    냈는데 수집은 09-08 이었다. 상한이 수집일보다 이르면 **가장 최근의, 가장
    볼 만한 활동 전부**가 범위 밖이 된다.
    """
    time_range = {"start": "2026-07-01T00:00:00Z", "end": "2026-08-31T23:59:59Z"}
    raw = "키오스크 단말의 KAPE 수집본이다. 전반 트리아지를 수행한다."

    adjustment = timeband.clamp_to_collection(time_range, COLLECTED, raw)

    assert adjustment is not None
    assert time_range["end"] == "2026-09-08T03:26:57Z"


def test_a_range_reaching_past_the_collection_is_pulled_back():
    """수집 뒤는 증거에 없는 구간이다."""
    time_range = {"start": "2026-09-01T00:00:00Z", "end": "2026-12-31T00:00:00Z"}

    adjustment = timeband.clamp_to_collection(time_range, COLLECTED, "아무 서술")

    assert adjustment is not None
    assert time_range["end"] == "2026-09-08T03:26:57Z"


def test_a_window_the_text_asked_for_is_not_widened_back_out():
    """사람이 좁혀 준 창을 우리가 도로 넓히면 그 지시를 무시하는 것이다."""
    time_range = {"start": "2026-09-07T11:35:00Z", "end": "2026-09-07T15:35:00Z"}
    raw = "2026년 9월 7일 밤 10시 35분경 USB가 삽입됐습니다."

    assert timeband.clamp_to_collection(time_range, COLLECTED, raw) is None
    assert time_range["end"] == "2026-09-07T15:35:00Z"


def test_no_collection_time_means_no_guess():
    """못 찾으면 지어내지 않는다 — 틀린 상한은 없는 상한보다 나쁘다."""
    time_range = {"start": "2026-07-01T00:00:00Z", "end": "2026-08-31T23:59:59Z"}

    assert timeband.clamp_to_collection(time_range, None, "시각 단서 없음") is None
    assert time_range["end"] == "2026-08-31T23:59:59Z"


def test_clamping_never_inverts_the_range():
    """상한을 당기다 시작보다 앞서면 손대지 않는다."""
    time_range = {"start": "2026-10-01T00:00:00Z", "end": "2026-10-02T00:00:00Z"}

    assert timeband.clamp_to_collection(time_range, COLLECTED, "아무 서술") is None
    assert time_range["start"] == "2026-10-01T00:00:00Z"


# ── 수집 시각을 어디서 읽나 ────────────────────────────────────────────


def _kape(tmp_path, name="2026-09-08T03_26_57_6608239_CopyLog.csv"):
    root = tmp_path / "KIOSK_snapshotA" / "C"
    root.mkdir(parents=True)
    (tmp_path / "KIOSK_snapshotA" / name).write_text("SourceFile\n", encoding="utf-8")
    return root


def test_collection_time_comes_from_the_kape_copylog(tmp_path):
    assert timeband.collection_time(str(_kape(tmp_path))) == COLLECTED


def test_collection_time_is_none_without_a_copylog(tmp_path):
    root = tmp_path / "loose" / "C"
    root.mkdir(parents=True)

    assert timeband.collection_time(str(root)) is None


@pytest.mark.parametrize("value", [None, ""])
def test_collection_time_handles_a_missing_root(value):
    assert timeband.collection_time(value) is None
