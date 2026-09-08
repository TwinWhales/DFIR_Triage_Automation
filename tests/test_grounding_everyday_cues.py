"""신고자의 일상 표현도 명령 셸을 가리킨다 — 다만 다른 도구와 겹치지 않게.

이 가드는 기법을 **떨구기만** 한다. 그래서 어휘가 좁으면 정상 판단이 사라지고,
넓으면 엉뚱한 기법이 살아남는다. 양쪽을 함께 고정한다.
"""

import pytest

from src.stage02_normalize import grounding


def _scenario(technique: str = "T1059.003") -> dict:
    return {"techniques": [{"id": technique, "evidence_text": "근거 구간"}]}


def _dropped(raw: str, technique: str = "T1059.003") -> bool:
    return bool(grounding.ungrounded_techniques(_scenario(technique), raw))


# ── 넓힌 쪽 ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw",
    [
        "키오스크 단말에서 명령 창이 열리고 스크립트를 내려받았습니다",
        "화면에 명령창이 잠깐 떴습니다",
        "검은 창이 잠깐 떴다가 사라졌습니다",
        "검은창이 떴습니다",
        "도스 창이 열렸습니다",
        "콘솔 창에서 뭔가 실행됐습니다",
        "터미널 창이 떠 있었습니다",
        "a command prompt window appeared",
    ],
)
def test_everyday_words_for_a_shell_window_are_accepted(raw):
    """실측(2026-09-08)에서 `명령 창` 하나가 02단계를 통째로 멈췄다.

    모델이 T1059.003 을 골랐고, 어휘에 그 말이 없어 기각됐고, 남는 기법이
    없으니 스키마 위반이 됐다. 재시도해도 모델은 같은 답을 내므로 3회 만에
    파이프라인이 멈춘다 — 오분류가 아니라 전면 실패였다.
    """
    assert not _dropped(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "명령창이 떴습니다",
        "명령 창이 떴습니다",
        "명령  창이 떴습니다",
        "명령\t창이 떴습니다",
    ],
)
def test_one_base_form_covers_every_spacing_variant(raw):
    """어휘에는 붙여 쓴 기본형 하나만 둔다.

    변형을 손으로 나열하면 목록이 길어지기만 하고 다음 변형은 또 빠진다.
    원문과 낱말을 같은 방식으로 눌러 비교하므로 ``명령창`` 하나로 족하다.
    """
    assert not _dropped(raw)


def test_the_cue_table_holds_no_hand_written_spacing_variants():
    """기본형만 둔다는 규칙 자체를 고정한다 — 다음 사람이 다시 늘리지 않게."""
    korean_window_cues = [
        cue for cue in grounding.MECHANISM_CUES["T1059.003"] if cue.endswith("창")
    ]

    assert korean_window_cues, "창 어휘가 사라졌다"
    assert all(" " not in cue for cue in korean_window_cues)


def test_a_cue_containing_a_space_still_matches():
    """낱말 쪽도 함께 눌러야 ``command shell`` 같은 것이 살아남는다."""
    assert not _dropped("the command shell was used")


# ── 넓히지 않은 쪽 ─────────────────────────────────────────────────────


def test_powershell_alone_does_not_ground_the_command_shell():
    """맨 `셸` 을 넣었다면 `파워셸` 이 걸려 T1059.001 서술이 통과했을 것이다."""
    assert _dropped("파워셸이 실행된 정황이 있습니다")


def test_a_kiosk_terminal_is_not_a_shell_window():
    """맨 `터미널` 을 넣었다면 장치를 뜻하는 말이 셸 근거가 됐을 것이다."""
    assert _dropped("키오스크 터미널에서 알 수 없는 프로그램이 돌았습니다")


def test_a_description_that_names_no_shell_still_drops_it():
    """가드의 본래 일은 그대로다."""
    assert _dropped(
        "실행 파일 518.exe가 실행된 정황이 있습니다. 실행 주체와 실행 방법은 "
        "아직 확인되지 않았습니다"
    )


def test_powershell_words_still_ground_powershell():
    assert not _dropped("파워셸이 실행된 정황이 있습니다", "T1059.001")
