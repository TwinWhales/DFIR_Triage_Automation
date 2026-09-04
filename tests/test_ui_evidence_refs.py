"""웹 UI 의 근거 추적이 아는 ref 접두어가 04단계와 어긋나지 않는지.

이 테스트가 있는 이유는 실제로 어긋났기 때문이다. ``ui/routes/results.py``
와 ``ui/static/js/report.js`` 가 접두어를 각자 손으로 3종만 적어 뒀고
(``USN``·``REG-SYS``·``MFT``), ``src/common/refs.py`` 는 28종을 알았다.
04단계는 ``evtx_security.jsonl`` 을 정상적으로 만들어 뒀는데도 보고서의
``EVTX-SEC#40912`` 를 누르면 400 이 났고, C-001 보고서의 ref 3개 중
눌리는 것이 1개였다.

``ui/`` 에 테스트가 하나도 없어서 조용했다. 이 파일은 그 자리를 막는다 —
파서를 늘릴 때 UI 만 뒤처지면 여기서 걸린다.

``ui.evidence_refs`` 는 fastapi 를 들이지 않는다. 그래서 웹 의존성이 없는
기계에서도 이 테스트는 돈다.
"""

from __future__ import annotations

import re

from src.common.refs import PREFIX_ARTIFACT
from src.stage04_parse.parse import OUTPUT_FILENAMES
from ui.evidence_refs import EVIDENCE_FILES, REF_PREFIXES


def test_모든_접두어가_파일명을_갖는다():
    """``refs.py`` 가 아는 접두어는 전부 04단계 파일로 이어져야 한다."""

    assert set(EVIDENCE_FILES) == set(PREFIX_ARTIFACT)


def test_파일명이_04단계_것과_같다():
    """UI 가 04단계와 다른 이름을 짐작하지 않는다."""

    for prefix, filename in EVIDENCE_FILES.items():
        artifact = PREFIX_ARTIFACT[prefix]

        assert filename == OUTPUT_FILENAMES[artifact], (
            f"{prefix}({artifact}) 의 파일명이 04단계와 다르다"
        )


def test_회귀_evtx_security_가_눌린다():
    """400 을 냈던 그 접두어. 이름을 박아 둔다 — 이게 증상이었다."""

    assert EVIDENCE_FILES["EVTX-SEC"] == "evtx_security.jsonl"


def test_회귀_예전_세_종만_있는_상태가_아니다():
    """3종으로 되돌아가면 걸린다."""

    assert len(EVIDENCE_FILES) > 3
    assert len(EVIDENCE_FILES) == len(PREFIX_ARTIFACT)


def test_키오스크_채널이_전부_있다():
    """목표 시나리오 축. 빠졌던 25종에 이 다섯이 전부 들어 있었다."""

    kiosk = (
        "EVTX-AAOP",
        "EVTX-AAADM",
        "EVTX-AABRK",
        "EVTX-DRV",
        "EVTX-RDPCM",
    )

    for prefix in kiosk:
        assert prefix in EVIDENCE_FILES, f"{prefix} 는 근거 추적이 안 된다"


def test_접두어가_긴_것부터_온다():
    """프론트엔드가 이 순서로 정규식 교대를 만든다.

    짧은 접두어가 긴 접두어의 앞부분과 겹치면, 교대는 왼쪽부터 맞춰 보므로
    짧은 쪽이 먼저 걸려 뒤가 잘린다.
    """

    lengths = [len(prefix) for prefix in REF_PREFIXES]

    assert lengths == sorted(lengths, reverse=True)
    assert set(REF_PREFIXES) == set(EVIDENCE_FILES)


def test_그_순서가_실제로_겹침을_막는다():
    """접두어끼리 앞부분이 겹치는 짝이 생겨도 긴 쪽이 먼저 물린다.

    지금 목록에는 그런 짝이 없다. 그래서 순서만 검사하면 늘 통과해
    아무것도 지키지 못한다 — 정규식을 실제로 만들어 재 본다.
    """

    pattern = re.compile(
        "\\b(?:"
        + "|".join(re.escape(prefix) for prefix in REF_PREFIXES)
        + ")#[A-Za-z0-9._:-]+"
    )

    for prefix in REF_PREFIXES:
        ref = f"{prefix}#12345"
        match = pattern.search(ref)

        assert match is not None, f"{ref} 가 정규식에 안 걸린다"
        assert match.group(0) == ref, (
            f"{ref} 가 {match.group(0)} 로 잘렸다 — 접두어 순서 문제"
        )


def test_점이나_콜론으로_끝나는_ref_도_통째로_잡힌다():
    """뒤쪽 ``\\b`` 를 붙이면 이런 ref 가 빠진다.

    레지스트리 값 이름처럼 ``.`` 이 섞인 식별자가 있어서, 끝 문자가 단어
    경계가 아닌 경우를 정규식이 잘라 먹으면 안 된다.
    """

    pattern = re.compile(
        "\\b(?:"
        + "|".join(re.escape(prefix) for prefix in REF_PREFIXES)
        + ")#[A-Za-z0-9._:-]+"
    )

    for identifier in ("9735092", "Run:shell.aspx", "v1.2.3", "a-b_c"):
        ref = f"REG-SYS#{identifier}"
        match = pattern.search(ref)

        assert match is not None, f"{ref} 가 안 걸린다"
        assert match.group(0) == ref, f"{ref} 가 {match.group(0)} 로 잘렸다"
