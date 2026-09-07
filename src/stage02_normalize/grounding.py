r"""모델이 고른 세부 기법에 입력이 실제로 근거를 주는지 본다.

`coverage` 와 같은 자리에 있다 — **모델을 믿지 않고 결과물과 원문을 직접
대조한다.** 다만 보는 방향이 반대다. `coverage` 는 *입력에 있는데 옮겨지지
않은 것* 을 세고, 여기는 *입력에 없는데 나온 것* 을 센다.

왜 필요한가. 2026-09-07 `518_Test_0907` 실측에서 입력은 이랬다.

    2026년 9월 7일 오전 11시경 실행 파일 518.exe 가 실행된 정황이 있습니다.
    실행 주체와 실행 방법은 아직 확인되지 않았습니다.

셸이라는 낱말이 없고 **실행 방법은 확인되지 않았다고 명시**돼 있는데 모델은
``T1059.003``(Windows Command Shell)을 골랐다. 그 한 줄이 파이프라인 전체를
돌렸다 — ``T1059.003`` 매핑은 ``prefetch`` 를 Tier 2 로 두므로 03단계가
프리패치를 유예했고, Tier 2 루프백이 없어 영구 미수집이 됐다.
``Windows/Prefetch/518.EXE-71CD1C31.pf`` 에 3회 실행 기록이 그대로 있는데도
보고서에 ``518.exe`` 가 한 줄도 오르지 않았다.

**이것은 분류기가 아니다.** 어느 기법이 맞는지 판정하지 않는다. 판정하는 것은
하나뿐이다 — **모델이 고른 세부 기법이 이름 붙은 메커니즘을 전제하는데
입력에 그 메커니즘이 한 번도 안 나왔는가.** 아래 `MECHANISM_CUES` 에 적힌
기법만 보고, 적히지 않은 기법은 손대지 않는다. 그래서 목록을 안 넓히면 이
검사는 조용하다(`work.md` 10번의 "02 에 가드를 두면 분류기를 다시 만드는
것" 이라는 판단과 부딪히지 않는 선이 여기다).

두 번째 일은 반대 방향이다. **입력이 이름을 댄 실행 파일을
``entities.processes`` 에 되돌려 놓는다.** 같은 실측에서 모델은 ``518.exe``
를 어느 필드에도 남기지 않았다. ``entities`` 는 03단계의 ``scope`` 를 채우는
값이라, 조사 대상의 이름이 거기 없으면 05단계가 무엇을 골라야 하는지 모른다.
지어내는 것이 아니라 **원문에 글자 그대로 있는 것을 옮기는 것**이므로
`coverage.ungrounded_entities` 의 검사도 그대로 통과한다.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "MECHANISM_CUES",
    "PROCESS_EXTENSIONS",
    "named_processes",
    "restore_named_processes",
    "ungrounded_techniques",
]


#: 이름 붙은 메커니즘을 전제하는 기법과, 입력에 그 메커니즘이 있었다고 볼
#: 낱말들. **여기 없는 기법은 검사하지 않는다.**
#:
#: 고르는 기준은 하나다 — 기법 이름이 *도구* 를 지목하는가. ``T1059.003`` 은
#: "Windows **Command Shell**", ``T1059.001`` 은 "**PowerShell**",
#: ``T1218.011`` 은 "**Rundll32**" 다. 이런 기법은 그 도구가 서술에 나오지
#: 않으면 근거가 없다. 반대로 ``T1204.002``(User Execution: Malicious File)
#: 처럼 행위만 말하는 기법은 낱말로 가를 수 없으므로 여기 넣지 않는다.
#:
#: 낱말은 **한국어와 영어를 함께** 둔다. 입력이 한국어라도 분석가는 도구
#: 이름을 영어로 적는다(``cmd.exe 가 떴습니다``).
#:
#: 대소문자는 무시하고 **부분문자열로** 본다. ``명령 프롬프트를`` 안의
#: ``명령 프롬프트`` 를 잡기 위해서다 — 조사를 떼는 형태소 분석 없이
#: 넘어가는 것은 `coverage` 와 같은 방식이다.
MECHANISM_CUES: dict[str, tuple[str, ...]] = {
    "T1059.003": (
        "cmd", "cmd.exe", "command shell", "명령 셸", "명령셸", "명령 프롬프트",
        "커맨드", "배치 파일", "batch", ".bat", ".cmd", "conhost",
    ),
    "T1059.001": (
        "powershell", "파워셸", "파워쉘", "ps1", ".ps1", "pwsh",
        "스크립트블록", "scriptblock",
    ),
    "T1218.011": ("rundll32", "런들", "런DLL"),
    "T1197": ("bits", "bitsadmin", "백그라운드 전송", "background intelligent"),
    "T1219": (
        "원격 제어", "원격제어", "remote access", "rdp", "anydesk", "teamviewer",
        "vnc", "원격 지원", "팀뷰어", "애니데스크",
    ),
    "T1021.001": ("rdp", "원격 데스크톱", "원격데스크톱", "remote desktop", "mstsc", "3389"),
    "T1021.002": ("smb", "관리 공유", "admin$", "ipc$", "c$", "psexec", "445"),
}


#: ``entities.processes`` 로 되돌릴 파일의 확장자.
#:
#: **실행되는 것만** 넣는다. ``.txt``·``.log`` 까지 넣으면 그 이름이
#: 03단계의 ``scope`` 로 들어가 엉뚱한 경로를 훑는다. 목록은
#: ``T1204.002`` 매핑의 ``$MFT`` 확장자 목록과 같은 뜻이고, 스크립트
#: 확장자 몇 개를 더 갖는다.
PROCESS_EXTENSIONS: tuple[str, ...] = (
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jse", ".hta", ".msi", ".jar", ".pif", ".sys",
)

#: 파일명 한 덩어리. 경로 구분자·공백·따옴표·한글은 이름에 들어가지 않는다.
#: 확장자는 위 목록으로 따로 거르므로 여기서는 형태만 본다.
_FILENAME = re.compile(r"[A-Za-z0-9_\-.$~()]+\.[A-Za-z0-9]{1,4}")


def named_processes(raw: str) -> list[str]:
    r"""입력이 이름을 댄 실행 파일. 나온 순서대로, 중복 없이.

    경로가 붙어 있으면 **마지막 조각만** 낸다 —
    ``C:\Users\Public\518.exe`` 에서 ``518.exe``. 경로 자체는
    ``entities.paths`` 의 몫이고, 그쪽은 03단계의 ``web_root`` 로 쓰여
    매핑의 ``defaults`` 를 덮으므로 여기서 건드리지 않는다
    (`scope_resolver.ENTITY_VARIABLES`).
    """
    found: list[str] = []
    for match in _FILENAME.finditer(raw):
        name = match.group(0).rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if not name.lower().endswith(PROCESS_EXTENSIONS):
            continue
        if name not in found:
            found.append(name)
    return found


def restore_named_processes(scenario: dict[str, Any], raw: str) -> list[str]:
    """입력에 있는데 ``entities.processes`` 에 없는 실행 파일을 채운다.

    채운 이름을 돌려준다. 채울 것이 없으면 빈 목록이다.

    **뒤에 붙인다.** ``processes`` 의 첫 항목은 `scope_resolver` 가
    ``{process}`` 로 쓰므로, 모델이 이미 골라 둔 순서를 우리가 뒤집지
    않는다. 모델이 아무것도 안 냈을 때만 우리가 첫 항목을 정한다.
    """
    entities = scenario.setdefault("entities", {})
    current = list(entities.get("processes") or [])
    lowered = {str(value).lower() for value in current}

    added = [name for name in named_processes(raw) if name.lower() not in lowered]
    if added:
        entities["processes"] = current + added
    return added


def ungrounded_techniques(scenario: dict[str, Any], raw: str) -> list[dict[str, str]]:
    """`MECHANISM_CUES` 에 있는 기법 중 입력에 그 메커니즘이 없는 것.

    **입력 전체를 본다.** ``evidence_text`` 만 보지 않는 이유는 모델이
    인용을 다듬기 때문이다(`coverage.nonverbatim_quotes` 의 실측). 원문
    어디에도 그 도구가 없으면 어느 절을 인용했든 근거가 아니다.
    """
    lowered = raw.lower()
    found: list[dict[str, str]] = []
    for technique in scenario.get("techniques") or []:
        cues = MECHANISM_CUES.get(str(technique.get("id")))
        if cues is None:
            continue
        if any(cue.lower() in lowered for cue in cues):
            continue
        found.append(
            {
                "technique": str(technique.get("id")),
                "evidence_text": str(technique.get("evidence_text", "")),
                "expected_any_of": ", ".join(cues),
            }
        )
    return found
