"""입력 서술의 어느 구간이 기법으로 옮겨지지 않았는지 센다.

**이 검사는 모델을 믿지 않는다.** 프롬프트가 ``evidence_text`` 를 원문 그대로
쓰라고, ``unmapped_text`` 를 비워 두지 말라고 적어 두었지만 소형 모델은 둘 다
지키지 않는다(2026-09-04 실측: `qwen2.5:latest` 8회 중 8회가 인용을 다듬었고
8회 모두 ``unmapped_text`` 가 빈 배열이었다). 그래서 지킨다고 가정하지 않고
**결과물과 원문을 직접 대조한다.**

왜 필요한가. 02단계의 기법 목록이 03단계의 유일한 입력이라, 02가 축 하나를
빠뜨리면 그 아티팩트는 요청되지 않고 뒤에서 되살릴 자리가 없다. 그런데 07단계
보고서는 "모델이 놓쳤다"와 "증거에 없다"를 **같은 말로 인쇄한다.**
`K-LIVE-0902-wide` 에서 입력이 "계정 관련 변경"을 물었는데 계정 기법이 하나도
나오지 않았고, `evtx:Security` 는 "식별된 기법에 매핑된 아티팩트가 아님" 으로
실렸다 — 그 파일은 같은 수집 안에 15.8MB 로 있었다.

**재시도하지 않는다.** 실측에서 이 검사는 8/8 걸렸고, 재시도를 붙이면 매 실행이
``MAX_ATTEMPTS`` 를 전부 소진해 02단계가 13.8초에서 41.4초가 된다. 그러고도
통과하지 못한다 — 모델이 매번 같은 방식으로 다듬기 때문이다(``normalize.py``
의 ``MAX_ATTEMPTS`` 주석과 같은 이유). 검사 자체는 문자열 비교라 사실상 공짜
이므로, **재시도 대신 기록하고 보고서에 인쇄한다.** 놓친 것을 없애지는 못해도
**놓쳤다는 사실이 보이게** 만든다.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "nonverbatim_quotes",
    "uncovered_spans",
    "ungrounded_entities",
    "MIN_RUN_WORDS",
]

#: 몇 낱말이 잇따라 덮이지 않아야 보고할 것인가.
#:
#: **2로 두면 골든 픽스처가 걸린다.** 사람이 손으로 쓴
#: `benchmark/fixtures/02_scenario.json` 에서 `비슷한 시기에` 같은 이음말이
#: 남는다 — 완벽한 입력에서 늑대를 외치면 이 검사는 쓸모가 없어진다.
#: 3이면 그런 이음말은 빠지고 `계정 관련 변경이`(실제로 통째로 빠진 축,
#: 2026-09-04 실측)는 남는다.
MIN_RUN_WORDS = 3

#: 낱말을 가를 때 떼어 낼 문장부호. 한국어는 조사가 붙어 오므로 어간까지
#: 자르지는 않는다 — 자르기 시작하면 규칙이 언어에 종속된다.
_PUNCT = " \t\n.,()[]{}··\"'`?!~:;/\\"


def nonverbatim_quotes(scenario: dict[str, Any], raw: str) -> list[dict[str, str]]:
    """``evidence_text`` 중 원문의 부분문자열이 **아닌** 것.

    프롬프트가 요구하는 불변식이라 위반은 그 자체로 기록 대상이다. 다듬는
    과정에서 절이 통째로 사라지는 것이 실제로 관측된 실패 방식이다 —
    ``자동 실행 등록과 계정 관련 변경이`` 가 ``자동 실행 등록이`` 가 됐다.

    골든 픽스처는 이 검사를 통과한다. 사람이 쓰면 인용은 원문에서 잘라 온다.
    """
    return [
        {"technique": technique.get("id", "?"), "evidence_text": quote}
        for technique in scenario.get("techniques") or []
        if (quote := technique.get("evidence_text", "")) and quote not in raw
    ]


def _words(text: str) -> list[str]:
    return [w for w in (part.strip(_PUNCT) for part in re.split(r"\s+", text)) if w]


def _accounted_for(scenario: dict[str, Any]) -> list[str]:
    """이 시나리오가 입력의 무엇을 받아 갔는가.

    **기법만 보면 안 된다.** 호스트 이름은 ``entities`` 가, 날짜는
    ``time_range.basis`` 가 받는 몫이다. 그것까지 "안 옮겼다"고 세면
    사람이 쓴 시나리오도 걸리고(실측: 골든 픽스처 3건), 검사가 신호를 잃는다.
    """
    parts = [t.get("evidence_text", "") for t in scenario.get("techniques") or []]
    parts += list(scenario.get("unmapped_text") or [])

    for values in (scenario.get("entities") or {}).values():
        if isinstance(values, list):
            parts += [str(v) for v in values]

    basis = (scenario.get("time_range") or {}).get("basis")
    if basis:
        parts.append(str(basis))

    return [p for p in parts if p]


def uncovered_spans(
    scenario: dict[str, Any], raw: str, *, min_run_words: int = MIN_RUN_WORDS
) -> list[str]:
    """입력에서 시나리오의 **어느 필드에도** 들어가지 않은 낱말이 잇따르는 구간.

    **낱말 단위로 본다.** 모델이 인용을 다듬으므로 문자 구간으로 대조하면
    멀쩡히 옮긴 절까지 통째로 미커버가 된다(실측 커버리지 29%). 낱말이
    어딘가에 부분문자열로 나타나거나 그 반대면 덮인 것으로 친다 — 조사가
    붙고 떨어지는 것을 어간 분석 없이 넘기기 위해서다.

    **잡는 것과 못 잡는 것.** 절이 통째로 빠진 것은 잡는다. 절을 옮기긴
    했는데 **엉뚱한 기법에 붙인 것은 못 잡는다** — 인용은 있으므로 덮인
    것으로 보인다(2026-09-04 실측에서 `계정 관련 변경이` 가 `T1543.003`
    (Windows Service)에 붙은 실행이 그랬다).
    """
    haystack = " ".join(_accounted_for(scenario))
    haystack_words = set(_words(haystack))

    def covered(word: str) -> bool:
        if word in haystack:
            return True
        # 조사가 붙어 길어진 낱말(``WEB01에서``)이 원형(``WEB01``)을 품는 경우.
        return any(known in word for known in haystack_words if len(known) >= 2)

    spans: list[str] = []
    run: list[str] = []
    for word in _words(raw):
        if covered(word):
            if len(run) >= min_run_words:
                spans.append(" ".join(run))
            run = []
        else:
            run.append(word)
    if len(run) >= min_run_words:
        spans.append(" ".join(run))
    return spans

def ungrounded_entities(scenario: dict[str, Any], raw: str) -> dict[str, list[str]]:
    r"""``entities`` 중 입력 원문에 없는 값. 축별로 모아서 낸다.

    프롬프트는 ``entities`` 를 "입력에 명시된 것만" 이라고 못박아 두었는데,
    실측에서 ``paths`` 는 **16/16 전부 지어냈다**(2026-09-05, `qwen2.5:latest`,
    키오스크·웹셸 두 입력 8회씩). 모델이 입력에서 경로를 뽑아낸 적이 한 번도
    없다.

    **왜 지우는가 — 도메인 추론은 이미 매핑에 있다.** 지어낸 값이 그냥
    남는 것이 아니라 **사람이 기법별로 써 둔 기본값을 덮는다.**
    ``scope_resolver.build_context`` 가 ``dict(defaults)`` 로 시작해 entity
    값이 있으면 덮기 때문이다.

    실제로 겹쳐 보면 이렇다. 웹셸 픽스처가 낸 ``C:\inetpub\wwwroot`` 는
    ``T1505.003.yaml`` 의 ``defaults.web_root`` 와 **글자 그대로 같다** —
    지워도 같은 값이 나온다. 키오스크가 낸
    ``C:\Users\Public\Documents`` 는 그 실행에 ``{web_root}`` 를 쓰는
    기법이 없어 피해가 없었을 뿐, 웹셸 기법이 함께 걸렸다면 **엉뚱한 폴더를
    훑었을 것이다.**

    그래서 "입력에 없으면 버린다"가 도메인 추론을 잃지 않는다. 추론은
    매핑이 기법별로 갖고 있고, 그쪽이 사람이 쓴 것이라 더 낫다.

    **부분문자열로 본다.** 입력 ``웹서버 WEB01에서`` 에 대해 ``WEB01`` 은
    입력에서 온 것이다. 조사·수식어를 떼고 이름만 남기는 것은 정규화이지
    창작이 아니다.
    """
    raw_lower = raw.lower()
    found: dict[str, list[str]] = {}
    for axis, values in (scenario.get("entities") or {}).items():
        if not isinstance(values, list):
            continue
        bad = [str(v) for v in values if str(v) and str(v).lower() not in raw_lower]
        if bad:
            found[axis] = bad
    return found
