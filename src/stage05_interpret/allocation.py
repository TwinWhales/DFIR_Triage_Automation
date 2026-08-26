"""05단계 레코드 배분 — 아티팩트마다 몇 자리를 줄 것인가.

``record_filter``가 "이 레코드가 볼 만한가"를 판정한다면 이 모듈은 **"어느
아티팩트에 몇 자리를 줄 것인가"**를 정한다. 둘을 나눈 이유는 질문이
다르기 때문이다. 앞의 것은 룰의 문제이고 뒤의 것은 배분의 문제다.

**왜 배분이 필요한가.** 예전에는 신호를 전부 모아 앞에서 60개를 잘랐다.
자르는 기준이 파일명 알파벳순이라 어느 증거가 모델에 도달하는지가 파일
이름 철자에 달려 있었고, 무엇보다 **파이프라인에서 이 자르기만 시나리오의
영향을 받지 않았다.** 03단계가 "이 기법 때문에 이 아티팩트를 본다"고 정해
놓은 것을 05단계가 통째로 무시했다. 이 도구의 논지가 시나리오 기반 선별인데
마지막 관문이 시나리오와 무관했다(``docs/limitations.md`` 4-2, 4-2-1).

**2단 배분.**

.. code-block:: text

    매핑 priority   →  이 케이스에서 어느 아티팩트가 중요한가   [가중치]
    후보 수 상한    →  가진 것보다 많이 받지 않는다             [보정]
                              ↓
                    아티팩트별 자릿수 배분 (쿼터)
                              ↓
                    쿼터 안에서 레코드 선택 (신호 → 시간창 근접)

가중치만 있으면 시끄러운 아티팩트가 자리를 쓸어가고, 보정만 있으면 모든
아티팩트를 똑같이 취급한다. 둘 다 있어야 "웹셸 케이스에서 ``$MFT``를
우선하되, ``$UsnJrnl``이 30만 건이라고 ``$MFT``를 밀어내지는 못한다"가 된다.

**바닥 한 자리.** 후보가 있는 아티팩트는 가중치와 무관하게 최소 한 자리를
받는다. 03단계가 보라고 한 아티팩트가 보고서에서 통째로 사라지지 않는다는
보장이다. 레지스트리가 정확히 그 경우였다 — 파싱은 1,754건이 되는데 플래그가
0건이라 모델에 한 건도 가지 않았다(``docs/limitations.md`` 6-7).

**토큰 예산.** 자릿수만으로는 컨텍스트 창을 넘는지 알 수 없다. 레코드
하나의 크기가 아티팩트마다 열 배씩 차이 나기 때문이다 — 적재 파일 103개를
들고 있는 프리패치 레코드와 ``$MFT`` 레코드는 같은 "한 자리"가 아니다.
2026-08-26 실측에서 60건이 71,476자(추정 28,600토큰)가 되어 32,768 창을
넘겼고, 05단계가 3회 재시도 끝에 중단됐다(``docs/limitations.md``).

그래서 ``char_budget``을 주면 **예산에 맞을 때까지 자릿수를 줄인다.**
꼬리를 자르지 않고 ``limit``을 낮춰 다시 배분하는 것은, 꼬리를 자르면
시간순으로 마지막인 아티팩트가 통째로 사라져 4-2-1이 고친 문제가 그대로
되살아나기 때문이다. 줄어든 사실은 ``Budget``에 담겨 밖으로 나간다 —
**넘는데도 조용히 도는 것**이 이 자리에서 가장 나쁜 성질이다.

**이 모듈이 풀지 못하는 것.** 쿼터 안에서 어느 레코드를 고를지는 여전히
시간창 근접성에 기댄다. ``$MFT``의 ``MISMATCH_PAIRS``처럼 물리적 근거가 있는
판별자를 찾기 전까지는 임시다(``docs/limitations.md`` 6-6).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
from typing import Any, Iterable, Sequence

from ..stage03_select.mapping_loader import (
    DEFAULT_PRIORITY,
    DEFAULT_SIGNAL_SOURCE,
    PRIORITIES,
)
from .record_filter import (
    DEFAULT_LIMIT,
    DEFAULT_WINDOW_SECONDS,
    NO_TIME,
    AnchorIndex,
    activity_times,
    is_signal,
)

__all__ = [
    "CHARS_PER_TOKEN",
    "MAX_LIST_ITEMS",
    "RESERVE_OUTPUT_TOKENS",
    "PRIORITY_WEIGHT",
    "Budget",
    "Quota",
    "char_budget",
    "for_prompt",
    "record_chars",
    "priorities_from_selection",
    "allocate_seats",
    "allocate_records",
]

#: 글자 하나가 몇 토큰인가 — 의 역수. **토크나이저를 돌린 값이 아니라
#: 추정치다.**
#:
#: 우리 레코드는 ASCII 경로가 대부분이고 한글이 섞인다. 순수 ASCII 는
#: 토큰당 3~4자, 한글은 1~1.5자라 그 사이를 잡았다. 2026-08-26 실측에서
#: 71,476자를 28,600토큰으로 환산할 때 쓴 값과 같다.
#:
#: **틀리는 방향이 중요하다.** 실제보다 크게 잡으면(글자를 적은 토큰으로
#: 세면) 예산이 헐거워져 창을 넘고, 그러면 지금 고치는 증상 그대로다.
#: 작게 잡으면 자리를 덜 쓸 뿐이다. 그래서 의심스러우면 낮춘다.
CHARS_PER_TOKEN = 2.5

#: 모델이 답을 쓸 자리로 남겨 두는 토큰. 프롬프트가 창을 꽉 채우면 출력할
#: 자리가 없어 응답이 잘리고, 잘린 응답은 ``malformed_output`` 으로 온다.
#:
#: findings 여러 건과 timeline 을 담은 JSON 이 이 정도다. 실측 소견 4건이
#: 약 1,800토큰이었고, 재시도 없이 한 번에 끝나려면 여유가 있어야 한다.
RESERVE_OUTPUT_TOKENS = 4096

#: 프롬프트에 실을 때 ``fields`` 안의 목록을 몇 개까지 남길 것인가
#: (``for_prompt`` 참조). ``None`` 이면 안 자른다.
#:
#: **20 은 실측에서 나온 값이다.** ``win10_sysmon_testimage`` 의 60건이
#: 100,068자였고 그중 54%가 ``fields.loaded_files`` 하나였다. 상한별로:
#:
#: .. code-block:: text
#:
#:     안 자름  100,068자  →  32,768 창에 44건만 들어감
#:     40        78,026자  →  54건
#:     20        63,041자  →  60건 전부      ← 여기서 천장을 넘는다
#:     10        54,395자  →  60건 (더 줄여도 이득이 급감)
#:
#: **20 아래로는 수익이 급감한다.** 20→3 이 14,731자를 더 아낄 뿐인데,
#: 모델이 볼 수 있는 근거는 계속 줄어든다.
#:
#: 잘리지 않아야 할 것들과도 안 부딪힌다 — 실측에서 ``run_times`` 는 최대
#: 8(포맷 상한), ``volumes`` 는 1 이다. 10 이상이면 그 둘은 건드리지 않는다.
MAX_LIST_ITEMS = 20

#: ``priority`` → 자릿수 배분 가중치. priority는 작을수록 강하므로 뒤집는다.
#:
#: 한 눈금마다 두 배다. priority 1인 아티팩트는 3인 것의 네 배를 받는다.
#: 배수를 크게 잡지 않은 것은 **약한 아티팩트가 굶으면 안 되기 때문**이다 —
#: 자리를 적게 받는 것과 한 건도 못 받는 것은 보고서에서 전혀 다른 결과다.
PRIORITY_WEIGHT = {1: 4, 2: 2, 3: 1}

if set(PRIORITY_WEIGHT) != set(PRIORITIES):
    # 눈금을 늘리고 가중치를 안 채우면 배분이 KeyError 로 멈춘다. 임포트
    # 시점에 잡는다 — assert 로 두면 ``-O`` 에서 사라진다.
    raise RuntimeError(
        f"priority 눈금과 가중치가 어긋남: {sorted(PRIORITIES)} vs {sorted(PRIORITY_WEIGHT)}"
    )


@dataclass(frozen=True)
class Quota:
    """아티팩트 하나에 배분된 자리와 그 근거.

    ``interpret``이 이것을 그대로 찍는다. "왜 이 60건입니까"에 답하려면
    배분 결과가 사람이 읽을 수 있게 남아야 한다.
    """

    artifact: str
    priority: int
    candidates: int
    seats: int
    parsed: int

    @property
    def weight(self) -> int:
        return PRIORITY_WEIGHT[self.priority]


@dataclass(frozen=True)
class Budget:
    """토큰 예산과 그 적용 결과. ``interpret``이 그대로 찍는다.

    ``char_budget``이 ``None``이면 예산을 재지 않은 것입니다 — 예전 동작
    그대로이고, ``used_chars``만 참고값으로 채웁니다.
    """

    used_chars: int
    requested_limit: int
    effective_limit: int
    #: 예산이 없었다면 몇 건이 갔을까. ``--limit``이 아니라 **후보 수까지
    #: 반영한 실제 건수**다. 사람에게는 이쪽이 뜻이 있다 — 후보가 4건뿐인데
    #: "60 → 2 자리로 줄임"이라고 하면 58건을 버린 것처럼 읽힌다.
    natural_records: int = 0
    char_budget: int | None = None

    @property
    def enforced(self) -> bool:
        """예산을 실제로 쟀는가."""
        return self.char_budget is not None

    @property
    def trimmed(self) -> bool:
        """예산 때문에 자릿수가 깎였는가."""
        return self.enforced and self.effective_limit < self.requested_limit

    @property
    def estimated_tokens(self) -> int:
        return int(self.used_chars / CHARS_PER_TOKEN)


def for_prompt(record: dict[str, Any], max_list_items: int | None = MAX_LIST_ITEMS) -> dict[str, Any]:
    """레코드를 프롬프트에 실을 모양으로. ``04_parsed/``의 원본은 안 건드립니다.

    ``fields`` 안의 긴 목록을 앞에서 ``max_list_items``개까지만 남깁니다.
    ``None``이면 자르지 않습니다.

    **왜 자르나.** 실측(``win10_sysmon_testimage``, 60건 100,068자)에서
    ``fields.loaded_files`` 하나가 프롬프트의 **54%**를 먹었습니다. 한
    레코드가 1,017건을 들고 있었습니다. 그 목록 때문에 다른 아티팩트가
    자리를 잃는 것은 증거의 폭으로 보아 손해입니다.

    **왜 ``fields`` 안만.** 최상위는 스키마가 정한 자리라 길이가 묶여 있고,
    무엇보다 ``flags``가 거기 있습니다 — 신호 판정 자체를 자르면 안 됩니다.
    ``fields``는 아티팩트마다 다른 무제한 주머니이고, 터지는 곳은 늘 이쪽
    입니다.

    **왜 앞에서부터.** 어느 항목이 중요한지 고르는 물리적 근거가 없습니다.
    "시스템 DLL은 덜 중요하다" 같은 추측으로 순위를 매기면 그 추측이 틀렸을
    때 조용히 증거를 버립니다. 파일에 있던 순서는 근거는 아니지만 **재현은
    됩니다**(6-6이 말하는 "임시"와 같은 자리).

    **잘렸다는 사실은 프롬프트가 말합니다**(``llm_client.user_prompt``).
    말하지 않으면 모델이 "적재 파일은 20개였다"고 쓸 수 있고, 그것은 우리가
    **유발한** 환각입니다. 다만 그런 문장은 06단계가 잡습니다 — 검증은
    ``04_parsed/``의 원본을 읽으므로 ``loaded_file_count``가 1,017인 것과
    맞지 않아 기각됩니다.
    """
    fields = record.get("fields")
    if max_list_items is None or not isinstance(fields, dict):
        return record

    trimmed = {
        key: value[:max_list_items]
        if isinstance(value, list) and len(value) > max_list_items
        else value
        for key, value in fields.items()
    }
    if trimmed == fields:
        return record

    out = dict(record)
    out["fields"] = trimmed
    return out


def record_chars(
    record: dict[str, Any], max_list_items: int | None = MAX_LIST_ITEMS
) -> int:
    """레코드 하나가 프롬프트에서 차지할 글자 수.

    ``llm_client.user_prompt``이 레코드를 내보내는 방식(``for_prompt``을
    거친 뒤 줄당 하나의 JSONL, ``ensure_ascii=False``)과 **같은 문자열을
    잽니다.** 다르게 재면 예산이 맞아도 프롬프트가 넘칩니다. 줄바꿈 한
    글자를 더합니다.
    """
    return len(json.dumps(for_prompt(record, max_list_items), ensure_ascii=False)) + 1


def char_budget(
    num_ctx: int,
    overhead_chars: int,
    *,
    reserve_output_tokens: int = RESERVE_OUTPUT_TOKENS,
    chars_per_token: float = CHARS_PER_TOKEN,
) -> int:
    """레코드에 쓸 수 있는 글자 수. 음수면 0.

    ``num_ctx``에서 **출력 자리를 먼저 떼고**, 남은 것을 글자로 환산한 뒤
    프롬프트의 고정 부분(``overhead_chars`` — 시스템 프롬프트와 시나리오
    머리말)을 뺍니다.

    출력 자리를 토큰으로 떼는 것은 그쪽이 모델의 단위이기 때문이고,
    레코드를 글자로 재는 것은 우리가 가진 것이 글자이기 때문입니다.
    """
    for_prompt = (num_ctx - reserve_output_tokens) * chars_per_token
    return max(0, int(for_prompt) - overhead_chars)


def priorities_from_selection(selection: dict[str, Any]) -> dict[str, int]:
    """``03_selection.json``에서 아티팩트별 priority를 뽑는다.

    한 아티팩트를 여러 기법이 요청할 수 있다(04단계가 ``scope``를 합치는
    이유와 같다). 그때는 **요청한 기법들 중 가장 강한 값**을 쓴다. 합치거나
    평균 내면 여러 기법이 스치듯 요청한 아티팩트가 한 기법이 강하게 요청한
    아티팩트를 이긴다.
    """
    strongest: dict[str, int] = {}
    for entry in selection.get("selected") or []:
        artifact = entry.get("artifact")
        if not artifact:
            continue
        # 값을 거르는 것은 스키마의 일이다(1~3 정수). 여기서 한 번 더 보는
        # 것은 손으로 만든 selection 이 들어왔을 때를 위한 것이며, bool 을
        # 먼저 막는다 — ``True in PRIORITY_WEIGHT`` 가 참이라 그냥 두면
        # 가장 강한 값인 1 이 된다.
        priority = entry.get("priority", DEFAULT_PRIORITY)
        if isinstance(priority, bool) or priority not in PRIORITY_WEIGHT:
            priority = DEFAULT_PRIORITY
        strongest[artifact] = min(strongest.get(artifact, DEFAULT_PRIORITY), priority)
    return strongest


def allocate_seats(
    candidates: dict[str, int], priorities: dict[str, int], limit: int
) -> dict[str, int]:
    """아티팩트별 자릿수를 정한다. 후보가 있는 곳은 최소 한 자리.

    바닥을 채우고 남은 자리는 동트(D'Hondt)식으로 하나씩 나눈다. 매번
    ``가중치 / (이미 받은 자리 + 1)``이 가장 큰 아티팩트가 다음 자리를
    가져간다. 최대잔여법과 달리 소수점 잔여를 들고 다니지 않아 배분 결과를
    손으로 따라갈 수 있고, 자리마다 누가 왜 가져갔는지 말할 수 있다.

    후보 수가 상한이다. 가진 것보다 많이 받지 않고, 남은 자리는 다른
    아티팩트로 돌아간다.
    """
    seats = {artifact: 0 for artifact in candidates}
    remaining = max(0, limit)

    def weight(artifact: str) -> int:
        return PRIORITY_WEIGHT[priorities.get(artifact, DEFAULT_PRIORITY)]

    # 바닥. 자리가 아티팩트 수보다 적으면 강한 쪽부터 받는다.
    for artifact in sorted(candidates, key=lambda a: (-weight(a), a)):
        if remaining <= 0:
            break
        if candidates[artifact] > 0:
            seats[artifact] = 1
            remaining -= 1

    while remaining > 0:
        open_artifacts = [a for a in candidates if seats[a] < candidates[a]]
        if not open_artifacts:
            break
        # 동점은 이름순으로 가른다. 근거가 있어서가 아니라 **같은 입력에
        # 같은 배분이 나와야** 재현율이 모델 성능의 지표가 되기 때문이다.
        winner = min(
            open_artifacts,
            key=lambda a: (-Fraction(weight(a), seats[a] + 1), a),
        )
        seats[winner] += 1
        remaining -= 1

    return seats


def allocate_records(
    records: Iterable[dict[str, Any]],
    *,
    priorities: dict[str, int] | None = None,
    signal_sources: dict[str, str] | None = None,
    limit: int = DEFAULT_LIMIT,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    char_budget: int | None = None,
    max_list_items: int | None = MAX_LIST_ITEMS,
) -> tuple[list[dict[str, Any]], list[Quota], Budget]:
    """전달할 레코드를 시간순으로, 배분 내역·예산과 함께 돌려준다.

    ``priorities``가 비면 모든 아티팩트가 중립(``DEFAULT_PRIORITY``)이다.
    선별 결과 없이도 아티팩트별 배분은 그대로 작동한다 — 시나리오 반영만
    빠진다.

    ``char_budget``을 주면 **레코드 전체가 그 글자 수 안에 들어올 때까지
    ``limit``을 낮춰 다시 배분한다.** 자릿수만으로는 창을 넘는지 알 수
    없어서다(모듈 docstring 참조). 주지 않으면 재지 않는다.

    ``max_list_items``는 **크기를 잴 때만** 쓴다. 돌려주는 것은 원본
    레코드이고, 자르는 것은 ``llm_client``가 프롬프트를 만들 때다. 여기서
    미리 자르면 ``interpret``이 원본을 볼 길이 없어진다 — 둘이 같은
    ``for_prompt``을 쓰므로 크기는 어긋나지 않는다.
    """
    priorities = priorities or {}
    signal_sources = signal_sources or {}

    by_artifact: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_artifact.setdefault(record.get("artifact", ""), []).append(record)

    # 앵커는 **플래그가 붙은 레코드의 활동 시각**이다. 아티팩트를 가리지
    # 않으므로 evtx의 로그온 시각이 레지스트리 키를 끌어올 수 있다 —
    # 키오스크처럼 증거가 여러 계층에 흩어지는 사건에서 이 교차가 핵심이다.
    #
    # 시각을 못 읽는 신호는 앵커가 되지 못한다. "그 시각 주변"이라고 할
    # 시각이 없기 때문이다. 자기는 전달되되 창은 안 연다.
    anchors: list[datetime] = []
    for artifact_records in by_artifact.values():
        for record in artifact_records:
            if is_signal(record):
                anchors.extend(activity_times(record))

    # 앵커는 한 번만 정렬해 아티팩트마다 돌려 쓴다. 아티팩트마다 새로
    # 만들면 정렬 비용이 아티팩트 수만큼 붙는다.
    anchor_index = AnchorIndex(anchors)

    ranked = {
        artifact: _rank(
            artifact_records,
            anchor_index,
            window_seconds,
            signal_sources.get(artifact, DEFAULT_SIGNAL_SOURCE),
        )
        for artifact, artifact_records in by_artifact.items()
    }
    counts = {artifact: len(entries) for artifact, entries in ranked.items()}

    def pick(seat_limit: int) -> tuple[dict[str, int], list[tuple[datetime, dict[str, Any]]], int]:
        """자릿수 하나에 대한 배분·선택·글자수."""
        seats = allocate_seats(counts, priorities, seat_limit)
        picked: list[tuple[datetime, dict[str, Any]]] = []
        chars = 0
        for artifact in sorted(ranked):
            for _key, moment, record in ranked[artifact][: seats[artifact]]:
                picked.append((moment, record))
                chars += record_chars(record, max_list_items)
        return seats, picked, chars

    effective_limit = max(0, limit)
    seats, chosen, used_chars = pick(effective_limit)
    natural_records = len(chosen)

    if char_budget is not None and used_chars > char_budget:
        effective_limit = _fit_limit(pick, effective_limit, char_budget)
        seats, chosen, used_chars = pick(effective_limit)

    quotas = [
        Quota(
            artifact=artifact,
            priority=priorities.get(artifact, DEFAULT_PRIORITY),
            candidates=len(ranked[artifact]),
            seats=seats[artifact],
            parsed=len(by_artifact[artifact]),
        )
        for artifact in sorted(ranked)
    ]
    budget = Budget(
        used_chars=used_chars,
        requested_limit=max(0, limit),
        effective_limit=effective_limit,
        natural_records=natural_records,
        char_budget=char_budget,
    )

    chosen.sort(key=lambda item: item[0])
    return [record for _moment, record in chosen], quotas, budget


def _fit_limit(pick: Any, upper: int, budget: int) -> int:
    """예산 안에 들어오는 가장 큰 자릿수. 하나도 안 들어오면 0.

    글자 수는 자릿수에 대해 **단조 증가**합니다 — 동트 배분은 총 자리를
    늘렸을 때 어느 아티팩트의 자리도 줄지 않고(house-monotone), 레코드
    길이는 양수이기 때문입니다. 그래서 이분 탐색이 맞습니다.

    선형으로 내려가지 않는 것은 예산이 크게 모자랄 때 배분을 자릿수만큼
    되풀이하게 되어서입니다.
    """
    low, high = 0, upper
    while low < high:
        mid = (low + high + 1) // 2
        if pick(mid)[2] <= budget:
            low = mid
        else:
            high = mid - 1
    return low


def _rank(
    records: Sequence[dict[str, Any]],
    anchors: "AnchorIndex",
    window_seconds: float,
    signal_source: str,
) -> list[tuple[tuple[Any, ...], datetime, dict[str, Any]]]:
    """한 아티팩트 안에서 전달 순서를 매긴다. 앞에서부터 쿼터만큼 나간다.

    순위는 셋으로 나뉜다.

    0. **신호** — 룰이 볼 만하다고 판정했다. 가장 이른 활동 시각 순.
    1. **시간창 안의 주변 레코드** — 신호에 가까운 순. 의심스러운 사건
       하나만 보면 그것이 정상 작업인지 알 수 없다는 이유로 함께 넣는다.
    2. **선별이 골라 온 나머지** — ``signal_source: scope``인 아티팩트에만
       있다. 아래 설명 참조.

    ``signal_source``가 갈리는 지점이 2번이다. ``flags`` 아티팩트에서
    플래그도 없고 시간창에도 안 걸린 레코드는 볼 이유가 없으므로 후보에서
    빠진다. ``scope`` 아티팩트는 반대다 — 03단계의 ``path_prefix``가 이미
    신호 판정을 끝냈으므로 **모든 레코드가 후보**이고, 시간창으로 다시
    거르면 선별이 골라 온 것이 통째로 사라진다. 레지스트리의 LastWrite는
    대개 OS 설치 시각이라 사건 시간창에 걸리지 않는다.
    """
    entries: list[tuple[tuple[Any, ...], datetime, dict[str, Any]]] = []

    for index, record in enumerate(records):
        times = activity_times(record)
        ref = str(record.get("ref", ""))

        if is_signal(record):
            moment = min(times) if times else NO_TIME
            entries.append(((0, moment, ref), moment, record))
            continue

        found = anchors.nearest(times, window_seconds)
        if found is not None:
            distance, moment = found
            entries.append(((1, distance, moment, ref), moment, record))
            continue

        if signal_source == "scope":
            # 앵커에서 멀거나 앵커가 아예 없다. 그래도 선별이 골라 온
            # 것이므로 버리지 않고, 창 밖 거리로 줄을 세운다. 거리를 잴 수
            # 없으면 파일에 있던 순서를 쓴다 — 근거가 아니라 재현성을 위한
            # 것이며, 6-6이 말하는 "임시"가 바로 이 자리다.
            moment = min(times) if times else NO_TIME
            entries.append(((2, anchors.distance_to_any(times), index), moment, record))

    entries.sort(key=lambda item: item[0])
    return entries



