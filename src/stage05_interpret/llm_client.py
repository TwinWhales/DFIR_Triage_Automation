"""해석 단계용 LLM 클라이언트.

02단계와 파일이 나뉜 것은 의도된 설계다. 정규화는 짧은 구조화 출력이라
작은 모델로도 되지만, 해석은 레코드를 읽고 문장을 만들어야 해서 더 큰
모델이 필요할 수 있다.

전송과 응답 파싱은 ``src/common/llm.py``가 맡는다. 여기 있는 것은
**이 단계의 프롬프트와 파라미터**뿐이다.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..common import schema
from ..common.llm import Backend, extract_json, output_schema
from .allocation import MAX_LIST_ITEMS, for_prompt

__all__ = [
    "DEFAULT_MODEL",
    "FINDINGS_BODY_FIELDS",
    "InterpretClient",
    "constrained_schema",
]

#: 해석은 정규화보다 무거운 작업이다. 같은 7B로 시작하되 모델별 비교
#: 실험에서 이 단계만 키웠을 때의 효과를 따로 측정한다.
#:
#: ``ollama pull``에 넣을 수 있는 태그를 그대로 쓴다. 02단계와 값이 같아도
#: 상수를 공유하지 않는 것은, 이 단계만 큰 모델로 바꾸는 실험이 잦기 때문이다.
DEFAULT_MODEL = "qwen2.5:7b-instruct-q4_K_M"

PROMPT_DIR = Path(__file__).parent / "prompts"

#: 05단계가 모델에게 열어 줄 컨텍스트 창(토큰).
#:
#: ``src/common/llm.py`` 의 값을 그대로 쓰지 않는 이유는 ``DEFAULT_MODEL`` 과
#: 같다 — 02단계와 창 크기를 묶어 두면 한쪽을 실험할 때 다른 쪽이 따라
#: 움직인다. 02는 시나리오 한 건이라 프롬프트가 작고, 05는 레코드를 싣는다.
#:
#: **내려야 할 값이고, 아직 내리지 못했다.** 6GB VRAM 에서 32,768 창은 KV
#: 캐시만 1.8GB 라 모델이 GPU 에 다 올라가지 않는다(실측 2026-09-03,
#: ``qwen2.5:7b``: 창 32,768 에서 GPU 61%, 8,192 에서 79%, 4,096 에서 81%).
#: 그런데 **지금 질의 형태로 창만 내리면 레코드가 급감한다** — 출력 예약을
#: 빼고 나면 8,192 창에 남는 것이 열 건 남짓이다. 창을 내리는 일은 질의를
#: 여러 번으로 쪼개는 일과 함께 와야 하고, 따로 내리면 커버리지만 잃는다.
DEFAULT_NUM_CTX = 32768


#: 모델에게 요구하는 필드. ``input_refs``는 **모델에게 묻지 않는다.**
#: 무엇을 전달했는지는 우리가 안다. 모델이 보고하게 하면 실제로 받지
#: 않은 레코드를 목록에 넣어 ref_not_in_input 검사를 무력화할 수 있다.
FINDINGS_BODY_FIELDS = ("findings", "timeline")


def constrained_schema(
    scenario: dict[str, Any], records: list[dict[str, Any]]
) -> dict[str, Any]:
    """이 호출에 한정된 출력 스키마. **배치마다 다르다.**

    02단계와 달리 목록이 고정돼 있지 않다. 모델이 인용해도 되는 ``ref``는
    이번에 실제로 실어 보낸 레코드의 것뿐이고, 그 목록은 호출할 때 정해진다.

    **우리는 무엇을 보냈는지 이미 알고 있다.** 프롬프트가 "이 목록에 없는
    ref를 쓰면 기각됩니다"라고 적어 부탁해 왔고, 06단계가 사후에
    ``ref_not_in_input``으로 걸러 왔다. 같은 목록을 enum으로 주면 없는 ref를
    만들 토큰 경로가 사라진다 — 걸러 낼 것이 아니라 나오지 않는다.

    ``$defs.ref`` 하나를 갈아 끼운다. ``findings[].refs``·
    ``findings[].claims[].ref``·``timeline[].refs`` 셋이 모두 이 정의를
    가리키므로, 자리마다 손대면 언젠가 하나를 빠뜨린다.

    ``technique``도 시나리오가 든 기법으로 묶는다. 동결 스키마가 ``null``을
    허용하므로("특정 기법에 귀속되지 않을 수 있다") enum에 ``None``을 남긴다.
    """
    built = output_schema(schema.load_schema("findings"), FINDINGS_BODY_FIELDS)

    refs = [record["ref"] for record in records if "ref" in record]
    if refs:
        # 비었으면 갈아 끼우지 않는다. 빈 enum 은 아무 값도 만족시킬 수
        # 없어 모델이 무엇을 내든 실패하고, 그 실패는 "레코드를 한 건도
        # 못 받았다"는 앞 단계의 문제를 05단계 환각으로 둔갑시킨다.
        built["$defs"]["ref"] = {"enum": sorted(set(refs))}

    techniques = [t["id"] for t in scenario.get("techniques", []) if "id" in t]
    if techniques:
        built["properties"]["findings"]["items"]["properties"]["technique"] = {
            "enum": [*sorted(set(techniques)), None]
        }
    return built


class InterpretClient:
    """레코드 → 해석 문장과 claims."""

    def __init__(
        self,
        backend: Backend,
        *,
        max_list_items: int | None = MAX_LIST_ITEMS,
        constrain: bool = True,
    ) -> None:
        self.backend = backend
        #: 출력 모양을 디코딩 단계에서 강제할 것인가. 02단계와 같은 규약이고
        #: **폴백이 아니라 측정용**이다 (``stage02_normalize/llm_client.py``).
        self.constrain = constrain
        #: ``fields`` 안의 목록을 몇 개까지 실을 것인가. ``allocation``이
        #: 예산을 잴 때 쓰는 값과 **같아야 한다** — 어긋나면 예산이 맞아도
        #: 프롬프트가 넘친다. ``interpret``이 둘에 같은 값을 넘긴다.
        self.max_list_items = max_list_items
        #: 마지막으로 받은 모델 응답 원문. 실패했을 때 무엇을 뱉었는지
        #: 파일로 떨구기 위한 것이다. 파싱 전에 채우므로 JSON 을 못 찾은
        #: 경우에도 남는다. 성공하면 아무도 읽지 않는다.
        self.last_raw: str | None = None

    @property
    def name(self) -> str:
        return self.backend.name

    def system_prompt(self) -> str:
        return (PROMPT_DIR / "interpret_system.txt").read_text(encoding="utf-8")

    def _trim_notice(self) -> str:
        """목록이 잘렸다는 사실을 모델에게 말한다.

        말하지 않으면 모델이 "적재 파일은 20개였다"고 쓸 수 있고, 그것은
        우리가 **유발한** 환각이다. 전체 개수는 레코드의 ``*_count`` 필드에
        원본 그대로 실려 있다(프리패치의 ``loaded_file_count`` 등).

        **"앞에서"라고 말하지 않는다.** ``allocation.for_prompt``가
        눈여겨볼 자리를 먼저 골라 넣으므로 실린 것이 앞머리가 아닐 수
        있다(``mappings/_flags.yaml`` 의 ``prompt_keep_paths``). 앞에서
        잘랐다고 말해 두면 모델이 "그 뒤는 못 봤다"를 잘못된 근거로 쓴다.
        """
        if self.max_list_items is None:
            return ""
        return (
            f". fields 안의 목록은 {self.max_list_items}개까지만 실려 있고 "
            "원래 순서를 지킨 부분집합이니, 전체 개수는 함께 있는 개수 필드를 "
            "보고 말하십시오"
        )

    def user_prompt(
        self,
        scenario: dict[str, Any],
        records: list[dict[str, Any]],
        feedback: str | None = None,
    ) -> str:
        techniques = ", ".join(
            f"{t['id']}({t['name']})" for t in scenario.get("techniques", [])
        )
        time_range = scenario.get("time_range", {})

        parts = [
            "### 시나리오\n"
            f"- 대상 OS: {scenario.get('target_os', '?')}\n"
            f"- 의심 기법: {techniques or '없음'}\n"
            f"- 분석 기간: {time_range.get('start', '?')} ~ {time_range.get('end', '?')}",
            # 레코드를 JSONL로 준다. 한 줄이 한 레코드라 모델이 경계를
            # 헷갈리지 않고, 토큰도 들여쓰기 JSON보다 적게 든다.
            "### 레코드 ("
            f"{len(records)}건, 이 목록에 없는 ref를 쓰면 기각됩니다{self._trim_notice()})\n"
            + "\n".join(
                json.dumps(for_prompt(record, self.max_list_items), ensure_ascii=False)
                for record in records
            ),
        ]

        if feedback:
            parts.append(
                "### 직전 출력의 문제\n"
                f"{feedback}\n"
                "이 점만 고쳐서 JSON 객체 하나를 다시 출력하십시오."
            )

        parts.append("### 출력")
        return "\n\n".join(parts)

    def prompt_overhead_chars(self, scenario: dict[str, Any]) -> int:
        """레코드를 빼고 프롬프트가 이미 차지하는 글자 수.

        토큰 예산이 레코드에 얼마를 쓸 수 있는지 정할 때 씁니다
        (``allocation.char_budget``). **추정하지 않고 실제로 조립해 잽니다** —
        시스템 프롬프트가 길어지거나 머리말에 줄이 늘면 그만큼 예산이
        자동으로 줄어야 하고, 상수로 적어 두면 그 순간 어긋납니다.

        재시도의 ``feedback`` 은 빠져 있습니다. 길이가 지적 하나만큼이라
        작고, 예산은 첫 시도 기준으로 잡습니다.
        """
        return len(self.system_prompt()) + len(self.user_prompt(scenario, []))

    def propose_findings(
        self,
        scenario: dict[str, Any],
        records: list[dict[str, Any]],
        feedback: str | None = None,
    ) -> dict[str, Any]:
        """모델을 호출해 해석 본문을 받는다.

        스텁 응답은 헤더와 ``input_refs``가 포함된 완성 문서일 수 있으므로
        본문 필드만 골라낸다.
        """
        raw = self.backend.complete(
            self.system_prompt(),
            self.user_prompt(scenario, records, feedback),
            fmt=constrained_schema(scenario, records) if self.constrain else None,
        )
        self.last_raw = raw
        parsed = extract_json(raw)
        return {key: parsed.get(key, []) for key in FINDINGS_BODY_FIELDS}
