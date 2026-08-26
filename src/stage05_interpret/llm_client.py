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

from ..common.llm import Backend, extract_json

__all__ = ["DEFAULT_MODEL", "FINDINGS_BODY_FIELDS", "InterpretClient"]

#: 해석은 정규화보다 무거운 작업이다. 같은 7B로 시작하되 모델별 비교
#: 실험에서 이 단계만 키웠을 때의 효과를 따로 측정한다.
#:
#: ``ollama pull``에 넣을 수 있는 태그를 그대로 쓴다. 02단계와 값이 같아도
#: 상수를 공유하지 않는 것은, 이 단계만 큰 모델로 바꾸는 실험이 잦기 때문이다.
DEFAULT_MODEL = "qwen2.5:7b-instruct-q4_K_M"

PROMPT_DIR = Path(__file__).parent / "prompts"

#: 모델에게 요구하는 필드. ``input_refs``는 **모델에게 묻지 않는다.**
#: 무엇을 전달했는지는 우리가 안다. 모델이 보고하게 하면 실제로 받지
#: 않은 레코드를 목록에 넣어 ref_not_in_input 검사를 무력화할 수 있다.
FINDINGS_BODY_FIELDS = ("findings", "timeline")


class InterpretClient:
    """레코드 → 해석 문장과 claims."""

    def __init__(self, backend: Backend) -> None:
        self.backend = backend
        #: 마지막으로 받은 모델 응답 원문. 실패했을 때 무엇을 뱉었는지
        #: 파일로 떨구기 위한 것이다. 파싱 전에 채우므로 JSON 을 못 찾은
        #: 경우에도 남는다. 성공하면 아무도 읽지 않는다.
        self.last_raw: str | None = None

    @property
    def name(self) -> str:
        return self.backend.name

    def system_prompt(self) -> str:
        return (PROMPT_DIR / "interpret_system.txt").read_text(encoding="utf-8")

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
            f"{len(records)}건, 이 목록에 없는 ref를 쓰면 기각됩니다)\n"
            + "\n".join(json.dumps(record, ensure_ascii=False) for record in records),
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
            self.system_prompt(), self.user_prompt(scenario, records, feedback)
        )
        self.last_raw = raw
        parsed = extract_json(raw)
        return {key: parsed.get(key, []) for key in FINDINGS_BODY_FIELDS}
