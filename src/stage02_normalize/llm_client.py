"""정규화 단계용 LLM 클라이언트.

05단계와 파일이 나뉜 것은 의도된 설계다. 정규화는 짧은 구조화 출력이라
작은 모델로도 되지만 해석은 더 큰 모델이 필요할 수 있다. 두 단계가 서로
다른 모델·파라미터를 쓸 수 있어야 한다.

전송과 응답 파싱은 ``src/common/llm.py``가 맡는다. 여기 있는 것은
**이 단계의 프롬프트와 파라미터**뿐이다.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..common import attack
from ..common.llm import Backend, extract_json

__all__ = ["DEFAULT_MODEL", "NormalizeClient", "SCENARIO_BODY_FIELDS"]

#: 정규화는 짧은 구조화 출력이라 7B 양자화로 충분하다는 가정에서 출발한다.
#: 모델별 비교 실험의 기준선이다.
#:
#: **Ollama 태그를 그대로 쓴다.** ``ollama pull``에 넣을 수 있는 문자열이어야
#: 하고, 이 값이 산출물의 ``generator``에 기록되어 실험 조건을 복원한다.
#: 양자화 수준까지 태그에 들어 있어야 Q4/Q8 비교가 결과 파일만으로 구분된다.
DEFAULT_MODEL = "qwen2.5:7b-instruct-q4_K_M"

PROMPT_DIR = Path(__file__).parent / "prompts"

#: 모델에게 요구하는 필드. 공통 헤더는 스크립트가 붙이므로 모델이
#: 만들 필요가 없다. 모델이 만들게 하면 case_id나 generated_at을
#: 지어내고, 그것이 스키마 위반으로 집계되어 통계를 오염시킨다.
SCENARIO_BODY_FIELDS = (
    "target_os",
    "techniques",
    "time_range",
    "entities",
    "overall_confidence",
    "unmapped_text",
)


class NormalizeClient:
    """자연어 서술 → 시나리오 본문."""

    def __init__(self, backend: Backend, *, few_shot: bool = True) -> None:
        self.backend = backend
        self.few_shot = few_shot
        #: 마지막으로 받은 모델 응답 원문. 실패했을 때 무엇을 뱉었는지
        #: 파일로 떨구기 위한 것이다. 파싱 전에 채우므로 JSON 을 못 찾은
        #: 경우에도 남는다. 성공하면 아무도 읽지 않는다.
        self.last_raw: str | None = None

    @property
    def name(self) -> str:
        return self.backend.name

    def system_prompt(self) -> str:
        base = (PROMPT_DIR / "normalize_system.txt").read_text(encoding="utf-8")
        catalogue = "\n".join(
            f"- {tid}: {name}" for tid, name in sorted(attack.KNOWN_TECHNIQUES.items())
        )
        # 사용 가능한 ID를 프롬프트에 실어 준다. 이것 없이는 모델이
        # 그럴듯한 ID를 지어내고, 그게 가장 흔한 스키마 위반이 된다.
        return f"{base}\n\n## 사용 가능한 기법 목록\n\n{catalogue}\n"

    def user_prompt(self, raw: str, evidence: dict[str, Any], feedback: str | None = None) -> str:
        parts: list[str] = []

        if self.few_shot:
            examples = json.loads((PROMPT_DIR / "normalize_fewshot.json").read_text(encoding="utf-8"))
            for example in examples["examples"]:
                parts.append(f"### 입력\n{example['input']}\n\n### 출력\n"
                             f"{json.dumps(example['output'], ensure_ascii=False, indent=2)}")

        parts.append(
            "### 수집된 증거\n"
            f"- OS: {evidence.get('os_hint', '알 수 없음')}\n"
            f"- 사용 가능한 아티팩트: {', '.join(evidence.get('artifacts_available', [])) or '없음'}"
        )
        parts.append(f"### 입력\n{raw}")

        if feedback:
            # 지적은 한 번에 하나만 준다. 여러 건을 한꺼번에 주면 소형
            # 모델은 대개 더 나빠진다.
            parts.append(
                "### 직전 출력의 문제\n"
                f"{feedback}\n"
                "이 점만 고쳐서 JSON 객체 하나를 다시 출력하십시오."
            )

        parts.append("### 출력")
        return "\n\n".join(parts)

    def propose_scenario(
        self, raw: str, evidence: dict[str, Any], feedback: str | None = None
    ) -> dict[str, Any]:
        """모델을 호출해 시나리오 본문을 받는다.

        스텁 응답은 헤더가 포함된 완성 문서일 수 있으므로, 본문 필드만
        골라낸다. 실제 모델은 본문만 내도록 프롬프트가 지시한다.
        """
        raw_response = self.backend.complete(self.system_prompt(), self.user_prompt(raw, evidence, feedback))
        self.last_raw = raw_response
        parsed = extract_json(raw_response)
        return {key: parsed[key] for key in SCENARIO_BODY_FIELDS if key in parsed}
