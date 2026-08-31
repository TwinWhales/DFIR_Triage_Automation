"""sLLM 호출 전송 계층과 응답 파싱.

각 단계의 ``llm_client.py``가 이 위에 얹힌다. 단계별로 다른 모델·파라미터를
쓰는 것은 의도된 설계이므로 **설정은 각 단계가 들고**, 여기에는 전송과
응답 파싱만 둔다.

응답 파싱이 별도 관심사인 이유가 있다. 소형 모델은 JSON만 내라고 해도
코드펜스를 두르거나 앞뒤에 설명을 붙인다. 그것을 파싱 실패로 처리하면
모델이 내용은 맞게 냈는데도 실패로 집계된다. 껍데기를 벗기는 것과
내용이 틀린 것을 구분해야 ``errors.jsonl``의 통계가 의미를 가진다.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Protocol

__all__ = [
    "DEFAULT_NUM_CTX",
    "DEFAULT_TIMEOUT",
    "LLMError",
    "LLMTimeout",
    "MalformedOutput",
    "Backend",
    "StubBackend",
    "OllamaBackend",
    "build_backend",
    "extract_json",
]


#: 모델 응답을 기다리는 기본 상한(초).
#:
#: 각 단계가 ``--timeout``으로 덮어쓴다. 단계마다 프롬프트 크기가 달라
#: 하나로 맞출 수 없다 — 02는 서술 한 문단이고 05는 레코드 수십 건이다.
DEFAULT_TIMEOUT = 120.0


#: 모델에게 열어 줄 컨텍스트 창(토큰).
#:
#: **Ollama에 맡기면 안 된다.** 지정하지 않으면 서버가 자기 기본값
#: (4096)으로 모델을 띄우고, 넘치는 프롬프트를 **말없이 자릅니다.**
#: 05단계는 레코드 수십 건을 실어 보내므로 이 창을 넘기기 쉽고, 잘린
#: 뒤에는 "모델이 그 레코드를 못 봤다"와 "보고도 언급하지 않았다"가
#: 구별되지 않습니다 — 06단계도 잡을 수 없는 층입니다.
#:
#: 값은 모델이 실제로 지원하는 범위 안이어야 합니다. 넘겨도 Ollama가
#: 거부하지 않고 조용히 깎으므로, 바꿀 때는 ``/api/ps``의
#: ``context_length``로 실제 적용값을 확인하십시오.
DEFAULT_NUM_CTX = 32768


class LLMError(RuntimeError):
    """모델 호출 실패."""


class LLMTimeout(LLMError):
    """응답 시간 초과. ``errors.jsonl``의 ``timeout``에 대응한다."""


class MalformedOutput(ValueError):
    """응답에서 JSON을 찾지 못했다. ``malformed_output``에 대응한다."""


class Backend(Protocol):
    """모델 호출 인터페이스."""

    name: str

    def complete(self, system: str, user: str) -> str: ...


class StubBackend:
    """미리 기록해 둔 응답을 돌려준다.

    모델이 준비되지 않은 상태에서 파이프라인 배선을 확인하기 위한 것이다.
    프롬프트 조립·응답 파싱·스키마 검증·재시도까지 실제 경로를 그대로
    지나가고, 네트워크 호출만 대체된다.

    LLM을 먼저 붙이면 파이프라인 버그인지 모델 한계인지 구분되지 않는다.
    선형 경로가 안정된 뒤에 모델을 끼우는 것이 순서다.
    """

    def __init__(self, fixture: str | os.PathLike[str]) -> None:
        self.path = Path(fixture)
        if not self.path.is_file():
            raise LLMError(f"스텁 응답 파일 없음: {self.path}")
        self.name = f"stub({self.path.name})"

    def complete(self, system: str, user: str) -> str:
        return self.path.read_text(encoding="utf-8")


class OllamaBackend:
    """Ollama HTTP API.

    온프레미스 전제이므로 기본 호스트는 localhost다. 증거 데이터가
    외부로 나가면 안 되는 것이 이 프로젝트가 sLLM을 쓰는 이유다.

    ``num_predict``를 주지 않으면 Ollama 기본값(``-1`` — EOS를 낼 때까지)이
    걸린다. 대개는 멈추지만, **안 멈출 때 바닥이 없다.** 소형 모델이 JSON을
    닫지 못하고 맴돌면 붙잡을 것이 타임아웃밖에 없고, 그 시도는 원문도 남기지
    못한다(응답이 아예 오지 않았으므로). 실측(2026-08-31, ``qwen2.5:latest``,
    05단계 프롬프트 16,330토큰): 상한 없이 35분을 기다려도 응답이 없었고,
    상한을 걸자 같은 프롬프트가 37.7초에 끝났다.

    상한은 길이 목표가 아니라 **실패의 종류를 바꾸는 자리**다. 걸어 두면
    맴도는 응답이 "시간 초과"가 아니라 "잘린 응답"으로 돌아오고, 잘린 것은
    원문이 남아 ``malformed_output``으로 기록되고 재시도된다.

    값은 각 단계가 정한다. 정상 출력 길이를 아는 것은 단계 쪽이다.
    """

    def __init__(
        self,
        model: str,
        *,
        host: str = "http://localhost:11434",
        temperature: float = 0.0,
        timeout: float = DEFAULT_TIMEOUT,
        num_ctx: int = DEFAULT_NUM_CTX,
        num_predict: "int | None" = None,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.name = model

    def complete(self, system: str, user: str) -> str:
        import requests

        options: dict[str, Any] = {
            # 재현성이 우선이다. 같은 입력에 같은 출력이 나와야
            # 프롬프트 변경의 효과를 측정할 수 있다.
            "temperature": self.temperature,
            # 서버 기본값에 맡기면 프롬프트가 조용히 잘린다.
            "num_ctx": self.num_ctx,
        }
        if self.num_predict is not None:
            # 상한은 길이 목표가 아니라 **폭주를 끊는 자리**다. 정상 응답의
            # 몇 배로 잡아 두어 정상 응답은 절대 잘리지 않게 한다.
            options["num_predict"] = self.num_predict

        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "system": system,
                    "prompt": user,
                    "stream": False,
                    "options": options,
                },
                timeout=self.timeout,
            )
        except requests.Timeout as e:
            raise LLMTimeout(f"{self.model}: {self.timeout}초 내 응답 없음") from e
        except requests.RequestException as e:
            raise LLMError(f"{self.model}: 호출 실패 — {e}") from e

        if response.status_code != 200:
            raise LLMError(f"{self.model}: HTTP {response.status_code} — {response.text[:200]}")
        return response.json().get("response", "")


def build_backend(
    kind: str,
    *,
    fixture: str | os.PathLike[str] | None = None,
    model: str | None = None,
    host: str = "http://localhost:11434",
    temperature: float = 0.0,
    timeout: float = DEFAULT_TIMEOUT,
    num_ctx: int = DEFAULT_NUM_CTX,
    num_predict: "int | None" = None,
) -> Backend:
    """``--llm`` 값에 따라 백엔드를 만든다."""
    if kind == "stub":
        if fixture is None:
            raise LLMError("stub 백엔드에는 --replay 로 응답 파일을 줘야 한다")
        return StubBackend(fixture)
    if kind == "ollama":
        if not model:
            raise LLMError("ollama 백엔드에는 --model 이 필요하다")
        return OllamaBackend(
            model,
            host=host,
            temperature=temperature,
            timeout=timeout,
            num_ctx=num_ctx,
            num_predict=num_predict,
        )
    raise LLMError(f"알 수 없는 백엔드: {kind!r} (사용 가능: stub, ollama)")


#: ```json ... ``` 또는 ``` ... ``` 코드펜스.
_FENCE = re.compile(r"^\s*```(?:json)?\s*(?P<body>.*?)\s*```\s*$", re.DOTALL)


def extract_json(text: str) -> dict[str, Any]:
    """모델 응답에서 JSON 객체를 꺼낸다.

    세 단계로 시도한다. 앞 단계가 되면 뒤는 하지 않는다.

    1. 그대로 파싱
    2. 코드펜스를 벗기고 파싱
    3. 첫 ``{`` 부터 짝이 맞는 ``}`` 까지를 잘라 파싱

    3번은 모델이 JSON 앞뒤에 설명을 붙였을 때를 위한 것이다. 중괄호
    개수만 세면 문자열 안의 ``{``에 속으므로 따옴표 상태를 함께 본다.
    """
    if not text or not text.strip():
        raise MalformedOutput("응답이 비어 있음")

    for candidate in (text, _strip_fence(text), _first_object(text)):
        if candidate is None:
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
        raise MalformedOutput(f"JSON 최상위가 객체가 아님: {type(parsed).__name__}")

    if "{" in text and _first_object(text) is None:
        # 여는 중괄호는 있는데 짝이 안 맞는다. 모델이 형식을 어긴 것이 아니라
        # 말하다 만 것이다. 둘을 같은 문구로 적으면 프롬프트를 고쳐야 할 일과
        # 상한을 올려야 할 일이 errors.jsonl 에서 구별되지 않는다.
        raise MalformedOutput(
            f"응답이 중간에 잘림 — 여는 중괄호가 닫히지 않음 ({len(text):,}자). "
            "출력 상한(num_predict)이나 컨텍스트가 모자란 것이지 형식 위반이 아니다"
        )
    raise MalformedOutput("응답에서 JSON 객체를 찾지 못함")


def _strip_fence(text: str) -> str | None:
    match = _FENCE.match(text)
    return match.group("body") if match else None


def _first_object(text: str) -> str | None:
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None
