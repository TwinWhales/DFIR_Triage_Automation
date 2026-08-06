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
    "LLMError",
    "LLMTimeout",
    "MalformedOutput",
    "Backend",
    "StubBackend",
    "OllamaBackend",
    "build_backend",
    "extract_json",
]


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
    """

    def __init__(
        self,
        model: str,
        *,
        host: str = "http://localhost:11434",
        temperature: float = 0.0,
        timeout: float = 120.0,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout
        self.name = model

    def complete(self, system: str, user: str) -> str:
        import requests

        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "system": system,
                    "prompt": user,
                    "stream": False,
                    # 재현성이 우선이다. 같은 입력에 같은 출력이 나와야
                    # 프롬프트 변경의 효과를 측정할 수 있다.
                    "options": {"temperature": self.temperature},
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
    timeout: float = 120.0,
) -> Backend:
    """``--llm`` 값에 따라 백엔드를 만든다."""
    if kind == "stub":
        if fixture is None:
            raise LLMError("stub 백엔드에는 --replay 로 응답 파일을 줘야 한다")
        return StubBackend(fixture)
    if kind == "ollama":
        if not model:
            raise LLMError("ollama 백엔드에는 --model 이 필요하다")
        return OllamaBackend(model, host=host, temperature=temperature, timeout=timeout)
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
