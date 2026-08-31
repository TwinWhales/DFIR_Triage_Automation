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

import copy
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Protocol

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
    "output_schema",
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


def output_schema(frozen: dict[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    """동결 스키마에서 **모델이 낼 부분만** 떼어 낸 JSON Schema.

    손으로 다시 쓰지 않는 이유가 있다. 모델에게 요구하는 모양과
    ``schemas/``가 검증하는 모양이 갈라지면, 모델은 시키는 대로 냈는데
    검증에서 떨어지고 그것이 환각률에 집계된다. 원본은 하나여야 한다 —
    ``tools/sync_flag_enum.py``가 ``_flags.yaml``을 원본으로 삼는 것과
    같은 이유다.

    **헤더는 떼어 낸다.** ``case_id``·``stage``·``schema_version``·
    ``generated_at``·``generator``는 우리 코드가 붙이는 값이다. 동결
    스키마를 그대로 넘기면 모델에게 그 다섯을 지어내라고 요구하는 셈이
    된다(05단계는 ``input_refs``가 하나 더 있다).

    ``$defs``는 함께 옮긴다. ``findings``의 ``ref``처럼 ``$ref``로 가리키는
    정의가 있어 빼면 참조가 끊긴다.

    **``pattern``은 걷어낸다.** 이 스키마는 문법으로 변환되려고 존재하는데
    변환기가 정규식을 다 삼키지 못한다(2026-08-31, Ollama 0.32.14 실측):
    앵커 없는 패턴은 ``Pattern must start with``로 아예 거부하고, 앵커가
    있어도 ``\\d``가 들어가면 ``failed to parse grammar``로 400이 온다.
    우리 정규식 둘이 모두 걸린다 — ``^T\\d{4}(\\.\\d{3})?$``와
    ``^\\d{4}-\\d{2}-...Z$``.

    **잃는 것이 없다.** 제약은 얹는 층이고 판정은 여전히 ``schemas/``가
    한다. 모델이 형식을 어긴 값을 내면 ``schema.validate``가 예전 그대로
    잡는다. 여기서 노리는 것은 enum이고, enum은 변환기가 삼킨다.

    호출부가 enum을 꽂아 넣을 수 있도록 **깊은 복사본**을 낸다.
    ``schema.load_schema``는 캐시된 객체를 돌려주므로, 여기서 얕게 넘기면
    한 단계가 꽂은 enum이 검증기가 쓰는 스키마까지 오염시킨다.
    """
    properties = frozen.get("properties", {})
    kept = [name for name in fields if name in properties]
    required = [name for name in kept if name in frozen.get("required", [])]

    built: dict[str, Any] = {
        "type": "object",
        "properties": {name: _without_pattern(properties[name]) for name in kept},
        "required": required,
    }
    if "$defs" in frozen:
        built["$defs"] = _without_pattern(frozen["$defs"])
    return built


def _without_pattern(node: Any) -> Any:
    """``pattern`` 을 뺀 깊은 복사본. 이유는 ``output_schema`` 에 있다."""
    if isinstance(node, dict):
        return {key: _without_pattern(value) for key, value in node.items() if key != "pattern"}
    if isinstance(node, list):
        return [_without_pattern(value) for value in node]
    return copy.deepcopy(node)


class Backend(Protocol):
    """모델 호출 인터페이스.

    ``fmt``는 모델이 낼 수 있는 출력의 **모양**이다(JSON Schema). 주면
    백엔드가 디코딩 단계에서 강제하고, 주지 않으면 예전처럼 프롬프트로만
    부탁한다. 기본값이 ``None``이라 이 인자를 모르는 호출부는 그대로다.

    부탁과 강제는 다르다. ``T1200.001``처럼 형식은 맞고 실재하지 않는 ID는
    프롬프트로 막을 수 없어 ``attack.is_known``이 사후에 잡았는데,
    ``temperature 0``에서는 재시도해도 같은 답이 온다(``limitations.md``의
    2026-08-24 절 ⑤). enum으로 묶으면 그 토큰 자체가 나오지 않는다.
    """

    name: str

    def complete(self, system: str, user: str, *, fmt: "dict[str, Any] | None" = None) -> str: ...


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

    def complete(self, system: str, user: str, *, fmt: "dict[str, Any] | None" = None) -> str:
        #: ``fmt``을 받고 버린다. 리플레이는 기록해 둔 응답을 그대로 내는
        #: 것이라 강제할 디코딩이 없다. 스텁이 스키마를 만족하는지는
        #: 호출부의 ``schema.validate``가 예전처럼 본다 — 여기서 한 번 더
        #: 보면 픽스처가 두 곳을 만족해야 하고, 못 지키는 응답을 일부러
        #: 넣어 두는 실패 경로 테스트가 통과하지 못한다.
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
        timeout: float = DEFAULT_TIMEOUT,
        num_ctx: int = DEFAULT_NUM_CTX,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.name = model

    def payload(
        self, system: str, user: str, *, fmt: "dict[str, Any] | None" = None
    ) -> dict[str, Any]:
        """보낼 요청 본문. 조립과 전송을 나눈 것은 테스트를 위해서다.

        ``format``을 **빈 값일 때 넣지 않는다.** Ollama는 이 키가 있으면
        문법을 컴파일하므로, ``{}``나 ``None``을 넣어 두면 제약이 없는데도
        비용만 붙거나 서버 버전에 따라 거부된다. 제약을 걸지 않기로 한
        실행은 예전과 **바이트 단위로 같은 요청**을 보내야, 켰을 때와 껐을
        때의 차이가 제약 때문임을 말할 수 있다.
        """
        body: dict[str, Any] = {
            "model": self.model,
            "system": system,
            "prompt": user,
            "stream": False,
            "options": {
                # 재현성이 우선이다. 같은 입력에 같은 출력이 나와야
                # 프롬프트 변경의 효과를 측정할 수 있다.
                "temperature": self.temperature,
                # 서버 기본값에 맡기면 프롬프트가 조용히 잘린다.
                "num_ctx": self.num_ctx,
            },
        }
        if fmt:
            body["format"] = fmt
        return body

    def complete(self, system: str, user: str, *, fmt: "dict[str, Any] | None" = None) -> str:
        import requests

        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json=self.payload(system, user, fmt=fmt),
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
            model, host=host, temperature=temperature, timeout=timeout, num_ctx=num_ctx
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
