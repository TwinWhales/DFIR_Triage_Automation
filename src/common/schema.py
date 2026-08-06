"""JSON Schema 로드 및 검증 래퍼.

각 단계 스크립트는 시작 시 입력을, 종료 시 출력을 이 모듈로 검증한다.
검증 실패는 ``errors.jsonl``에 기록 후 비정상 종료한다.

위반 위치를 ``techniques[0].id`` 형태로 만들어 주는 것이 이 래퍼의 핵심이다.
``errors.jsonl``의 ``detail.field``가 그 형식이어야 "어떤 필드에서 sLLM이 자주
틀리는가"를 집계할 수 있다. jsonschema가 주는 deque를 그대로 넣으면 집계가
불가능하다.
"""

from __future__ import annotations

import functools
import os
from pathlib import Path
from typing import Any, Iterator

import jsonschema

__all__ = [
    "SchemaViolation",
    "STAGE_SCHEMA",
    "schema_dir",
    "load_schema",
    "validate",
    "iter_violations",
    "validate_stage",
]


class SchemaViolation(ValueError):
    """스키마 위반 한 건.

    ``field``/``value``/``message``를 그대로 ``errors.jsonl``의 ``detail``에
    넣을 수 있게 구성했다.
    """

    def __init__(self, field: str, value: Any, message: str, schema_name: str = "") -> None:
        self.field = field
        self.value = value
        self.message = message
        self.schema_name = schema_name
        where = f"{schema_name}: " if schema_name else ""
        super().__init__(f"{where}{field}: {message} (값: {value!r})")

    def as_detail(self) -> dict[str, Any]:
        """``ErrorLog.record(detail=...)`` 에 그대로 넘길 수 있는 형태."""
        return {"field": self.field, "value": self.value, "message": self.message}


#: 공통 헤더의 ``stage`` 값 → 스키마 파일 이름.
STAGE_SCHEMA: dict[str, str] = {
    "01_input": "input",
    "02_normalize": "scenario",
    "03_select": "selection",
    "05_interpret": "findings",
    "06_verify": "verified",
}


def schema_dir() -> Path:
    """``schemas/`` 위치. ``DFIR_SCHEMA_DIR`` 환경변수로 덮어쓸 수 있다."""
    override = os.environ.get("DFIR_SCHEMA_DIR")
    if override:
        return Path(override)
    # src/common/schema.py → src/common → src → <repo root>
    return Path(__file__).resolve().parents[2] / "schemas"


@functools.lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    """``schemas/<name>.schema.json``을 읽는다. 결과는 캐시된다."""
    path = schema_dir() / f"{name}.schema.json"
    if not path.is_file():
        available = sorted(p.name for p in schema_dir().glob("*.schema.json"))
        raise FileNotFoundError(f"스키마 없음: {path} (있는 것: {', '.join(available)})")
    import json

    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError(f"스키마 파일이 비어 있음: {path}")
    return json.loads(text)


def _format_path(parts: Any) -> str:
    """jsonschema의 경로 deque를 ``techniques[0].id`` 형태로 만든다."""
    out = ""
    for part in parts:
        if isinstance(part, int):
            out += f"[{part}]"
        elif out:
            out += f".{part}"
        else:
            out = str(part)
    return out or "<root>"


def iter_violations(doc: Any, name: str) -> Iterator[SchemaViolation]:
    """위반을 전부 훑는다. 위반이 없으면 아무것도 내지 않는다."""
    validator = jsonschema.Draft202012Validator(load_schema(name))
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        yield SchemaViolation(
            field=_format_path(err.absolute_path),
            value=err.instance,
            message=err.message,
            schema_name=name,
        )


def validate(doc: Any, name: str) -> None:
    """첫 위반에서 ``SchemaViolation``을 던진다.

    첫 건만 던지는 이유는 재시도 프롬프트에 넣을 지적이 하나여야 sLLM이
    그것을 고치기 때문이다. 열 건을 한꺼번에 주면 대개 더 나빠진다.
    전수 목록이 필요하면 ``iter_violations``를 쓴다.
    """
    for violation in iter_violations(doc, name):
        raise violation


def validate_stage(doc: dict[str, Any]) -> None:
    """문서의 ``stage`` 값을 보고 알맞은 스키마로 검증한다."""
    stage = doc.get("stage")
    if stage not in STAGE_SCHEMA:
        raise SchemaViolation(
            field="stage",
            value=stage,
            message=f"검증 스키마가 없는 단계 (등록된 값: {', '.join(sorted(STAGE_SCHEMA))})",
        )
    validate(doc, STAGE_SCHEMA[stage])
