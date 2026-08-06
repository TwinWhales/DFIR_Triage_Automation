"""공통 헤더 생성·검증, JSON·JSONL 읽기·쓰기.

단계 간 통신은 파일로만 한다(work-guide 원칙 3). 그 파일을 만들고 읽는
유일한 경로가 이 모듈이다.

주의할 점 두 가지:

1. **줄바꿈을 항상 LF로 고정한다.** Windows에서 ``open(p, "w")``는 ``\\n``을
   ``\\r\\n``으로 바꾼다. JSONL에 CR이 섞이면 리눅스 분석 장비에서 마지막
   필드에 ``\\r``이 달려 들어가 값 비교가 조용히 틀어진다.
2. **쓰기는 원자적으로 한다.** 파싱은 오래 걸리고 실험 중 자주 중단된다.
   반쯤 쓰인 파일이 남으면 다음 실행이 그것을 정상 산출물로 읽는다.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

__all__ = [
    "SCHEMA_VERSION",
    "HEADER_FIELDS",
    "HeaderError",
    "utc_now",
    "make_generator",
    "new_document",
    "check_header",
    "read_json",
    "write_json",
    "read_jsonl",
    "write_jsonl",
    "append_jsonl",
    "count_jsonl",
]

#: 이 값이 다르면 즉시 에러를 낸다. 개발 중 필드가 바뀌는 것을 조용히
#: 흡수하면 어느 버전으로 만든 산출물인지 알 수 없게 된다.
SCHEMA_VERSION = "1.0"

HEADER_FIELDS = ("case_id", "stage", "schema_version", "generated_at", "generator")


class HeaderError(ValueError):
    """공통 헤더 누락 또는 불일치."""


def utc_now() -> str:
    """``"2026-08-06T04:12:33Z"`` 형식의 현재 UTC 시각."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_generator(script: str, model: str | None = None) -> str:
    """``generator`` 필드 값을 규약대로 조립한다.

    LLM을 쓰는 단계는 모델명과 양자화 수준까지 남긴다. 결과 파일만 보고
    실험 조건을 복원할 수 있어야 모델별 비교가 가능하다.

    >>> make_generator("normalize.py", "qwen2.5-7b-instruct-q4")
    'normalize.py / qwen2.5-7b-instruct-q4'
    >>> make_generator("select.py")
    'select.py'
    """
    return f"{script} / {model}" if model else script


def new_document(case_id: str, stage: str, generator: str, **body: Any) -> dict[str, Any]:
    """공통 헤더가 앞에 오는 새 문서를 만든다.

    헤더를 먼저 넣는 이유는 사람이 파일을 열었을 때 첫 다섯 줄로 어느
    케이스의 어느 단계인지 알 수 있어야 하기 때문이다.
    """
    doc: dict[str, Any] = {
        "case_id": case_id,
        "stage": stage,
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "generator": generator,
    }
    doc.update(body)
    return doc


def check_header(
    doc: dict[str, Any],
    *,
    expected_stage: str | None = None,
    expected_case: str | None = None,
    require_generator: bool = True,
) -> None:
    """헤더를 검증한다. 위반 시 ``HeaderError``.

    ``require_generator``가 False인 것은 ``01_input.json`` 때문이다. 사람이나
    수집 스크립트가 만드는 파일이라 생성 주체를 적을 수 없는 경우가 있다.
    """
    required = (
        HEADER_FIELDS
        if require_generator
        else tuple(f for f in HEADER_FIELDS if f != "generator")
    )
    missing = [f for f in required if f not in doc]
    if missing:
        raise HeaderError(f"공통 헤더 누락: {', '.join(missing)}")

    if doc["schema_version"] != SCHEMA_VERSION:
        raise HeaderError(
            f"schema_version 불일치: 파일은 {doc['schema_version']!r}, "
            f"코드는 {SCHEMA_VERSION!r}. 스키마 변경은 전체 공지 대상이다."
        )
    if expected_stage is not None and doc["stage"] != expected_stage:
        raise HeaderError(f"stage 불일치: {doc['stage']!r} (기대값 {expected_stage!r})")
    if expected_case is not None and doc["case_id"] != expected_case:
        raise HeaderError(f"case_id 불일치: {doc['case_id']!r} (기대값 {expected_case!r})")


def read_json(path: str | os.PathLike[str]) -> dict[str, Any]:
    """JSON 문서를 읽는다."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise FileNotFoundError(f"입력 파일 없음: {p}") from None
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"{p}: JSON 파싱 실패 (line {e.lineno} col {e.colno}): {e.msg}"
        ) from None


def write_json(path: str | os.PathLike[str], doc: dict[str, Any]) -> Path:
    """JSON 문서를 원자적으로 쓴다."""
    return _atomic_write(Path(path), json.dumps(doc, ensure_ascii=False, indent=2) + "\n")


def read_jsonl(path: str | os.PathLike[str]) -> Iterator[dict[str, Any]]:
    """JSONL을 한 줄씩 흘려보낸다.

    레코드가 수십만 건이 될 수 있어 전부 메모리에 올리지 않는다.
    깨진 줄은 줄 번호와 함께 보고한다 — 어느 레코드에서 파서가 틀렸는지
    ``docs/artifact-notes.md``에 적으려면 위치가 필요하다.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{p}:{lineno}: JSONL 파싱 실패: {e.msg}") from None


def write_jsonl(path: str | os.PathLike[str], records: Iterable[dict[str, Any]]) -> int:
    """JSONL을 원자적으로 쓰고 기록한 레코드 수를 돌려준다."""
    lines = [json.dumps(r, ensure_ascii=False) for r in records]
    _atomic_write(Path(path), "".join(f"{ln}\n" for ln in lines))
    return len(lines)


def append_jsonl(path: str | os.PathLike[str], record: dict[str, Any]) -> None:
    """JSONL에 한 줄 덧붙인다. ``errors.jsonl``이 이 방식으로 누적된다."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def count_jsonl(path: str | os.PathLike[str]) -> int:
    """레코드 수를 센다. ``_manifest.json``의 ``record_count`` 대조용."""
    return sum(1 for _ in read_jsonl(path))


def _atomic_write(path: Path, text: str) -> Path:
    """같은 디렉터리에 임시 파일로 쓴 뒤 이름을 바꾼다.

    같은 디렉터리를 쓰는 이유는 ``os.replace``가 파일시스템 경계를 넘지
    못하기 때문이다. 시스템 임시 폴더에 만들면 다른 볼륨일 때 실패한다.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path
