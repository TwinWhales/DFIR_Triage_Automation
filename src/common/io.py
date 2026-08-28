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
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

__all__ = [
    "SCHEMA_VERSION",
    "HEADER_FIELDS",
    "TIMESTAMP_PATTERN",
    "HeaderError",
    "utc_now",
    "parse_timestamp",
    "normalize_path",
    "make_generator",
    "new_document",
    "check_header",
    "read_json",
    "write_json",
    "read_jsonl",
    "write_jsonl",
    "append_jsonl",
    "count_jsonl",
    "JsonlEncodeError",
    "DuplicateRefError",
    "read_parsed_records",
    "configure_console",
]


def configure_console() -> None:
    """표준 출력을 UTF-8로 바꾼다. 각 단계 CLI가 시작할 때 부른다.

    Windows 콘솔 기본 코드페이지(cp949)는 한글은 처리하지만 em dash 같은
    문자에서 ``UnicodeEncodeError``로 죽는다. 진행 상황을 찍다가 파이프라인이
    멈추는 것은 어이없는 실패다.

    ``errors="replace"``를 두는 것은 콘솔 출력이 실패해도 실행은 계속되어야
    하기 때문이다. 파일 출력은 항상 UTF-8이므로 산출물에는 영향이 없다.
    """
    import sys

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass

#: 이 값이 다르면 즉시 에러를 낸다. 개발 중 필드가 바뀌는 것을 조용히
#: 흡수하면 어느 버전으로 만든 산출물인지 알 수 없게 된다.
SCHEMA_VERSION = "1.0"

HEADER_FIELDS = ("case_id", "stage", "schema_version", "generated_at", "generator")


class HeaderError(ValueError):
    """공통 헤더 누락 또는 불일치."""


#: 초 이하 자릿수를 제한하지 않는다. NTFS는 100ns 단위라 7자리가 오는데
#: ``datetime``은 마이크로초(6자리)까지만 담는다. 남는 자리는 버린다.
TIMESTAMP_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ]"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)


def utc_now() -> str:
    """``"2026-08-06T04:12:33Z"`` 형식의 현재 UTC 시각."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value: Any) -> datetime | None:
    """ISO 8601 문자열을 UTC ``datetime``으로. 형식이 아니면 ``None``.

    파이프라인 전체가 이 형식으로 시각을 주고받으므로 파서도 한 곳에
    둔다. 05단계의 레코드 정렬과 06단계의 값 비교가 같은 규칙을 써야
    "정렬은 됐는데 비교는 안 되는" 상황이 생기지 않는다.

    타임존이 없으면 UTC로 간주한다. 스키마가 Z 표기를 강제하므로
    파이프라인 내부 데이터에서는 안전한 가정이다.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    m = TIMESTAMP_PATTERN.match(value.strip())
    if not m:
        return None

    frac = (m.group("frac") or "")[:6].ljust(6, "0")
    parsed = datetime.fromisoformat(f"{m.group('date')}T{m.group('time')}.{frac}")

    tz = m.group("tz")
    if tz in (None, "Z"):
        return parsed.replace(tzinfo=timezone.utc)
    digits = tz[1:].replace(":", "")
    offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
    return parsed.replace(tzinfo=timezone(offset if tz[0] == "+" else -offset))


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


def normalize_path(value: str) -> str:
    """경로를 비교 가능한 형태로 만든다. 대소문자와 구분자를 정규화한다.

    NTFS는 대소문자를 구별하지 않고, 같은 경로가 ``\\``와 ``/`` 양쪽으로
    표기된다. 이것은 정책이 아니라 **파일시스템의 사실**이므로 04단계의
    범위 매칭과 06단계의 값 비교가 같은 규칙을 써야 한다.

    끝의 구분자도 떼어 ``C:\\dir``과 ``C:/dir/``를 같게 본다.
    """
    normalized = value.replace("\\", "/").lower()
    stripped = normalized.rstrip("/")
    # "/" 하나만 있던 경우까지 빈 문자열로 만들지는 않는다.
    return stripped or normalized


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


class JsonlEncodeError(ValueError):
    """JSONL 한 줄을 UTF-8로 쓸 수 없다. **어느 레코드인지 함께 든다.**

    맨 ``UnicodeEncodeError``는 "position 112" 같은 말만 해서, 수십만 건
    중 어느 레코드가 원인인지 알 수 없다. 게다가 ``write_jsonl``이
    임시 파일을 지우므로 산출물이 통째로 사라져 되짚을 것도 남지 않는다.

    **여기 담는 값은 전부 ASCII로 안전하게 만든다.** 원인이 인코딩할 수
    없는 문자열인데 그것을 그대로 담으면, 이 오류를 ``errors.jsonl``에
    기록하는 ``append_jsonl``이 같은 이유로 또 터진다.
    """

    def __init__(self, *, path: Path, index: int, ref: Any, field: str, reason: str) -> None:
        self.path = path
        #: 0부터 센 레코드 순번. 파일이 안 남으므로 줄 번호로는 못 찾는다.
        self.index = index
        self.ref = ref
        #: 인코딩할 수 없는 값이 있던 자리. 못 찾으면 ``"<record>"``.
        self.field = field
        self.reason = reason
        super().__init__(
            f"{path.name}: {index}번째 레코드(ref={ref})의 {field} 를 UTF-8로 쓸 수 없습니다 — {reason}"
        )

    def as_detail(self) -> dict[str, Any]:
        """``ErrorLog.record(detail=...)`` 에 그대로 넘길 수 있는 형태."""
        return {
            "field": self.field,
            "value": {"ref": self.ref, "record_index": self.index, "file": self.path.name},
            "message": self.reason,
        }


def _unencodable_field(record: dict[str, Any]) -> "tuple[str, str]":
    """인코딩할 수 없는 값이 어느 키에 있는지 찾는다.

    오류 경로에서만 부른다. 한 단계 아래(``fields`` 안)까지 본다 — 파서가
    자유 형식으로 싣는 자리가 거기라 실제로 자주 걸리는 곳이다.

    돌려주는 것은 **키 이름과 ASCII로 안전한 표현**이다. 원본 문자열을
    그대로 돌려주면 이것을 기록하다 다시 터진다.
    """
    def probe(value: Any) -> "str | None":
        if not isinstance(value, str):
            return None
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            # ascii(...) 는 서로게이트도 \udcff 형태로 escape 해 준다.
            return ascii(value)
        return None

    for key, value in record.items():
        found = probe(value)
        if found is not None:
            return key, found
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                found = probe(sub_value)
                if found is not None:
                    return f"{key}.{sub_key}", found
    return "<record>", "(어느 키인지 찾지 못했습니다)"


def write_jsonl(path: str | os.PathLike[str], records: Iterable[dict[str, Any]]) -> int:
    """JSONL을 원자적으로 쓰고 기록한 레코드 수를 돌려준다.

    한 줄씩 흘려 쓴다. ``$MFT``는 레코드가 수십만 건이라 전부 문자열로
    모으면 수백 MB가 된다. 원자성은 임시 파일 + rename으로 유지한다.

    **바이너리로 열고 줄마다 직접 인코딩한다.** 텍스트 모드로 열면
    인코딩이 버퍼 안쪽에서 일어나, 실패가 어느 레코드에서 났는지 알 수
    없고 flush 시점까지 미뤄질 수도 있다. 여기서 직접 하면 실패한 레코드를
    정확히 짚어 ``JsonlEncodeError``로 올릴 수 있다. 인코딩 횟수는 그대로다.

    UTF-8로 쓸 수 없는 문자열이 오는 경로는 실재한다 — NTFS 이름은 짝 없는
    서로게이트를 허용한다(``parsers/usnjrnl.py``). 파서가 걸러 내는 것이
    1차이고 이것은 2차 방어다. **삼키지 않는다.**
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    written = 0
    try:
        with os.fdopen(fd, "wb") as fh:
            for record in records:
                line = json.dumps(record, ensure_ascii=False) + "\n"
                try:
                    payload = line.encode("utf-8")
                except UnicodeEncodeError as e:
                    field, shown = _unencodable_field(record)
                    raise JsonlEncodeError(
                        path=target,
                        index=written,
                        ref=record.get("ref"),
                        field=field,
                        reason=f"{e.reason} — 값 {shown}",
                    ) from e
                fh.write(payload)
                written += 1
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return written


def append_jsonl(path: str | os.PathLike[str], record: dict[str, Any]) -> None:
    """JSONL에 한 줄 덧붙인다. ``errors.jsonl``이 이 방식으로 누적된다."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def count_jsonl(path: str | os.PathLike[str]) -> int:
    """레코드 수를 센다. ``_manifest.json``의 ``record_count`` 대조용."""
    return sum(1 for _ in read_jsonl(path))


class DuplicateRefError(ValueError):
    """같은 ref를 가진 레코드가 둘 이상이다. 파서 쪽 결함이다."""


def read_parsed_records(directory: str | os.PathLike[str]) -> dict[str, dict[str, Any]]:
    """``04_parsed/*.jsonl``을 전부 읽어 ref로 색인한다.

    05단계(전달할 레코드 추림)와 06단계(근거 대조)가 같은 방식으로 읽어야
    하므로 공용에 둔다. 한쪽만 다르게 읽으면 ``input_refs``와 검증 대상이
    어긋나 환각률이 엉뚱하게 나온다.

    ref가 겹치면 즉시 실패한다. 조용히 덮어쓰면 검증이 어느 레코드를
    봤는지 알 수 없게 되고, 판정이 파일 읽는 순서에 좌우된다.
    """
    root = Path(directory)
    if not root.is_dir():
        raise NotADirectoryError(f"파싱 결과 디렉터리 없음: {root}")

    records: dict[str, dict[str, Any]] = {}
    sources: dict[str, str] = {}
    for path in sorted(root.glob("*.jsonl")):
        for record in read_jsonl(path):
            ref = record.get("ref")
            if ref is None:
                raise ValueError(f"{path}: ref 없는 레코드")
            if ref in records:
                raise DuplicateRefError(
                    f"ref 중복: {ref} ({sources[ref]}, {path.name}). "
                    "레코드 번호는 아티팩트 내부에서 고유해야 한다."
                )
            records[ref] = record
            sources[ref] = path.name
    return records


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
