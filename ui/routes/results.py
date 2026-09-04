from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from ui.evidence_refs import EVIDENCE_FILES


router = APIRouter(
    prefix="/api/results",
    tags=["results"],
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = PROJECT_ROOT / "cases"


def _case_dir(case_id: str) -> Path:
    """Case ID에 해당하는 케이스 디렉터리를 반환한다."""

    safe_case_id = case_id.strip()

    if not safe_case_id:
        raise HTTPException(
            status_code=400,
            detail="Case ID가 비어 있습니다.",
        )

    # 경로 탈출 방지
    if safe_case_id in {".", ".."}:
        raise HTTPException(
            status_code=400,
            detail="잘못된 Case ID입니다.",
        )

    if "/" in safe_case_id or "\\" in safe_case_id:
        raise HTTPException(
            status_code=400,
            detail="Case ID에는 경로 구분자를 사용할 수 없습니다.",
        )

    return CASES_DIR / safe_case_id


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """JSONL 파일을 안전하게 읽는다."""

    events: list[dict[str, Any]] = []

    if not path.exists():
        return events

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            for line_number, line in enumerate(
                file,
                start=1,
            ):
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)

                except json.JSONDecodeError as exc:
                    events.append(
                        {
                            "stage": "ui",
                            "type": "parse_error",
                            "action": "skip",
                            "detail": {
                                "message": (
                                    f"errors.jsonl {line_number}번째 줄을 "
                                    f"JSON으로 읽을 수 없습니다: {exc}"
                                )
                            },
                        }
                    )

                    continue

                if isinstance(event, dict):
                    events.append(event)

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"errors.jsonl을 읽을 수 없습니다: {exc}",
        ) from exc

    return events


def _summarize_errors(
    events: list[dict[str, Any]],
) -> dict[str, int]:
    """Errors 패널에서 사용할 action별 집계를 만든다."""

    retry = 0
    skip = 0
    abort = 0

    for event in events:
        action = event.get("action")

        if action == "retry":
            retry += 1

        elif action == "skip":
            skip += 1

        elif action == "abort":
            abort += 1

    return {
        "total": len(events),
        "retry": retry,
        "skip": skip,
        "abort": abort,
    }


def _evidence_prefix(ref: str) -> str:
    """
    Evidence Ref에서 prefix를 추출한다.

    예:
        USN#503461160
        → USN

        REG-SYS#9735092
        → REG-SYS
    """

    if "#" not in ref:
        raise HTTPException(
            status_code=400,
            detail="올바르지 않은 Evidence Ref입니다.",
        )

    prefix, identifier = ref.split(
        "#",
        maxsplit=1,
    )

    prefix = prefix.strip().upper()
    identifier = identifier.strip()

    if not prefix or not identifier:
        raise HTTPException(
            status_code=400,
            detail="올바르지 않은 Evidence Ref입니다.",
        )

    return prefix


def _find_evidence_record(
    jsonl_path: Path,
    ref: str,
) -> tuple[dict[str, Any] | None, int | None]:
    """
    Stage 04 JSONL 파일을 한 줄씩 읽으면서
    ref가 일치하는 원본 레코드를 찾는다.

    대용량 JSONL 전체를 메모리에 올리지 않는다.
    """

    if not jsonl_path.exists():
        return None, None

    try:
        with jsonl_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            for line_number, line in enumerate(
                file,
                start=1,
            ):
                line = line.strip()

                if not line:
                    continue

                try:
                    record = json.loads(line)

                except json.JSONDecodeError:
                    # 일부 손상된 레코드가 있어도
                    # Evidence 조회 전체를 중단하지 않는다.
                    continue

                if not isinstance(record, dict):
                    continue

                if record.get("ref") == ref:
                    return record, line_number

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Evidence JSONL을 읽을 수 없습니다: {exc}",
        ) from exc

    return None, None


@router.get("/{case_id}/errors")
async def get_errors(
    case_id: str,
) -> dict[str, Any]:
    """한 케이스의 errors.jsonl 내용을 반환한다."""

    case_dir = _case_dir(case_id)

    if not case_dir.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Case를 찾을 수 없습니다: {case_id}",
        )

    errors_path = case_dir / "errors.jsonl"

    events = _read_jsonl(
        errors_path
    )

    summary = _summarize_errors(
        events
    )

    return {
        "case_id": case_id,
        "exists": errors_path.exists(),
        "summary": summary,
        "events": events,
    }


@router.get("/{case_id}/report")
async def get_report(
    case_id: str,
) -> dict[str, Any]:
    """한 케이스의 07_report.md 내용을 반환한다."""

    case_dir = _case_dir(case_id)

    if not case_dir.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Case를 찾을 수 없습니다: {case_id}",
        )

    report_path = case_dir / "07_report.md"

    if not report_path.exists():
        return {
            "case_id": case_id,
            "exists": False,
            "filename": "07_report.md",
            "content": "",
        }

    try:
        content = report_path.read_text(
            encoding="utf-8"
        )

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"07_report.md를 읽을 수 없습니다: {exc}",
        ) from exc

    return {
        "case_id": case_id,
        "exists": True,
        "filename": report_path.name,
        "content": content,
    }


@router.get("/{case_id}/evidence/{ref}")
async def get_evidence(
    case_id: str,
    ref: str,
) -> dict[str, Any]:
    """
    Evidence Ref를 이용하여
    Stage 04 원본 레코드를 조회한다.

    지원 Ref는 ``ui/evidence_refs.py`` 가 ``src/common/refs.py`` 에서
    유도한다 — 여기 목록을 적지 않는다. 04단계가 만드는 아티팩트가
    늘면 함께 늘어난다.
    """

    case_dir = _case_dir(case_id)

    if not case_dir.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Case를 찾을 수 없습니다: {case_id}",
        )

    safe_ref = ref.strip()

    if not safe_ref:
        raise HTTPException(
            status_code=400,
            detail="Evidence Ref가 비어 있습니다.",
        )

    prefix = _evidence_prefix(
        safe_ref
    )

    filename = EVIDENCE_FILES.get(
        prefix
    )

    if filename is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"지원하지 않는 Evidence Ref입니다: "
                f"{safe_ref}"
            ),
        )

    parsed_dir = (
        case_dir
        / "04_parsed"
    )

    if not parsed_dir.exists():
        raise HTTPException(
            status_code=404,
            detail="Stage 04 분석 결과를 찾을 수 없습니다.",
        )

    jsonl_path = (
        parsed_dir
        / filename
    )

    if not jsonl_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"{safe_ref}에 필요한 "
                f"{filename} 파일이 존재하지 않습니다."
            ),
        )

    record, line_number = _find_evidence_record(
        jsonl_path,
        safe_ref,
    )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Evidence Ref를 찾을 수 없습니다: "
                f"{safe_ref}"
            ),
        )

    return {
        "case_id": case_id,
        "ref": safe_ref,
        "artifact": record.get("artifact"),
        "source_file": filename,
        "line_number": line_number,
        "record": record,
    }