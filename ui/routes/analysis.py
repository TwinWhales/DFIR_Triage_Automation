from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ui.services.pipeline_runner import (
    pipeline_runner,
    state_to_dict,
)


router = APIRouter(
    prefix="/api/analysis",
    tags=["analysis"],
)


class AnalysisStartRequest(BaseModel):
    case_id: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    raw: str = Field(min_length=1)

    model: str = "qwen2.5:7b"

    volume: int | None = None
    force: bool = False


@router.post("/start")
async def start_analysis(
    request: AnalysisStartRequest,
):
    case_id = request.case_id.strip()
    evidence = request.evidence.strip()
    raw = request.raw.strip()
    model = request.model.strip()

    evidence_path = Path(evidence)

    if not evidence_path.exists():
        raise HTTPException(
            status_code=400,
            detail="Evidence Path가 존재하지 않습니다.",
        )

    # --force는 Volume을 실제로 선택한 재실행에서만 허용
    if request.force and request.volume is None:
        raise HTTPException(
            status_code=400,
            detail="Volume이 선택되지 않은 상태에서는 force 재실행을 사용할 수 없습니다.",
        )

    try:
        state = pipeline_runner.start(
            case_id=case_id,
            evidence=evidence,
            raw=raw,
            model=model,
            volume=request.volume,
            force=request.force,
        )

    except RuntimeError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc

    return state_to_dict(state)


@router.get("/{case_id}/status")
async def analysis_status(
    case_id: str,
):
    state = pipeline_runner.get_state(case_id)

    if state is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown case: {case_id}",
        )

    return state_to_dict(state)