from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ui.services.progress import detect_stage


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PYTHON_EXE = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
LIVE_CHECK = PROJECT_ROOT / "tools" / "live_check.py"


STAGE_IDS = (
    "01",
    "02",
    "03",
    "04",
    "05",
    "06",
    "07",
)


@dataclass
class AnalysisState:
    case_id: str

    status: str = "ready"
    current_stage: str | None = None
    return_code: int | None = None

    logs: list[str] = field(default_factory=list)

    stages: dict[str, str] = field(
        default_factory=lambda: {
            stage: "waiting"
            for stage in STAGE_IDS
        }
    )

    # Stage별 시작 시각
    stage_started_at: dict[str, float | None] = field(
        default_factory=lambda: {
            stage: None
            for stage in STAGE_IDS
        }
    )

    # Stage별 종료 시각
    stage_completed_at: dict[str, float | None] = field(
        default_factory=lambda: {
            stage: None
            for stage in STAGE_IDS
        }
    )

    # Stage별 확정 소요시간(초)
    stage_elapsed_seconds: dict[str, float | None] = field(
        default_factory=lambda: {
            stage: None
            for stage in STAGE_IDS
        }
    )

    volume_candidates: list[dict[str, str | int]] = field(
        default_factory=list
    )

    error: str | None = None


class PipelineRunner:
    def __init__(self) -> None:
        self._states: dict[str, AnalysisState] = {}
        self._lock = threading.Lock()

    def get_state(
        self,
        case_id: str,
    ) -> AnalysisState | None:
        with self._lock:
            return self._states.get(case_id)

    def start(
        self,
        *,
        case_id: str,
        evidence: str,
        raw: str,
        model: str,
        volume: int | None = None,
        force: bool = False,
    ) -> AnalysisState:

        with self._lock:
            existing = self._states.get(case_id)

            if existing and existing.status == "running":
                raise RuntimeError(
                    f"Case {case_id} is already running."
                )

            state = AnalysisState(
                case_id=case_id,
                status="running",
            )

            self._states[case_id] = state

        thread = threading.Thread(
            target=self._run,
            kwargs={
                "state": state,
                "case_id": case_id,
                "evidence": evidence,
                "raw": raw,
                "model": model,
                "volume": volume,
                "force": force,
            },
            daemon=True,
        )

        thread.start()

        return state

    def _run(
        self,
        *,
        state: AnalysisState,
        case_id: str,
        evidence: str,
        raw: str,
        model: str,
        volume: int | None,
        force: bool,
    ) -> None:

        cmd = [
            str(PYTHON_EXE),
            "-u",
            str(LIVE_CHECK),
            "--case-id",
            case_id,
            "--evidence",
            evidence,
            "--raw",
            raw,
            "--model",
            model,
        ]

        if volume is not None:
            cmd += [
                "--volume",
                str(volume),
            ]

        if force:
            cmd.append("--force")

        self._append_log(
            state,
            "실행 명령: " + " ".join(cmd),
        )

        try:
            process = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )

        except Exception as exc:
            state.status = "failed"
            state.error = str(exc)

            self._append_log(
                state,
                f"[ERROR] subprocess 실행 실패: {exc}",
            )

            return

        assert process.stdout is not None

        for raw_line in process.stdout:
            line = raw_line.rstrip()

            if not line:
                continue

            self._append_log(
                state,
                line,
            )

            # 현재 DFIR Stage 감지
            stage = detect_stage(line)

            if stage is not None:
                self._set_running_stage(
                    state,
                    stage,
                )

            # 다중 NTFS Volume 후보 감지
            volume_match = re.search(
                r"--volume\s+(\d+)\s{2,}(.+?)\s{2,}(.+)$",
                line,
            )

            if volume_match:
                candidate = {
                    "index": int(volume_match.group(1)),
                    "size": volume_match.group(2).strip(),
                    "name": volume_match.group(3).strip(),
                }

                # 같은 Volume index가 중복으로 들어가는 것을 방지
                already_exists = any(
                    item["index"] == candidate["index"]
                    for item in state.volume_candidates
                )

                if not already_exists:
                    state.volume_candidates.append(candidate)

        process.wait()

        state.return_code = process.returncode

        if process.returncode == 0:

            # 마지막으로 실행 중이던 Stage의 시간 확정
            self._finish_current_stage(
                state,
                final_status="done",
            )

            state.status = "completed"

            self._append_log(
                state,
                "[8vidence] Analysis completed.",
            )

            return

        # Volume 후보가 발견된 경우 일반 실패와 구분
        if state.volume_candidates:

            # 볼륨 선택 전까지 진행했던 Stage의 시간은
            # 이번 시도에서 완료된 것으로 확정하지 않는다.
            current_stage = state.current_stage

            if current_stage is not None:
                if state.stages.get(current_stage) == "running":
                    state.stages[current_stage] = "waiting"

                    state.stage_started_at[current_stage] = None
                    state.stage_completed_at[current_stage] = None
                    state.stage_elapsed_seconds[current_stage] = None

            state.current_stage = None
            state.status = "volume_required"

            self._append_log(
                state,
                "[8vidence] NTFS 볼륨 선택이 필요합니다.",
            )

            return

        # 일반 실패
        self._finish_current_stage(
            state,
            final_status="failed",
        )

        state.status = "failed"

        self._append_log(
            state,
            f"[8vidence] Analysis failed. return code={process.returncode}",
        )

    def _set_running_stage(
        self,
        state: AnalysisState,
        stage: str,
    ) -> None:

        previous = state.current_stage

        # 이전 Stage에서 다음 Stage로 넘어온 순간
        # 이전 Stage의 실행시간을 확정한다.
        if (
            previous is not None
            and previous != stage
            and state.stages.get(previous) == "running"
        ):
            self._finish_stage(
                state,
                previous,
                final_status="done",
            )

        state.current_stage = stage

        if state.stages.get(stage) != "done":

            # 최초 진입 시에만 시작 시각 기록
            if state.stage_started_at.get(stage) is None:
                state.stage_started_at[stage] = time.monotonic()

            state.stages[stage] = "running"

    def _finish_stage(
        self,
        state: AnalysisState,
        stage: str,
        *,
        final_status: str,
    ) -> None:

        now = time.monotonic()

        started_at = state.stage_started_at.get(stage)

        if started_at is not None:
            state.stage_completed_at[stage] = now
            state.stage_elapsed_seconds[stage] = max(
                0.0,
                now - started_at,
            )

        state.stages[stage] = final_status

    def _finish_current_stage(
        self,
        state: AnalysisState,
        *,
        final_status: str,
    ) -> None:

        stage = state.current_stage

        if stage is None:
            return

        if state.stages.get(stage) != "running":
            return

        self._finish_stage(
            state,
            stage,
            final_status=final_status,
        )

    def _append_log(
        self,
        state: AnalysisState,
        line: str,
    ) -> None:

        state.logs.append(line)

        # 브라우저에 로그를 계속 전달하되
        # 메모리가 무한히 증가하지 않도록 제한
        if len(state.logs) > 3000:
            state.logs = state.logs[-3000:]


pipeline_runner = PipelineRunner()


def state_to_dict(
    state: AnalysisState,
) -> dict[str, Any]:

    now = time.monotonic()

    stage_details: dict[str, dict[str, Any]] = {}

    for stage in STAGE_IDS:

        status = state.stages[stage]
        elapsed_seconds = state.stage_elapsed_seconds.get(stage)

        # 현재 실행 중인 Stage는 아직 종료되지 않았으므로
        # API를 조회하는 현재 시점까지의 경과시간을 계산한다.
        if status == "running":
            started_at = state.stage_started_at.get(stage)

            if started_at is not None:
                elapsed_seconds = max(
                    0.0,
                    now - started_at,
                )

        stage_details[stage] = {
            "status": status,
            "elapsed_seconds": (
                round(elapsed_seconds, 1)
                if elapsed_seconds is not None
                else None
            ),
        }

    return {
        "case_id": state.case_id,
        "status": state.status,
        "current_stage": state.current_stage,
        "return_code": state.return_code,

        # 기존 프론트엔드 호환성을 위해 유지
        "stages": state.stages,

        # 단계별 상태 + 소요시간
        "stage_details": stage_details,

        "volume_candidates": state.volume_candidates,
        "logs": state.logs,
        "error": state.error,
    }