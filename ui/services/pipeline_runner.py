from __future__ import annotations

import re
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ui.services.progress import detect_stage


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PYTHON_EXE = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
LIVE_CHECK = PROJECT_ROOT / "tools" / "live_check.py"


@dataclass
class AnalysisState:
    case_id: str

    status: str = "ready"
    current_stage: str | None = None
    return_code: int | None = None

    logs: list[str] = field(default_factory=list)

    stages: dict[str, str] = field(
        default_factory=lambda: {
            "01": "waiting",
            "02": "waiting",
            "03": "waiting",
            "04": "waiting",
            "05": "waiting",
            "06": "waiting",
            "07": "waiting",
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

                # 같은 Volume index가 중복으로 들어가는 것 방지
                already_exists = any(
                    item["index"] == candidate["index"]
                    for item in state.volume_candidates
                )

                if not already_exists:
                    state.volume_candidates.append(candidate)

        process.wait()

        state.return_code = process.returncode

        if process.returncode == 0:

            for stage in state.stages:
                if state.stages[stage] == "running":
                    state.stages[stage] = "done"

            state.status = "completed"

            self._append_log(
                state,
                "[8vidence] Analysis completed.",
            )

            return

        # Volume 후보가 발견된 경우에는 일반 실패와 구분
        if state.volume_candidates:
            state.status = "volume_required"

            if state.current_stage is not None:
                if state.stages.get(state.current_stage) == "running":
                    state.stages[state.current_stage] = "waiting"

            self._append_log(
                state,
                "[8vidence] NTFS 볼륨 선택이 필요합니다.",
            )

            return

        # 일반 실패
        state.status = "failed"

        if state.current_stage is not None:
            if state.stages.get(state.current_stage) == "running":
                state.stages[state.current_stage] = "failed"

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

        if (
            previous is not None
            and previous != stage
            and state.stages.get(previous) == "running"
        ):
            state.stages[previous] = "done"

        state.current_stage = stage

        if state.stages.get(stage) != "done":
            state.stages[stage] = "running"

    def _append_log(
        self,
        state: AnalysisState,
        line: str,
    ) -> None:

        state.logs.append(line)

        # 브라우저에 로그를 계속 전달하므로
        # 메모리가 무한히 증가하지 않도록 제한
        if len(state.logs) > 3000:
            state.logs = state.logs[-3000:]


pipeline_runner = PipelineRunner()


def state_to_dict(
    state: AnalysisState,
) -> dict[str, Any]:

    return {
        "case_id": state.case_id,
        "status": state.status,
        "current_stage": state.current_stage,
        "return_code": state.return_code,
        "stages": state.stages,
        "volume_candidates": state.volume_candidates,
        "logs": state.logs,
        "error": state.error,
    }