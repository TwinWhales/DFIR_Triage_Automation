import os
import sys
import shutil
import subprocess
import threading
import time
import json
import hashlib
from pathlib import Path

from PySide6.QtCore import QThread, Signal


class AnalysisStopped(Exception):
    pass


class PipelineWorker(QThread):

    log = Signal(str)
    progress = Signal(int)
    finished = Signal()
    stopped = Signal()
    error = Signal(str)
    state_changed = Signal(str)
    stage_changed = Signal(str, int)

    STUB_MODE = "테스트 모드 (Stub)"
    OLLAMA_MODE = "실제 AI 분석 (Ollama)"

    OLLAMA_MODEL = "qwen2.5:7b"
    OLLAMA_HOST = "http://localhost:11434"
    OLLAMA_TIMEOUT = 600.0

    def __init__(
        self,
        case_id,
        incident_description,
        evidence_dir,
        mode,
        stage05_limit=15,
        stage02_num_ctx=8192,
        stage05_num_ctx=8192,
        stage05_max_list_items=10,
        use_stage04_cache=True,
        profile_name="빠른 분석",
    ):
        super().__init__()

        self.case_id = case_id.strip()
        self.incident_description = incident_description.strip()
        self.evidence_dir = str(evidence_dir).strip()
        self.mode = mode
        self.stage05_limit = int(stage05_limit)
        self.stage02_num_ctx = int(stage02_num_ctx)
        self.stage05_num_ctx = int(stage05_num_ctx)
        self.stage05_max_list_items = int(stage05_max_list_items)
        self.use_stage04_cache = bool(use_stage04_cache)
        self.profile_name = str(profile_name)

        self._pause_requested = threading.Event()
        self._resume_gate = threading.Event()
        self._resume_gate.set()
        self._stop_requested = threading.Event()
        self._process_lock = threading.Lock()
        self._current_process = None

        self.project_root = Path(__file__).resolve().parent
        self.case_dir = self.project_root / "cases" / self.case_id

        # GUI가 어떤 Python으로 실행되었든 프로젝트 .venv를 우선 사용
        venv_python = (
            self.project_root
            / ".venv"
            / "Scripts"
            / "python.exe"
        )

        if venv_python.exists():
            self.python_exe = str(venv_python)
        else:
            self.python_exe = sys.executable

    # =====================================================
    # Main Pipeline
    # =====================================================

    def run(self):
        try:
            self.state_changed.emit("RUNNING")
            self.log.emit("8vidence 분석을 시작합니다.")
            self.log.emit(f"Case ID : {self.case_id}")
            self.log.emit(f"Incident : {self.incident_description}")
            self.log.emit(f"Evidence : {self.evidence_dir}")
            self.log.emit(f"Mode : {self.mode}")
            self.log.emit(f"Python : {self.python_exe}")

            if self.mode == self.OLLAMA_MODE:
                self.log.emit(
                    f"Ollama : {self.OLLAMA_MODEL} @ {self.OLLAMA_HOST}"
                )
                self.log.emit(
                    f"Profile : {self.profile_name} | "
                    f"Stage02 ctx={self.stage02_num_ctx} | "
                    f"Stage05 ctx={self.stage05_num_ctx}, limit={self.stage05_limit}, "
                    f"max-list-items={self.stage05_max_list_items} | "
                    f"Stage04 cache={'ON' if self.use_stage04_cache else 'OFF'}"
                )

            self.log.emit("-" * 60)

            self.validate_common_inputs()

            if self.mode == self.STUB_MODE:
                self.run_stub_pipeline()

            elif self.mode == self.OLLAMA_MODE:
                self.run_ollama_pipeline()

            else:
                raise ValueError(
                    f"지원하지 않는 분석 모드입니다: {self.mode}"
                )

        except AnalysisStopped:
            self.state_changed.emit("STOPPED")
            self.log.emit("[STOP] 분석이 사용자 요청으로 중지되었습니다.")
            self.stopped.emit()
        except Exception as e:
            self.state_changed.emit("ERROR")
            self.error.emit(str(e))

    # =====================================================
    # Runtime Control
    # =====================================================

    def request_pause(self):
        if self._stop_requested.is_set():
            return
        self._pause_requested.set()
        self._resume_gate.clear()
        self.state_changed.emit("PAUSING")
        self.log.emit("[CONTROL] 일시정지를 요청했습니다. 현재 Stage를 중단한 뒤 체크포인트에서 대기합니다.")
        self._terminate_current_process()

    def request_resume(self):
        if self._stop_requested.is_set():
            return
        self._pause_requested.clear()
        self._resume_gate.set()
        self.state_changed.emit("RUNNING")
        self.log.emit("[CONTROL] 분석을 재개합니다. 중단된 Stage를 다시 실행합니다.")

    def request_stop(self):
        self._stop_requested.set()
        self._pause_requested.clear()
        self._resume_gate.set()
        self.state_changed.emit("STOPPING")
        self.log.emit("[CONTROL] 분석 중지를 요청했습니다.")
        self._terminate_current_process()

    def _terminate_current_process(self):
        with self._process_lock:
            process = self._current_process

        if process is None or process.poll() is not None:
            return

        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            else:
                process.terminate()
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    def _wait_if_paused(self):
        if self._stop_requested.is_set():
            raise AnalysisStopped()

        if not self._pause_requested.is_set():
            return

        self.state_changed.emit("PAUSED")
        self.log.emit("[PAUSED] 분석이 일시정지되었습니다.")

        while self._pause_requested.is_set():
            if self._stop_requested.is_set():
                raise AnalysisStopped()
            self._resume_gate.wait(0.2)

        if self._stop_requested.is_set():
            raise AnalysisStopped()

    # =====================================================
    # Validation
    # =====================================================

    def validate_common_inputs(self):
        if not self.case_id:
            raise ValueError("Case ID를 입력하세요.")

        if not self.incident_description:
            raise ValueError("Incident Description을 입력하세요.")

        if not self.evidence_dir:
            raise ValueError("Evidence Directory를 선택하세요.")

        evidence_path = Path(self.evidence_dir)

        if not evidence_path.exists():
            raise FileNotFoundError(
                f"Evidence Directory를 찾을 수 없습니다.\n"
                f"{evidence_path}"
            )

        self.case_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    # =====================================================
    # Stub Pipeline
    # =====================================================

    def run_stub_pipeline(self):
        if self.case_id != "C-001":
            raise ValueError(
                "현재 테스트 모드(Stub)는 C-001 샘플 케이스만 지원합니다."
            )

        self.log.emit("[MODE] Stub Pipeline")
        self.log.emit("-" * 60)

        # Stage 01
        self.stage_changed.emit("Stage 01 · Case Input", 1)
        self.run_stage01_stub()
        self.progress.emit(10)

        # Stage 02
        self.stage_changed.emit("Stage 02 · Scenario Normalize", 2)
        scenario_file = self.run_stage02_stub()
        self.progress.emit(20)

        # Stage 03
        self.stage_changed.emit("Stage 03 · Artifact Selection", 3)
        selection_file = self.run_stage03(
            scenario_file
        )
        self.progress.emit(35)

        # Stage 04
        self.stage_changed.emit("Stage 04 · Artifact Parsing", 4)
        parsed_dir = self.run_stage04_stub()
        self.progress.emit(55)

        # Stage 05
        self.stage_changed.emit("Stage 05 · Evidence Interpretation", 5)
        findings_file = self.run_stage05_stub()
        self.progress.emit(70)

        # Stage 06
        self.stage_changed.emit("Stage 06 · Evidence Verification", 6)
        verified_file = self.run_stage06(
            findings_file,
            parsed_dir,
        )
        self.progress.emit(85)

        # Stage 07
        self.stage_changed.emit("Stage 07 · Report", 7)
        report_file = self.run_stage07(
            verified_file,
            findings_file,
            selection_file,
            scenario_file,
            parsed_dir,
        )
        self.progress.emit(100)

        self.complete_pipeline(report_file)

    # =====================================================
    # Ollama / Real Pipeline
    # =====================================================

    def run_ollama_pipeline(self):
        self.log.emit("[MODE] 실제 AI 분석 (Ollama)")
        self.log.emit("-" * 60)

        # 이전 실행 결과가 남아 잘못 섞이지 않도록
        # 파이프라인 생성물만 정리한다.
        self.clean_previous_outputs()

        # Stage 01
        self.stage_changed.emit("Stage 01 · Case Input", 1)
        input_file = self.run_stage01_real()
        self.progress.emit(10)

        # Stage 02
        self.stage_changed.emit("Stage 02 · Scenario Normalize", 2)
        scenario_file = self.run_stage02_real(
            input_file
        )
        self.progress.emit(25)

        # Stage 03
        self.stage_changed.emit("Stage 03 · Artifact Selection", 3)
        selection_file = self.run_stage03(
            scenario_file
        )
        self.progress.emit(35)

        # Stage 04
        self.stage_changed.emit("Stage 04 · Artifact Parsing", 4)
        parsed_dir = self.run_stage04_real(
            selection_file
        )
        self.progress.emit(60)

        # Stage 05
        self.stage_changed.emit("Stage 05 · Evidence Interpretation", 5)
        findings_file = self.run_stage05_real(
            parsed_dir,
            scenario_file,
            selection_file,
        )
        self.progress.emit(78)

        # Stage 06
        self.stage_changed.emit("Stage 06 · Evidence Verification", 6)
        verified_file = self.run_stage06(
            findings_file,
            parsed_dir,
        )
        self.progress.emit(90)

        # Stage 07
        self.stage_changed.emit("Stage 07 · Report", 7)
        report_file = self.run_stage07(
            verified_file,
            findings_file,
            selection_file,
            scenario_file,
            parsed_dir,
        )
        self.progress.emit(100)

        self.complete_pipeline(report_file)

    def complete_pipeline(self, report_file):
        self.log.emit("-" * 60)
        self.log.emit("[DONE] 전체 Pipeline 완료")
        self.log.emit(f"최종 보고서 → {report_file}")
        self.state_changed.emit("COMPLETED")
        self.finished.emit()

    # =====================================================
    # Helpers
    # =====================================================

    def clean_previous_outputs(self):
        targets = [
            self.case_dir / "01_input.json",
            self.case_dir / "02_scenario.json",
            self.case_dir / "03_selection.json",
            self.case_dir / "04_parsed",
            self.case_dir / "05_findings.json",
            self.case_dir / "06_verified.json",
            self.case_dir / "07_report.md",
        ]

        for target in targets:
            if not target.exists():
                continue

            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()

    def run_command(self, command, stage_name, cleanup_path=None, summarize_noise=False):
        """
        자식 프로세스를 실행하고 stdout을 GUI에 실시간 전달한다.

        일시정지 요청 시 현재 자식 프로세스 트리를 종료하고,
        직전 Stage 출력만 정리한 뒤 Resume까지 대기한다. Resume 시
        같은 Stage를 처음부터 다시 실행한다. 완료된 이전 Stage 결과는 유지한다.
        """

        display_command = subprocess.list2cmdline(
            [str(item) for item in command]
        )

        while True:
            self._wait_if_paused()

            if self._stop_requested.is_set():
                raise AnalysisStopped()

            self.log.emit(f"    $ {display_command}")
            started_at = time.monotonic()

            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            env["PYTHONUTF8"] = "1"

            process = subprocess.Popen(
                [str(item) for item in command],
                cwd=self.project_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
            )

            with self._process_lock:
                self._current_process = process

            output_lines = []
            noisy_counts = {"evtx_recovery": 0, "registry_vk": 0}
            noisy_examples = {"evtx_recovery": 0, "registry_vk": 0}
            full_log_path = self.case_dir / "backend_full.log"
            full_log_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                with full_log_path.open("a", encoding="utf-8") as full_log:
                    full_log.write(f"\n[{stage_name}] {display_command}\n")
                    if process.stdout is not None:
                        for line in process.stdout:
                            clean_line = line.rstrip()
                            if clean_line:
                                output_lines.append(clean_line)
                                full_log.write(clean_line + "\n")

                                noise_key = None
                                if summarize_noise:
                                    if "선언(chunk_count=" in clean_line and "복구했습니다" in clean_line:
                                        noise_key = "evtx_recovery"
                                    elif "Unknown VK Record type" in clean_line:
                                        noise_key = "registry_vk"

                                if noise_key is None:
                                    self.log.emit(clean_line)
                                else:
                                    noisy_counts[noise_key] += 1
                                    if noisy_examples[noise_key] < 3:
                                        self.log.emit(clean_line)
                                        noisy_examples[noise_key] += 1
                                    elif noisy_examples[noise_key] == 3:
                                        label = "EVTX 복구" if noise_key == "evtx_recovery" else "Registry VK 경고"
                                        self.log.emit(f"    … {label} 반복 로그는 생략하고 backend_full.log에 저장합니다.")
                                        noisy_examples[noise_key] += 1

                            if self._stop_requested.is_set():
                                self._terminate_current_process()
                                break
            finally:
                return_code = process.wait()
                with self._process_lock:
                    if self._current_process is process:
                        self._current_process = None

            if self._stop_requested.is_set():
                raise AnalysisStopped()

            if self._pause_requested.is_set():
                self._cleanup_partial_output(cleanup_path)
                self.log.emit(
                    f"[PAUSE] {stage_name} 중간 결과를 정리했습니다. "
                    "재개하면 이 Stage부터 다시 실행합니다."
                )
                self._wait_if_paused()
                self.state_changed.emit("RUNNING")
                continue

            elapsed = time.monotonic() - started_at
            if summarize_noise:
                if noisy_counts["evtx_recovery"]:
                    self.log.emit(f"[LOG] EVTX 복구 메시지 {noisy_counts['evtx_recovery']}건 (전체: backend_full.log)")
                if noisy_counts["registry_vk"]:
                    self.log.emit(f"[LOG] Registry VK 경고 {noisy_counts['registry_vk']}건 (전체: backend_full.log)")

            if return_code != 0:
                tail = "\n".join(output_lines[-30:])
                raise RuntimeError(
                    f"{stage_name} 실행 실패 (exit code {return_code})\n\n{tail}"
                )

            self.log.emit(f"[TIME] {stage_name}: {elapsed:.1f}초")
            return "\n".join(output_lines)

    def _cleanup_partial_output(self, path):
        if path is None:
            return
        target = Path(path)
        try:
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
            elif target.exists():
                target.unlink()
        except Exception as exc:
            self.log.emit(f"[WARN] 부분 출력 정리 실패: {target} ({exc})")

    # =====================================================
    # Stage 01
    # =====================================================

    def run_stage01_stub(self):
        self.log.emit("[1] Case Input 준비 시작...")

        source_file = (
            self.project_root
            / "benchmark"
            / "datasets"
            / "C-001-webshell"
            / "input.json"
        )

        output_file = self.case_dir / "01_input.json"

        if not source_file.exists():
            raise FileNotFoundError(
                "Stage 01 input fixture를 찾을 수 없습니다."
            )

        shutil.copy2(
            source_file,
            output_file,
        )

        self.log.emit("[1] Case Input 준비 완료")
        self.log.emit(f"    → {output_file}")

        return output_file

    def run_stage01_real(self):
        self.log.emit(
            "[1] 실제 Case Input 생성 시작..."
        )

        make_case_file = (
            self.project_root
            / "tools"
            / "make_case.py"
        )

        if not make_case_file.exists():
            raise FileNotFoundError(
                f"tools/make_case.py를 찾을 수 없습니다.\n"
                f"{make_case_file}"
            )

        command = [
            self.python_exe,
            str(make_case_file),
            "--case-id",
            self.case_id,
            "--cases-dir",
            str(self.project_root / "cases"),
            "--evidence",
            self.evidence_dir,
            "--raw",
            self.incident_description,
            "--os-hint",
            "windows_10",
        ]

        self.run_command(
            command,
            "Stage 01",
            cleanup_path=self.case_dir / "01_input.json",
        )

        output_file = (
            self.case_dir
            / "01_input.json"
        )

        if not output_file.exists():
            raise FileNotFoundError(
                "Stage 01 완료 후 01_input.json이 생성되지 않았습니다."
            )

        self.log.emit(
            "[1] 실제 Case Input 생성 완료"
        )
        self.log.emit(
            f"    → {output_file}"
        )

        return output_file

    # =====================================================
    # Stage 02
    # =====================================================

    def run_stage02_stub(self):
        self.log.emit(
            "[2] Scenario Normalize 시작..."
        )

        fixture_file = (
            self.project_root
            / "benchmark"
            / "fixtures"
            / "C-001-webshell"
            / "02_scenario.json"
        )

        output_file = (
            self.case_dir
            / "02_scenario.json"
        )

        if not fixture_file.exists():
            raise FileNotFoundError(
                "Stage 02 fixture를 찾을 수 없습니다."
            )

        shutil.copy2(
            fixture_file,
            output_file,
        )

        self.log.emit(
            "[2] Scenario Normalize 완료"
        )
        self.log.emit(
            f"    → {output_file}"
        )

        return output_file

    def run_stage02_real(
        self,
        input_file,
    ):
        self.log.emit(
            "[2] Ollama Scenario Normalize 시작..."
        )
        self.log.emit(
            "    자연어 사고 설명 → 구조화 시나리오"
        )

        output_file = (
            self.case_dir
            / "02_scenario.json"
        )

        command = [
            self.python_exe,
            "-m",
            "src.stage02_normalize.normalize",
            "--in",
            str(input_file),
            "--out",
            str(output_file),
            "--llm",
            "ollama",
            "--model",
            self.OLLAMA_MODEL,
            "--host",
            self.OLLAMA_HOST,
            "--num-ctx",
            str(self.stage02_num_ctx),
            "--timeout",
            str(self.OLLAMA_TIMEOUT),
        ]

        self.run_command(
            command,
            "Stage 02",
            cleanup_path=output_file,
        )

        if not output_file.exists():
            raise FileNotFoundError(
                "Stage 02 완료 후 02_scenario.json이 생성되지 않았습니다."
            )

        self.log.emit(
            "[2] Ollama Scenario Normalize 완료"
        )
        self.log.emit(
            f"    → {output_file}"
        )

        return output_file

    # =====================================================
    # Stage 03
    # =====================================================

    def run_stage03(
        self,
        scenario_file,
    ):
        self.log.emit(
            "[3] Artifact Selection 시작..."
        )

        selection_file = (
            self.case_dir
            / "03_selection.json"
        )

        mappings_dir = (
            self.project_root
            / "mappings"
        )

        command = [
            self.python_exe,
            "-m",
            "src.stage03_select.select",
            "--in",
            str(scenario_file),
            "--out",
            str(selection_file),
            "--mappings",
            str(mappings_dir),
        ]

        self.run_command(
            command,
            "Stage 03",
            cleanup_path=selection_file,
        )

        if not selection_file.exists():
            raise FileNotFoundError(
                "Stage 03 완료 후 03_selection.json이 생성되지 않았습니다."
            )

        self.log.emit(
            "[3] Artifact Selection 완료"
        )
        self.log.emit(
            f"    → {selection_file}"
        )

        return selection_file

    # =====================================================
    # Stage 04
    # =====================================================

    def run_stage04_stub(self):
        self.log.emit(
            "[4] Artifact Parsing 시작..."
        )

        fixture_dir = (
            self.project_root
            / "benchmark"
            / "fixtures"
            / "C-001-webshell"
            / "04_parsed"
        )

        output_dir = (
            self.case_dir
            / "04_parsed"
        )

        if not fixture_dir.exists():
            raise FileNotFoundError(
                "Stage 04 parsed fixture를 찾을 수 없습니다."
            )

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copytree(
            fixture_dir,
            output_dir,
            dirs_exist_ok=True,
        )

        self.log.emit(
            "[4] Artifact Parsing 완료 (Stub)"
        )
        self.log.emit(
            f"    → {output_dir}"
        )

        return output_dir

    def _stage04_cache_dir(self, selection_file, evidence_path):
        """같은 Case ID + Evidence + Selection + parser 버전에만 재사용되는 안전한 캐시."""
        if not self.use_stage04_cache:
            return None

        h = hashlib.sha256()
        h.update(self.case_id.encode("utf-8", errors="replace"))
        h.update(Path(selection_file).read_bytes())

        resolved = evidence_path.resolve()
        h.update(str(resolved).encode("utf-8", errors="replace"))

        # 증적 전체 내용을 해시하지 않고 파일 메타데이터만 사용한다.
        # KAPE 폴더 재분석 시 raw parse보다 훨씬 저렴하다.
        if resolved.is_file():
            st = resolved.stat()
            h.update(f"{st.st_size}:{st.st_mtime_ns}".encode())
        else:
            for root, dirs, files in os.walk(resolved):
                dirs.sort()
                files.sort()
                root_path = Path(root)
                for name in files:
                    fp = root_path / name
                    try:
                        st = fp.stat()
                    except OSError:
                        continue
                    rel = fp.relative_to(resolved)
                    h.update(str(rel).replace("\\", "/").encode("utf-8", errors="replace"))
                    h.update(f":{st.st_size}:{st.st_mtime_ns}".encode())

        parser_file = self.project_root / "src" / "stage04_parse" / "parse.py"
        if parser_file.exists():
            st = parser_file.stat()
            h.update(f"parser:{st.st_size}:{st.st_mtime_ns}".encode())

        key = h.hexdigest()[:24]
        safe_case = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in self.case_id)
        return self.project_root / ".cache" / "8vidence" / "stage04" / safe_case / key / "04_parsed"

    def run_stage04_real(
        self,
        selection_file,
    ):
        self.log.emit(
            "[4] 실제 Artifact Parsing 시작..."
        )
        self.log.emit(
            f"    Evidence → {self.evidence_dir}"
        )

        evidence_path = Path(self.evidence_dir)
        if not evidence_path.exists():
            raise FileNotFoundError(
                f"Evidence 경로가 존재하지 않습니다.\n{evidence_path}"
            )

        output_dir = self.case_dir / "04_parsed"
        cache_dir = self._stage04_cache_dir(selection_file, evidence_path)

        if output_dir.exists():
            shutil.rmtree(output_dir)

        if cache_dir is not None and cache_dir.exists():
            started = time.monotonic()
            shutil.copytree(cache_dir, output_dir)
            self.log.emit("[CACHE HIT] Stage 04 파싱 결과를 재사용했습니다.")
            self.log.emit(f"    cache → {cache_dir}")
            self.log.emit(f"[TIME] Stage 04: {time.monotonic() - started:.1f}초 (cache)")
            return output_dir

        if cache_dir is not None:
            self.log.emit("[CACHE MISS] Stage 04 캐시가 없어 실제 증적을 파싱합니다.")

        command = [
            self.python_exe,
            "-m",
            "src.stage04_parse.parse",
            "--in",
            str(selection_file),
            "--out",
            str(output_dir),
            "--evidence",
            str(evidence_path),
        ]

        self.run_command(
            command,
            "Stage 04",
            cleanup_path=output_dir,
            summarize_noise=True,
        )

        if not output_dir.exists():
            raise FileNotFoundError(
                "Stage 04 완료 후 04_parsed 디렉터리가 생성되지 않았습니다."
            )

        if cache_dir is not None:
            try:
                cache_dir.parent.mkdir(parents=True, exist_ok=True)
                if cache_dir.exists():
                    shutil.rmtree(cache_dir)
                shutil.copytree(output_dir, cache_dir)
                self.log.emit("[CACHE SAVE] Stage 04 결과를 다음 재분석용으로 저장했습니다.")
            except Exception as exc:
                self.log.emit(f"[WARN] Stage 04 캐시 저장 실패: {exc}")

        self.log.emit("[4] 실제 Artifact Parsing 완료")
        self.log.emit(f"    → {output_dir}")
        return output_dir

    # =====================================================
    # Stage 05
    # =====================================================

    def run_stage05_stub(self):
        self.log.emit(
            "[5] sLLM Interpretation 시작..."
        )

        fixture_file = (
            self.project_root
            / "benchmark"
            / "fixtures"
            / "C-001-webshell"
            / "05_findings.json"
        )

        output_file = (
            self.case_dir
            / "05_findings.json"
        )

        if not fixture_file.exists():
            raise FileNotFoundError(
                "Stage 05 findings fixture를 찾을 수 없습니다."
            )

        shutil.copy2(
            fixture_file,
            output_file,
        )

        self.log.emit(
            "[5] sLLM Interpretation 완료 (Stub)"
        )
        self.log.emit(
            f"    → {output_file}"
        )

        return output_file

    def run_stage05_real(
        self,
        parsed_dir,
        scenario_file,
        selection_file,
    ):
        self.log.emit(
            "[5] Ollama Evidence Interpretation 시작..."
        )
        self.log.emit(
            "    파싱된 Evidence → sLLM 해석"
        )

        output_file = (
            self.case_dir
            / "05_findings.json"
        )

        self.log.emit(
            f"    최적화 설정: ctx={self.stage05_num_ctx}, "
            f"후보 상한={self.stage05_limit}건, "
            f"artifact별 표시 상한={self.stage05_max_list_items}건"
        )

        command = [
            self.python_exe,
            "-m",
            "src.stage05_interpret.interpret",
            "--in",
            str(parsed_dir),
            "--scenario",
            str(scenario_file),
            "--selection",
            str(selection_file),
            "--out",
            str(output_file),
            "--llm",
            "ollama",
            "--model",
            self.OLLAMA_MODEL,
            "--host",
            self.OLLAMA_HOST,
            "--num-ctx",
            str(self.stage05_num_ctx),
            "--timeout",
            str(self.OLLAMA_TIMEOUT),
            "--limit",
            str(self.stage05_limit),
            "--max-list-items",
            str(self.stage05_max_list_items),
        ]

        self.run_command(
            command,
            "Stage 05",
            cleanup_path=output_file,
        )

        if not output_file.exists():
            raise FileNotFoundError(
                "Stage 05 완료 후 05_findings.json이 생성되지 않았습니다."
            )

        self.log.emit(
            "[5] Ollama Evidence Interpretation 완료"
        )
        self.log.emit(
            f"    → {output_file}"
        )

        return output_file

    # =====================================================
    # Stage 06
    # =====================================================

    def run_stage06(
        self,
        findings_file,
        parsed_dir,
    ):
        self.log.emit(
            "[6] Evidence Verification 시작..."
        )

        output_file = (
            self.case_dir
            / "06_verified.json"
        )

        command = [
            self.python_exe,
            "-m",
            "src.stage06_verify.verify",
            "--findings",
            str(findings_file),
            "--parsed",
            str(parsed_dir),
            "--out",
            str(output_file),
        ]

        self.run_command(
            command,
            "Stage 06",
            cleanup_path=output_file,
        )

        if not output_file.exists():
            raise FileNotFoundError(
                "Stage 06 완료 후 06_verified.json이 생성되지 않았습니다."
            )

        self.log.emit(
            "[6] Evidence Verification 완료"
        )
        self.log.emit(
            f"    → {output_file}"
        )

        return output_file

    # =====================================================
    # Stage 07
    # =====================================================

    def run_stage07(
        self,
        verified_file,
        findings_file,
        selection_file,
        scenario_file,
        parsed_dir,
    ):
        self.log.emit(
            "[7] Report 생성 시작..."
        )

        output_file = (
            self.case_dir
            / "07_report.md"
        )

        command = [
            self.python_exe,
            "-m",
            "src.stage07_report.report",
            "--in",
            str(verified_file),
            "--findings",
            str(findings_file),
            "--selection",
            str(selection_file),
            "--scenario",
            str(scenario_file),
            "--parsed",
            str(parsed_dir),
            "--out",
            str(output_file),
        ]

        self.run_command(
            command,
            "Stage 07",
            cleanup_path=output_file,
        )

        if not output_file.exists():
            raise FileNotFoundError(
                "Stage 07 완료 후 07_report.md가 생성되지 않았습니다."
            )

        self.log.emit(
            "[7] Report 생성 완료"
        )
        self.log.emit(
            f"    → {output_file}"
        )

        return output_file
