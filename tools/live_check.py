"""목업 없이 실물 증거·실제 모델로 01→07을 관통시키고 단계마다 판정한다.

``run_pipeline.sh``와 무엇이 다른가.

- **스텁을 받지 않는다.** ``--replay``·``--seed-parsed``에 해당하는 인자가
  아예 없다. 목업이 한 군데라도 섞이면 나머지 판정이 전부 무의미해지므로,
  섞을 수 있는 자리를 만들지 않았다. 마지막에 "정말 안 섞였는가"를 산출물의
  ``generator``와 매니페스트 시각으로 다시 확인한다.
- **무엇을 확인하는지·무엇이 나와야 하는지를 실행 전에 찍는다.** 결과를 보고
  기준을 정하면 그것은 판정이 아니다. 아래 ``PLAN``이 그 표이고, 화면에
  나오는 것과 같은 것이다.
- **판정과 측정을 나눈다.** PASS/FAIL은 구조 불변식에만 건다. 환각률·재시도
  횟수·소요 시간은 측정만 하고 실행을 실패시키지 않는다 — 이 프로젝트에서
  모델이 틀리는 것은 결함이 아니라 측정 대상이다. 환각률이 높다고 붉은 글씨가
  뜨면 그 수치를 낮추려고 검증기를 무르게 만들고 싶어진다. 그 유혹을 도구가
  만들지 않게 한다.
- ``run_pipeline.sh``에 없는 ``--model``을 02·05로 넘긴다. 해석만 큰 모델로
  바꿔 보는 실험이 잦으므로 ``--model-interpret``을 따로 둔다.

사용법::

    # 자연어 경로
    .venv/Scripts/python.exe tools/live_check.py --case-id K-LIVE-0831 \\
        --evidence evidence/win10_sysmon_testimage.001 --volume 1 \\
        --model qwen2.5:latest \\
        --raw "키오스크 KIOSK-03에서 8월 24일 USB를 꽂은 뒤 알 수 없는 서비스가 설치됐습니다"

    # SIEM 알럿 경로 (01_input.json 을 직접 만들어 넘긴다)
    .venv/Scripts/python.exe tools/live_check.py --case-id K-LIVE-ALERT \\
        --evidence evidence/win10_sysmon_testimage.001 --volume 1 \\
        --model qwen2.5:latest --input samples/alert_01_input.json

종료 코드는 판정에 하나라도 실패하면 1이다. 측정치는 종료 코드를 바꾸지 않는다.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import attack, io  # noqa: E402
from src.common import errors as errlog  # noqa: E402
from src.common.llm import DEFAULT_NUM_CTX  # noqa: E402
from src.stage05_interpret import allocation, record_filter  # noqa: E402
from src.stage02_normalize.llm_client import DEFAULT_MODEL  # noqa: E402

BAR = "─" * 74

#: 아티팩트마다 몇 건을 골라 원본 바이트와 대조할지. 이미지에서 매번 탐색이
#: 일어나므로 크게 잡으면 느려진다. 20은 CLAUDE.md 가 권하는 값이다.
DEFAULT_SAMPLE = 5

#: 단계 출력이 길면 화면이 판정으로 안 보인다. 넘는 만큼은 줄 수만 알린다.
MAX_ECHO_LINES = 40


@dataclass
class Plan:
    """단계 하나. ``what``·``expect``는 실행 **전에** 찍힌다."""

    key: str
    title: str
    what: str
    expect: str
    llm: bool = False


#: 이 표가 곧 화면 출력이다. 여기 없는 판정은 하지 않는다.
PLAN: list[Plan] = [
    Plan(
        "preflight",
        "사전 점검 — 인터프리터·모델·증거",
        "이 파이썬이 프로젝트 venv인가, Ollama에 그 모델 태그가 실제로 있는가, "
        "증거 경로가 존재하는가",
        "Evtx·Registry·dissect·requests import 성공 / 모델 태그가 /api/tags 목록에 있음 / "
        f"모델 context_length ≥ --num-ctx({DEFAULT_NUM_CTX})",
    ),
    Plan(
        "stage01",
        "01 입력 — 이번 실행의 진입점",
        "목업이나 이전 실행의 잔재 없이 새 케이스가 만들어지는가",
        "cases/<id>/01_input.json 생성, source_type이 요청한 경로와 일치, 04_parsed 없음",
    ),
    Plan(
        "stage02",
        "02 정규화 — 시나리오 구조화",
        "자연어면 모델이 KNOWN_TECHNIQUES 안의 기법으로 스키마를 채우는가. "
        "알럿이면 어댑터가 LLM 없이 같은 형식을 내는가",
        "techniques ≥ 1 / 전부 실재하는 ATT&CK ID / time_range.start < end / "
        "generator에 모델 태그(자연어) 또는 alert_adapter.py(알럿)",
        llm=True,
    ),
    Plan(
        "stage03",
        "03 선별 — 볼 아티팩트 결정",
        "기법마다 매핑이 있어 읽을 대상이 정해지는가",
        "selected ≥ 1. 매핑 없는 기법은 stderr에 '매핑 없음'으로 드러나야 하고 "
        "조용히 사라지면 안 된다",
    ),
    Plan(
        "stage04",
        "04 파싱 — 실물 증거를 실제로 판다",
        "--skip-existing을 주지 않으므로 이번 실행이 진짜로 이미지를 읽는가",
        "아티팩트 ≥ 1 / 총 레코드 ≥ 1 / _manifest.json의 generated_at이 이번 실행 시작 이후",
    ),
    Plan(
        "inspect",
        "04 검산 ① — 매니페스트·ref 유일성",
        "tools/inspect_jsonl.py — 산출물이 자기 매니페스트와 맞는가, ref가 유일한가",
        "종료 코드 0",
    ),
    Plan(
        "hexdump",
        "04 검산 ② — offset이 원본 바이트를 가리키는가",
        "tools/hexdump_record.py --sample — 레코드가 말하는 위치에 그 레코드가 실제로 있는가",
        "종료 코드 0. **목업과 실물을 가르는 자리다** — 지어낸 레코드는 여기서 반드시 실패한다",
    ),
    Plan(
        "stage05",
        "05 해석 — 근거가 달린 문장",
        "전달받은 레코드만 근거로 문장을 만드는가",
        "findings ≥ 1 / generator에 모델 태그. "
        "input_refs 밖 참조는 여기서 실패시키지 않고 06이 잡는지 본다(측정)",
        llm=True,
    ),
    Plan(
        "stage06",
        "06 검증 — claims를 04 산출물과 대조",
        "검증기가 실제로 일하는가. 05가 흘린 것을 잡아내는가",
        "passed+rejected+unverifiable == findings 수 / "
        "05에 input_refs 밖 참조가 있었다면 rejected ≥ 1. 환각률은 판정이 아니라 측정치",
    ),
    Plan(
        "stage07",
        "07 보고 — 통과분만 싣는다",
        "검증을 통과한 문장만 보고서에 오르는가",
        "보고서의 '확인된 사항' 건수 == 06의 passed 건수",
    ),
    Plan(
        "nomock",
        "결산 ① — 목업이 섞이지 않았는가",
        "산출물이 스텁·시드가 아니라 이번 실행의 모델과 이미지에서 나온 것인가",
        "02·05 generator에 'stub(' 없음 / 04 매니페스트 시각이 실행 시작 이후",
    ),
]


@dataclass
class Result:
    """단계 하나의 결과. ``verdict``는 PASS·FAIL·건너뜀 셋뿐이다."""

    plan: Plan
    verdict: str = "건너뜀"
    note: str = ""
    seconds: float = 0.0
    #: 계획상 LLM 단계라도 실제로 안 불렀으면 내린다 — 알럿 경로의 02가 그렇다.
    used_llm: bool | None = None
    measures: dict[str, Any] = field(default_factory=dict)


class StepFailed(Exception):
    """판정 실패. 뒤 단계는 의미가 없으므로 멈춘다."""


class Runner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.case_dir = Path(args.cases_dir) / args.case_id
        self.parsed_dir = self.case_dir / "04_parsed"
        self.errors_path = self.case_dir / "errors.jsonl"
        self.results: dict[str, Result] = {}
        self.started_at = datetime.now(timezone.utc)
        # 단계 간에 넘기는 값. 뒤 단계의 판정이 앞 단계의 사실에 기대는 곳이
        # 있다 (05의 흘린 참조를 06이 잡았는지 등).
        self.carry: dict[str, Any] = {}

    # ── 화면 ────────────────────────────────────────────────────────────

    def echo_plan(self, index: int, plan: Plan) -> None:
        print(BAR)
        tag = " (LLM)" if plan.llm else ""
        print(f"[{index}/{len(PLAN)}] {plan.title}{tag}")
        print(f"  확인: {plan.what}")
        print(f"  기대: {plan.expect}")

    def echo_cmd(self, cmd: list[str]) -> None:
        shown = " ".join(f'"{c}"' if " " in c else c for c in cmd)
        print(f"  실행: {shown}")

    def echo_output(self, text: str, marker: str) -> None:
        lines = [line for line in text.splitlines() if line.strip()]
        for line in lines[:MAX_ECHO_LINES]:
            print(f"  {marker} {line}")
        if len(lines) > MAX_ECHO_LINES:
            print(f"  {marker} … ({len(lines) - MAX_ECHO_LINES}줄 생략)")

    # ── 실행 ────────────────────────────────────────────────────────────

    def run_cmd(self, cmd: list[str]) -> tuple[int, str, str]:
        """단계 CLI를 그대로 부른다. 사람이 치는 명령과 같아야 하므로 in-process로
        부르지 않는다 — 화면에 찍힌 명령을 복사해 재현할 수 있어야 한다."""
        self.echo_cmd(cmd)
        proc = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
        )
        if proc.stdout:
            self.echo_output(proc.stdout, "│")
        if proc.stderr:
            self.echo_output(proc.stderr, "!")
        return proc.returncode, proc.stdout or "", proc.stderr or ""

    def py(self, *args: str) -> list[str]:
        return [sys.executable, *args]

    def execute(self) -> int:
        print()
        print(f"실물 관통 점검 — case {self.args.case_id}")
        print(f"  증거   {self.args.evidence}" + (f" (volume {self.args.volume})" if self.args.volume is not None else ""))
        print(f"  모델   02 {self.args.model} / 05 {self.model_interpret}")
        print(f"  시작   {io.utc_now()}")
        print("  목업   없음 (스텁·시드 인자가 이 도구에 존재하지 않음)")
        print()

        stopped = False
        for index, plan in enumerate(PLAN, start=1):
            result = Result(plan, used_llm=plan.llm)
            self.results[plan.key] = result
            if stopped:
                result.note = "앞 단계 실패로 실행하지 않음"
                continue

            self.echo_plan(index, plan)
            handler: Callable[[Result], str] = getattr(self, f"do_{plan.key}")
            started = time.perf_counter()
            try:
                result.note = handler(result)
                result.verdict = "PASS"
            except StepFailed as failure:
                result.verdict = "FAIL"
                result.note = str(failure)
                stopped = True
            finally:
                result.seconds = time.perf_counter() - started

            print(f"  판정: {result.verdict}  {result.note}")
            print(f"  시간: {result.seconds:.1f}초")
            print()

        self.summary()
        self.write_report()
        return 1 if any(r.verdict == "FAIL" for r in self.results.values()) else 0

    # ── 단계 ────────────────────────────────────────────────────────────

    @property
    def model_interpret(self) -> str:
        return self.args.model_interpret or self.args.model

    def do_preflight(self, result: Result) -> str:
        missing = []
        for module, why in (
            ("Evtx", "evtx 파서"),
            ("Registry", "레지스트리 파서"),
            ("dissect.target", "디스크 이미지"),
            ("requests", "Ollama 호출"),
        ):
            try:
                __import__(module)
            except ImportError:
                missing.append(f"{module}({why})")
        if missing:
            raise StepFailed(
                f"import 실패: {', '.join(missing)}. "
                "맨 python 으로 부르면 하네스의 venv 가 잡힌다 — .venv/Scripts/python.exe 로 실행한다"
            )

        evidence = Path(self.args.evidence)
        if not evidence.exists():
            raise StepFailed(f"증거 경로 없음: {evidence}")
        if evidence.is_file() and self.args.volume is None:
            # 실패가 아니다. 04가 후보를 보여 주고 멈추는 것이 정상 동작이다.
            print("  참고: 디스크 이미지인데 --volume 이 없다. NTFS가 여럿이면 04가 후보를 보여 주고 멈춘다")

        import requests

        try:
            response = requests.get(f"{self.args.host.rstrip('/')}/api/tags", timeout=5)
            response.raise_for_status()
            models = response.json().get("models", [])
        except Exception as e:  # noqa: BLE001 - 연결 실패 종류가 환경마다 다르다
            raise StepFailed(f"Ollama 응답 없음 ({self.args.host}): {e}") from None

        tags = {m.get("name", "") for m in models}
        wanted = {self.args.model, self.model_interpret}
        absent = sorted(t for t in wanted if t not in tags)
        if absent:
            raise StepFailed(
                f"모델 태그 없음: {', '.join(absent)}. "
                f"설치된 것: {', '.join(sorted(tags)) or '없음'}. "
                f"ollama pull <태그> 하거나 --model 로 위 목록 중 하나를 지정한다"
            )

        for entry in models:
            if entry.get("name") in wanted:
                ctx = (entry.get("details") or {}).get("context_length")
                if ctx and ctx < self.args.num_ctx:
                    raise StepFailed(
                        f"{entry['name']}의 context_length {ctx} < --num-ctx {self.args.num_ctx}. "
                        "Ollama는 넘치는 프롬프트를 말없이 자르므로 --num-ctx 를 낮춰 맞춘다"
                    )
                result.measures[f"context_length:{entry['name']}"] = ctx

        return f"venv·모델({', '.join(sorted(wanted))})·증거 확인"

    def do_stage01(self, result: Result) -> str:
        if self.case_dir.exists() and not self.args.force:
            raise StepFailed(
                f"{self.case_dir} 가 이미 있다. 새 --case-id 를 쓰거나 --force 로 지운다 "
                "(이전 산출물이 남아 있으면 파싱이 안 돌고도 돈 것처럼 보인다)"
            )
        if self.case_dir.exists():
            print(f"  --force: {self.case_dir} 삭제")
            shutil.rmtree(self.case_dir)

        cmd = self.py(
            "tools/make_case.py",
            "--case-id", self.args.case_id,
            "--cases-dir", self.args.cases_dir,
            "--evidence", self.args.evidence,
        )
        if self.args.raw:
            cmd += ["--raw", self.args.raw, "--os-hint", self.args.os_hint]
        else:
            cmd += ["--input", self.args.input]

        code, _, err = self.run_cmd(cmd)
        if code != 0:
            raise StepFailed(f"make_case.py 실패 (코드 {code}): {err.strip().splitlines()[-1] if err.strip() else ''}")

        document = io.read_json(self.case_dir / "01_input.json")
        expected = "natural_language" if self.args.raw else "edr_alert"
        if document["source_type"] != expected:
            raise StepFailed(
                f"source_type 이 {document['source_type']} — {expected} 를 기대했다. "
                "--raw 는 자연어 전용이고 알럿은 --input 으로 넣는다"
            )
        if self.args.artifacts:
            # artifacts_available 은 02 프롬프트에만 실리는 힌트다(03·04를 막지 않는다).
            # make_case 의 기본값은 레지스트리를 빼므로 필요하면 여기서 채운다.
            document["evidence"]["artifacts_available"] = self.args.artifacts
            io.write_json(self.case_dir / "01_input.json", document)
            print(f"  artifacts_available 지정: {', '.join(self.args.artifacts)}")
        if self.parsed_dir.exists():
            raise StepFailed(f"{self.parsed_dir} 가 벌써 있다 — 이번 실행이 판 것이 아니다")

        self.carry["source_type"] = expected
        return f"source_type {expected} / 04_parsed 없음(이번 실행이 만든다)"

    def do_stage02(self, result: Result) -> str:
        cmd = self.py(
            "-m", "src.stage02_normalize.normalize",
            "--in", str(self.case_dir / "01_input.json"),
            "--out", str(self.case_dir / "02_scenario.json"),
        )
        result.used_llm = self.carry["source_type"] == "natural_language"
        if result.used_llm:
            cmd += [
                "--llm", "ollama",
                "--model", self.args.model,
                "--host", self.args.host,
                "--num-ctx", str(self.args.num_ctx),
                "--timeout", str(self.args.timeout),
            ]
        code, _, err = self.run_cmd(cmd)
        if code != 0:
            raise StepFailed(
                f"02 실패 (코드 {code}). {self.errors_path} 와 "
                f"{self.case_dir}/02_normalize_raw_attempt*.txt 를 본다"
            )

        scenario = io.read_json(self.case_dir / "02_scenario.json")
        techniques = scenario.get("techniques", [])
        if not techniques:
            raise StepFailed("techniques 가 비었다 — 03이 볼 것을 정할 수 없다")

        unknown = [t["id"] for t in techniques if not attack.is_known(t["id"])]
        if unknown:
            raise StepFailed(f"KNOWN_TECHNIQUES 밖의 ID: {', '.join(unknown)}")

        start, end = scenario["time_range"]["start"], scenario["time_range"]["end"]
        if _parse_utc(start) >= _parse_utc(end):
            raise StepFailed(f"time_range 가 뒤집혔다: {start} → {end}")

        generator = scenario["generator"]
        wanted = "alert_adapter.py" if self.carry["source_type"] == "edr_alert" else self.args.model
        if wanted not in generator:
            raise StepFailed(f"generator 가 '{generator}' — '{wanted}' 를 기대했다")

        result.measures["techniques"] = [t["id"] for t in techniques]
        result.measures["time_range_days"] = round(
            (_parse_utc(end) - _parse_utc(start)).total_seconds() / 86400, 2
        )
        self.carry["techniques"] = [t["id"] for t in techniques]
        return (
            f"techniques {len(techniques)}건 ({', '.join(t['id'] for t in techniques)}) "
            f"/ 범위 {result.measures['time_range_days']}일 / generator {generator}"
        )

    def do_stage03(self, result: Result) -> str:
        code, _, err = self.run_cmd(
            self.py(
                "-m", "src.stage03_select.select",
                "--in", str(self.case_dir / "02_scenario.json"),
                "--out", str(self.case_dir / "03_selection.json"),
                "--mappings", "mappings/",
            )
        )
        if code != 0:
            raise StepFailed(
                f"03 실패 (코드 {code}). 선별된 아티팩트가 없으면 매핑 결손이다 — "
                "mappings/windows/<기법>.yaml 이 있는지 본다"
            )

        selection = io.read_json(self.case_dir / "03_selection.json")
        stats = selection["stats"]
        if stats["selected_count"] < 1:
            raise StepFailed("selected 가 0 — 볼 아티팩트가 없다")

        unmapped = sorted({m.group(1) for m in re.finditer(r"매핑 없음: (T\S+)", err)})
        if unmapped:
            print(f"  참고: 매핑 없는 기법 {', '.join(unmapped)} — 판정에는 안 넣는다(측정치)")
        result.measures["unmapped_techniques"] = unmapped
        result.measures["selected_artifacts"] = sorted({s["artifact"] for s in selection["selected"]})
        return (
            f"selected {stats['selected_count']} / deferred {stats['deferred_count']} "
            f"/ excluded {stats['excluded_count']} "
            f"→ {', '.join(result.measures['selected_artifacts'])}"
        )

    def do_stage04(self, result: Result) -> str:
        cmd = self.py(
            "-m", "src.stage04_parse.parse",
            "--in", str(self.case_dir / "03_selection.json"),
            "--out", str(self.parsed_dir),
            "--evidence", self.args.evidence,
        )
        if self.args.volume is not None:
            cmd += ["--volume", str(self.args.volume)]
        # --skip-existing 을 일부러 주지 않는다. 이번 실행이 실제로 파야 한다.
        code, _, err = self.run_cmd(cmd)
        if code != 0:
            raise StepFailed(f"04 실패 (코드 {code}). {self.errors_path} 에 사유가 있다")

        manifest = io.read_json(self.parsed_dir / "_manifest.json")
        if not manifest["files"]:
            raise StepFailed("아티팩트가 하나도 나오지 않았다")
        if manifest["total_records"] < 1:
            raise StepFailed("레코드가 0건 — 05에 전달할 것이 없다")

        made = _parse_utc(manifest["generated_at"])
        if made < self.started_at.replace(microsecond=0):
            raise StepFailed(
                f"매니페스트 시각 {manifest['generated_at']} 이 실행 시작 이전 — "
                "이번에 판 산출물이 아니다"
            )

        result.measures["total_records"] = manifest["total_records"]
        result.measures["flagged_records"] = manifest["flagged_records"]
        result.measures["parse_errors"] = sum(f["parse_errors"] for f in manifest["files"])
        self.carry["manifest"] = manifest
        return (
            f"{len(manifest['files'])}개 아티팩트 / 총 {manifest['total_records']}건 "
            f"(플래그 {manifest['flagged_records']}건, 파싱 오류 {result.measures['parse_errors']}건)"
        )

    def do_inspect(self, result: Result) -> str:
        code, _, _ = self.run_cmd(
            self.py("tools/inspect_jsonl.py", "--parsed", str(self.parsed_dir))
        )
        if code != 0:
            raise StepFailed("매니페스트 대조 또는 ref 유일성 위반 (위 출력 참조)")
        return "매니페스트 일치 / ref 유일"

    def do_hexdump(self, result: Result) -> str:
        if self.args.sample < 1:
            # 건너뛴 것을 PASS 로 적으면 대조하지 않고 통과한 것처럼 보인다.
            raise StepFailed("--sample 0 으로 건너뜀 — 실물 대조 없이는 이 실행을 실물이라 말할 수 없다")
        cmd = self.py(
            "tools/hexdump_record.py",
            "--sample", str(self.args.sample),
            "--parsed", str(self.parsed_dir),
            "--evidence", self.args.evidence,
        )
        if self.args.volume is not None:
            cmd += ["--volume", str(self.args.volume)]
        code, out, _ = self.run_cmd(cmd)
        if code != 0:
            raise StepFailed(
                "offset 이 원본 바이트와 어긋난다. 파서가 틀렸거나 레코드가 실물이 아니다"
            )
        result.measures["sample_per_artifact"] = self.args.sample
        return f"아티팩트마다 {self.args.sample}건 표본 — 전부 원본과 일치"

    def do_stage05(self, result: Result) -> str:
        cmd = self.py(
            "-m", "src.stage05_interpret.interpret",
            "--in", str(self.parsed_dir),
            "--scenario", str(self.case_dir / "02_scenario.json"),
            "--selection", str(self.case_dir / "03_selection.json"),
            "--out", str(self.case_dir / "05_findings.json"),
            "--llm", "ollama",
            "--model", self.model_interpret,
            "--host", self.args.host,
            "--num-ctx", str(self.args.num_ctx),
            "--timeout", str(self.args.timeout),
            "--limit", str(self.args.limit),
            "--max-list-items", str(self.args.max_list_items),
        )
        code, _, _ = self.run_cmd(cmd)
        if code != 0:
            raise StepFailed(
                f"05 실패 (코드 {code}). {self.errors_path} 와 "
                f"{self.case_dir}/05_interpret_raw_attempt*.txt 를 본다"
            )

        findings_doc = io.read_json(self.case_dir / "05_findings.json")
        findings = findings_doc["findings"]
        if not findings:
            raise StepFailed("findings 가 0건 — 06이 검증할 문장이 없다")
        if self.model_interpret not in findings_doc["generator"]:
            raise StepFailed(f"generator 가 '{findings_doc['generator']}' — 모델 태그가 없다")

        allowed = set(findings_doc["input_refs"])
        stray = sorted(
            {ref for f in findings for ref in f.get("refs", []) if ref not in allowed}
        )
        empty_claims = [f["id"] for f in findings if not f.get("claims")]

        self.carry["stray_refs"] = stray
        self.carry["findings_count"] = len(findings)
        result.measures["stray_refs"] = stray
        result.measures["findings_without_claims"] = empty_claims

        note = (
            f"findings {len(findings)}건 / 전달 레코드 {len(allowed)}건 "
            f"(--limit {self.args.limit})"
        )
        if stray:
            note += f" / 측정: input_refs 밖 참조 {len(stray)}건 {stray[:3]} → 06이 잡아야 한다"
        if empty_claims:
            note += f" / 측정: claims 빈 문장 {len(empty_claims)}건 → unverifiable 로 갈 것"
        return note

    def do_stage06(self, result: Result) -> str:
        code, out, _ = self.run_cmd(
            self.py(
                "-m", "src.stage06_verify.verify",
                "--findings", str(self.case_dir / "05_findings.json"),
                "--parsed", str(self.parsed_dir),
                "--out", str(self.case_dir / "06_verified.json"),
            )
        )
        if code != 0:
            raise StepFailed(f"06 실패 (코드 {code})")

        stats = io.read_json(self.case_dir / "06_verified.json")["stats"]
        total = stats["passed"] + stats["rejected"] + stats["unverifiable"]
        if total != self.carry["findings_count"]:
            raise StepFailed(
                f"판정 합계 {total} != findings {self.carry['findings_count']} — "
                "검증에서 새어 나간 문장이 있다"
            )
        if self.carry["stray_refs"] and stats["rejected"] < 1:
            raise StepFailed(
                "05가 input_refs 밖 레코드를 참조했는데 rejected 가 0 — "
                "ref_in_input 검사가 일하지 않았다"
            )

        self.carry["passed"] = stats["passed"]
        result.measures.update(stats)
        return (
            f"passed {stats['passed']} / rejected {stats['rejected']} "
            f"/ unverifiable {stats['unverifiable']} "
            f"(환각률 {stats['hallucination_rate']:.1%} — 측정치)"
        )

    def do_stage07(self, result: Result) -> str:
        code, out, _ = self.run_cmd(
            self.py(
                "-m", "src.stage07_report.report",
                "--in", str(self.case_dir / "06_verified.json"),
                "--findings", str(self.case_dir / "05_findings.json"),
                "--selection", str(self.case_dir / "03_selection.json"),
                "--scenario", str(self.case_dir / "02_scenario.json"),
                "--parsed", str(self.parsed_dir),
                "--out", str(self.case_dir / "07_report.md"),
            )
        )
        if code != 0:
            raise StepFailed(f"07 실패 (코드 {code})")

        match = re.search(r"확인된 사항 (\d+)건", out)
        if not match:
            raise StepFailed("07 출력에서 '확인된 사항' 건수를 읽지 못했다")
        reported = int(match.group(1))
        if reported != self.carry["passed"]:
            raise StepFailed(
                f"보고서의 확인된 사항 {reported}건 != 06의 passed {self.carry['passed']}건 — "
                "검증을 통과하지 않은 문장이 실렸거나 통과분이 빠졌다"
            )
        result.measures["report_bytes"] = (self.case_dir / "07_report.md").stat().st_size
        return f"확인된 사항 {reported}건 == 06 passed / {self.case_dir / '07_report.md'}"

    def do_nomock(self, result: Result) -> str:
        offenders = []
        for name in ("02_scenario.json", "05_findings.json"):
            generator = io.read_json(self.case_dir / name)["generator"]
            if "stub(" in generator:
                offenders.append(f"{name}: {generator}")
        if offenders:
            raise StepFailed(f"스텁 산출물이 섞였다 — {', '.join(offenders)}")

        manifest_time = _parse_utc(self.carry["manifest"]["generated_at"])
        if manifest_time < self.started_at.replace(microsecond=0):
            raise StepFailed("04 산출물이 이번 실행 것이 아니다")
        return "02·05는 실제 모델, 04는 이번 실행의 이미지 파싱"

    # ── 결산 ────────────────────────────────────────────────────────────

    def summary(self) -> None:
        print(BAR)
        print("판정")
        for index, plan in enumerate(PLAN, start=1):
            result = self.results[plan.key]
            print(f"  {_pad(result.verdict, 6)}  [{index:>2}] {plan.title}")
            if result.verdict != "PASS":
                print(f"        {result.note}")

        print()
        print("시간")
        llm_total = sum(r.seconds for r in self.results.values() if r.used_llm)
        det_total = sum(r.seconds for r in self.results.values() if not r.used_llm)
        for index, plan in enumerate(PLAN, start=1):
            result = self.results[plan.key]
            if result.verdict == "건너뜀":
                continue
            tag = " (LLM)" if result.used_llm else ""
            print(f"  {result.seconds:>7.1f}초  {plan.title}{tag}")
        print(f"  {'─' * 7}")
        print(f"  {llm_total:>7.1f}초  LLM 합계 (02·05)")
        print(f"  {det_total:>7.1f}초  결정론 합계")
        print(f"  {llm_total + det_total:>7.1f}초  전체")

        print()
        print("측정치 — 판정이 아니다. 프롬프트를 바꿀 때마다 이 값을 같이 남긴다")
        verified = self.case_dir / "06_verified.json"
        if verified.is_file():
            stats = io.read_json(verified)["stats"]
            judged = stats["passed"] + stats["rejected"]
            print(f"  환각률       {stats['hallucination_rate']:.1%}  (rejected {stats['rejected']} / 판정대상 {judged})")
            if stats["total_findings"]:
                rate = stats["unverifiable"] / stats["total_findings"]
                print(f"  검증 불가율  {rate:.1%}  (claims 가 빈 문장)")
        if self.errors_path.is_file():
            counted = errlog.tally(self.errors_path)
            print(f"  재시도·실패  {counted['total']}건 — {self.errors_path}")
            for etype, count in sorted(counted["by_type"].items()):
                print(f"      type {etype}: {count}")
            for field_name, count in sorted(counted["by_field"].items(), key=lambda kv: -kv[1])[:5]:
                print(f"      field {field_name}: {count}   ← 프롬프트 개선의 근거")
        else:
            print("  재시도·실패  0건 (errors.jsonl 없음 — 모든 단계가 첫 시도에 통과)")

    def write_report(self) -> None:
        path = self.case_dir / "live_check.json"
        document = {
            "case_id": self.args.case_id,
            "started_at": self.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence": self.args.evidence,
            "volume": self.args.volume,
            "model_normalize": self.args.model,
            "model_interpret": self.model_interpret,
            "num_ctx": self.args.num_ctx,
            "source_type": self.carry.get("source_type"),
            "steps": [
                {
                    "key": r.plan.key,
                    "title": r.plan.title,
                    "verdict": r.verdict,
                    "note": r.note,
                    "seconds": round(r.seconds, 3),
                    "llm": bool(r.used_llm),
                    "measures": r.measures,
                }
                for r in self.results.values()
            ],
        }
        if not self.case_dir.is_dir():
            return

        io.write_json(path, document)
        print()
        print(f"기록: {path}  (실행끼리 비교할 때 이 파일을 diff 한다)")

        # 같은 기록을 benchmark/results/ 에도 남긴다. 케이스 디렉터리는
        # --force 로 지워지고 gitignore 대상이지만, 측정치는 실행이 끝난 뒤에도
        # 남아야 한다 — 발표에 쓸 수치를 손으로 옮겨 적지 않으려는 것이다.
        stamp = self.started_at.strftime("%Y%m%dT%H%M%SZ")
        archived = REPO_ROOT / "benchmark/results" / f"{self.args.case_id}-{stamp}.json"
        io.write_json(archived, document)
        print(f"      {archived}  (benchmark/collect.py 가 여기를 읽는다)")


def _pad(text: str, width: int) -> str:
    """한글은 폭이 2다. 판정 열이 어긋나면 훑어볼 수 없다."""
    import unicodedata

    shown = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)
    return " " * max(0, width - shown) + text


def _parse_utc(text: str) -> datetime:
    parsed = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python tools/live_check.py",
        description="목업 없이 실물 증거·실제 모델로 01→07을 관통시키고 단계마다 판정한다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "스텁·시드 인자는 일부러 두지 않았다. 배선만 볼 때는 run_pipeline.sh 의\n"
            "세 번째 인자(replay 디렉터리)를 쓴다."
        ),
    )
    parser.add_argument("--case-id", required=True, help="실행마다 새로 준다 (K-LIVE-0831 처럼)")
    parser.add_argument("--evidence", required=True, help="볼륨 루트 또는 디스크 이미지")
    parser.add_argument("--volume", type=int, default=None, help="이미지에 NTFS가 여럿일 때 볼 볼륨")
    parser.add_argument("--cases-dir", default="cases")
    parser.add_argument("--raw", default=None, help="자연어 경로 — 상황 서술")
    parser.add_argument("--input", default=None, help="알럿 경로 — 만들어 둔 01_input.json")
    parser.add_argument("--os-hint", default="windows_10", help="--raw 일 때만. 기본 %(default)s")
    parser.add_argument(
        "--artifacts",
        nargs="+",
        default=None,
        metavar="NAME",
        help="artifacts_available 을 덮어쓴다 (02 프롬프트 힌트). 예: --artifacts '$MFT' evtx registry",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help="02 정규화 모델. 기본 %(default)s")
    parser.add_argument(
        "--model-interpret",
        default=None,
        help="05 해석 모델. 생략하면 --model 과 같다 (해석만 키우는 실험용)",
    )
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument("--num-ctx", type=int, default=DEFAULT_NUM_CTX)
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help=(
            "단계별 모델 대기 상한(초). 기본 %(default)s. **모자라면 timeout 3회로 중단된다** — "
            "출력 토큰에 상한이 없어(num_predict 미지정) 모델이 멈추지 않으면 컨텍스트가 찰 때까지 쓴다"
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=record_filter.DEFAULT_LIMIT,
        help="05가 모델에 실을 최대 레코드 수. 기본 %(default)s. 줄이면 프롬프트가 작아진다",
    )
    parser.add_argument(
        "--max-list-items",
        type=int,
        default=allocation.MAX_LIST_ITEMS,
        help="fields 안 목록을 몇 개까지 실을지. 기본 %(default)s, 0이면 안 자른다",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=DEFAULT_SAMPLE,
        help=f"원본 바이트 대조 표본 수. 기본 {DEFAULT_SAMPLE}, 0이면 이 검산을 건너뛴다",
    )
    parser.add_argument("--force", action="store_true", help="같은 case-id 디렉터리를 지우고 다시 만든다")
    args = parser.parse_args(argv)

    if bool(args.raw) == bool(args.input):
        parser.error("--raw(자연어) 또는 --input(알럿) 중 하나만 지정하십시오")
    return args


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    return Runner(args).execute()


if __name__ == "__main__":
    raise SystemExit(main())
