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

**05는 기본이 ``--mode assemble``이다.** 모델은 어느 레코드가 의심스러운지만
고르고 문장·claims·타임라인은 파이썬이 원본에서 조립한다. 그 경로에서만
성립해야 하는 것 셋을 05단계가 함께 판정한다 — claims 값이 원본과 글자
그대로 같은가, 근거 필드가 그 레코드에 실재하는가, 조각을 나눠도
``input_refs``가 겹치지 않는가. 셋 다 **모델이 무엇을 골랐든 성립해야 하는
것**이라, 깨지면 모델 사정이 아니라 우리 회귀다.

예전 경로(모델이 문장을 직접 쓴다)와 비교하려면 ``--mode model``로 한 번 더
돌리고 ``cases/*/live_check.json``을 diff 한다. 그 파일에 ``mode``와
``max_chunks``가 기록된다.

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
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import attack, io  # noqa: E402
from src.common import errors as errlog  # noqa: E402
from src.stage06_verify import verify as verify_mod  # noqa: E402
from src.stage06_verify.checkers import statement_grounded  # noqa: E402
from src.stage05_interpret.llm_client import (  # noqa: E402
    ASSEMBLE_NUM_CTX,
    DEFAULT_NUM_CTX,
)
from src.stage05_interpret import allocation, assembly, record_filter  # noqa: E402
from src.stage02_normalize.llm_client import DEFAULT_MODEL  # noqa: E402
from src.stage03_select import mapping_loader  # noqa: E402
from src.stage03_select import select as select_mod  # noqa: E402

BAR = "─" * 74

#: 아티팩트마다 몇 건을 골라 원본 바이트와 대조할지. 이미지에서 매번 탐색이
#: 일어나므로 크게 잡으면 느려진다. 20은 CLAUDE.md 가 권하는 값이다.
DEFAULT_SAMPLE = 5

#: 단계 출력이 길면 화면이 판정으로 안 보인다. 넘는 만큼은 줄 수만 알린다.
MAX_ECHO_LINES = 40

#: 실패가 아니라 **측정**인 오류 유형. "재시도·실패" 수에서 뺀다 —
#: 02단계가 입력을 얼마나 옮겼는지를 세는 것이라 조치가 ``record`` 다.
MEASUREMENT_TYPES = frozenset(
    {"uncovered_input", "nonverbatim_evidence", "ungrounded_entity"}
)


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
        "모델 context_length ≥ --num-ctx (창은 --mode 가 정한다: "
        f"model {DEFAULT_NUM_CTX}, assemble {ASSEMBLE_NUM_CTX})",
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
        "기법마다 매핑이 있어 읽을 대상이 정해지는가. --artifacts 를 줬다면 "
        "그것이 기법 매핑과 무관하게 Tier 1 로 올라오는가",
        "selected ≥ 1. 매핑 없는 기법은 stderr에 '매핑 없음'으로 드러나야 하고 "
        "조용히 사라지면 안 된다. --artifacts 로 지정한 것은 전부 selected 이거나 "
        "(OS 미해당이면) excluded 에 사유와 함께 있어야 한다",
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
        "전달받은 레코드만 근거로 문장을 만드는가. "
        "--mode assemble 이면 claims 가 정말 원본의 복사인가",
        "findings ≥ 1 / generator에 모델 태그. "
        "input_refs 밖 참조는 여기서 실패시키지 않고 06이 잡는지 본다(측정). "
        "assemble: claims 값이 원본과 글자 그대로 일치 / 근거 필드가 그 레코드에 실재 / "
        "input_refs 에 중복 없음(조각을 나눠도 잃지 않는가)",
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
        "보고서의 '확인된 사실' 건수 == 06의 passed 건수",
    ),
    Plan(
        "nomock",
        "결산 ① — 목업이 섞이지 않았는가",
        "산출물이 스텁·시드가 아니라 이번 실행의 모델과 이미지에서 나온 것인가",
        "02·05 generator에 'stub(' 없음 / 04 매니페스트 시각이 실행 시작 이후",
    ),
]


#: ``--loop`` 일 때만 표에 끼는 단계. 05와 06 **사이**에 들어간다 —
#: 루프백이 끝나면 정규 이름이 2차를 가리키므로, 06·07은 자기가 무엇을
#: 읽는지 몰라도 되고 이 도구의 나머지 판정도 그대로 성립한다.
LOOPBACK_PLAN = Plan(
    "loopback",
    "루프백 — 05가 요청한 것을 한 번 더 본다",
    "05가 낸 추가 조사 요청으로 02→03→04→05를 다시 돌린다. **넓히기만 했는가**를 본다",
    "**1차 소견이 인용한 레코드가 2차에도 전달** / 시간·기법이 1차의 상위집합 / "
    "재사용 아티팩트의 record_count 가 1차와 동일 / 총 레코드 감소 없음 / "
    "05_requests.json 이 정확히 한 번만 생김(2차는 재요청하지 않는다). "
    "요청이 없거나 전부 기각이면 종료 코드 3 이고 그것은 실패가 아니다",
    llm=True,
)


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
        self.plan = list(PLAN)
        if args.loop:
            self.plan.insert(
                next(i for i, p in enumerate(self.plan) if p.key == "stage06"),
                LOOPBACK_PLAN,
            )
        self.started_at = datetime.now(timezone.utc)
        # 단계 간에 넘기는 값. 뒤 단계의 판정이 앞 단계의 사실에 기대는 곳이
        # 있다 (05의 흘린 참조를 06이 잡았는지 등).
        self.carry: dict[str, Any] = {}

    # ── 화면 ────────────────────────────────────────────────────────────

    def echo_plan(self, index: int, plan: Plan) -> None:
        print(BAR)
        tag = " (LLM)" if plan.llm else ""
        print(f"[{index}/{len(self.plan)}] {plan.title}{tag}")
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
        chunks = f" / 조각 최대 {self.args.max_chunks}" if self.args.mode == "assemble" else ""
        print(f"  05     mode={self.args.mode} / 창 {self.args.num_ctx:,}{chunks}")
        print(f"  시작   {io.utc_now()}")
        print("  목업   없음 (스텁·시드 인자가 이 도구에 존재하지 않음)")
        print()

        stopped = False
        for index, plan in enumerate(self.plan, start=1):
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
        # qwen2.5:7b-instruct-q4_K_M 이 없고 qwen2.5:latest 가 있으면 자동 매핑
        if self.args.model not in tags and "qwen2.5:latest" in tags:
            print(f"  안내: {self.args.model} 대신 설치된 qwen2.5:latest 로 자동 전환합니다.")
            self.args.model = "qwen2.5:latest"
        if self.args.model_interpret and self.args.model_interpret not in tags and "qwen2.5:latest" in tags:
            self.args.model_interpret = "qwen2.5:latest"

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
            # 두 군데에 쓰인다. artifacts_available 은 02 프롬프트에 실리는
            # 힌트이고(make_case 의 기본값은 레지스트리를 빼므로 여기서 채운다),
            # 같은 목록이 03단계에 --force-artifacts 로 넘어가 Tier 1 을 강제한다.
            # **힌트만으로는 부족했다** — 2026-09-07 `518_Test_0907` 에서 prefetch 를
            # 지정했는데 02가 T1059.003 을 고르는 바람에 03이 그것을 유예했고,
            # Tier 2 루프백이 없어 영구 미수집이 됐다.
            document["evidence"]["artifacts_available"] = self.args.artifacts
            io.write_json(self.case_dir / "01_input.json", document)
            forced = "" if self.args.no_force_artifacts else " (03단계 Tier 1 강제)"
            print(f"  artifacts_available 지정: {', '.join(self.args.artifacts)}{forced}")
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
        cmd = self.py(
            "-m", "src.stage03_select.select",
            "--in", str(self.case_dir / "02_scenario.json"),
            "--out", str(self.case_dir / "03_selection.json"),
            "--mappings", "mappings/",
        )
        if self.args.artifacts and not self.args.no_force_artifacts:
            cmd += ["--force-artifacts", *self.args.artifacts]
        code, _, err = self.run_cmd(cmd)
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

        if self.args.artifacts and not self.args.no_force_artifacts:
            # **판정이다.** 사람이 "이건 꼭 봐라"고 적어 준 것이 선별에서
            # 빠지면 뒤 단계는 그것을 되살릴 자리가 없다(Tier 2 루프백 없음).
            # OS 때문에 못 읽는 것은 excluded 가 사유와 함께 받으므로 뺀다.
            catalog = mapping_loader.load_catalog("mappings/")
            forced = select_mod.resolve_force_names(self.args.artifacts, catalog)
            excluded_names = {e["artifact"] for e in selection["excluded"]}
            missing = [
                name
                for name in forced
                if name not in result.measures["selected_artifacts"]
                and name not in excluded_names
            ]
            if missing:
                raise StepFailed(
                    f"--artifacts 로 지정한 {', '.join(missing)} 가 selected 에도 "
                    "excluded 에도 없다 — 강제 선별이 일하지 않았다"
                )
            result.measures["forced_artifacts"] = forced

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

    def check_assembled(
        self, findings: list, findings_doc: dict, result: Result
    ) -> None:
        """조립 경로가 약속한 것을 실제로 지켰는가. **어기면 실패시킨다.**

        스텁이나 단위 테스트로는 여기까지 못 본다. 스텁은 우리가 적어 둔
        응답을 그대로 돌려주므로 "모델이 무엇을 골랐든" 성립해야 할 성질이
        실물에서 서는지 알 수 없다.

        셋을 본다. 셋 다 **우리 코드가 틀렸을 때만** 깨진다 — 모델이 무엇을
        골랐든 성립해야 하는 것들이라, 깨지면 모델 사정이 아니라 회귀다.

        1. **claims 의 값이 원본과 글자 그대로 같은가.** 이 경로의 논지가
           "모델은 이름만 고르고 값은 파이썬이 옮긴다" 이다. 다르면 조립기가
           값을 손댄 것이고, 06단계의 통과가 의미를 잃는다.
        2. **근거 필드가 그 레코드에 실재하는가.** 레코드마다 문법 갈래를
           따로 두었으므로 없는 이름은 나올 수 없다. 나왔다면 문법이 안
           걸린 것이다(2026-09-03 에 합집합 enum 으로 무너진 자리).
        3. **``input_refs`` 에 중복이 없는가.** 조각을 나눠 물으면 합집합이
           되는데, 겹치거나 빠지면 06단계의 ``ref_in_input`` 이 헐거워진다.
        """
        records = io.read_parsed_records(self.parsed_dir)

        mismatched: list[str] = []
        missing: list[str] = []
        for finding in findings:
            for claim in finding.get("claims", []):
                record = records.get(claim["ref"])
                if record is None:
                    continue
                found, actual = assembly.walk_field(record, claim["field"])
                if not found:
                    missing.append(f"{claim['ref']}.{claim['field']}")
                elif claim["value"] != actual:
                    mismatched.append(
                        f"{claim['ref']}.{claim['field']} "
                        f"({claim['value']!r} != {actual!r})"
                    )

        if mismatched:
            raise StepFailed(
                f"조립한 claim 이 원본과 다르다 {mismatched[:3]} — "
                "파이썬이 값을 손댔다. 이 경로의 논지가 무너진 것이라 "
                "06단계의 통과도 의미가 없다"
            )
        if missing:
            raise StepFailed(
                f"그 레코드에 없는 필드를 근거로 들었다 {missing[:3]} — "
                "레코드별 문법 갈래가 안 걸렸다(selection_schema)"
            )

        input_refs = findings_doc["input_refs"]
        if len(input_refs) != len(set(input_refs)):
            raise StepFailed(
                "input_refs 에 중복이 있다 — 조각을 합칠 때 겹쳤다. "
                "06단계의 ref_in_input 이 헐거워진다"
            )

        result.measures["claims_verified_against_source"] = sum(
            len(f.get("claims", [])) for f in findings
        )

    def do_loopback(self, result: Result) -> str:
        """05가 요청한 것을 한 번 더 본다. **넓히기만 했는가**를 판정한다.

        내용이 맞는지는 보지 않는다 — 모델이 무엇을 요청했든 성립해야 하는
        구조 불변식만 본다. 깨지면 모델 사정이 아니라 우리 회귀다.
        """
        requests_path = self.case_dir / "05_requests.json"
        if not requests_path.is_file():
            # 05가 --investigate 로 돌았는데 파일이 없다. 질의가 실패했거나
            # 물어볼 것이 없었다는 뜻이고, 사유는 errors.jsonl 에 있다.
            result.used_llm = False
            result.measures["requests"] = 0
            return "05가 조사 요청을 내지 않았다 — 루프백 없이 1차로 끝난다"

        requests_doc = io.read_json(requests_path)
        if requests_doc.get("round") != 1:
            raise StepFailed(
                f"05_requests.json 의 round 가 {requests_doc.get('round')} — "
                "재요청은 한 번뿐이어야 한다"
            )
        result.measures["requests"] = len(requests_doc.get("requests", []))

        before = {
            "scenario": io.read_json(self.case_dir / "02_scenario.json"),
            "findings": io.read_json(self.case_dir / "05_findings.json"),
            "manifest": io.read_json(self.parsed_dir / "_manifest.json"),
        }

        cmd = self.py(
            "tools/react_loop.py",
            "--case", str(self.case_dir),
            "--evidence", str(self.args.evidence),
            "--python", sys.executable,
            "--model", self.model_interpret,
            "--mode", self.args.mode,
            "--host", self.args.host,
            "--num-ctx", str(self.args.num_ctx),
            "--timeout", str(self.args.timeout),
            "--limit", str(self.args.limit),
        )
        if self.args.volume is not None:
            cmd += ["--volume", str(self.args.volume)]
        if self.args.mode == "assemble":
            cmd += ["--max-chunks", str(self.args.max_chunks)]

        code, out, _ = self.run_cmd(cmd)
        for line in out.splitlines():
            if line.strip():
                print(f"        {line.rstrip()}")

        if code == 3:
            # 돌릴 이유가 없었다. **실패가 아니다** — 요청이 전부 기각됐거나
            # 2차 선별이 1차와 같았다는 뜻이고, 케이스는 1차로 완결돼 있다.
            result.used_llm = False
            if (self.case_dir / "05_findings.round1.json").exists():
                raise StepFailed(
                    "2차를 돌지 않았는데 .round1 파일이 남아 있다 — "
                    "사람도 도구도 '2차가 돌았다'로 읽는다"
                )
            return "수용된 요청이 없어 1차로 끝났다 (실패 아님)"
        if code != 0:
            raise StepFailed(f"루프백 실패 (코드 {code}). {self.errors_path} 를 본다")

        # ── 넓히기만 했는가 ────────────────────────────────────────────
        after = {
            "scenario": io.read_json(self.case_dir / "02_scenario.json"),
            "findings": io.read_json(self.case_dir / "05_findings.json"),
            "manifest": io.read_json(self.parsed_dir / "_manifest.json"),
        }

        # **1차가 인용한 레코드**가 2차에도 전달됐는가. ``--pin-refs`` 가
        # 약속하는 것이 이것이고, 1차 소견이 최종 보고서에서 사라지지 않는
        # 근거도 이것뿐이다.
        #
        # **전달 목록 전체로 걸지 않는다.** 처음에 그렇게 걸었다가
        # `K-LOOP-0909-on`(2026-09-09) 에서 걸렸는데, 잡힌 것이 결함이
        # 아니었다 — 2차는 레코드가 늘어난 상태에서 **같은 자릿수 예산**으로
        # 배분하므로, 아무도 인용하지 않은 레코드가 새 증거에 밀리는 것이
        # 정상 동작이다(그 실행에서 61건 중 24건이 그렇게 바뀌었고 인용된
        # 12건은 전부 남았다). 전달 목록의 단조 증가를 요구하면 새 증거가
        # 옛 레코드를 대체할 수 없게 되어, 루프백이 가져온 것을 프롬프트에
        # 실을 자리가 없어진다. 예산이 고정인 한 성립할 수 없는 불변식이다.
        cited = {
            ref
            for finding in before["findings"]["findings"]
            for ref in finding.get("refs", [])
        } | {
            ref
            for moment in before["findings"].get("timeline", [])
            for ref in moment.get("refs", [])
        }
        delivered = set(after["findings"]["input_refs"])
        lost_refs = sorted(cited - delivered)
        if lost_refs:
            raise StepFailed(
                f"1차 소견이 인용한 레코드 {len(lost_refs)}건이 2차에 전달되지 않았다 "
                f"({', '.join(lost_refs[:5])}) — --pin-refs 가 일을 못 했다. "
                "그 소견은 최종 보고서에서 사라진다"
            )
        result.measures["pinned_refs"] = len(cited)
        result.measures["delivered_before"] = len(before["findings"]["input_refs"])
        result.measures["delivered_after"] = len(delivered)
        # 인용되지 않은 레코드가 새 증거에 밀린 수. 판정이 아니라 측정이다 —
        # 크면 2차가 1차와 다른 것을 보고 있다는 뜻이라 눈에 보여야 한다.
        result.measures["displaced_uncited"] = len(
            set(before["findings"]["input_refs"]) - delivered
        )

        was = {t["id"] for t in before["scenario"]["techniques"]}
        now = {t["id"] for t in after["scenario"]["techniques"]}
        if not was <= now:
            raise StepFailed(f"2차 시나리오가 기법을 잃었다: {sorted(was - now)}")

        old_range, new_range = before["scenario"]["time_range"], after["scenario"]["time_range"]
        if new_range["start"] > old_range["start"] or new_range["end"] < old_range["end"]:
            raise StepFailed(
                f"2차 분석 기간이 1차보다 좁다 "
                f"({old_range['start']}~{old_range['end']} → "
                f"{new_range['start']}~{new_range['end']})"
            )

        # 재사용은 **다시 안 읽었다**는 뜻이므로 건수가 1차와 같아야 한다.
        # 다르면 재사용 판정이 범위가 바뀐 아티팩트를 그냥 넘긴 것이다.
        counts_before = {e["artifact"]: e["record_count"] for e in before["manifest"]["files"]}
        reused = [e for e in after["manifest"]["files"] if e.get("reused")]
        for entry in reused:
            if counts_before.get(entry["artifact"]) != entry["record_count"]:
                raise StepFailed(
                    f"{entry['artifact']} 를 재사용했다는데 건수가 다르다 "
                    f"({counts_before.get(entry['artifact'])} → {entry['record_count']})"
                )

        if before["manifest"]["total_records"] > after["manifest"]["total_records"]:
            raise StepFailed(
                f"2차 파싱이 1차보다 적다 "
                f"({before['manifest']['total_records']} → {after['manifest']['total_records']})"
            )

        # 2차가 재요청하지 않았는가. 구조로 걸어 둔 가드레일의 확인이다.
        round2_queries = sorted(
            path.name for path in (self.case_dir / "05_llm_queries_round2").glob("*.txt")
        )
        if any("investigation" in name for name in round2_queries):
            raise StepFailed(
                "2차 질의 내역에 조사 요청 질의가 있다 — 재요청은 한 번뿐이어야 한다"
            )

        # **06이 검증할 대상이 바뀌었다.** 05단계가 넘긴 값은 1차의 것이라
        # 그대로 두면 06 관문이 "판정 합계 != findings" 로 걸린다 — 실제로
        # 걸렸다(`K-LOOP-0909-on2`, 2026-09-09). 06 이후의 판정은 전부
        # 최종 산출물을 봐야 하므로 여기서 2차 값으로 바꾼다.
        after_findings = after["findings"]["findings"]
        allowed = set(after["findings"]["input_refs"])
        self.carry["findings_count"] = len(after_findings)
        self.carry["stray_refs"] = sorted(
            {
                ref
                for finding in after_findings
                for ref in finding.get("refs", [])
                if ref not in allowed
            }
        )

        accepted = [
            request
            for request in io.read_json(requests_path).get("requests", [])
            if (request.get("disposition") or {}).get("verdict") == "accepted"
        ]
        result.measures["requests_accepted"] = len(accepted)
        result.measures["reused_artifacts"] = [e["artifact"] for e in reused]
        result.measures["records_before"] = before["manifest"]["total_records"]
        result.measures["records_after"] = after["manifest"]["total_records"]
        result.measures["findings_before"] = len(before["findings"]["findings"])
        result.measures["findings_after"] = len(after["findings"]["findings"])

        return (
            f"요청 {len(requests_doc.get('requests', []))}건 중 {len(accepted)}건 수용 / "
            f"레코드 {before['manifest']['total_records']}→"
            f"{after['manifest']['total_records']}건 "
            f"(재사용 {len(reused)}개 아티팩트) / "
            f"소견 {len(before['findings']['findings'])}→{len(after['findings']['findings'])}건"
        )

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
            "--mode", self.args.mode,
        )
        if self.args.mode == "assemble":
            cmd += ["--max-chunks", str(self.args.max_chunks)]
        if self.args.loop:
            # **1차에만 묻는다.** 2차 05는 react_loop.py 가 이 인자 없이
            # 부르므로 3차 요청이 생길 자리가 없다(구조로 거는 가드레일).
            cmd += ["--investigate"]
        code, out, _ = self.run_cmd(cmd)
        if code != 0:
            raise StepFailed(
                f"05 실패 (코드 {code}). {self.errors_path} 와 "
                f"{self.case_dir}/05_interpret_raw_attempt*.txt 를 본다"
            )

        # **05가 스스로 말하는 것을 그대로 보여 준다.** 여기서 삼키면 배분·
        # 조각 수·토큰 추정과 실측이 산출물 어디에도 안 남는다 — 이 도구를
        # 돌리는 이유가 "관통하는가" 만이 아니라 "어떻게 돌았나" 이기도 하다.
        for line in out.splitlines():
            if line.strip():
                print(f"        {line.rstrip()}")

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

        # 무엇을 물었고 무엇이 돌아왔는지. 두 모드 다 남는다.
        queries_dir = self.case_dir / "05_llm_queries"
        query_files = sorted(f.name for f in queries_dir.glob("*.txt")) if queries_dir.is_dir() else []
        result.measures["llm_queries"] = query_files

        note = (
            f"findings {len(findings)}건 / 전달 레코드 {len(allowed)}건 "
            f"(--limit {self.args.limit})"
        )
        if query_files:
            note += f" / 질의 {len(query_files)}건 → {queries_dir}"

        if self.args.mode == "assemble":
            self.check_assembled(findings, findings_doc, result)

            # 조립 경로에서만 보이는 것들이다. 묶음이 0이면 Reduce 가 아무것도
            # 잇지 못했거나 건너뛴 것이고, 그 사실은 errors.jsonl 에 있다.
            tied = [f for f in findings if len(f.get("refs", [])) > 1]
            cited = {ref for f in findings for ref in f.get("refs", [])}
            fields = sorted({c["field"] for f in findings for c in f.get("claims", [])})
            result.measures["connected_findings"] = len(tied)
            result.measures["cited_records"] = len(cited)
            result.measures["claim_fields"] = fields
            note += (
                f" / 묶음 {len(tied)}건"
                + (f" (최대 {max(len(f['refs']) for f in tied)}ref)" if tied else "")
                + f" / 소견이 인용한 레코드 {len(cited)}건"
                + f" / 근거 필드 {len(fields)}종 {fields[:4]}"
            )
        if stray:
            note += f" / 측정: input_refs 밖 참조 {len(stray)}건 {stray[:3]} → 06이 잡아야 한다"
        if empty_claims:
            # **하한이다.** 06 은 증거 밖 표현을 쓴 문장도 강등하므로
            # (`checkers/statement_grounded.py`) unverifiable 은 이보다 클 수
            # 있다. "같아야 한다"로 읽으면 정상 동작을 어긋남으로 본다.
            note += f" / 측정: claims 빈 문장 {len(empty_claims)}건 → unverifiable 하한"
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

        verified_doc = io.read_json(self.case_dir / "06_verified.json")
        stats = verified_doc["stats"]
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

        # **환각률이 무엇을 재고 있는지 함께 말한다.** claims 를 파이썬이
        # 조립하면 value_match 는 항등식이라 언제나 통과한다. 그때 기각을
        # 만드는 것은 technique_supported 뿐인데, 그 검사는 technique 이
        # 붙은 소견만 본다 — null 인 소견은 지나간다. 분모를 안 적으면
        # "환각률 0%" 를 성능으로 읽게 된다(docs/limitations.md 의 유형 표).
        findings = io.read_json(self.case_dir / "05_findings.json")["findings"]
        with_technique = [f for f in findings if f.get("technique")]
        result.measures["findings_with_technique"] = len(with_technique)

        # 강등은 기각이 아니라 분모에서 빠지는 쪽이다. 세어 두지 않으면
        # unverifiable 이 늘어난 것이 "종합 판단 문장이 많았다"인지
        # "증거 밖 표현을 썼다"인지 뒤에서 가릴 수 없다.
        ungrounded = [
            entry
            for entry in verified_doc["unverifiable"]
            if entry["reason"].startswith(statement_grounded.REASON)
        ]
        result.measures["statement_ungrounded"] = len(ungrounded)

        # 기각 상세는 여기 싣지 않는다. 06단계가 실행마다
        # `benchmark/results/rejections.jsonl` 에 직접 덧붙이므로
        # (`stage06_verify.runlog`), 여기 또 실으면 한 실행이 두 곳에 잡혀
        # `collect.py --rejections` 가 두 번 센다. 이 도구만 기록하던 때에는
        # `run_pipeline.sh` 나 웹 UI 로 돌린 실행이 통째로 새고 있었다.

        note = (
            f"passed {stats['passed']} / rejected {stats['rejected']} "
            f"/ unverifiable {stats['unverifiable']} "
            f"({verify_mod.format_rate(stats)} — 측정치)"
        )
        note += (
            f" / technique 이 붙은 소견 {len(with_technique)}/{len(findings)}건"
            " ← technique_supported 가 실제로 판정한 범위"
        )
        if ungrounded:
            names = ", ".join(entry["id"] for entry in ungrounded)
            note += f" / 증거 밖 표현으로 강등 {len(ungrounded)}건 ({names})"
        if self.args.mode == "assemble":
            note += " / claims 는 파이썬이 조립했으므로 value_match 는 항등식이다"
        return note

    def do_stage07(self, result: Result) -> str:
        code, out, _ = self.run_cmd(
            self.py(
                "-m", "src.stage07_report.report",
                "--in", str(self.case_dir / "06_verified.json"),
                "--findings", str(self.case_dir / "05_findings.json"),
                "--selection", str(self.case_dir / "03_selection.json"),
                "--scenario", str(self.case_dir / "02_scenario.json"),
                *(
                    ["--requests", str(self.case_dir / "05_requests.json")]
                    if (self.case_dir / "05_requests.json").is_file()
                    else []
                ),
                "--parsed", str(self.parsed_dir),
                "--out", str(self.case_dir / "07_report.md"),
            )
        )
        if code != 0:
            raise StepFailed(f"07 실패 (코드 {code})")

        match = re.search(r"확인된 사실 (\d+)건", out)
        if not match:
            raise StepFailed("07 출력에서 '확인된 사실' 건수를 읽지 못했다")
        reported = int(match.group(1))
        if reported != self.carry["passed"]:
            raise StepFailed(
                f"보고서의 확인된 사실 {reported}건 != 06의 passed {self.carry['passed']}건 — "
                "검증을 통과하지 않은 문장이 실렸거나 통과분이 빠졌다"
            )
        result.measures["report_bytes"] = (self.case_dir / "07_report.md").stat().st_size
        return f"확인된 사실 {reported}건 == 06 passed / {self.case_dir / '07_report.md'}"

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
                print(f"  검증 불가율  {rate:.1%}  (claims 가 비었거나 증거 밖 표현)")
        if self.errors_path.is_file():
            counted = errlog.tally(self.errors_path)
            # ``record`` 는 실패가 아니라 측정이다(``errors.py`` 어휘 주석).
            # 같이 세면 "재시도·실패"가 부풀어, 프롬프트를 고쳐 나아졌는지
            # 볼 자리가 오히려 흐려진다.
            measured = counted["by_action"].get("record", 0)
            # ``by_field`` 는 tally 가 둘을 섞어 낸다. 실패 아래에 측정에서
            # 온 필드가 찍히면 "무엇이 실패했나"를 잘못 읽게 되므로 직접 센다.
            fields: dict[str, Counter] = {"fail": Counter(), "record": Counter()}
            for entry in io.read_jsonl(self.errors_path):
                field = (entry.get("detail") or {}).get("field")
                if field:
                    fields["record" if entry.get("action") == "record" else "fail"][str(field)] += 1

            print(f"  재시도·실패  {counted['total'] - measured}건 — {self.errors_path}")
            for etype, count in sorted(counted["by_type"].items()):
                if etype in MEASUREMENT_TYPES:
                    continue
                print(f"      type {etype}: {count}")
            for name, count in sorted(fields["fail"].items(), key=lambda kv: -kv[1])[:5]:
                print(f"      field {name}: {count}   ← 프롬프트 개선의 근거")
            if measured:
                print(f"  02 측정치    {measured}건 (실행을 실패시키지 않는다)")
                for etype in sorted(MEASUREMENT_TYPES):
                    if counted["by_type"].get(etype):
                        print(f"      type {etype}: {counted['by_type'][etype]}")
                for name, count in sorted(fields["record"].items(), key=lambda kv: -kv[1])[:5]:
                    print(f"      field {name}: {count}   ← 프롬프트 개선의 근거")
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
            # 05가 어느 경로로 돌았는지. 창·질의 횟수·소견 수가 다 여기 달려
            # 있어서, 안 남기면 실행끼리 비교할 때 무엇이 달라서 다른지
            # 알 수 없다(benchmark/collect.py 가 이 파일을 읽는다).
            "mode": self.args.mode,
            "max_chunks": self.args.max_chunks if self.args.mode == "assemble" else None,
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

        # 05가 어떻게 판단했는지는 산출물이 아니라 여기에 있다. 이 도구를
        # 돌리는 사람이 가장 자주 여는 자리라 마지막에 한 번 더 말한다.
        queries_dir = self.case_dir / "05_llm_queries"
        if queries_dir.is_dir():
            names = sorted(f.name for f in queries_dir.glob("*.txt"))
            print()
            print(f"05 질의 내역 ({len(names)}건) — 무엇을 묻고 무엇이 돌아왔나:")
            for name in names:
                print(f"      {queries_dir / name}")


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
        help=(
            "이번 실행에서 반드시 볼 아티팩트. 01_input 의 artifacts_available 을 덮고"
            "(02 프롬프트 힌트), **03단계에 --force-artifacts 로 그대로 넘어가** 기법 "
            "매핑과 무관하게 Tier 1 로 올라간다. 예: --artifacts '$MFT' evtx registry"
        ),
    )
    parser.add_argument(
        "--no-force-artifacts",
        action="store_true",
        help=(
            "--artifacts 를 02 프롬프트 힌트로만 쓰고 03단계에 강제하지 않는다. "
            "예전 동작이다 — 강제 선별이 결과를 얼마나 바꾸는지 재려고 남겨 둔다"
        ),
    )
    parser.add_argument("--model", default="qwen2.5:latest", help="02 정규화 모델. 기본 %(default)s")
    parser.add_argument(
        "--model-interpret",
        default=None,
        help="05 해석 모델. 생략하면 --model 과 같다 (해석만 키우는 실험용)",
    )
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument(
        "--mode",
        choices=["assemble", "model"],
        default="assemble",
        help=(
            "05가 findings 를 만드는 방식. 기본 %(default)s. "
            "assemble 은 모델이 {ref, 기법, 사유, 근거 필드}만 고르고 파이썬이 "
            "원본에서 조립한다 — 질의를 조각으로 나눠 보내므로 창 하나에 "
            "들어가는 것보다 많이 본다. model 은 모델이 문장·claims·타임라인을 "
            "전부 쓰는 예전 경로이고, 둘을 비교할 때 쓴다. "
            "**이 도구의 기본이 assemble 인 것은 지금 파이프라인의 기본 경로가 "
            "그쪽이기 때문이다** — 점검 도구가 안 쓰는 경로를 재면 의미가 없다"
        ),
    )
    parser.add_argument(
        "--max-chunks",
        type=int,
        default=8,
        help=(
            "--mode assemble 에서 질의를 몇 번까지 나눌 것인가. 기본 %(default)s. "
            "**이 값이 커버리지의 상한이다** — --limit 과 함께 올려야 는다"
        ),
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help=(
            "05→02 자율 루프백을 켠다. 05가 소견을 낸 뒤 추가 조사를 요청하고 "
            "02→03→04→05를 **한 번만** 다시 돈다. 관문이 하나 늘어 "
            "'넓히기만 했는가'를 판정한다 (2차 input_refs ⊇ 1차, 시간·기법이 "
            "상위집합, 인용 레코드 유지, 재사용 아티팩트의 건수 동일). **끄고 한 번 켜고 한 번 "
            "돌려 나란히 놓는 것이 이 스위치의 쓰임이다**"
        ),
    )
    parser.add_argument(
        "--num-ctx",
        type=int,
        default=None,
        help=(
            "컨텍스트 창. 생략하면 --mode 가 정한다 "
            f"(model {DEFAULT_NUM_CTX}, assemble {ASSEMBLE_NUM_CTX})"
        ),
    )
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

    if args.num_ctx is None:
        # 05단계와 같은 규칙이다. 단일 질의는 창이 곧 커버리지라 넓어야 하고,
        # 분할 질의는 여러 번 보내므로 좁혀도 잃지 않는다. 여기서 정해 두는
        # 것은 사전 점검이 "모델 context_length ≥ 창" 을 재기 때문이다.
        args.num_ctx = ASSEMBLE_NUM_CTX if args.mode == "assemble" else DEFAULT_NUM_CTX
    return args


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    return Runner(args).execute()


if __name__ == "__main__":
    raise SystemExit(main())
