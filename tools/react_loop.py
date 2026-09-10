"""05→02 자율 루프백 오케스트레이터. 05와 06 **사이**에 한 번 돈다.

05단계가 ``--investigate`` 로 낸 ``05_requests.json`` 을 받아 02단계 확장 →
03 재선별 → 04 부분 재파싱 → 05 재해석을 돌린다. 끝나면 정규 이름
(``02_scenario.json``·``03_selection.json``·``05_findings.json``)이 **2차
결과**를 가리키고, 1차는 ``.round1`` 으로 남는다. 06·07 은 아무것도 모르고
평소대로 최종 파일을 읽는다.

::

    cases/C-001/
      02_scenario.round1.json  03_selection.round1.json  05_findings.round1.json  ← 1차
      05_requests.json         ← 요청과 판정
      02_scenario.json  03_selection.json  04_parsed/  05_findings.json           ← 최종

**1차를 정규 이름에서 밀어내는 이유**는 뒤 도구들이 그 이름을 하드코딩하기
때문이다(``benchmark/evaluate.py``·``tools/live_check.py``·``pipeline_worker.py``).
2차를 ``.r2`` 로 두면 그 도구들이 전부 1차를 본다.

## 세 가지를 하지 않는다

- **모델에게 시나리오를 다시 쓰게 하지 않는다.** 02단계 확장은 결정론이고,
  2차 시나리오는 1차의 상위집합임이 코드로 보장된다.
- **2차 05에 ``--investigate`` 를 주지 않는다.** 묻지 않으므로 3차 요청이
  생길 자리가 없다 — 무한 루프 방지를 카운터가 아니라 구조로 거는 자리다.
- **04를 통째로 다시 읽지 않는다.** ``--reuse-from`` 으로 범위가 바뀐
  아티팩트만 읽는다.

## 종료 코드

- ``0`` — 2차까지 끝났다. 06·07 은 최종 파일을 읽으면 된다
- ``3`` — 돌릴 이유가 없었다(요청 0건, 전부 기각, 또는 2차 선별이 1차와 같다).
  **실패가 아니다.** 케이스는 1차 결과 그대로 완결돼 있다
- ``1``/``2`` — 어느 단계가 실패했다. 그 단계의 출력과 ``errors.jsonl`` 을 본다

사용법::

    PYTHON=.venv/Scripts/python.exe python tools/react_loop.py \\
        --case cases/C-001 --evidence evidence/x.001 --volume 1 \\
        --model qwen2.5:latest --mode assemble

설계는 ``docs/proposals/stage05-investigation-loopback.md``.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import io, schema  # noqa: E402
from src.stage02_normalize.expand import EXIT_NOTHING_TO_DO  # noqa: E402
from src.stage04_parse.parse import group_by_artifact, scope_key  # noqa: E402
from src.stage05_interpret import behavior_search, coverage  # noqa: E402

# ``EXIT_NOTHING_TO_DO`` 는 ``expand`` 의 값을 그대로 쓴다(위 import).
# 부르는 쪽은 "요청이 없었다"와 "확장할 것이 없었다"를 갈라 볼 이유가 없다.

#: 1차를 보존할 이름. ``<이름>.round1.json``.
PRESERVED = ("02_scenario.json", "03_selection.json", "05_findings.json")


def round1_name(name: str) -> str:
    stem, _, suffix = name.rpartition(".")
    return f"{stem}.round1.{suffix}"


class Runner:
    """단계를 부르고 실패하면 그 자리에서 멈춘다."""

    def __init__(self, python: str, quiet: bool = False) -> None:
        # **상대 경로를 리포 기준으로 편다.** 단계는 ``cwd=REPO_ROOT`` 로
        # 부르는데, 실행 파일 경로는 부모의 cwd 로 풀린다. 그래서
        # ``PYTHON=.venv/Scripts/python.exe`` 처럼 넘기면(run_pipeline.sh 의
        # 규약) 어디서 부르느냐에 따라 FileNotFoundError 가 난다.
        candidate = Path(python)
        if not candidate.is_absolute() and (REPO_ROOT / candidate).is_file():
            candidate = REPO_ROOT / candidate
        self.python = str(candidate)
        self.quiet = quiet

    def run(self, title: str, args: list[str]) -> int:
        if not self.quiet:
            print(f"== {title} ==", flush=True)
        completed = subprocess.run([self.python, *args], cwd=REPO_ROOT)
        return completed.returncode


def accepted_artifacts(requests_doc: dict[str, Any]) -> list[str]:
    """03단계에 ``--force-artifacts`` 로 넘길 이름.

    시나리오에는 아티팩트를 담을 자리가 없으므로(동결 스키마) 확장이
    ``applied.artifacts`` 에 남겨 둔 것을 여기서 옮긴다.
    """
    return list((requests_doc.get("applied") or {}).get("artifacts") or [])


def selection_changed(first: Path, second: Path) -> bool:
    """2차 선별이 1차와 다른가.

    **같으면 04·05를 돌리지 않는다**(가드레일 G4). 기법이 늘어도 그 기법이
    요청하는 아티팩트와 범위가 이미 1차에 다 들어 있으면 2차는 같은 것을
    다시 읽고 같은 것을 다시 해석한다 — 시간만 쓰고 결과가 같다.

    비교는 ``scope_key`` 로 한다. 04단계가 "다시 읽어야 하는가"를 가르는
    것과 **같은 기준**이어야, 여기서 "달라졌다"고 판단한 것이 저기서
    실제로 다시 읽히는 것과 어긋나지 않는다.
    """
    before = group_by_artifact(io.read_json(first))
    after = group_by_artifact(io.read_json(second))
    if set(before) != set(after):
        return True
    return any(scope_key(before[name]) != scope_key(after[name]) for name in after)


def apply_behavior_requests(case: Path, requests_path: Path, mappings: str) -> set[str]:
    """행위 요청만 먼저 실행하고 원장·요청 문서를 원자적 산출물처럼 갱신한다."""
    requests_doc = io.read_json(requests_path)
    if not any(item.get("type") == "request_behavior" for item in requests_doc.get("requests", [])):
        return set()

    scenario = io.read_json(case / "02_scenario.json")
    findings = io.read_json(case / "05_findings.json")
    raw = ""
    input_path = case / "01_input.json"
    if input_path.is_file():
        raw_value = io.read_json(input_path).get("raw")
        if isinstance(raw_value, str):
            raw = raw_value

    ledger_path = case / "05_coverage.json"
    previous = io.read_json(ledger_path) if ledger_path.is_file() else None
    ledger = coverage.build(
        scenario,
        findings,
        raw=raw,
        previous=previous,
        mappings=mappings,
        generator=io.make_generator("coverage.py / behavior_search.py"),
    )
    records = list(io.read_parsed_records(case / "04_parsed").values())
    promoted = behavior_search.apply_requests(
        requests_doc,
        ledger,
        records,
        input_refs=set(findings.get("input_refs", [])),
        mappings=mappings,
    )
    schema.validate(requests_doc, "investigation")
    schema.validate(ledger, "coverage")
    io.write_json(requests_path, requests_doc)
    io.write_json(ledger_path, ledger)
    return promoted


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)

    case = Path(args.case)
    requests_path = case / "05_requests.json"
    if not requests_path.is_file():
        print(
            f"{requests_path} 가 없다 — 05단계를 --investigate 로 돌리지 않았거나 "
            "질의가 실패했다. 1차로 끝난다.",
        )
        return EXIT_NOTHING_TO_DO

    try:
        behavior_refs = apply_behavior_requests(case, requests_path, args.mappings)
    except (ValueError, KeyError) as exc:
        print(f"행위 기반 재검색 실패: {exc}", file=sys.stderr)
        return 2

    runner = Runner(args.python, quiet=args.quiet)

    # ── 02 확장 ────────────────────────────────────────────────────
    # 1차를 먼저 밀어 둔다. 확장이 읽는 것도 쓰는 것도 그 뒤의 이름이라,
    # 실패해도 1차 파일은 .round1 에 온전히 남는다.
    for name in PRESERVED:
        source = case / name
        if not source.is_file():
            print(f"{source} 가 없다 — 1차가 완결되지 않았다.", file=sys.stderr)
            return 2
        shutil.copy(source, case / round1_name(name))

    code = runner.run(
        "루프백 02 확장 (LLM 없음)",
        [
            "-m", "src.stage02_normalize.expand",
            "--scenario", str(case / round1_name("02_scenario.json")),
            "--requests", str(requests_path),
            "--findings", str(case / round1_name("05_findings.json")),
            "--selection", str(case / round1_name("03_selection.json")),
            "--out", str(case / "02_scenario.json"),
            "--mappings", args.mappings,
            *(["--input", str(case / "01_input.json")] if (case / "01_input.json").is_file() else []),
        ],
    )
    if code == EXIT_NOTHING_TO_DO:
        # 확장이 아무것도 안 썼다. 1차 파일이 정규 이름에 그대로 있으므로
        # 밀어 둔 사본만 걷어 낸다 — 안 걷으면 "2차가 돌았다"로 읽힌다.
        for name in PRESERVED:
            (case / round1_name(name)).unlink(missing_ok=True)
        print("수용된 요청이 없다 — 1차로 끝난다.")
        return EXIT_NOTHING_TO_DO
    if code != 0:
        return code

    # ── 03 재선별 ──────────────────────────────────────────────────
    forced = accepted_artifacts(io.read_json(requests_path))
    code = runner.run(
        "루프백 03 선별",
        [
            "-m", "src.stage03_select.select",
            "--in", str(case / "02_scenario.json"),
            "--out", str(case / "03_selection.json"),
            "--mappings", args.mappings,
            *(["--force-artifacts", *forced] if forced else []),
        ],
    )
    if code != 0:
        return code

    changed = selection_changed(
        case / round1_name("03_selection.json"), case / "03_selection.json"
    )
    if not changed and not behavior_refs:
        # 시나리오는 넓어졌는데 볼 것이 그대로다. 04·05를 돌려 봐야 같은
        # 결과가 나오므로 여기서 멈추고 1차를 정규 이름으로 되돌린다.
        for name in PRESERVED:
            shutil.move(str(case / round1_name(name)), case / name)
        print("2차 선별이 1차와 같다 — 다시 읽을 것이 없어 1차로 끝난다.")
        return EXIT_NOTHING_TO_DO

    # ── 04 부분 재파싱 ─────────────────────────────────────────────
    # request_behavior만 수용된 경우 04 데이터는 이미 있고, 달라진 것은
    # 보장 레인 ref뿐이다. 같은 85만 건을 다시 파싱하지 않는다.
    if changed:
        code = runner.run(
            "루프백 04 파싱 (범위가 바뀐 것만)",
            [
                "-m", "src.stage04_parse.parse",
                "--in", str(case / "03_selection.json"),
                "--out", str(case / "04_parsed"),
                "--evidence", args.evidence,
                "--reuse-from", str(case / round1_name("03_selection.json")),
                *(["--volume", str(args.volume)] if args.volume is not None else []),
            ],
        )
        if code != 0:
            return code

    # ── 05 재해석 ──────────────────────────────────────────────────
    # **--investigate 를 주지 않는다**(가드레일 G1). --pin-refs 로 1차가
    # 인용한 레코드의 자리를 보장한다 — 없으면 2차가 1차보다 얇아질 수 있다.
    interpret = [
        "-m", "src.stage05_interpret.interpret",
        "--in", str(case / "04_parsed"),
        "--scenario", str(case / "02_scenario.json"),
        "--selection", str(case / "03_selection.json"),
        "--out", str(case / "05_findings.json"),
        "--pin-refs", str(case / round1_name("05_findings.json")),
        "--coverage", str(case / "05_coverage.json"),
        "--mode", args.mode,
        "--mappings", args.mappings,
        "--queries", str(case / "05_llm_queries_round2"),
    ]
    if args.replay:
        interpret += ["--llm", "stub", "--replay", args.replay]
    else:
        interpret += ["--llm", "ollama", "--model", args.model]
        for flag, value in (
            ("--host", args.host),
            ("--num-ctx", args.num_ctx),
            ("--timeout", args.timeout),
            ("--temperature", args.temperature),
            ("--limit", args.limit),
            ("--max-chunks", args.max_chunks),
        ):
            if value is not None:
                interpret += [flag, str(value)]

    code = runner.run("루프백 05 해석 (2차, 재요청 없음)", interpret)
    if code != 0:
        return code

    _summarize(case)
    return 0


def _summarize(case: Path) -> None:
    """무엇이 늘었는지 한 표로. 없으면 2차가 왜 돌았는지 알 수 없다."""
    requests_doc = io.read_json(case / "05_requests.json")
    accepted = [
        request
        for request in requests_doc.get("requests", [])
        if (request.get("disposition") or {}).get("verdict") == "accepted"
    ]
    first = io.read_json(case / round1_name("05_findings.json"))
    second = io.read_json(case / "05_findings.json")
    manifest = io.read_json(case / "04_parsed" / "_manifest.json")
    reused = [entry["artifact"] for entry in manifest.get("files", []) if entry.get("reused")]

    print()
    print(f"루프백 완료 — 요청 {len(requests_doc.get('requests', []))}건 중 {len(accepted)}건 수용")
    for request in accepted:
        detail = (request.get("disposition") or {}).get("detail", "")
        based_on = request.get("based_on") or {}
        ground = request.get("based_on_ref") or based_on.get("ref") or based_on.get("claim_id") or "-"
        print(f"  {request['type']:<18} {str(ground):<16} {detail}")
    print(
        f"  전달 레코드 {len(first.get('input_refs', []))}건 → "
        f"{len(second.get('input_refs', []))}건 / "
        f"소견 {len(first.get('findings', []))}건 → {len(second.get('findings', []))}건"
    )
    if reused:
        print(f"  04 재사용 {len(reused)}개 아티팩트: {', '.join(sorted(reused))}")
    lost = set(first.get("input_refs", [])) - set(second.get("input_refs", []))
    if lost:
        # 2차는 1차의 상위집합이어야 한다. 어긋나면 --pin-refs 가 일을 못 한
        # 것이고, 그 소견은 최종 보고서에서 사라진다.
        print(
            f"  경고: 1차에 있던 레코드 {len(lost)}건이 2차 전달 목록에 없습니다 "
            f"({', '.join(sorted(lost)[:5])})",
            file=sys.stderr,
        )
    print()
    print(f"최종: {case}/05_findings.json (1차는 {round1_name('05_findings.json')})")


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python tools/react_loop.py",
        description=(
            "05단계의 추가 조사 요청을 받아 02→03→04→05를 한 번 더 돌린다. "
            f"돌릴 이유가 없으면 종료 코드 {EXIT_NOTHING_TO_DO} (실패가 아니다)"
        ),
    )
    parser.add_argument("--case", required=True, help="케이스 디렉터리 (cases/<id>)")
    parser.add_argument("--evidence", required=True, help="증거 루트 또는 이미지 파일")
    parser.add_argument("--volume", type=int, default=None, help="이미지에 NTFS가 여럿일 때 볼륨 번호")
    parser.add_argument("--python", default=sys.executable, help="단계를 부를 인터프리터")
    parser.add_argument("--mappings", default="mappings", help="매핑 디렉터리")
    parser.add_argument("--mode", default="assemble", choices=["assemble", "model"])
    parser.add_argument("--model", default=None, help="ollama 모델명. --replay 가 없으면 필수")
    parser.add_argument("--replay", default=None, help="스텁 재생 파일 (배선 확인용)")
    parser.add_argument("--host", default=None)
    parser.add_argument("--num-ctx", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--temperature", type=float, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--max-chunks", type=int, default=None)
    parser.add_argument("--quiet", action="store_true", help="단계 제목을 찍지 않는다")

    args = parser.parse_args(argv)
    if not args.replay and not args.model:
        # 05단계가 기본 모델을 갖고 있지만 여기서는 받지 않는다.
        # run_pipeline.sh 가 MODEL 을 필수로 두는 것과 같은 이유다 —
        # 산출물의 generator 가 실행한 사람의 기계 사정에 좌우되면 안 된다.
        parser.error("--model 이 필요하다 (스텁으로 배선만 볼 거면 --replay)")
    return args


if __name__ == "__main__":
    raise SystemExit(main())
