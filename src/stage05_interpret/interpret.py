"""05단계 — sLLM 해석.

파싱된 레코드를 읽고 "무엇이 확인되는가"를 문장으로 만든다. 모든 문장은
``refs``로 원본 레코드를 가리켜야 하고, 문장이 주장하는 사실은 ``claims``
삼중항으로 분해되어야 한다. 06단계가 그 삼중항만 대조한다.

**``input_refs``는 모델에게 묻지 않는다.** 무엇을 전달했는지는 우리가
안다. 모델이 보고하게 하면 실제로 받지 않은 레코드를 목록에 넣어
``ref_not_in_input`` 검사를 무력화할 수 있다. 이 단계에서 가장 중요한
설계 결정이다.

사용법::

    python -m src.stage05_interpret.interpret \\
        --in cases/C-001/04_parsed/ --scenario cases/C-001/02_scenario.json \\
        --selection cases/C-001/03_selection.json \\
        --out cases/C-001/05_findings.json \\
        --llm stub --replay benchmark/datasets/C-001-webshell/mock/05_findings.json

``--selection``은 선택이지만 **주는 것이 정상이다.** 없으면 모든 아티팩트가
같은 비중으로 자리를 나눠 갖는다 — 배분은 그대로 돌지만 "이 기법 때문에 이
아티팩트가 중요하다"는 03단계의 판단만 빠진다.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from ..common import errors as errlog
from ..common import io, llm, schema
from ..common.llm import DEFAULT_NUM_CTX, DEFAULT_TIMEOUT
from ..stage03_select import mapping_loader
from . import allocation, record_filter
from .llm_client import DEFAULT_MODEL, FINDINGS_BODY_FIELDS, InterpretClient

__all__ = ["STAGE", "build_findings", "interpret", "main"]

STAGE = "05_interpret"
MAX_ATTEMPTS = 3


def build_findings(
    body: dict[str, Any], case_id: str, generator: str, input_refs: list[str]
) -> dict[str, Any]:
    """모델이 만든 본문에 헤더와 ``input_refs``를 붙인다."""
    return io.new_document(
        case_id,
        STAGE,
        generator,
        input_refs=input_refs,
        findings=body.get("findings", []),
        timeline=body.get("timeline", []),
    )


def interpret(
    scenario: dict[str, Any],
    records: list[dict[str, Any]],
    client: InterpretClient,
    log: errlog.ErrorLog,
    *,
    max_attempts: int = MAX_ATTEMPTS,
) -> dict[str, Any]:
    """레코드를 해석해 findings 문서를 만든다. 검증 실패 시 재시도한다."""
    case_id = scenario["case_id"]
    generator = io.make_generator("interpret.py", client.name)
    input_refs = [record["ref"] for record in records]
    feedback: str | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            body = client.propose_findings(scenario, records, feedback)
            findings = build_findings(body, case_id, generator, input_refs)
            schema.validate(findings, "findings")
            return findings

        except llm.MalformedOutput as e:
            log.record(
                STAGE, "malformed_output", {"message": str(e)}, action="retry", attempt=attempt
            )
            feedback = f"응답에서 JSON을 찾지 못했습니다: {e}"

        except llm.LLMTimeout as e:
            log.record(STAGE, "timeout", {"message": str(e)}, action="retry", attempt=attempt)
            feedback = None

        except schema.SchemaViolation as violation:
            log.record(
                STAGE, "schema_violation", violation.as_detail(), action="retry", attempt=attempt
            )
            feedback = f"{violation.field}: {violation.message}"

    log.abort(
        STAGE,
        "schema_violation",
        {"field": "<retries>", "message": f"{max_attempts}회 재시도 후에도 스키마를 만족하지 못함"},
    )


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage05_interpret.interpret",
        description="파싱된 레코드를 해석해 근거가 달린 문장을 만든다.",
    )
    parser.add_argument("--in", dest="in_path", required=True, help="04_parsed/ 디렉터리")
    parser.add_argument("--scenario", required=True, help="02_scenario.json 경로")
    parser.add_argument(
        "--selection",
        default=None,
        help="03_selection.json 경로. 아티팩트별 자릿수를 시나리오에 맞춰 배분한다",
    )
    parser.add_argument("--out", required=True, help="05_findings.json 출력 경로")
    parser.add_argument("--llm", choices=["stub", "ollama"], default="stub")
    parser.add_argument("--replay", default=None, help="stub 백엔드가 돌려줄 응답 파일")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=(
            "모델 응답 대기 상한(초). 기본 %(default)s. 05단계 프롬프트는 "
            "레코드가 실려 02단계보다 훨씬 크므로, 느린 장비에서는 올려야 한다"
        ),
    )
    parser.add_argument(
        "--num-ctx",
        type=int,
        default=DEFAULT_NUM_CTX,
        help=(
            "모델에게 열어 줄 컨텍스트 창(토큰). 기본 %(default)s. "
            "작으면 프롬프트가 조용히 잘린다"
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=record_filter.DEFAULT_LIMIT,
        help="모델에 전달할 최대 레코드 수. 기본 %(default)s",
    )
    parser.add_argument(
        "--window-seconds",
        type=float,
        default=record_filter.DEFAULT_WINDOW_SECONDS,
        help="신호 주변으로 함께 볼 시간 폭(초). 기본 %(default)s",
    )
    parser.add_argument("--max-attempts", type=int, default=MAX_ATTEMPTS)
    parser.add_argument(
        "--mappings",
        default="mappings",
        help="매핑 디렉터리. 아티팩트의 signal_source를 읽는다. 기본 %(default)s",
    )
    parser.add_argument("--errors", default=None)
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    out_path = Path(args.out)
    log = errlog.ErrorLog(Path(args.errors) if args.errors else out_path.parent / "errors.jsonl")

    scenario = io.read_json(args.scenario)
    try:
        io.check_header(scenario, expected_stage="02_normalize")
        schema.validate(scenario, "scenario")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())
    except io.HeaderError as e:
        log.abort(STAGE, "schema_violation", {"field": "<header>", "message": str(e)})

    try:
        parsed = io.read_parsed_records(args.in_path)
    except (ValueError, NotADirectoryError) as e:
        log.abort(STAGE, "parse_error", {"message": str(e)})

    if not parsed:
        log.abort(
            STAGE,
            "empty_result",
            {"message": f"파싱 결과가 비어 있음: {args.in_path}. 04단계를 먼저 실행한다."},
        )

    # priority는 **이 케이스의 판단**이라 03단계 산출물에서 읽는다. 매핑을
    # 다시 읽으면 그 사이 매핑이 바뀌었을 때 보고서와 대조가 되지 않는다.
    priorities: dict[str, int] = {}
    if args.selection:
        selection = io.read_json(args.selection)
        try:
            io.check_header(selection, expected_stage="03_select")
            schema.validate(selection, "selection")
        except schema.SchemaViolation as violation:
            log.abort(STAGE, "schema_violation", violation.as_detail())
        except io.HeaderError as e:
            log.abort(STAGE, "schema_violation", {"field": "<header>", "message": str(e)})
        priorities = allocation.priorities_from_selection(selection)

    # signal_source는 반대로 **아티팩트의 고정된 성질**이다. 케이스마다
    # 달라지지 않으므로 카탈로그가 원본이고 여기서 그대로 읽는다.
    try:
        catalog = mapping_loader.load_catalog(args.mappings)
    except mapping_loader.MappingError as e:
        log.abort(STAGE, "schema_violation", {"field": "<mappings>", "message": str(e)})
    signal_sources = {name: spec.signal_source for name, spec in catalog.artifacts.items()}

    records, quotas = allocation.allocate_records(
        parsed.values(),
        priorities=priorities,
        signal_sources=signal_sources,
        limit=args.limit,
        window_seconds=args.window_seconds,
    )
    if not records:
        # 파싱은 됐는데 후보가 하나도 없다. 모델을 부를 이유가 없고,
        # 빈 findings를 만들면 06단계 통계가 0/0이 되어 무의미해진다.
        log.abort(
            STAGE,
            "empty_result",
            {
                "message": (
                    f"전달할 레코드가 없음 (파싱 {len(parsed)}건 중 후보 0건). "
                    "flags 룰 또는 선별 범위를 확인한다."
                )
            },
        )

    try:
        backend = llm.build_backend(
            args.llm,
            fixture=args.replay,
            model=args.model,
            host=args.host,
            temperature=args.temperature,
            timeout=args.timeout,
            num_ctx=args.num_ctx,
        )
    except llm.LLMError as e:
        print(f"[{STAGE}] {e}", file=sys.stderr)
        return 2

    findings = interpret(
        scenario, records, InterpretClient(backend), log, max_attempts=args.max_attempts
    )
    io.write_json(out_path, findings)

    # 배분 내역을 찍는다. "왜 이 60건입니까"에 답할 수 있어야 하고, 어느
    # 아티팩트가 후보를 다 못 넣었는지가 여기서만 보인다.
    for quota in quotas:
        short = "전량" if quota.seats >= quota.candidates else f"{quota.candidates}건 중"
        print(
            f"  {quota.artifact:<18} priority {quota.priority}  "
            f"파싱 {quota.parsed}건 / 후보 {quota.candidates}건 / "
            f"전달 {quota.seats}건 ({short})"
        )
    print(
        f"{out_path}: 레코드 {len(parsed)}건 중 {len(records)}건 전달, "
        f"findings {len(findings['findings'])}건 / generator {findings['generator']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
