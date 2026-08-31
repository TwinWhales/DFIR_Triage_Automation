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
        --llm stub --replay benchmark/fixtures/C-001-webshell/05_findings.json

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

__all__ = ["STAGE", "build_findings", "dump_raw", "interpret", "main"]

STAGE = "05_interpret"
MAX_ATTEMPTS = 3


def dump_raw(log: errlog.ErrorLog, attempt: int, raw: "str | None") -> "str | None":
    """실패한 시도의 모델 응답 원문을 ``errors.jsonl`` 옆에 떨군다.

    무엇이 잘못됐는지 **추측하지 않기 위해서** 있다. 원문 없이는 프롬프트가
    잘린 것인지 모델이 형식을 어긴 것인지 가릴 수 없고, 다음 사람이 크기를
    다시 재고 ``--limit``을 낮춰 재현하는 일을 반복한다.

    돌려주는 값은 기록한 파일 이름이다. 남길 것이 없으면 ``None``.
    """
    if not raw:
        return None
    path = log.path.parent / f"{STAGE}_raw_attempt{attempt}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw, encoding="utf-8")
    return path.name


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
            detail: dict[str, Any] = {"message": str(e)}
            saved = dump_raw(log, attempt, client.last_raw)
            if saved:
                detail["raw"] = saved
            log.record(STAGE, "malformed_output", detail, action="retry", attempt=attempt)
            feedback = f"응답에서 JSON을 찾지 못했습니다: {e}"

        except llm.LLMTimeout as e:
            # 시간 초과는 응답 자체가 없다. last_raw 는 이전 시도의 것이므로
            # 떨구면 이번 실패의 원문으로 오해된다.
            log.record(STAGE, "timeout", {"message": str(e)}, action="retry", attempt=attempt)
            feedback = None

        except llm.LLMError as e:
            # 02단계와 같은 이유로 재시도하지 않는다 — 모델명 오타·서버
            # 미기동은 세 번 불러도 같은 답이다. normalize.py 의 같은 자리
            # 주석 참고.
            log.abort(STAGE, "llm_error", {"message": str(e)})

        except schema.SchemaViolation as violation:
            detail = violation.as_detail()
            saved = dump_raw(log, attempt, client.last_raw)
            if saved:
                detail["raw"] = saved
            log.record(STAGE, "schema_violation", detail, action="retry", attempt=attempt)
            feedback = f"{violation.field}: {violation.message}"

    log.abort(
        STAGE,
        "schema_violation",
        {
            "field": "<retries>",
            "message": (
                f"{max_attempts}회 재시도 후에도 스키마를 만족하지 못함. "
                f"모델 응답 원문은 {log.path.parent}/{STAGE}_raw_attempt*.txt 에 있다"
            ),
        },
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
        help=(
            "모델에 전달할 최대 레코드 수. 기본 %(default)s. **상한이지 목표가 "
            "아니다** — 토큰 예산에 안 맞으면 이보다 적게 나간다"
        ),
    )
    parser.add_argument(
        "--max-list-items",
        type=int,
        default=allocation.MAX_LIST_ITEMS,
        help=(
            "프롬프트에 실을 때 fields 안의 목록을 몇 개까지 남길지. 기본 %(default)s, "
            "0 이면 안 자른다. 04_parsed/ 의 원본과 06단계 검증은 영향받지 않는다"
        ),
    )
    parser.add_argument(
        "--reserve-output-tokens",
        type=int,
        default=allocation.RESERVE_OUTPUT_TOKENS,
        help=(
            "모델이 답을 쓸 자리로 남겨 둘 토큰. 기본 %(default)s. "
            "프롬프트가 창을 꽉 채우면 응답이 잘려 malformed_output 으로 온다. "
            "**이 값은 num_predict 로도 그대로 나간다** — 자리를 비워 두는 것과 "
            "그만큼만 쓰게 하는 것이 같은 수여야 예산이 가정이 아니라 약속이 된다"
        ),
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
    parser.add_argument(
        "--no-constrain",
        action="store_true",
        help=(
            "출력 스키마를 디코딩 단계에서 강제하지 않는다. 폴백이 아니라 "
            "측정용이다 (02단계와 같은 규약)"
        ),
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

    # 클라이언트를 배분보다 **먼저** 만든다. 예산이 시스템 프롬프트와
    # 머리말의 실제 길이에서 나오기 때문이다(추정하지 않는다).
    try:
        backend = llm.build_backend(
            args.llm,
            fixture=args.replay,
            model=args.model,
            host=args.host,
            temperature=args.temperature,
            timeout=args.timeout,
            num_ctx=args.num_ctx,
            # 예산에서 답을 쓸 자리로 빼 둔 양이 곧 출력 상한이다. 둘을 따로
            # 두면 "비워 둔 자리"와 "실제로 쓸 수 있는 양"이 갈라지고, 갈라진
            # 쪽이 맞는지 알 방법이 없다.
            num_predict=args.reserve_output_tokens,
        )
    except llm.LLMError as e:
        print(f"[{STAGE}] {e}", file=sys.stderr)
        return 2

    # 0 은 "안 자른다"로 읽는다. argparse 에 None 을 넘길 방법이 마땅치 않고,
    # 목록을 0개만 싣는 것은 아무도 원하지 않는 동작이다.
    max_list_items = args.max_list_items if args.max_list_items > 0 else None

    client = InterpretClient(
        backend, max_list_items=max_list_items, constrain=not args.no_constrain
    )
    budget_chars = allocation.char_budget(
        args.num_ctx,
        client.prompt_overhead_chars(scenario),
        reserve_output_tokens=args.reserve_output_tokens,
    )

    records, quotas, budget = allocation.allocate_records(
        parsed.values(),
        priorities=priorities,
        signal_sources=signal_sources,
        limit=args.limit,
        window_seconds=args.window_seconds,
        char_budget=budget_chars,
        max_list_items=max_list_items,
    )
    if not records:
        # 파싱은 됐는데 후보가 하나도 없다. 모델을 부를 이유가 없고,
        # 빈 findings를 만들면 06단계 통계가 0/0이 되어 무의미해진다.
        #
        # 예산이 한 건도 못 들여보내는 경우도 여기로 온다. 그 경우는 사유가
        # 다르므로 따로 말한다 — flags 룰을 들여다봐야 풀리는 문제가 아니다.
        if budget.enforced and budget.effective_limit == 0 and budget.requested_limit > 0:
            log.abort(
                STAGE,
                "empty_result",
                {
                    "message": (
                        f"레코드 한 건도 예산에 들어가지 않음 "
                        f"(예산 {budget_chars:,}자 = --num-ctx {args.num_ctx} "
                        f"− 출력 {args.reserve_output_tokens}토큰 − 프롬프트 고정분). "
                        "--num-ctx 를 올리거나 창이 더 큰 모델을 쓴다."
                    )
                },
            )
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

    findings = interpret(
        scenario, records, client, log, max_attempts=args.max_attempts
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
    # 예산은 깎였을 때만 말한다. 안 깎였으면 --limit 이 그대로 상한이라
    # 위 배분 내역이 이미 전부를 말하고 있다.
    if budget.trimmed:
        print(
            f"  토큰 예산: {budget.natural_records}건 → {len(records)}건으로 줄임 "
            f"({budget.used_chars:,}자 ≈ {budget.estimated_tokens:,}토큰 / "
            f"예산 {budget_chars:,}자). "
            f"--num-ctx {args.num_ctx} 에서 출력 {args.reserve_output_tokens}토큰을 뺀 값이다"
        )
    print(
        f"{out_path}: 레코드 {len(parsed)}건 중 {len(records)}건 전달, "
        f"findings {len(findings['findings'])}건 / generator {findings['generator']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
