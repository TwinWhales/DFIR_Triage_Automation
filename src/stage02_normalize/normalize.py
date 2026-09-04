"""02단계 — 시나리오 정규화.

sLLM이 채우는 첫 구조체를 만든다. 이후 단계는 이 스키마만 신뢰하므로,
여기서 나가는 문서는 반드시 검증을 통과해야 한다.

``source_type``에 따라 두 경로로 갈린다.

- ``edr_alert`` → ``alert_adapter`` (결정론적, LLM 없음)
- ``natural_language`` → LLM + 스키마 검증 + 재시도

재시도가 이 단계의 핵심이다. 실패할 때마다 ``errors.jsonl``에 사유가
쌓이고, 그 분포가 "sLLM이 어떤 필드에서 자주 틀리는가"라는 정량 근거가
된다. 폴백은 아직 넣지 않는다 — 선형 경로가 안정되기 전에 폴백을 넣으면
폴백이 잘못 걸린 것인지 원래 로직이 틀린 것인지 구분되지 않는다.

사용법::

    # 모델 없이 배선만 확인 (스텁)
    python -m src.stage02_normalize.normalize \\
        --in cases/C-001/01_input.json --out cases/C-001/02_scenario.json \\
        --llm stub --replay benchmark/fixtures/C-001-webshell/02_scenario.json

    # 실제 모델
    python -m src.stage02_normalize.normalize \\
        --in cases/C-001/01_input.json --out cases/C-001/02_scenario.json \\
        --llm ollama --model qwen2.5:7b-instruct-q4_K_M
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from ..common import attack
from ..common import errors as errlog
from ..common import io, llm, schema
from ..common.llm import DEFAULT_NUM_CTX, DEFAULT_TIMEOUT
from . import alert_adapter, coverage
from .llm_client import (
    DEFAULT_MODEL,
    DEFAULT_NUM_PREDICT,
    SCENARIO_BODY_FIELDS,
    NormalizeClient,
)

__all__ = [
    "STAGE",
    "build_scenario",
    "check_attack_ids",
    "dump_raw",
    "normalize",
    "record_coverage",
    "main",
]

STAGE = "02_normalize"

#: 재시도 횟수. 늘려도 소형 모델은 대개 같은 실수를 반복하므로,
#: 이 값을 키우기보다 프롬프트를 고치는 것이 낫다.
MAX_ATTEMPTS = 3


def dump_raw(log: errlog.ErrorLog, attempt: int, raw: "str | None") -> "str | None":
    """실패한 시도의 모델 응답 원문을 ``errors.jsonl`` 옆에 떨군다.

    무엇이 잘못됐는지 **추측하지 않기 위해서** 있다. 원문 없이는 프롬프트가
    잘린 것인지 모델이 형식을 어긴 것인지 가릴 수 없다.

    돌려주는 값은 기록한 파일 이름이다. 남길 것이 없으면 ``None``.
    """
    if not raw:
        return None
    path = log.path.parent / f"{STAGE}_raw_attempt{attempt}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw, encoding="utf-8")
    return path.name


def build_scenario(body: dict[str, Any], case_id: str, generator: str) -> dict[str, Any]:
    """모델이 만든 본문에 공통 헤더를 붙여 완성 문서로 만든다."""
    missing = [field for field in SCENARIO_BODY_FIELDS if field not in body]
    if missing:
        raise schema.SchemaViolation(
            field=missing[0], value=None, message=f"필수 필드 없음 ({', '.join(missing)})"
        )
    return io.new_document(
        case_id, STAGE, generator, **{key: body[key] for key in SCENARIO_BODY_FIELDS}
    )


def check_attack_ids(doc: dict[str, Any]) -> None:
    """실재하는 기법 ID인지 확인한다.

    스키마는 ``T####.###`` 형식만 본다. ``T9999``처럼 형식은 맞고
    존재하지 않는 ID는 여기서 걸린다. 실무에서 더 흔하고, 형식 위반과
    나눠 집계해야 프롬프트 개선의 효과가 보인다.
    """
    for index, technique in enumerate(doc.get("techniques", [])):
        try:
            attack.check_id(technique.get("id"))
        except attack.AttackIdError as e:
            raise schema.SchemaViolation(
                field=f"techniques[{index}].id", value=technique.get("id"), message=str(e)
            ) from None


def record_coverage(
    scenario: dict[str, Any], raw: str, log: errlog.ErrorLog
) -> dict[str, Any]:
    """입력에서 옮겨지지 않은 구간을 세어 기록하고 ``unmapped_text`` 를 채운다.

    **재시도하지 않는다.** 이유는 `coverage` 모듈에 있다 — 실측에서 8/8이
    걸렸고, 재시도를 붙이면 매 실행이 재시도 예산을 다 쓰고도 통과하지
    못한다. 여기서 하는 일은 **놓친 것을 보이게 만드는 것**이지 없애는
    것이 아니다.

    ``unmapped_text`` 를 우리가 채우는 것이 모델의 답을 고치는 것처럼
    보일 수 있으나 반대다. 그 필드의 정의가 "기법으로 매핑하지 못한
    서술"이고, 모델은 매핑하지 못한 것이 있는데도 8/8 빈 배열을 냈다.
    비워 두면 07단계가 **놓친 축과 증거가 없는 축을 같은 말로 인쇄한다.**
    """
    quotes = coverage.nonverbatim_quotes(scenario, raw)
    if quotes:
        # 프롬프트가 요구하는 불변식 위반이다. 다듬는 과정에서 절이 통째로
        # 사라지는 것이 실제 실패 방식이라, 세어 두면 프롬프트를 고쳤을 때
        # 나아졌는지 알 수 있다.
        log.record(
            STAGE,
            "nonverbatim_evidence",
            {"field": "techniques[].evidence_text", "quotes": quotes},
            action="record",
        )

    spans = coverage.uncovered_spans(scenario, raw)
    if not spans:
        return scenario

    known = list(scenario.get("unmapped_text") or [])
    added = [s for s in spans if s not in known]
    if added:
        scenario["unmapped_text"] = known + added
        log.record(
            STAGE,
            "uncovered_input",
            {"field": "unmapped_text", "spans": added},
            action="record",
        )
    return scenario


def normalize(
    input_doc: dict[str, Any],
    client: NormalizeClient,
    log: errlog.ErrorLog,
    *,
    max_attempts: int = MAX_ATTEMPTS,
) -> dict[str, Any]:
    """자연어 입력을 시나리오로 만든다. 검증에 실패하면 재시도한다."""
    case_id = input_doc["case_id"]
    generator = io.make_generator("normalize.py", client.name)
    raw, evidence = input_doc["raw"], input_doc.get("evidence", {})
    feedback: str | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            body = client.propose_scenario(raw, evidence, feedback)
            scenario = build_scenario(body, case_id, generator)
            schema.validate(scenario, "scenario")
            check_attack_ids(scenario)
            # **받아들이기로 한 응답에만** 센다. 검증 전에 부르면 재시도로
            # 버려질 응답의 커버리지가 errors.jsonl 에 남아, 나중에 "얼마나
            # 자주 놓치는가"를 셀 때 분모가 실행 수가 아니라 시도 수가 된다.
            scenario = record_coverage(scenario, raw, log)
            # 우리가 넣은 값도 같은 관문을 지난다.
            schema.validate(scenario, "scenario")
            return scenario

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
            # 타임아웃이 아닌 호출 실패는 **재시도해도 같은 결과다** — 모델명
            # 오타, 서버 미기동, 잘못된 호스트. 세 번 반복하며 시간만 쓴다.
            #
            # 예전에는 이 예외를 아무도 잡지 않아 파이썬 트레이스백이 그대로
            # 올라왔다. 멈추기는 했지만 errors.jsonl 에 남지 않아 07단계가
            # 볼 수 없었고, "폴백을 만들지 않는다 — 실패는 errors.jsonl 에
            # 기록하고 사유를 출력하며 중단한다"는 규약 밖이었다.
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
            "message": (
                f"{max_attempts}회 재시도 후에도 스키마를 만족하지 못함. "
                f"모델 응답 원문은 {log.path.parent}/{STAGE}_raw_attempt*.txt 에 있다"
            ),
            "field": "<retries>",
        },
    )


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage02_normalize.normalize",
        description="자연어 서술 또는 EDR 알럿을 시나리오 스키마로 정규화한다.",
    )
    parser.add_argument("--in", dest="in_path", required=True, help="01_input.json 경로")
    parser.add_argument("--out", required=True, help="02_scenario.json 출력 경로")
    parser.add_argument(
        "--llm",
        choices=["stub", "ollama"],
        default="stub",
        help="모델 백엔드. 기본 %(default)s (배선 확인용, 실제 추론 없음)",
    )
    parser.add_argument("--replay", default=None, help="stub 백엔드가 돌려줄 응답 파일")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="ollama 모델명. 기본 %(default)s")
    parser.add_argument("--host", default="http://localhost:11434", help="ollama 호스트")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="모델 응답 대기 상한(초). 기본 %(default)s",
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
        "--num-predict",
        type=int,
        default=DEFAULT_NUM_PREDICT,
        help=(
            "모델이 쓸 수 있는 출력 토큰의 상한. 기본 %(default)s. "
            "**길이 목표가 아니라 폭주를 끊는 자리다** — 주지 않으면 모델이 "
            "JSON을 닫지 못할 때 컨텍스트가 찰 때까지 쓰고 타임아웃으로만 끝난다"
        ),
    )
    parser.add_argument("--max-attempts", type=int, default=MAX_ATTEMPTS)
    parser.add_argument("--no-fewshot", action="store_true", help="few-shot 예시를 빼고 호출")
    parser.add_argument(
        "--no-constrain",
        action="store_true",
        help=(
            "출력 스키마를 디코딩 단계에서 강제하지 않는다. 폴백이 아니라 "
            "측정용이다 — 켠 실행과 나란히 돌려 제약의 효과를 잰다"
        ),
    )
    parser.add_argument("--errors", default=None, help="errors.jsonl 경로")
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    out_path = Path(args.out)
    log = errlog.ErrorLog(Path(args.errors) if args.errors else out_path.parent / "errors.jsonl")

    input_doc = io.read_json(args.in_path)
    try:
        # 01_input은 사람이나 수집 스크립트가 만들므로 generator가 없을 수 있다.
        io.check_header(input_doc, expected_stage="01_input", require_generator=False)
        schema.validate(input_doc, "input")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())
    except io.HeaderError as e:
        log.abort(STAGE, "schema_violation", {"field": "<header>", "message": str(e)})

    if input_doc["source_type"] == "edr_alert":
        try:
            body = alert_adapter.convert(input_doc["raw"], input_doc.get("evidence", {}))
        except alert_adapter.AlertAdapterError as e:
            log.abort(STAGE, "empty_result", {"field": "raw", "message": str(e)})
        scenario = build_scenario(body, input_doc["case_id"], io.make_generator("alert_adapter.py"))
        try:
            schema.validate(scenario, "scenario")
            check_attack_ids(scenario)
        except schema.SchemaViolation as violation:
            # 결정론적 변환이 스키마를 못 맞추면 어댑터의 결함이다.
            # 재시도해도 같은 결과가 나오므로 즉시 중단한다.
            log.abort(STAGE, "schema_violation", violation.as_detail())
    else:
        try:
            backend = llm.build_backend(
                args.llm,
                fixture=args.replay,
                model=args.model,
                host=args.host,
                temperature=args.temperature,
                timeout=args.timeout,
                num_ctx=args.num_ctx,
                num_predict=args.num_predict,
            )
        except llm.LLMError as e:
            print(f"[{STAGE}] {e}", file=sys.stderr)
            return 2
        client = NormalizeClient(
            backend, few_shot=not args.no_fewshot, constrain=not args.no_constrain
        )
        scenario = normalize(input_doc, client, log, max_attempts=args.max_attempts)

    io.write_json(out_path, scenario)
    print(
        f"{out_path}: techniques {len(scenario['techniques'])} "
        f"({', '.join(t['id'] for t in scenario['techniques'])}) "
        f"/ generator {scenario['generator']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
