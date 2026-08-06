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
        --llm stub --replay benchmark/datasets/C-001-webshell/mock/02_scenario.json

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
from . import alert_adapter
from .llm_client import DEFAULT_MODEL, SCENARIO_BODY_FIELDS, NormalizeClient

__all__ = ["STAGE", "build_scenario", "check_attack_ids", "normalize", "main"]

STAGE = "02_normalize"

#: 재시도 횟수. 늘려도 소형 모델은 대개 같은 실수를 반복하므로,
#: 이 값을 키우기보다 프롬프트를 고치는 것이 낫다.
MAX_ATTEMPTS = 3


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
            return scenario

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
        {
            "message": f"{max_attempts}회 재시도 후에도 스키마를 만족하지 못함",
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
    parser.add_argument("--max-attempts", type=int, default=MAX_ATTEMPTS)
    parser.add_argument("--no-fewshot", action="store_true", help="few-shot 예시를 빼고 호출")
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
            )
        except llm.LLMError as e:
            print(f"[{STAGE}] {e}", file=sys.stderr)
            return 2
        client = NormalizeClient(backend, few_shot=not args.no_fewshot)
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
