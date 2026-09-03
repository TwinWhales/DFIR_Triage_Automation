"""05단계 — sLLM 해석.

파싱된 레코드를 읽고 "무엇이 확인되는가"를 문장으로 만든다. 모든 문장은
``refs``로 원본 레코드를 가리켜야 하고, 문장이 주장하는 사실은 ``claims``
삼중항으로 분해되어야 한다. 06단계가 그 삼중항만 대조한다.

**``input_refs``는 모델에게 묻지 않는다.** 무엇을 전달했는지는 우리가
안다. 모델이 보고하게 하면 실제로 받지 않은 레코드를 목록에 넣어
``ref_not_in_input`` 검사를 무력화할 수 있다. 이 단계에서 가장 중요한
설계 결정이다.

05단계에서는 모델이 만든 claim의 ``(ref, field, value)``가 실제로 모델에게
전달한 레코드에 존재하는지도 기계적으로 확인한다. 잘못된 claim을 발견하면
그 내용을 feedback으로 모델에 돌려보내 다시 작성하게 한다.

이 검사는 06단계 검증을 대체하지 않는다.

- 05단계: 모델 출력 자체의 명백한 근거 오류를 보정한다.
- 06단계: 저장된 findings를 원본 파싱 결과와 독립적으로 다시 검증한다.

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
from ..stage06_verify import comparators
from . import allocation, record_filter
from .llm_client import DEFAULT_MODEL, FINDINGS_BODY_FIELDS, InterpretClient

__all__ = [
    "STAGE",
    "build_findings",
    "dump_raw",
    "interpret",
    "main",
]

STAGE = "05_interpret"
MAX_ATTEMPTS = 3

#: claim 값 대조의 허용 오차. **06단계의 ``DEFAULT_TOLERANCE_SECONDS`` 와
#: 같은 값이어야 한다.** 두 단계가 갈라지면 05가 통과시킨 문장을 06이
#: 기각하거나 그 반대가 되고, 그때 어느 쪽이 옳은지 가릴 수단이 없다.
CLAIM_TOLERANCE_SECONDS = 1.0


class ClaimValidationError(ValueError):
    """모델 claim이 실제 전달 레코드와 일치하지 않을 때 발생한다."""

    def __init__(
        self,
        message: str,
        *,
        ref: str | None = None,
        field: str | None = None,
        claimed: Any = None,
        actual: Any = None,
    ) -> None:
        super().__init__(message)
        self.ref = ref
        self.field = field
        self.claimed = claimed
        self.actual = actual

    def as_detail(self) -> dict[str, Any]:
        detail: dict[str, Any] = {
            "message": str(self),
        }

        if self.ref is not None:
            detail["ref"] = self.ref

        if self.field is not None:
            detail["field"] = self.field

        if self.claimed is not None:
            detail["claimed"] = self.claimed

        if self.actual is not None:
            detail["actual"] = self.actual

        return detail


def dump_raw(
    log: errlog.ErrorLog,
    attempt: int,
    raw: "str | None",
) -> "str | None":
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
    body: dict[str, Any],
    case_id: str,
    generator: str,
    input_refs: list[str],
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


def _walk_field(
    record: dict[str, Any],
    field: str,
) -> tuple[bool, Any]:
    """모델이 지정한 점 표기 field를 레코드에서 찾는다."""

    current: Any = record

    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None

        current = current[part]

    return True, current


def _get_claim_field(
    record: dict[str, Any],
    field: str,
) -> tuple[bool, Any, str]:
    """claim field를 실제 전달 레코드에서 찾는다.

    모델이 ``DeviceDesc``와 ``fields.DeviceDesc``를 혼용하는 경우를 고려해
    06단계와 같은 수준의 ``fields.`` 표기 차이만 허용한다.

    값 자체는 정규화하지 않는다. 05단계 프롬프트의 계약대로 모델은
    레코드에 들어 있는 원본 값을 그대로 claim 해야 한다.
    """

    found, value = _walk_field(record, field)

    if found:
        return True, value, field

    if field.startswith("fields."):
        alternative = field[len("fields.") :]
        found, value = _walk_field(record, alternative)

        if found:
            return True, value, alternative

    elif isinstance(record.get("fields"), dict):
        alternative = f"fields.{field}"
        found, value = _walk_field(record, alternative)

        if found:
            return True, value, alternative

    return False, None, field


def _claim_values_equal(
    field: str,
    claimed: Any,
    actual: Any,
) -> bool:
    """claim의 값이 원본 값과 같은지 **06단계와 같은 규칙으로** 본다.

    이 관문이 잡으려는 것은 "모델이 레코드에 없는 값을 지어냈는가"다.
    그것은 위임해도 그대로 잡힌다 — 지어낸 값은 ``compare`` 도 기각하고,
    없는 ref·field 는 이 함수에 오기 전에 걸린다. 위임으로 느슨해지는 것은
    **표기 차이뿐**이고, 그것은 애초에 이 관문이 잡을 대상이 아니다.

    **여기서 자체 규칙을 세우지 않는다.** 한때 정확 문자열 비교를 했는데,
    06단계가 "관대하게 본다"고 명시한 것을 05단계가 기각했다. 같은 질문에
    관문이 둘인데 답이 다르면 어느 쪽이 옳은지 가릴 수 없고, 이 단계에는
    폴백이 없어 불일치가 문장 기각이 아니라 **파이프라인 중단**이 된다.
    실제로 골든 픽스처의 claim 6건 중 3건이 그렇게 막혀 관통이 죽었다.

    ``flags`` 는 위임하지 않으면 **만족 자체가 불가능하다.** 레코드의
    ``flags`` 는 배열인데 ``schemas/findings.schema.json`` 이 ``value`` 를
    스칼라로 못 박아, 스키마를 지킨 어떤 값도 배열과 같아질 수 없다.
    스키마가 "타입 정규화는 comparators.py가 맡는다"고 적어 둔 이유다.
    """

    return comparators.compare(
        field,
        claimed,
        actual,
        tolerance_seconds=CLAIM_TOLERANCE_SECONDS,
    )


def validate_model_claims(
    findings: dict[str, Any],
    records: list[dict[str, Any]],
) -> None:
    """모델이 만든 모든 claim을 실제 전달 레코드와 대조한다.

    하나라도 다음 조건을 위반하면 ``ClaimValidationError``를 발생시킨다.

    1. ref가 실제 전달 레코드에 존재해야 한다.
    2. field가 해당 ref의 레코드에 실제로 존재해야 한다.
    3. value가 그 field의 실제 값과 일치해야 한다. 같은가의 판단은
       06단계 비교기에 위임한다 (``_claim_values_equal``).

    실패하면 모델에게 구체적인 feedback을 주고 다음 시도에서 수정하게 한다.
    """

    record_by_ref = {
        record["ref"]: record
        for record in records
        if "ref" in record
    }

    for finding in findings.get("findings", []):
        finding_id = finding.get("id", "<unknown>")

        for claim_index, claim in enumerate(
            finding.get("claims", []),
            start=1,
        ):
            ref = claim.get("ref")
            field = claim.get("field")
            claimed = claim.get("value")

            if ref not in record_by_ref:
                raise ClaimValidationError(
                    (
                        f"{finding_id} claim #{claim_index}: "
                        f"ref {ref!r}는 모델에게 전달된 레코드에 없습니다."
                    ),
                    ref=ref,
                    field=field,
                    claimed=claimed,
                )

            if not isinstance(field, str) or not field:
                raise ClaimValidationError(
                    (
                        f"{finding_id} claim #{claim_index}: "
                        "field가 비어 있거나 문자열이 아닙니다."
                    ),
                    ref=ref,
                    field=field,
                    claimed=claimed,
                )

            record = record_by_ref[ref]

            found, actual, resolved_field = _get_claim_field(
                record,
                field,
            )

            if not found:
                available_top = sorted(record.keys())

                fields = record.get("fields")
                available_nested = (
                    sorted(fields.keys())
                    if isinstance(fields, dict)
                    else []
                )

                raise ClaimValidationError(
                    (
                        f"{finding_id} claim #{claim_index}: "
                        f"ref {ref}에는 field {field!r}가 없습니다. "
                        f"최상위 필드={available_top}, "
                        f"fields 내부={available_nested}. "
                        "해당 ref에 실제로 존재하는 field/value만 사용하십시오."
                    ),
                    ref=ref,
                    field=field,
                    claimed=claimed,
                )

            if not _claim_values_equal(resolved_field, claimed, actual):
                raise ClaimValidationError(
                    (
                        f"{finding_id} claim #{claim_index}: "
                        f"ref {ref}의 {resolved_field!r} 값이 "
                        "실제 레코드 값과 다릅니다. "
                        "레코드의 값을 요약하거나 표시 문자열로 바꾸지 말고 "
                        "원본 값을 그대로 사용하십시오."
                    ),
                    ref=ref,
                    field=resolved_field,
                    claimed=claimed,
                    actual=actual,
                )


def interpret(
    scenario: dict[str, Any],
    records: list[dict[str, Any]],
    client: InterpretClient,
    log: errlog.ErrorLog,
    *,
    max_attempts: int = MAX_ATTEMPTS,
) -> dict[str, Any]:
    """레코드를 해석해 findings 문서를 만든다.

    모델 출력에 대해 다음 순서로 검사한다.

    1. JSON/출력 구조
    2. findings 스키마
    3. claim의 ref/field/value가 실제 전달 레코드와 일치하는지 확인

    claim 검증에 실패하면 구체적인 오류를 feedback으로 모델에 전달하고
    다시 생성한다.
    """

    case_id = scenario["case_id"]
    generator = io.make_generator(
        "interpret.py",
        client.name,
    )

    input_refs = [
        record["ref"]
        for record in records
    ]

    feedback: str | None = None

    for attempt in range(
        1,
        max_attempts + 1,
    ):
        try:
            body = client.propose_findings(
                scenario,
                records,
                feedback,
            )

            findings = build_findings(
                body,
                case_id,
                generator,
                input_refs,
            )

            schema.validate(
                findings,
                "findings",
            )

            validate_model_claims(
                findings,
                records,
            )

            return findings

        except ClaimValidationError as e:
            detail = e.as_detail()

            saved = dump_raw(
                log,
                attempt,
                client.last_raw,
            )

            if saved:
                detail["raw"] = saved

            log.record(
                STAGE,
                "claim_validation",
                detail,
                action="retry",
                attempt=attempt,
            )

            feedback = (
                "이전 응답의 claim이 실제 입력 레코드와 일치하지 않습니다.\n"
                f"{e}\n"
                "claims의 ref, field, value는 반드시 같은 입력 레코드에서 "
                "직접 가져오십시오. 다른 레코드의 값을 추론해서 붙이지 마십시오. "
                "특히 value는 요약하지 말고 입력 레코드의 원본 값을 그대로 "
                "사용하십시오."
            )

        except llm.MalformedOutput as e:
            detail: dict[str, Any] = {
                "message": str(e),
            }

            saved = dump_raw(
                log,
                attempt,
                client.last_raw,
            )

            if saved:
                detail["raw"] = saved

            log.record(
                STAGE,
                "malformed_output",
                detail,
                action="retry",
                attempt=attempt,
            )

            feedback = (
                f"응답에서 JSON을 찾지 못했습니다: {e}"
            )

        except llm.LLMTimeout as e:
            # 시간 초과는 응답 자체가 없다.
            # last_raw는 이전 시도의 것이므로 이번 실패 원문으로 저장하지 않는다.
            log.record(
                STAGE,
                "timeout",
                {"message": str(e)},
                action="retry",
                attempt=attempt,
            )

            feedback = None

        except llm.LLMError as e:
            # 모델명 오타나 서버 미기동 같은 오류는 재시도해도 동일하다.
            log.abort(
                STAGE,
                "llm_error",
                {"message": str(e)},
            )

        except schema.SchemaViolation as violation:
            detail = violation.as_detail()

            saved = dump_raw(
                log,
                attempt,
                client.last_raw,
            )

            if saved:
                detail["raw"] = saved

            log.record(
                STAGE,
                "schema_violation",
                detail,
                action="retry",
                attempt=attempt,
            )

            feedback = (
                f"{violation.field}: {violation.message}"
            )

    log.abort(
        STAGE,
        "claim_validation",
        {
            "field": "<retries>",
            "message": (
                f"{max_attempts}회 재시도 후에도 "
                "스키마 또는 claim 근거 검증을 만족하지 못함. "
                f"모델 응답 원문은 "
                f"{log.path.parent}/{STAGE}_raw_attempt*.txt 에 있다"
            ),
        },
    )


def _parse_args(
    argv: "list[str] | None" = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage05_interpret.interpret",
        description="파싱된 레코드를 해석해 근거가 달린 문장을 만든다.",
    )

    parser.add_argument(
        "--in",
        dest="in_path",
        required=True,
        help="04_parsed/ 디렉터리",
    )

    parser.add_argument(
        "--scenario",
        required=True,
        help="02_scenario.json 경로",
    )

    parser.add_argument(
        "--selection",
        default=None,
        help=(
            "03_selection.json 경로. "
            "아티팩트별 자릿수를 시나리오에 맞춰 배분한다"
        ),
    )

    parser.add_argument(
        "--out",
        required=True,
        help="05_findings.json 출력 경로",
    )

    parser.add_argument(
        "--llm",
        choices=["stub", "ollama"],
        default="stub",
    )

    parser.add_argument(
        "--replay",
        default=None,
        help="stub 백엔드가 돌려줄 응답 파일",
    )

    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
    )

    parser.add_argument(
        "--host",
        default="http://localhost:11434",
    )

    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=(
            "모델 응답 대기 상한(초). 기본 %(default)s. "
            "05단계 프롬프트는 레코드가 실려 02단계보다 훨씬 크므로, "
            "느린 장비에서는 올려야 한다"
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
            "모델에 전달할 최대 레코드 수. 기본 %(default)s. "
            "**상한이지 목표가 아니다** — "
            "토큰 예산에 안 맞으면 이보다 적게 나간다"
        ),
    )

    parser.add_argument(
        "--max-list-items",
        type=int,
        default=allocation.MAX_LIST_ITEMS,
        help=(
            "프롬프트에 실을 때 fields 안의 목록을 몇 개까지 남길지. "
            "기본 %(default)s, 0 이면 안 자른다. "
            "04_parsed/ 의 원본과 06단계 검증은 영향받지 않는다"
        ),
    )

    parser.add_argument(
        "--reserve-output-tokens",
        type=int,
        default=allocation.RESERVE_OUTPUT_TOKENS,
        help=(
            "모델이 답을 쓸 자리로 남겨 둘 토큰. 기본 %(default)s. "
            "프롬프트가 창을 꽉 채우면 응답이 잘려 malformed_output 으로 온다. "
            "**이 값은 num_predict 로도 그대로 나간다** — "
            "자리를 비워 두는 것과 그만큼만 쓰게 하는 것이 "
            "같은 수여야 예산이 가정이 아니라 약속이 된다"
        ),
    )

    parser.add_argument(
        "--window-seconds",
        type=float,
        default=record_filter.DEFAULT_WINDOW_SECONDS,
        help="신호 주변으로 함께 볼 시간 폭(초). 기본 %(default)s",
    )

    parser.add_argument(
        "--max-attempts",
        type=int,
        default=MAX_ATTEMPTS,
    )

    parser.add_argument(
        "--mappings",
        default="mappings",
        help=(
            "매핑 디렉터리. 아티팩트의 signal_source를 읽는다. "
            "기본 %(default)s"
        ),
    )

    parser.add_argument(
        "--no-constrain",
        action="store_true",
        help=(
            "출력 스키마를 디코딩 단계에서 강제하지 않는다. "
            "폴백이 아니라 측정용이다 (02단계와 같은 규약)"
        ),
    )

    parser.add_argument(
        "--errors",
        default=None,
    )

    return parser.parse_args(argv)


def main(
    argv: "list[str] | None" = None,
) -> int:
    io.configure_console()

    args = _parse_args(argv)

    out_path = Path(args.out)

    log = errlog.ErrorLog(
        Path(args.errors)
        if args.errors
        else out_path.parent / "errors.jsonl"
    )

    scenario = io.read_json(args.scenario)

    try:
        io.check_header(
            scenario,
            expected_stage="02_normalize",
        )

        schema.validate(
            scenario,
            "scenario",
        )

    except schema.SchemaViolation as violation:
        log.abort(
            STAGE,
            "schema_violation",
            violation.as_detail(),
        )

    except io.HeaderError as e:
        log.abort(
            STAGE,
            "schema_violation",
            {
                "field": "<header>",
                "message": str(e),
            },
        )

    try:
        parsed = io.read_parsed_records(
            args.in_path
        )

    except (
        ValueError,
        NotADirectoryError,
    ) as e:
        log.abort(
            STAGE,
            "parse_error",
            {"message": str(e)},
        )

    if not parsed:
        log.abort(
            STAGE,
            "empty_result",
            {
                "message": (
                    f"파싱 결과가 비어 있음: "
                    f"{args.in_path}. "
                    "04단계를 먼저 실행한다."
                )
            },
        )

    # priority는 이 케이스의 판단이므로
    # 03단계 산출물에서 읽는다.
    priorities: dict[str, int] = {}

    if args.selection:
        selection = io.read_json(
            args.selection
        )

        try:
            io.check_header(
                selection,
                expected_stage="03_select",
            )

            schema.validate(
                selection,
                "selection",
            )

        except schema.SchemaViolation as violation:
            log.abort(
                STAGE,
                "schema_violation",
                violation.as_detail(),
            )

        except io.HeaderError as e:
            log.abort(
                STAGE,
                "schema_violation",
                {
                    "field": "<header>",
                    "message": str(e),
                },
            )

        priorities = allocation.priorities_from_selection(
            selection
        )

    # signal_source는 아티팩트의 고정된 성질이므로
    # mappings 카탈로그에서 읽는다.
    try:
        catalog = mapping_loader.load_catalog(
            args.mappings
        )

    except mapping_loader.MappingError as e:
        log.abort(
            STAGE,
            "schema_violation",
            {
                "field": "<mappings>",
                "message": str(e),
            },
        )

    signal_sources = {
        name: spec.signal_source
        for name, spec in catalog.artifacts.items()
    }

    # 클라이언트를 배분보다 먼저 만든다.
    # 토큰 예산이 실제 프롬프트 길이에 의존하기 때문이다.
    try:
        backend = llm.build_backend(
            args.llm,
            fixture=args.replay,
            model=args.model,
            host=args.host,
            temperature=args.temperature,
            timeout=args.timeout,
            num_ctx=args.num_ctx,
            num_predict=args.reserve_output_tokens,
        )

    except llm.LLMError as e:
        print(
            f"[{STAGE}] {e}",
            file=sys.stderr,
        )
        return 2

    # 0은 "목록을 자르지 않는다"는 의미다.
    max_list_items = (
        args.max_list_items
        if args.max_list_items > 0
        else None
    )

    client = InterpretClient(
        backend,
        max_list_items=max_list_items,
        constrain=not args.no_constrain,
    )

    budget_chars = allocation.char_budget(
        args.num_ctx,
        client.prompt_overhead_chars(
            scenario
        ),
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
        # 파싱은 됐는데 후보가 하나도 없다.
        if (
            budget.enforced
            and budget.effective_limit == 0
            and budget.requested_limit > 0
        ):
            log.abort(
                STAGE,
                "empty_result",
                {
                    "message": (
                        "레코드 한 건도 예산에 들어가지 않음 "
                        f"(예산 {budget_chars:,}자 = "
                        f"--num-ctx {args.num_ctx} "
                        f"− 출력 {args.reserve_output_tokens}토큰 "
                        "− 프롬프트 고정분). "
                        "--num-ctx 를 올리거나 "
                        "창이 더 큰 모델을 쓴다."
                    )
                },
            )

        log.abort(
            STAGE,
            "empty_result",
            {
                "message": (
                    "전달할 레코드가 없음 "
                    f"(파싱 {len(parsed)}건 중 후보 0건). "
                    "flags 룰 또는 선별 범위를 확인한다."
                )
            },
        )

    findings = interpret(
        scenario,
        records,
        client,
        log,
        max_attempts=args.max_attempts,
    )

    io.write_json(
        out_path,
        findings,
    )

    # 배분 내역 출력
    for quota in quotas:
        short = (
            "전량"
            if quota.seats >= quota.candidates
            else f"{quota.candidates}건 중"
        )

        print(
            f"  {quota.artifact:<18} "
            f"priority {quota.priority}  "
            f"파싱 {quota.parsed}건 / "
            f"후보 {quota.candidates}건 / "
            f"전달 {quota.seats}건 ({short})"
        )

    if budget.trimmed:
        print(
            f"  토큰 예산: "
            f"{budget.natural_records}건 → "
            f"{len(records)}건으로 줄임 "
            f"({budget.used_chars:,}자 ≈ "
            f"{budget.estimated_tokens:,}토큰 / "
            f"예산 {budget_chars:,}자). "
            f"--num-ctx {args.num_ctx} 에서 "
            f"출력 {args.reserve_output_tokens}토큰을 뺀 값이다"
        )

    print(
        f"{out_path}: "
        f"레코드 {len(parsed)}건 중 "
        f"{len(records)}건 전달, "
        f"findings {len(findings['findings'])}건 / "
        f"generator {findings['generator']}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())