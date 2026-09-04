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
from ..common.llm import DEFAULT_TIMEOUT
from ..stage03_select import mapping_loader
from ..stage06_verify import comparators
from . import allocation, assembly, record_filter
from .llm_client import (
    ASSEMBLE_NUM_CTX,
    DEFAULT_MODEL,
    DEFAULT_NUM_CTX,
    FINDINGS_BODY_FIELDS,
    InterpretClient,
)

__all__ = [
    "STAGE",
    "build_findings",
    "dump_raw",
    "interpret",
    "QueryLog",
    "interpret_assembled",
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


class QueryLog:
    """05단계가 모델과 주고받은 것을 케이스 디렉터리에 그대로 남긴다.

    **산출물만 보면 05단계는 블랙박스다.** findings 가 왜 그렇게 나왔는지
    되짚으려면 무엇을 물었고 무엇이 돌아왔는지가 있어야 한다. 특히 질의를
    조각으로 나누면 "몇 번 물었나·각 조각에 무엇이 실렸나·어느 질의에서 이
    소견이 나왔나" 가 산출물 어디에도 없다.

    ``errors.jsonl`` 옆의 ``_raw_attempt*.txt`` 와 다르다. 그쪽은 **실패한**
    시도의 응답만 남긴다 — 성공하면 아무것도 안 남는다. 이쪽은 성공한
    질의도 남긴다. 프롬프트를 고칠 때 무엇이 달라졌는지 대조할 것이
    있어야 하기 때문이다.

    파일 하나가 질의 하나다::

        05_llm_queries/
          01_selection_chunk1of3.txt
          02_selection_chunk2of3.txt
          03_selection_chunk3of3.txt
          04_connections.txt
    """

    def __init__(self, directory: "Path | None") -> None:
        self.directory = directory
        self.count = 0

    def record(
        self, client: InterpretClient, kind: str, note: str = "", refs: "list[str] | None" = None
    ) -> "str | None":
        """방금 보낸 질의와 받은 응답을 파일로. 껐으면 아무것도 안 한다."""
        if self.directory is None or client.last_user is None:
            return None

        self.count += 1
        name = f"{self.count:02d}_{kind}.txt"
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)

        tokens = getattr(client.backend, "last_prompt_tokens", None)
        header = [
            f"# 질의 {self.count} — {kind}",
            f"# 백엔드: {client.name}",
        ]
        if note:
            header.append(f"# {note}")
        if refs:
            header.append(f"# 실은 레코드 {len(refs)}건: {', '.join(refs)}")
        if tokens:
            header.append(f"# 프롬프트 실측 {tokens:,}토큰")

        path.write_text(
            "\n".join(header)
            + "\n\n===== system =====\n"
            + (client.last_system or "")
            + "\n\n===== user =====\n"
            + client.last_user
            + "\n\n===== response =====\n"
            + (client.last_raw or "(응답 없음)")
            + "\n",
            encoding="utf-8",
        )
        return name


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
    queries: "QueryLog | None" = None,
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

            if queries is not None:
                queries.record(
                    client,
                    "findings",
                    note=f"시도 {attempt}",
                    refs=[record["ref"] for record in records],
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


def _select_chunk(
    scenario: dict[str, Any],
    chunk: list[dict[str, Any]],
    client: InterpretClient,
    log: errlog.ErrorLog,
    index: int,
    total: int,
    *,
    max_attempts: int = MAX_ATTEMPTS,
    queries: "QueryLog | None" = None,
) -> list[dict[str, Any]]:
    """조각 하나를 모델에게 물어 고른 것을 받는다.

    **조각 하나가 실패하면 파이프라인이 멈춘다.** 남은 조각으로 완주하면
    그것이 폴백이다 — 증거의 일부만 본 보고서가 전부를 본 것처럼 나가고,
    그 사실은 산출물 어디에도 없다. 이 프로젝트에서 가장 나쁜 성질이다.

    **잃는 것이 있다.** 조각이 열이고 일곱째가 시간 초과면 앞의 여섯도
    버려진다. 그래도 멈추는 쪽인 것은, 부분 결과를 들고 가려면 "무엇을 못
    봤는가"가 07 보고서까지 나가야 하는데 그 통로가 아직 없기 때문이다.
    `--timeout` 을 올려 다시 도는 것이 지금의 답이다.
    """
    feedback: str | None = None
    where = f"조각 {index}/{total}" if total > 1 else "선별"

    for attempt in range(1, max_attempts + 1):
        try:
            picked = client.propose_selection(scenario, chunk, feedback)
            if queries is not None:
                suffix = f"chunk{index}of{total}" if total > 1 else "all"
                queries.record(
                    client,
                    f"selection_{suffix}",
                    note=f"시도 {attempt}, 고른 것 {len(picked)}건",
                    refs=[r["ref"] for r in chunk],
                )
            # **여기서 검사한다.** 조립까지 미루면 어느 조각이 틀렸는지 알 수
            # 없어 전부 다시 돌게 된다.
            assembly.validate_selection(picked, {r["ref"]: r for r in chunk})
            return picked

        except assembly.SelectionError as e:
            detail: dict[str, Any] = {"message": f"{where}: {e}"}
            saved = dump_raw(log, attempt, client.last_raw)
            if saved:
                detail["raw"] = saved
            log.record(STAGE, "claim_validation", detail, action="retry", attempt=attempt)
            feedback = (
                "이전 응답의 evidence_fields 가 그 레코드와 맞지 않습니다.\n"
                f"{e}\n"
                "각 레코드에 **실제로 있는** 필드 이름만 적으십시오."
            )

        except llm.MalformedOutput as e:
            detail = {"message": f"{where}: {e}"}
            saved = dump_raw(log, attempt, client.last_raw)
            if saved:
                detail["raw"] = saved
            log.record(STAGE, "malformed_output", detail, action="retry", attempt=attempt)
            feedback = f"응답에서 JSON을 찾지 못했습니다: {e}"

        except llm.LLMTimeout as e:
            log.record(
                STAGE, "timeout", {"message": f"{where}: {e}"}, action="retry", attempt=attempt
            )
            feedback = None

        except llm.LLMError as e:
            # 02단계와 같은 이유로 재시도하지 않는다 — 모델명 오타·서버
            # 미기동은 세 번 불러도 같은 답이다.
            log.abort(STAGE, "llm_error", {"message": f"{where}: {e}"})

    log.abort(
        STAGE,
        "malformed_output",
        {
            "message": (
                f"{where} 를 {max_attempts}회 재시도했으나 쓸 수 있는 선별을 받지 못함. "
                "남은 조각으로 완주하면 증거의 일부만 본 보고서가 전부를 본 것처럼 "
                f"나간다. 모델 응답 원문은 {log.path.parent}/{STAGE}_raw_attempt*.txt 에 있다"
            )
        },
    )


def _connect(
    scenario: dict[str, Any],
    picked: list[dict[str, Any]],
    client: InterpretClient,
    log: errlog.ErrorLog,
    char_budget: "int | None",
    queries: "QueryLog | None" = None,
) -> list[dict[str, Any]]:
    """고른 항목들 중 서로 이어지는 것을 묶는다 (Reduce).

    **이것이 없으면 Map-Reduce 가 이름만 Reduce 다.** 조각마다 따로 판정만
    하고 파이썬이 append 하면, 조각을 넘는 연결은 아무도 말한 적이 없다 —
    "파일이 떨어졌다"와 "그 파일이 실행됐다"가 각각 실릴 뿐 한 사건이라는
    말은 어디에도 없다.

    **묶을 것이 둘 미만이면 부르지 않는다.** 물어볼 것이 없다.

    **입력도 예산 판정을 받는다.** 단서가 수십 건이면 한 줄이 120자라도
    창을 넘는다. 넘으면 **건너뛰고 그 사실을 남긴다** — 조각 실패와 달리
    여기서 잃는 것은 종합이지 증거가 아니다. 고른 항목은 전부 단독 소견으로
    실리므로 산출물이 부분이 되지 않는다. 그래서 ``abort`` 가 아니라
    ``skip`` 이다.

    **실패해도 멈추지 않는다.** 같은 이유다. 종합을 못 했을 뿐 증거는 다
    실린다. 다만 조용히 넘어가지는 않는다.
    """
    if len(picked) < 2:
        return []

    if char_budget is not None and char_budget > 0:
        needed = client.reduce_chars(scenario, picked)
        if needed > char_budget:
            log.record(
                STAGE,
                "empty_result",
                {
                    "message": (
                        f"종합 질의 입력이 예산을 넘음 ({needed:,}자 > {char_budget:,}자, "
                        f"단서 {len(picked)}건). 교차 아티팩트 종합을 건너뛴다 — "
                        "고른 항목은 전부 단독 소견으로 실리므로 증거가 빠지지는 않는다"
                    )
                },
                action="skip",
            )
            return []

    try:
        found = client.propose_connections(scenario, picked)
        if queries is not None:
            queries.record(
                client, "connections", note=f"단서 {len(picked)}건 → 묶음 {len(found)}건"
            )
        return found
    except (llm.LLMError, llm.MalformedOutput) as e:
        if queries is not None:
            queries.record(client, "connections_failed", note=str(e))
        log.record(
            STAGE,
            "malformed_output" if isinstance(e, llm.MalformedOutput) else "llm_error",
            {"message": f"종합 질의 실패, 건너뜀: {e}"},
            action="skip",
        )
        return []


def interpret_assembled(
    scenario: dict[str, Any],
    records: list[dict[str, Any]],
    client: InterpretClient,
    log: errlog.ErrorLog,
    *,
    max_attempts: int = MAX_ATTEMPTS,
    char_budget: "int | None" = None,
    queries: "QueryLog | None" = None,
) -> dict[str, Any]:
    """모델에게 **고르게만** 하고 findings 는 파이썬이 조립한다.

    ``interpret`` 과 무엇이 다른가.

    .. code-block:: text

        interpret            모델이 문장·claims·타임라인을 전부 쓴다
        interpret_assembled  모델은 {ref, 기법, 사유, 근거 필드}만 고른다

    **실패 처리가 갈린다.** 이 경로에는 두 가지 실패가 있고 성질이 반대다.

    - ``SelectionError`` — 모델이 그 레코드에 없는 필드를 근거로 지목했다.
      **모델 잘못이라 다시 물어보면 고쳐질 수 있다.** 피드백을 주고 재시도.
    - ``AssemblyError`` — 조립기가 자기 일을 못 했다. **우리 잘못이라 같은
      코드가 같은 입력으로 같은 답을 낸다.** 재시도하면 모델을 세 번 더
      부르고 똑같이 죽으므로 한 번에 중단한다.

    이 갈림이 없으면 우리 버그가 모델 호출 세 번을 태우고, 그 실패가
    ``claim_validation`` 으로 쌓여 환각 통계를 오염시킨다.

    **claim 관문(``validate_model_claims``)은 여기서도 돈다.** 다만 뜻이
    다르다 — claims 를 파이썬이 원본에서 복사했으므로 통과는 항등식이고,
    실패는 **조립기의 버그**다. 그래서 이 경로에서는 그 실패도
    ``AssemblyError`` 로 다룬다. 공짜로 얻는 회귀 점검이라 끄지 않는다.
    """
    case_id = scenario["case_id"]
    generator = io.make_generator("interpret.py", client.name)
    by_ref = {record["ref"]: record for record in records}
    input_refs = list(by_ref)

    chunks = allocation.chunk_records(records, char_budget) if char_budget else [records]
    picked: list[dict[str, Any]] = []
    for index, chunk in enumerate(chunks, 1):
        picked.extend(
            _select_chunk(
                scenario,
                chunk,
                client,
                log,
                index,
                len(chunks),
                max_attempts=max_attempts,
                queries=queries,
            )
        )

    connections = _connect(scenario, picked, client, log, char_budget, queries)

    feedback: str | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            body = assembly.assemble_body(picked, by_ref, connections=connections)
            findings = build_findings(body, case_id, generator, input_refs)
            schema.validate(findings, "findings")
            try:
                validate_model_claims(findings, records)
            except ClaimValidationError as e:
                # 이 경로의 claims 는 우리가 만들었다. 불일치는 모델이 아니라
                # 조립기의 버그다 — 위 설명 참조.
                raise assembly.AssemblyError(
                    f"조립한 claim 이 원본과 어긋난다: {e}"
                ) from e
            return findings

        except assembly.AssemblyError as e:
            log.abort(STAGE, "assembly_error", {"message": str(e)})

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
                f"{max_attempts}회 재시도 후에도 조립 결과가 스키마를 만족하지 못함. "
                f"모델 응답 원문은 {log.path.parent}/{STAGE}_raw_attempt*.txt 에 있다"
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
        default=None,
        help=(
            "모델에게 열어 줄 컨텍스트 창(토큰). 생략하면 --mode 가 정한다 "
            f"(model {DEFAULT_NUM_CTX}, assemble {ASSEMBLE_NUM_CTX}). "
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
        "--max-chunks",
        type=int,
        default=8,
        help=(
            "--mode assemble 에서 질의를 몇 번까지 나눠 보낼 것인가. 기본 "
            "%(default)s. **이 값이 커버리지의 상한이다** — 한 번에 물으면 "
            "창 하나에 들어가는 만큼만 볼 수 있지만, 나눠 물으면 그 배수만큼 "
            "본다. 1 이면 분할하지 않는다(예전과 같다)"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["model", "assemble"],
        default="model",
        help=(
            "누가 findings 를 쓰는가. 기본 %(default)s. "
            "model 은 모델이 문장·claims·타임라인을 전부 쓰고, "
            "assemble 은 모델이 {ref, 기법, 사유, 근거 필드}만 고르고 "
            "파이썬이 원본에서 조립한다. **폴백이 아니라 측정용 스위치다** — "
            "같은 케이스를 두 경로로 돌려야 무엇이 달라졌는지 말할 수 있다 "
            "(--no-constrain 과 같은 규약)"
        ),
    )
    parser.add_argument(
        "--reserve-output-tokens",
        type=int,
        default=None,
        help=(
            "모델이 답을 쓸 자리로 남겨 둘 토큰. 생략하면 --mode 가 정한다 "
            f"(model {allocation.RESERVE_FINDINGS_TOKENS}, "
            f"assemble {allocation.RESERVE_SELECTION_TOKENS}). "
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
        "--queries",
        default=None,
        help=(
            "모델과 주고받은 내역을 남길 디렉터리. 생략하면 --out 옆의 "
            "05_llm_queries/. **산출물만 보면 이 단계는 블랙박스다** — 무엇을 "
            "물었고 무엇이 돌아왔는지가 있어야 findings 가 왜 그렇게 나왔는지 "
            "되짚는다. 'none' 을 주면 남기지 않는다"
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

    # **질의 종류가 예산을 정한다.** 선별 질의는 ref 와 한 줄 사유만 내므로
    # 답 쓸 자리가 소견 질의의 4분의 1이다. 큰 쪽에 맞춰 두면 작은 질의가
    # 쓰지도 않을 자리를 창에서 떼어 가고, 창이 좁을수록 그 낭비가 곧
    # 레코드 수다. 사용자가 직접 준 값은 그대로 존중한다.
    assembled = args.mode == "assemble"
    if args.num_ctx is None:
        # **창도 질의 종류를 따라간다.** 단일 질의는 창이 곧 커버리지라 넓어야
        # 하고, 분할 질의는 여러 번 보내므로 좁혀도 커버리지를 잃지 않는다 —
        # 오히려 GPU 에 다 올라가 빨라진다(`llm_client.ASSEMBLE_NUM_CTX`).
        args.num_ctx = ASSEMBLE_NUM_CTX if assembled else DEFAULT_NUM_CTX
    if args.reserve_output_tokens is None:
        args.reserve_output_tokens = (
            allocation.RESERVE_SELECTION_TOKENS
            if assembled
            else allocation.RESERVE_FINDINGS_TOKENS
        )

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
    # 프롬프트의 고정 부분을 **실제로 조립해서** 잰다. 아래 요약에서 한 번
    # 더 쓰므로 이름을 붙여 둔다 — 두 번 재면 두 값이 갈라질 수 있다.
    # **질의 종류마다 다르다.** 선별 질의의 시스템 프롬프트가 더 짧다.
    # 한쪽 값으로 두 질의의 예산을 잡으면 그 차이만큼 레코드가 덜
    # 실리거나 프롬프트가 창을 넘는다.
    overhead_chars = (
        client.selection_overhead_chars(scenario)
        if assembled
        else client.prompt_overhead_chars(scenario)
    )

    budget_chars = allocation.char_budget(
        args.num_ctx,
        overhead_chars,
        reserve_output_tokens=args.reserve_output_tokens,
    )

    # **조립 경로는 예산을 조각 수만큼 곱해서 고른다.** 한 번에 물으면 창
    # 하나에 들어가는 만큼만 볼 수 있는데, 나눠 물으면 그 배수만큼 볼 수
    # 있다. 여기서 곱하지 않으면 배분이 이미 한 창 크기로 잘라 놓아 분할이
    # 영영 걸리지 않고, Map-Reduce 가 이름만 남는다.
    #
    # 4-3 이 "Tier 1 아티팩트당 4건으로 7단계 체인을 재구성해야 한다"를
    # 미해결로 둔 자리가 이것이다(`docs/limitations.md`).
    alloc_budget = budget_chars
    if assembled and budget_chars > 0:
        alloc_budget = budget_chars * max(1, args.max_chunks)

    records, quotas, budget = allocation.allocate_records(
        parsed.values(),
        priorities=priorities,
        signal_sources=signal_sources,
        limit=args.limit,
        window_seconds=args.window_seconds,
        char_budget=alloc_budget,
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

    # 질의 내역은 기본으로 남긴다. 실패한 시도만 남기는 _raw_attempt*.txt 와
    # 달리 성공한 질의도 남긴다 — 프롬프트를 고칠 때 무엇이 달라졌는지
    # 대조할 것이 있어야 한다.
    queries = QueryLog(
        None if args.queries == "none"
        else Path(args.queries) if args.queries
        else out_path.parent / "05_llm_queries"
    )

    if assembled:
        findings = interpret_assembled(
            scenario,
            records,
            client,
            log,
            max_attempts=args.max_attempts,
            # 조각을 나누는 기준이 레코드를 고르는 기준과 같은 예산이어야
            # 한다. 다른 수를 쓰면 "예산에 맞춰 골랐는데 조각이 창을 넘는"
            # 상태가 조용히 생긴다.
            char_budget=budget_chars,
            queries=queries,
        )
    else:
        findings = interpret(
            scenario,
            records,
            client,
            log,
            max_attempts=args.max_attempts,
            queries=queries,
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
    # 창을 얼마나 쓰고 있는지는 **늘** 말한다. 넘었는지는 사후에 알 방법이
    # 없기 때문이다 — Ollama 는 창을 넘은 프롬프트를 거부하지 않고 앞을
    # 잘라서 받는다. 잘린 실행은 오류 없이 끝나고 findings 만 얇아진다
    # (`allocation.CHARS_PER_TOKEN` 의 실측 참조). 창을 좁히는 작업이
    # 이어질 자리라, 남은 여유가 눈에 보여야 한다.
    # **조립 경로는 조각마다 따로 보낸다.** 전체 글자 수를 조각당 예산에
    # 견주면 "694%" 같은 수가 나오고, 그것은 거짓말이다. 견줄 것은 **가장
    # 큰 조각**이다 — 창을 넘는지는 조각 단위로 결정된다.
    largest_chunk_chars = budget.used_chars
    if assembled and budget_chars > 0:
        chunks = allocation.chunk_records(records, budget_chars, max_list_items)
        largest_chunk_chars = max(
            (sum(allocation.record_chars(r, max_list_items) for r in chunk) for chunk in chunks),
            default=0,
        )
        print(f"  질의 {len(chunks)}회로 나눔 (조각당 예산 {budget_chars:,}자)")

    prompt_tokens = int((overhead_chars + largest_chunk_chars) / allocation.CHARS_PER_TOKEN)
    budget_tokens = allocation.prompt_token_budget(
        args.num_ctx, reserve_output_tokens=args.reserve_output_tokens
    )
    print(
        f"  프롬프트 추정 {prompt_tokens:,}토큰 "
        f"(쓸 수 있는 {budget_tokens:,}토큰의 {prompt_tokens * 100 // max(1, budget_tokens)}%, "
        f"창 {args.num_ctx:,} − 출력 예약 {args.reserve_output_tokens:,})"
    )

    # 실제로 몇 토큰이었는지는 모델만 안다. 추정 옆에 놓아야 상수가 어긋난
    # 것이 실행 중에 보인다 — 이 자리가 없어서 프롬프트가 잘리고 있다는
    # 사실을 사람이 따로 재서야 찾아냈다(`limitations-log.md`, 2026-09-03).
    # **가장 큰 프롬프트**를 본다. 질의를 여러 번 보내면 마지막 호출의 값은
    # 추정과 다른 프롬프트라 나란히 놓을 수 없고, 알고 싶은 것은 "어느
    # 프롬프트라도 창을 넘었는가"다.
    largest_chars, actual_tokens = client.largest_prompt
    if actual_tokens:
        observed = largest_chars / actual_tokens
        print(
            f"  프롬프트 실측 최대 {actual_tokens:,}토큰 "
            f"({observed:.2f}자/토큰, 예산이 쓴 값 {allocation.CHARS_PER_TOKEN})"
        )
        # 잘렸는지는 이 수로 직접 볼 수 없다. Ollama 가 앞을 자른 뒤의 수를
        # 돌려주기 때문이다. 드러나는 것은 **비율**이다 — 절반이 잘리면
        # 자·토큰 비가 두 배가 된다. 그래서 크게 벗어나면 말한다.
        #
        # **중단하지는 않는다.** 비율이 벗어나는 데는 잘림 말고 다른 이유도
        # 있다(레코드 구성이 달라져 상수가 이 케이스에 안 맞는 경우). 증명
        # 없이 중단하면 새로운 실패 모드를 만드는 것이라, 사람이 보게만 한다.
        if observed > allocation.CHARS_PER_TOKEN * 1.5:
            print(
                f"[{STAGE}] 경고: 자·토큰 비가 예산의 가정({allocation.CHARS_PER_TOKEN})보다 "
                f"{observed / allocation.CHARS_PER_TOKEN:.1f}배 큽니다. 프롬프트가 창을 넘어 "
                f"앞이 잘렸을 수 있습니다 — 모델이 받은 것이 보낸 것보다 적으면 "
                f"findings 는 조용히 얇아집니다. --num-ctx 를 올리거나 --limit 을 낮춰 "
                f"다시 재 보십시오.",
                file=sys.stderr,
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

    if queries.count:
        print(f"  질의 내역 {queries.count}건: {queries.directory}")
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