"""해석 단계용 LLM 클라이언트.

02단계와 파일이 나뉜 것은 의도된 설계다. 정규화는 짧은 구조화 출력이라
작은 모델로도 되지만, 해석은 레코드를 읽고 문장을 만들어야 해서 더 큰
모델이 필요할 수 있다.

전송과 응답 파싱은 ``src/common/llm.py``가 맡는다. 여기 있는 것은
**이 단계의 프롬프트와 파라미터**뿐이다.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..common import attack, schema
from ..common.llm import Backend, MalformedOutput, extract_json, output_schema
from ..stage04_parse.flagging import prompt_drop_fields
from .allocation import MAX_LIST_ITEMS, for_prompt

__all__ = [
    "DEFAULT_MAPPINGS",
    "DEFAULT_MODEL",
    "FINDINGS_BODY_FIELDS",
    "INVESTIGATION_BODY_FIELD",
    "MAX_INVESTIGATION_REQUESTS",
    "InterpretClient",
    "candidate_techniques",
    "constrained_schema",
    "investigation_schema",
]

#: 라벨 어휘를 읽을 매핑 디렉터리의 기본값. ``interpret`` 의 ``--mappings``
#: 기본값과 같아야 한다 — 어긋나면 03단계가 선별한 근거로 05단계가 붙일 수
#: 없는 라벨이 생긴다.
DEFAULT_MAPPINGS = "mappings"

#: 해석은 정규화보다 무거운 작업이다. 같은 7B로 시작하되 모델별 비교
#: 실험에서 이 단계만 키웠을 때의 효과를 따로 측정한다.
#:
#: ``ollama pull``에 넣을 수 있는 태그를 그대로 쓴다. 02단계와 값이 같아도
#: 상수를 공유하지 않는 것은, 이 단계만 큰 모델로 바꾸는 실험이 잦기 때문이다.
DEFAULT_MODEL = "qwen2.5:7b-instruct-q4_K_M"

PROMPT_DIR = Path(__file__).parent / "prompts"

#: 05단계가 모델에게 열어 줄 컨텍스트 창(토큰).
#:
#: ``src/common/llm.py`` 의 값을 그대로 쓰지 않는 이유는 ``DEFAULT_MODEL`` 과
#: 같다 — 02단계와 창 크기를 묶어 두면 한쪽을 실험할 때 다른 쪽이 따라
#: 움직인다. 02는 시나리오 한 건이라 프롬프트가 작고, 05는 레코드를 싣는다.
#:
#: **단일 질의(`--mode model`)의 값이다.** 여기서는 못 내린다 — 한 번에 다
#: 물으므로 창이 곧 커버리지이고, 8,192 로 내리면 레코드가 54건에서 열 건
#: 남짓이 된다.
DEFAULT_NUM_CTX = 32768

#: 분할 질의(``--mode assemble``)가 모델에게 열어 줄 창.
#:
#: ValleyRAT 실물에서는 8,192 창에서 선택 응답이 세 번 모두 잘린 JSON으로
#: 끝났고, 같은 입력을 16,384로 올리자 60건·5질의가 정상 완료됐다.
#: 분할 질의도 입력과 구조화 출력이 한 호출의 창을 공유하므로 16K를
#: 기본 하한으로 둔다. 더 큰 사건은 CLI ``--num-ctx``로 올릴 수 있다.
ASSEMBLE_NUM_CTX = 16384


#: 모델에게 요구하는 필드. ``input_refs``는 **모델에게 묻지 않는다.**
#: 무엇을 전달했는지는 우리가 안다. 모델이 보고하게 하면 실제로 받지
#: 않은 레코드를 목록에 넣어 ref_not_in_input 검사를 무력화할 수 있다.
FINDINGS_BODY_FIELDS = ("findings", "timeline")


def constrained_schema(
    scenario: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    mappings: "str | None" = None,
) -> dict[str, Any]:
    """이 호출에 한정된 출력 스키마. **배치마다 다르다.**

    02단계와 달리 목록이 고정돼 있지 않다. 모델이 인용해도 되는 ``ref``는
    이번에 실제로 실어 보낸 레코드의 것뿐이고, 그 목록은 호출할 때 정해진다.

    **우리는 무엇을 보냈는지 이미 알고 있다.** 프롬프트가 "이 목록에 없는
    ref를 쓰면 기각됩니다"라고 적어 부탁해 왔고, 06단계가 사후에
    ``ref_not_in_input``으로 걸러 왔다. 같은 목록을 enum으로 주면 없는 ref를
    만들 토큰 경로가 사라진다 — 걸러 낼 것이 아니라 나오지 않는다.

    ``$defs.ref`` 하나를 갈아 끼운다. ``findings[].refs``·
    ``findings[].claims[].ref``·``timeline[].refs`` 셋이 모두 이 정의를
    가리키므로, 자리마다 손대면 언젠가 하나를 빠뜨린다.

    ``technique``도 열거형으로 묶는다. 무엇으로 묶는지는
    ``candidate_techniques`` 가 정한다 — 시나리오가 든 것이 아니라 매핑이
    있는 것 전부다. 동결 스키마가 ``null``을 허용하므로("특정 기법에
    귀속되지 않을 수 있다") enum에 ``None``을 남긴다.
    """
    built = output_schema(schema.load_schema("findings"), FINDINGS_BODY_FIELDS)

    refs = [record["ref"] for record in records if "ref" in record]
    if refs:
        # 비었으면 갈아 끼우지 않는다. 빈 enum 은 아무 값도 만족시킬 수
        # 없어 모델이 무엇을 내든 실패하고, 그 실패는 "레코드를 한 건도
        # 못 받았다"는 앞 단계의 문제를 05단계 환각으로 둔갑시킨다.
        built["$defs"]["ref"] = {"enum": sorted(set(refs))}

    techniques = [tid for tid, _name in candidate_techniques(scenario, mappings)]
    if techniques:
        built["properties"]["findings"]["items"]["properties"]["technique"] = {
            "enum": [*techniques, None]
        }
    return built


#: 선별 질의에서 모델이 낼 필드. ``input_refs`` 를 묻지 않는 이유는
#: ``FINDINGS_BODY_FIELDS`` 와 같다 — 무엇을 보냈는지는 우리가 안다.
SELECTION_BODY_FIELD = "suspicious_records"

#: 소견의 ``severity`` 어휘. 동결 스키마와 같아야 조립이 그대로 통과한다.
SEVERITIES = ("high", "medium", "low", "info")


def candidate_techniques(
    scenario: dict[str, Any], mappings: "str | None" = None
) -> "list[tuple[str, str]]":
    """모델이 소견에 붙일 수 있는 기법 라벨. ``(ID, 이름)`` 을 ID 순으로.

    **시나리오가 든 기법이 아니라 매핑 테이블이 있는 기법 전부다.**

    예전에는 ``scenario["techniques"]`` 로 묶었다. 시나리오에 다 적혀 있는
    실행에서는 그것으로 충분했지만, 사건 서술이 짧으면 무너진다 —
    **02단계가 좁게 읽으면 모델이 관측한 것에 맞는 라벨을 못 갖는다.**

    실측(``K-2LINE-ANCHOR-LOOP``, 2026-09-09). 두 줄짜리 질문에서 02가 든
    기법은 T1091·T1078.003 둘뿐이었다. 05는 fodhelper 로 UAC 를 우회하고
    certutil 로 파일을 받는 것을 레코드에서 정확히 찾아냈지만, 붙일 이름이
    그 둘뿐이라 T1091 을 골랐다. 06단계는 제 일을 해서 그 둘을
    ``technique_unsupported`` 로 기각했고, **관측이 맞았는데 라벨이 없어서
    보고서에서 사라졌다.** 검증기의 잘못이 아니라 이 열거형의 잘못이다.

    그래서 그 기각은 세 번째 원인을 갖는다 —
    ``stage06_verify/checkers/technique_supported.py`` 가 적어 둔 둘(모델이
    잘못 붙였다 / 매핑이 좁다) 어느 쪽도 아니고, **모델에게 고를 것이
    없었다**이다. 그 원인은 여기서만 없앨 수 있다.

    넓혀도 지어내기는 막힌다. 여전히 열거형이고, ``KNOWN_TECHNIQUES`` 안이며,
    06단계가 인용한 아티팩트까지 본다. 넓어지는 것은 모델의 자유도이고,
    그래야 **06단계가 잴 것이 생긴다** — 선택지가 둘일 때 그 검사는 사실상
    판정할 것이 없었다.

    **03단계의 선별 범위는 바뀌지 않는다.** 무엇을 열지는 02단계가 정하고
    이 목록은 05단계의 라벨 어휘일 뿐이라, 파싱 비용도 그대로다.

    시나리오가 든 기법 중 매핑이 없는 것도 남긴다. 빼면 02가 옳게 읽은
    기법을 모델이 못 쓰게 되고, 그때의 기각(매핑 결손)은 우리가 세고 싶은
    쪽이다(``benchmark/rejections.yaml``).
    """
    listed = [t for t in scenario.get("techniques", []) if t.get("id")]
    named = {str(t["id"]): t.get("name") for t in listed}
    ids = set(named) | attack.mapped_techniques(mappings or DEFAULT_MAPPINGS)
    return sorted(
        (tid, str(named.get(tid) or attack.name_of(tid) or tid)) for tid in ids
    )


def evidence_field_names(
    records: list[dict[str, Any]], allowed: "tuple[str, ...]"
) -> list[str]:
    """모델이 ``evidence_fields`` 로 고를 수 있는 이름.

    **어휘 ∩ 이번 배치가 실제로 가진 필드**입니다. 둘을 곱하는 이유가 다릅니다.

    - 어휘(``mappings/_flags.yaml`` 의 ``claim_fields``)로 묶는 것은 무엇을
      검증 대상으로 삼을지가 우리 결정이기 때문입니다. 묶지 않으면 모델이
      ``Hashes`` 같은 것을 근거로 지목하고, 우리는 그 값으로 아무것도 확인할
      수 없습니다.
    - 이번 배치가 가진 것으로 좁히는 것은 **문법이 없는 이름을 못 내게**
      하기 위해서입니다. enum 에 없으면 그 토큰 경로가 사라집니다.

    그래도 검사는 남습니다 — 배치의 다른 레코드에 있는 이름을 이 레코드에
    붙일 수 있기 때문입니다. 그것은 문법으로 못 막고 조립이 잡습니다
    (``assembly.SelectionError``).
    """
    from .assembly import walk_field

    present = {
        name
        for record in records
        for name in allowed
        if walk_field(record, name)[0]
    }
    return sorted(present)


def record_field_names(
    record: dict[str, Any], allowed: "tuple[str, ...]"
) -> list[str]:
    """이 레코드 **하나**가 근거로 내놓을 수 있는 필드 이름.

    어휘(``claim_fields``)에 있고 그 레코드에 실제로 있는 것만이다.
    """
    from .assembly import walk_field

    return [name for name in allowed if walk_field(record, name)[0]]


def evidence_field_names(
    records: list[dict[str, Any]], allowed: "tuple[str, ...]"
) -> list[str]:
    """배치 전체가 내놓을 수 있는 필드 이름의 합집합.

    ``--no-constrain`` 실행처럼 레코드별 문법을 걸 수 없을 때의 목록이다.
    제약을 켠 실행은 ``selection_schema`` 가 레코드마다 따로 묶는다.
    """
    seen: set[str] = set()
    for record in records:
        seen.update(record_field_names(record, allowed))
    return sorted(seen)


def selection_schema(
    scenario: dict[str, Any],
    records: list[dict[str, Any]],
    allowed_fields: "tuple[str, ...]",
    max_evidence_fields: int = 4,
    *,
    mappings: "str | None" = None,
) -> dict[str, Any]:
    """선별 질의의 출력 스키마. **레코드마다 갈래를 따로 둔다.**

    ``ref`` 를 ``const`` 로 못 박은 갈래를 레코드 수만큼 만들고 ``oneOf`` 로
    잇는다. 그러면 **각 레코드가 자기가 가진 필드만 근거로 내놓을 수 있다.**

    **합집합 enum 으로는 부족했다** (2026-09-03 실물). 배치 전체의 필드
    이름을 하나의 enum 으로 주면, 파일 생성 이벤트(EID 11)에 프로세스 생성
    이벤트의 ``fields.CommandLine`` 을 붙이는 것이 문법상 합법이다. 실제로
    모델이 그렇게 했고, `temperature 0` 이라 재시도 세 번이 같은 답을 냈다.
    걸러 내는 것으로는 안 되고 **나오지 않게** 해야 하는 자리였다
    (``constrained_schema`` 가 ``ref`` 에 대해 내린 것과 같은 판단).

    ``oneOf``·``const`` 가 Ollama 문법으로 내려가는 것을 확인했다(같은 날).

    **근거로 내놓을 것이 하나도 없는 레코드**도 갈래를 받는다. 고를 수는
    있되 ``evidence_fields`` 가 빈 배열이라 claims 가 비고, 그 소견은
    06단계에서 ``unverifiable`` 이 된다. 갈래에서 빼면 모델이 그 레코드를
    아예 못 고르고, 그것은 증거를 조용히 숨기는 쪽이다.

    나머지 규약은 ``constrained_schema`` 와 같다 — ``pattern`` 은 쓰지 않고
    (변환기가 정규식을 못 삼킨다), 배열에는 상한을 건다(없으면 맴돈다),
    ``ref`` 를 맨 앞에 둔다(문법이 선언 순서대로 내보낸다).
    """
    techniques = [tid for tid, _name in candidate_techniques(scenario, mappings)]
    technique_schema: dict[str, Any] = (
        {"enum": [*techniques, None]} if techniques else {"type": ["string", "null"]}
    )

    predicate_names = [
        "equals", "contains", "list_contains", "under_path", "outside_path",
        "same_path", "same_hash", "spawned", "before", "after", "within",
        "duration", "count",
    ]
    branches: list[dict[str, Any]] = []
    for record in records:
        ref = record.get("ref")
        if not ref:
            continue
        names = record_field_names(record, allowed_fields)
        evidence: dict[str, Any] = (
            {
                "type": "array",
                "items": {"enum": names},
                "minItems": 1,
                "maxItems": min(len(names), max(1, max_evidence_fields)),
            }
            if names
            else {"type": "array", "maxItems": 0}
        )
        properties = {
            "ref": {"const": ref},
            "technique": technique_schema,
            "reason": {"type": "string"},
            "severity": {"enum": list(SEVERITIES)},
            "evidence_fields": evidence,
            "assertions": {
                "type": "array",
                "maxItems": 6,
                "items": {
                    "type": "object",
                    "properties": {
                        "predicate": {"enum": predicate_names},
                        "subject": {
                            "type": "object",
                            "properties": {"ref": {"const": ref}, "field": {"enum": names}},
                            "required": ["ref", "field"], "additionalProperties": False,
                        },
                        # Map owns one record. Cross-record endpoint relations
                        # belong to connection Reduce; allowing them here made
                        # the 7B model invent same_path links between unrelated
                        # records. Packet joins use a concrete ref string.
                        "object": {"type": ["string", "number", "boolean"]},
                        "tolerance_seconds": {"type": "number", "minimum": 0},
                    },
                    "required": ["predicate", "subject", "object"],
                    "additionalProperties": False,
                },
            },
        }
        packet_id = record.get("packet_id")
        if packet_id:
            properties["packet_id"] = {"const": packet_id}
        branches.append(
            {
                "type": "object",
                "properties": properties,
                "required": [
                    "ref", "technique", "reason", "severity", "evidence_fields",
                    *(["packet_id"] if packet_id else []),
                ],
                "additionalProperties": False,
            }
        )

    if not branches:
        # 비었으면 갈아 끼우지 않는다. 아무 값도 만족시키지 못하는 문법은
        # 모델이 무엇을 내든 실패시키고, 그 실패는 "레코드를 못 받았다"는
        # 앞 단계의 문제를 05단계 환각으로 둔갑시킨다.
        item: dict[str, Any] = {"type": "object"}
        picks: dict[str, Any] = {"type": "array", "items": item}
    else:
        item = branches[0] if len(branches) == 1 else {"oneOf": branches}
        picks = {"type": "array", "items": item, "maxItems": len(branches)}

    signal_ids = [
        f"{record['ref']}:{signal}"
        for record in records
        for signal in (record.get("attention_signals") or [])
        if record.get("ref")
    ]
    def disposition_value(record: dict[str, Any]) -> dict[str, Any]:
        names = record_field_names(record, allowed_fields)
        return {
            "type": "object",
            "properties": {
                "disposition": {"enum": ["selected", "dismissed", "uncertain"]},
                "reason": {"type": "string"},
                "evidence_fields": {"type": "array", "items": {"enum": names}, "minItems": 1, "maxItems": min(4, len(names))},
            },
            "required": ["disposition", "reason", "evidence_fields"],
            "additionalProperties": False,
        }
    signal_records = {
        f"{record['ref']}:{signal}": record
        for record in records
        for signal in (record.get("attention_signals") or [])
        if record.get("ref")
    }
    dispositions: dict[str, Any] = {
        "type": "object",
        "properties": {signal_id: disposition_value(signal_records[signal_id]) for signal_id in signal_ids},
        "required": signal_ids,
        "additionalProperties": False,
    }
    result = {
        "type": "object",
        "properties": {SELECTION_BODY_FIELD: picks},
        "required": [SELECTION_BODY_FIELD],
    }
    if signal_ids:
        result["properties"]["signal_dispositions"] = dispositions
        result["required"].append("signal_dispositions")
    return result


#: Reduce 질의에서 모델이 낼 필드.
CONNECTION_BODY_FIELD = "connections"


def critic_schema(story: dict[str, Any]) -> dict[str, Any]:
    ids = [item["id"] for item in story.get("sentences", []) if isinstance(item, dict) and item.get("id")]
    item = {
        "type": "object",
        "properties": {
            "sentence_id": {"enum": ids} if ids else {"type": "string"},
            "verdict": {"enum": ["supported", "contradicted", "insufficient"]},
            "reason": {"type": "string"},
        },
        "required": ["sentence_id", "verdict", "reason"], "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {"story_critic": {"type": "array", "minItems": len(ids), "maxItems": len(ids), "items": item}},
        "required": ["story_critic"], "additionalProperties": False,
    }


def connection_schema(
    scenario: dict[str, Any],
    picked: list[dict[str, Any]],
    relation_catalog: list[dict[str, Any]] | None = None,
    *,
    mappings: "str | None" = None,
) -> dict[str, Any]:
    """Reduce 질의의 출력 스키마.

    ``refs`` 의 enum 은 **Map 이 고른 것**뿐이다. 전달 레코드 전체가 아니다 —
    이 질의에는 원본 레코드가 실려 있지 않으므로, 고르지 않은 레코드를
    인용하면 모델이 못 본 것을 말하는 셈이 된다.

    ``minItems`` 가 2 인 것은 **한 항목짜리 묶음이 뜻이 없기 때문**이다.
    이어지는 것이 없으면 그 항목은 단독 소견으로 그대로 실린다.
    """
    refs = sorted({item["ref"] for item in picked if item.get("ref")})
    techniques = [tid for tid, _name in candidate_techniques(scenario, mappings)]

    relation_ids = [str(item["id"]) for item in relation_catalog or [] if item.get("id")]

    properties: dict[str, Any] = {
        "refs": {
            "type": "array",
            "items": {"enum": refs} if refs else {"type": "string"},
            "minItems": 2,
            **({"maxItems": len(refs)} if refs else {}),
        },
        "technique": (
            {"enum": [*techniques, None]} if techniques else {"type": ["string", "null"]}
        ),
        "reason": {"type": "string"},
        "severity": {"enum": list(SEVERITIES)},
        "assertion_ids": {
            "type": "array",
            "items": {"enum": relation_ids} if relation_ids else {"type": "string"},
            "maxItems": min(6, len(relation_ids)),
        },
    }
    items = {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }
    connections: dict[str, Any] = {"type": "array", "items": items}
    if refs:
        # 상한이 없으면 모델이 배열에서 맴돈다(selection_schema 참조).
        # 묶음이 항목 수보다 많을 이유가 없다.
        connections["maxItems"] = len(refs)

    sentence = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "text": {"type": "string"},
            "kind": {"enum": ["observed_fact", "analytical_assessment", "unknown"]},
            "refs": {"type": "array", "items": {"enum": refs}, "maxItems": len(refs)},
        },
        "required": ["id", "text", "kind", "refs"], "additionalProperties": False,
    }
    must_review_refs = sorted({
        str(item.get("ref")) for item in picked
        if item.get("ref") and item.get("attention_signals")
    })
    sentences_schema: dict[str, Any] = {
        "type": "array", "maxItems": 12, "items": sentence,
    }
    if must_review_refs:
        sentences_schema["allOf"] = [
            {
                "contains": {
                    "type": "object",
                    "properties": {
                        "refs": {"type": "array", "contains": {"const": ref}}
                    },
                    "required": ["refs"],
                }
            }
            for ref in must_review_refs
        ]
    story = {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "sentences": sentences_schema,
            "critical_threat": {"type": "string"},
        },
        "required": ["summary", "sentences", "critical_threat"], "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {CONNECTION_BODY_FIELD: connections, "incident_story": story},
        "required": [CONNECTION_BODY_FIELD, "incident_story"],
    }


#: 조사 요청 질의에서 모델이 낼 필드.
INVESTIGATION_BODY_FIELD = "investigation_requests"

#: 한 번에 받을 요청의 상한. ``schemas/investigation.schema.json`` 의
#: ``maxItems`` 와 **같아야 한다** — 여기서 더 받으면 문서가 스키마를 못
#: 맞춰 요청 전체가 버려진다.
MAX_INVESTIGATION_REQUESTS = 3


def investigation_schema(
    timed_refs: list[str],
    refs: list[str],
    techniques: list[str],
    artifacts: list[str],
    behaviors: "list[str] | None" = None,
    claim_ids: "list[str] | None" = None,
) -> dict[str, Any]:
    """조사 요청 질의의 출력 스키마. **요청할 수 있는 것만 열거한다.**

    ``constrained_schema`` 가 ``ref`` 에 대해 내린 것과 같은 판단이다 —
    걸러 낼 것이 아니라 나오지 않게 한다. 매핑 없는 기법이나 파서 없는
    아티팩트를 요청받아 봐야 02단계 확장이 기각할 뿐이고, 그 왕복은
    모델의 자리와 우리의 시간을 함께 쓴다.

    **``pivot_time`` 은 묻지 않는다.** 어느 레코드를 근거로 들었는지만
    받으면 그 레코드의 시각은 우리가 안다(``input_refs`` 를 묻지 않는 것과
    같은 이유). 모델이 타임스탬프를 지어낼 자리를 아예 없앤다.

    그래서 ``expand_time_range`` 의 ``based_on_ref`` 만 목록이 다르다 —
    **시각을 뽑을 수 있는 레코드**여야 축이 성립한다. 그런 레코드가 하나도
    없으면 그 갈래를 아예 넣지 않는다.
    """

    def branch(kind: str, allowed_refs: list[str], **extra: Any) -> dict[str, Any]:
        properties: dict[str, Any] = {
            "type": {"const": kind},
            "based_on_ref": {"enum": sorted(set(allowed_refs))},
            "rationale": {"type": "string"},
            **extra,
        }
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        }

    branches: list[dict[str, Any]] = []
    if timed_refs:
        branches.append(
            branch(
                "expand_time_range",
                timed_refs,
                window_hours={"type": "integer", "minimum": 1, "maximum": 24},
            )
        )
    if techniques:
        branches.append(
            branch("request_technique", refs, technique_id={"enum": sorted(set(techniques))})
        )
    if artifacts:
        branches.append(
            branch("request_artifact", refs, artifact={"enum": sorted(set(artifacts))})
        )
    if behaviors and (refs or claim_ids):
        grounds: list[dict[str, Any]] = []
        if refs:
            grounds.append(
                {
                    "type": "object",
                    "properties": {
                        "kind": {"const": "evidence_ref"},
                        "ref": {"enum": sorted(set(refs))},
                    },
                    "required": ["kind", "ref"],
                    "additionalProperties": False,
                }
            )
        if claim_ids:
            grounds.append(
                {
                    "type": "object",
                    "properties": {
                        "kind": {"const": "scenario_claim"},
                        "claim_id": {"enum": sorted(set(claim_ids))},
                    },
                    "required": ["kind", "claim_id"],
                    "additionalProperties": False,
                }
            )
        based_on = grounds[0] if len(grounds) == 1 else {"oneOf": grounds}
        branches.append(
            {
                "type": "object",
                "properties": {
                    "type": {"const": "request_behavior"},
                    "based_on": based_on,
                    "rationale": {"type": "string"},
                    "category": {"enum": sorted(set(behaviors))},
                    "pivots": {
                        "type": "array",
                        "maxItems": 5,
                        "uniqueItems": True,
                        "items": {"type": "string"},
                    },
                },
                "required": ["type", "based_on", "rationale", "category", "pivots"],
                "additionalProperties": False,
            }
        )

    return {
        "type": "object",
        "properties": {
            INVESTIGATION_BODY_FIELD: {
                "type": "array",
                "maxItems": MAX_INVESTIGATION_REQUESTS,
                "items": branches[0] if len(branches) == 1 else {"oneOf": branches},
            }
        },
        "required": [INVESTIGATION_BODY_FIELD],
        "additionalProperties": False,
    }


def selection_digest(picked: list[dict[str, Any]]) -> str:
    """Map 이 고른 것을 Reduce 프롬프트에 실을 한 줄씩.

    **원본 레코드를 다시 싣지 않는다.** 이 질의가 싼 이유가 그것이다 —
    수십 건이라도 한 줄이 120자 남짓이다. 대신 모델은 앞 단계가 요약한
    ``reason`` 만 보고 잇는다. 그래서 프롬프트가 "주어진 항목이 말하지 않는
    것을 보태지 말라"고 못 박는다.
    """
    lines = []
    for item in picked:
        technique = item.get("technique") or "-"
        lines.append(
            json.dumps(
                {
                    "ref": item.get("ref"),
                    "packet_id": item.get("packet_id"),
                    "attention_signals": item.get("attention_signals", []),
                    "attention_context": item.get("attention_context", {}),
                    "attention_requirements": item.get("attention_requirements", {}),
                    "technique": technique,
                    "severity": item.get("severity", "info"),
                    "reason": item.get("reason", ""),
                },
                ensure_ascii=False,
            )
        )
    return "\n".join(lines)


class InterpretClient:
    """레코드 → 해석 문장과 claims."""

    def __init__(
        self,
        backend: Backend,
        *,
        max_list_items: int | None = MAX_LIST_ITEMS,
        constrain: bool = True,
        mappings: "str | None" = None,
    ) -> None:
        self.backend = backend
        #: 라벨 어휘를 읽을 매핑 디렉터리. ``candidate_techniques`` 가 쓴다.
        self.mappings = mappings
        #: 출력 모양을 디코딩 단계에서 강제할 것인가. 02단계와 같은 규약이고
        #: **폴백이 아니라 측정용**이다 (``stage02_normalize/llm_client.py``).
        self.constrain = constrain
        #: ``fields`` 안의 목록을 몇 개까지 실을 것인가. ``allocation``이
        #: 예산을 잴 때 쓰는 값과 **같아야 한다** — 어긋나면 예산이 맞아도
        #: 프롬프트가 넘친다. ``interpret``이 둘에 같은 값을 넘긴다.
        self.max_list_items = max_list_items
        #: 마지막으로 받은 모델 응답 원문. 실패했을 때 무엇을 뱉었는지
        #: 파일로 떨구기 위한 것이다. 파싱 전에 채우므로 JSON 을 못 찾은
        #: 경우에도 남는다. 성공하면 아무도 읽지 않는다.
        self.last_raw: str | None = None
        #: 마지막으로 보낸 프롬프트. ``last_raw`` 와 짝이다 — 응답만 남기면
        #: "무엇을 물었길래 이렇게 답했나" 를 되짚을 수 없다. 질의 내역을
        #: 파일로 떨구는 쪽(``interpret.dump_query``)이 읽는다.
        self.last_system: str | None = None
        self.last_user: str | None = None
        #: 이 클라이언트가 보낸 프롬프트 중 **가장 큰 것**의 (글자, 실측 토큰).
        #:
        #: 질의를 여러 번 보내면 ``backend.last_prompt_tokens`` 는 마지막
        #: 호출의 값이라, 추정과 나란히 놓으면 서로 다른 프롬프트를 비교하게
        #: 된다. 실제로 알고 싶은 것은 "어느 프롬프트라도 창을 넘었는가"이고,
        #: 그 답은 최댓값에 있다.
        self.largest_prompt: tuple[int, int] = (0, 0)
        self.last_signal_dispositions: dict[str, Any] = {}
        self.last_incident_story: dict[str, Any] | None = None
        self.last_story_critic: list[dict[str, Any]] = []

    @property
    def name(self) -> str:
        return self.backend.name

    def _technique_labels(self, scenario: dict[str, Any]) -> str:
        """붙일 수 있는 기법 라벨 전체. **이름을 함께 보낸다.**

        ID 만 보내면 모델이 ``T1548`` 이 무엇인지 모르는 채로 고른다
        (``investigate_user_prompt`` 가 요청 목록에 대해 내린 것과 같은
        판단). 열거형은 무엇을 낼 수 있는지만 정하고, 무엇을 골라야 하는지는
        이 목록이 말한다.

        시나리오가 든 기법은 프롬프트에서 **따로** 보여 준다. 어느 것이
        사건 서술에서 나왔고 어느 것이 우리가 열어 둔 어휘인지는 다른
        정보다 — 섞으면 모델이 사건 서술을 넓게 읽은 것으로 오해한다.
        """
        return ", ".join(
            f"{tid}({name})"
            for tid, name in candidate_techniques(scenario, self.mappings)
        )

    def _note_prompt(self, chars: int) -> None:
        """방금 보낸 프롬프트의 크기를 기록한다. 가장 큰 것만 남긴다."""
        tokens = getattr(self.backend, "last_prompt_tokens", None)
        if tokens and chars > self.largest_prompt[0]:
            self.largest_prompt = (chars, tokens)

    def system_prompt(self) -> str:
        return (PROMPT_DIR / "interpret_system.txt").read_text(encoding="utf-8")

    def select_system_prompt(self) -> str:
        """선별 질의의 시스템 프롬프트. 소견 질의의 것보다 짧다.

        짧은 것이 이 질의의 요지다 — 출력 형식 설명이 줄고, 문장 작법과
        claims 규칙이 통째로 빠진다. 그 자리는 파이썬이 맡는다.
        """
        return (PROMPT_DIR / "select_system.txt").read_text(encoding="utf-8")

    def select_user_prompt(
        self,
        scenario: dict[str, Any],
        records: list[dict[str, Any]],
        feedback: str | None = None,
    ) -> str:
        """선별 질의의 사용자 프롬프트.

        레코드를 싣는 방식은 소견 질의와 **같아야 한다** — 같은 ``for_prompt``
        를 거친 같은 JSONL 이라야 ``allocation`` 의 예산이 두 질의에 다 맞는다.
        """
        techniques = ", ".join(
            f"{t['id']}({t['name']})" for t in scenario.get("techniques", [])
        )
        time_range = scenario.get("time_range", {})

        parts = [
            "### 시나리오\n"
            f"- 대상 OS: {scenario.get('target_os', '?')}\n"
            f"- 사건 서술에서 나온 기법: {techniques or '없음'}\n"
            f"- 붙일 수 있는 기법 라벨(이 중에서만 고릅니다): {self._technique_labels(scenario)}\n"
            f"- 분석 기간: {time_range.get('start', '?')} ~ {time_range.get('end', '?')}",
            "### 레코드 ("
            f"{len(records)}건, 이 목록에 없는 ref 는 쓸 수 없습니다{self._trim_notice()})\n"
            + "\n".join(
                json.dumps(for_prompt(record, self.max_list_items), ensure_ascii=False)
                for record in records
            ),
        ]
        if feedback:
            parts.append(
                "### 직전 출력의 문제\n"
                f"{feedback}\n"
                "이 점만 고쳐서 JSON 객체 하나를 다시 출력하십시오."
            )
        parts.append("### 출력")
        return "\n\n".join(parts)

    def selection_overhead_chars(self, scenario: dict[str, Any]) -> int:
        """선별 질의에서 레코드를 뺀 프롬프트의 글자 수.

        ``prompt_overhead_chars`` 와 같은 이유로 **실제로 조립해 잽니다.**
        두 질의의 시스템 프롬프트 길이가 다르므로 예산도 달라야 합니다.
        """
        return len(self.select_system_prompt()) + len(
            self.select_user_prompt(scenario, [])
        )

    def investigate_system_prompt(self) -> str:
        return (PROMPT_DIR / "investigate_system.txt").read_text(encoding="utf-8")

    def investigate_user_prompt(
        self,
        scenario: dict[str, Any],
        findings: dict[str, Any],
        *,
        pivots: dict[str, str],
        techniques: list[tuple[str, str]],
        artifacts: list[tuple[str, str]],
        behaviors: "list[tuple[str, str, bool]] | None" = None,
        claims: "list[dict[str, Any]] | None" = None,
    ) -> str:
        """조사 요청 질의의 사용자 프롬프트.

        **원본 레코드를 다시 싣지 않는다.** 1차 소견의 문장과 근거로 쓸 수
        있는 ``ref`` 목록만 보낸다 — 이 질의가 싼 이유가 그것이다
        (``selection_digest`` 와 같은 판단).

        요청 가능한 기법·아티팩트에는 **이름을 붙여 보낸다.** ID 만 보내면
        모델이 ``T1041`` 이 무엇인지 모르는 채로 고르게 된다. 열거형은
        무엇을 낼 수 있는지만 정하고, 무엇을 골라야 하는지는 이 목록이
        말한다.
        """
        time_range = scenario.get("time_range", {})
        identified = ", ".join(
            f"{t['id']}({t['name']})" for t in scenario.get("techniques", [])
        )
        story = (findings.get("incident_story") or {}).get("summary") or ""
        statements = "\n".join(
            f"- [{item.get('severity', 'info')}] {item.get('statement', '')}"
            for item in findings.get("findings", [])
        )

        parts = [
            "### 1차 분석 상태\n"
            f"- 분석 기간: {time_range.get('start', '?')} ~ {time_range.get('end', '?')}\n"
            f"- 이미 식별된 기법: {identified or '없음'}"
            + (f"\n- 사건 요약: {story}" if story else ""),
            f"### 1차 소견 ({len(findings.get('findings', []))}건)\n{statements or '없음'}",
            "### 근거로 들 수 있는 레코드 (based_on_ref)\n"
            + "\n".join(f"- {ref} ({when})" for ref, when in sorted(pivots.items()))
            + (
                "\n"
                + "\n".join(
                    f"- {ref} (시각 없음 — expand_time_range 의 근거로는 쓸 수 없음)"
                    for ref in sorted(set(findings.get("input_refs", [])) - set(pivots))
                )
                if set(findings.get("input_refs", [])) - set(pivots)
                else ""
            ),
            "### 추가할 수 있는 기법\n"
            + ("\n".join(f"- {tid}({name})" for tid, name in techniques) or "- 없음"),
            "### 추가로 수집할 수 있는 아티팩트\n"
            + ("\n".join(f"- {name}: {desc}" for name, desc in artifacts) or "- 없음"),
            "### 아직 비어 있는 행위 범주\n"
            + (
                "\n".join(
                    f"- {family_id}({label}) — 사용자 입력 관련: {'예' if relevant else '아니오'}"
                    for family_id, label, relevant in (behaviors or [])
                )
                or "- 없음"
            ),
            "### 사용자 원문 조사 근거 (scenario_claim)\n"
            + (
                "\n".join(
                    f"- {claim['id']}: {claim['text']} [범주: {', '.join(claim['categories'])}]"
                    for claim in (claims or [])
                )
                or "- 없음"
            ),
            "### 출력",
        ]
        return "\n\n".join(parts)

    def propose_investigation(
        self,
        scenario: dict[str, Any],
        findings: dict[str, Any],
        *,
        pivots: dict[str, str],
        techniques: list[tuple[str, str]],
        artifacts: list[tuple[str, str]],
        behaviors: "list[tuple[str, str, bool]] | None" = None,
        claims: "list[dict[str, Any]] | None" = None,
    ) -> list[dict[str, Any]]:
        """모델에게 "무엇을 더 봐야 하는가"를 묻는다.

        돌려주는 것은 ``schemas/investigation.schema.json`` 의 ``requests``
        항목들이다. ``expand_time_range`` 에는 근거 레코드의 시각을
        ``pivot_time`` 으로 **우리가 채워서** 넣는다.
        """
        refs = sorted(set(findings.get("input_refs", [])))
        system = self.investigate_system_prompt()
        user = self.investigate_user_prompt(
            scenario,
            findings,
            pivots=pivots,
            techniques=techniques,
            artifacts=artifacts,
            behaviors=behaviors,
            claims=claims,
        )
        self.last_system, self.last_user = system, user
        raw = self.backend.complete(
            system,
            user,
            fmt=(
                investigation_schema(
                    sorted(pivots),
                    refs,
                    [tid for tid, _ in techniques],
                    [name for name, _ in artifacts],
                    [family_id for family_id, _label, _relevant in (behaviors or [])],
                    [str(claim["id"]) for claim in (claims or [])],
                )
                if self.constrain
                else None
            ),
        )
        self.last_raw = raw
        self._note_prompt(len(system) + len(user))

        items = extract_json(raw).get(INVESTIGATION_BODY_FIELD)
        if not isinstance(items, list):
            raise MalformedOutput(
                f"{INVESTIGATION_BODY_FIELD} 가 목록이 아님: {type(items).__name__}"
            )
        if len(items) > MAX_INVESTIGATION_REQUESTS:
            # 자르지 않는다. 상한을 넘겼다는 것은 제약이 안 걸렸다는 뜻이고,
            # 그런 응답의 앞 세 건만 믿을 근거가 없다.
            raise MalformedOutput(
                f"요청이 {len(items)}건으로 상한 {MAX_INVESTIGATION_REQUESTS}건을 넘음"
            )

        required = {
            "expand_time_range": ("window_hours",),
            "request_technique": ("technique_id",),
            "request_artifact": ("artifact",),
            "request_behavior": ("based_on", "category", "pivots"),
        }
        requests: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                raise MalformedOutput(f"요청이 객체가 아님: {type(item).__name__}")
            kind = item.get("type")
            if kind not in required:
                raise MalformedOutput(f"알 수 없는 요청 종류: {kind!r}")
            common = ("rationale",) if kind == "request_behavior" else ("based_on_ref", "rationale")
            missing = [key for key in (*common, *required[kind]) if key not in item or item[key] in (None, "")]
            if missing:
                raise MalformedOutput(f"{kind} 에 필수 필드 없음: {', '.join(missing)}")

            request = {key: item[key] for key in ("type", *common, *required[kind])}
            if kind == "expand_time_range":
                # **시각은 우리가 채운다.** 모델은 어느 레코드를 근거로
                # 들었는지만 고르고, 그 레코드가 언제인지는 우리가 안다.
                pivot = pivots.get(request["based_on_ref"])
                if pivot is None:
                    raise MalformedOutput(
                        f"{request['based_on_ref']} 는 시각이 없어 "
                        "expand_time_range 의 근거가 될 수 없음"
                    )
                request["pivot_time"] = pivot
            requests.append(request)
        return requests

    def reduce_system_prompt(self) -> str:
        return (PROMPT_DIR / "reduce_system.txt").read_text(encoding="utf-8")

    def critic_system_prompt(self) -> str:
        return (PROMPT_DIR / "critic_system.txt").read_text(encoding="utf-8")

    def propose_critic(self, story: dict[str, Any], picked: list[dict[str, Any]]) -> list[dict[str, Any]]:
        system = self.critic_system_prompt()
        user = "\n\n".join([
            "### 검토할 사건 내러티브\n" + json.dumps(story, ensure_ascii=False),
            "### 검증 가능한 Map 근거\n" + selection_digest(picked),
            "### 출력",
        ])
        self.last_system, self.last_user = system, user
        raw = self.backend.complete(system, user, fmt=critic_schema(story) if self.constrain else None)
        self.last_raw = raw
        self._note_prompt(len(system) + len(user))
        parsed = extract_json(raw)
        critic = parsed.get("story_critic")
        if not isinstance(critic, list):
            raise MalformedOutput("story_critic 가 목록이 아님")
        expected = {item.get("id") for item in story.get("sentences", []) if isinstance(item, dict)}
        received = [item.get("sentence_id") for item in critic if isinstance(item, dict)]
        if len(received) != len(set(received)) or set(received) != expected:
            raise MalformedOutput(f"critic sentence_id 불일치: expected={sorted(expected)}, received={received}")
        self.last_story_critic = [item for item in critic if isinstance(item, dict)]
        return self.last_story_critic

    def reduce_user_prompt(
        self,
        scenario: dict[str, Any],
        picked: list[dict[str, Any]],
        relation_catalog: list[dict[str, Any]] | None = None,
        feedback: str | None = None,
    ) -> str:
        techniques = ", ".join(
            f"{t['id']}({t['name']})" for t in scenario.get("techniques", [])
        )
        parts = [
                "### 시나리오\n"
                f"- 대상 OS: {scenario.get('target_os', '?')}\n"
                f"- 사건 서술에서 나온 기법: {techniques or '없음'}\n"
                f"- 붙일 수 있는 기법 라벨(이 중에서만 고릅니다): {self._technique_labels(scenario)}",
                f"### 앞 단계가 고른 항목 ({len(picked)}건)\n"
                + selection_digest(picked),
                "### Python이 검증한 관계 후보\n"
                + ("\n".join(json.dumps(item, ensure_ascii=False) for item in relation_catalog or []) or "(없음)"),
        ]
        if feedback:
            parts.append(
                "### 직전 출력의 문제\n" + feedback
                + "\n이 문제만 고친 JSON 객체 하나를 다시 출력하십시오."
            )
        parts.append("### 출력")
        return "\n\n".join(parts)

    def reduce_chars(
        self,
        scenario: dict[str, Any],
        picked: list[dict[str, Any]],
        relation_catalog: list[dict[str, Any]] | None = None,
    ) -> int:
        """Reduce 질의가 차지할 글자 수. **보내기 전에 잰다.**

        단서가 수십 건이면 그것만으로 창을 넘는다. 넘는데도 보내면 앞이
        잘리고, 잘린 프롬프트는 오류 없이 돌아온다.
        """
        return len(self.reduce_system_prompt()) + len(
            self.reduce_user_prompt(scenario, picked, relation_catalog)
        )

    def propose_connections(
        self,
        scenario: dict[str, Any],
        picked: list[dict[str, Any]],
        relation_catalog: list[dict[str, Any]] | None = None,
        feedback: str | None = None,
    ) -> list[dict[str, Any]]:
        """고른 항목들 중 **서로 이어지는 것**을 묶어 달라고 묻는다.

        Map 이 조각마다 따로 판정했으므로, 조각을 넘는 연결은 아무도 말한
        적이 없다. 이 질의가 그것을 말한다 — 없으면 Map-Reduce 가 이름만
        Reduce 이고 실제로는 파이썬 append 다.
        """
        system = self.reduce_system_prompt()
        user = self.reduce_user_prompt(scenario, picked, relation_catalog, feedback)
        self.last_system, self.last_user = system, user
        raw = self.backend.complete(
            system,
            user,
            fmt=connection_schema(
                scenario, picked, relation_catalog, mappings=self.mappings
            ) if self.constrain else None,
        )
        self.last_raw = raw
        self._note_prompt(len(system) + len(user))
        parsed = extract_json(raw)
        found = parsed.get(CONNECTION_BODY_FIELD)
        if not isinstance(found, list):
            raise MalformedOutput(
                f"{CONNECTION_BODY_FIELD} 가 목록이 아님: {type(found).__name__}"
            )
        relations_by_id = {
            str(item["id"]): item for item in relation_catalog or [] if item.get("id")
        }
        for connection in found:
            if not isinstance(connection, dict):
                continue
            refs = list(dict.fromkeys(connection.get("refs") or []))
            for relation_id in connection.get("assertion_ids") or []:
                relation = relations_by_id.get(str(relation_id))
                if relation is None:
                    raise MalformedOutput(f"알 수 없는 관계 assertion ID: {relation_id}")
                # Selecting a catalogued edge necessarily selects both of its
                # endpoints. Completing this set changes no analytical claim.
                refs.extend(ref for ref in relation.get("refs") or [] if ref not in refs)
            connection["refs"] = refs
        story = parsed.get("incident_story")
        candidate_story = story if isinstance(story, dict) else None
        if candidate_story is not None:
            sentences = candidate_story.get("sentences")
            if not isinstance(sentences, list):
                raise MalformedOutput("incident_story.sentences 가 목록이 아님")
            for sentence in sentences:
                if isinstance(sentence, dict) and isinstance(sentence.get("refs"), list):
                    # Constrained decoding can still repeat enum values.  Refs
                    # are a set semantically, so canonicalize before Critic and
                    # persisted-schema validation.
                    sentence["refs"] = list(dict.fromkeys(sentence["refs"]))
            ids = [item.get("id") for item in sentences if isinstance(item, dict)]
            expected_ids = [f"N{index}" for index in range(1, len(sentences) + 1)]
            if ids != expected_ids:
                raise MalformedOutput(f"incident_story 문장 ID가 순차적이지 않음: {ids}")
            allowed_refs = {item.get("ref") for item in picked}
            story_refs = {
                ref for item in sentences if isinstance(item, dict)
                for ref in (item.get("refs") or [])
            }
            if not story_refs <= allowed_refs:
                raise MalformedOutput(f"incident_story가 Map에 없는 ref를 인용함: {sorted(story_refs - allowed_refs)}")
            # **인용했는가만 본다.** 시그널 어휘가 문장에 문자 그대로
            # 있는지까지 요구하면, "Wi-Fi 자격증명을 평문으로 내보내는 명령이
            # 실행됐다" 처럼 옳게 쓴 문장이 `key=clear` 가 없다는 이유로
            # 기각된다. 그것은 의미 검사가 아니라 전사(轉寫) 강요이고, 모델에게
            # 무엇을 쓸지 받아쓰게 하는 것이다. 우리가 보장할 것은 "그 증거가
            # 서사에서 다뤄졌는가"까지이고, 잘 다뤘는지는 Critic 이 판정한다.
            cited = {
                ref for sentence in sentences if isinstance(sentence, dict)
                for ref in (sentence.get("refs") or [])
            }
            missing_review = sorted({
                str(item.get("ref"))
                for item in picked
                if item.get("ref") and item.get("attention_signals")
                and str(item.get("ref")) not in cited
            })
            # 못 채우면 기각하고 재시도한다. **파이썬이 대신 쓰지 않는다** —
            # 서사를 만드는 것이 sLLM 의 일이고, 대신 써 주면 그 문장이
            # Critic 심사와 story_review 를 거쳐 모델 판단으로 보이게 된다.
            if missing_review:
                raise MalformedOutput(
                    "incident_story가 must_review 증거를 인용하지 않음: "
                    + ", ".join(missing_review)
                )
        self.last_incident_story = candidate_story
        return [item for item in found if isinstance(item, dict)]

    def propose_selection(
        self,
        scenario: dict[str, Any],
        records: list[dict[str, Any]],
        feedback: str | None = None,
        *,
        allowed_fields: "tuple[str, ...] | None" = None,
    ) -> list[dict[str, Any]]:
        """모델을 불러 **고른 목록**을 받는다. 문장·claims 는 묻지 않는다.

        돌려주는 것은 ``{ref, technique, reason, severity, evidence_fields}``
        의 목록이다. 이것으로 findings 를 만드는 것은 ``assembly`` 의 일이고,
        그 경계가 이 구조의 요지다 — 모델은 고르고 파이썬은 옮긴다.
        """
        from ..stage04_parse.flagging import claim_fields

        allowed = claim_fields().names if allowed_fields is None else allowed_fields
        system, user = self.select_system_prompt(), self.select_user_prompt(scenario, records, feedback)
        self.last_system, self.last_user = system, user
        raw = self.backend.complete(
            system,
            user,
            fmt=selection_schema(
                scenario, records, allowed, mappings=self.mappings
            ) if self.constrain else None,
        )
        self.last_raw = raw
        self._note_prompt(
            len(self.select_system_prompt())
            + len(self.select_user_prompt(scenario, records, feedback))
        )
        parsed = extract_json(raw)
        expected_signals = {
            f"{record['ref']}:{signal}"
            for record in records
            for signal in (record.get("attention_signals") or [])
            if record.get("ref")
        }
        dispositions = parsed.get("signal_dispositions", {})
        if not isinstance(dispositions, dict):
            raise MalformedOutput("signal_dispositions 가 객체가 아님")
        received_signals = set(dispositions)
        if received_signals != expected_signals:
            missing = sorted(expected_signals - received_signals)
            extra = sorted(received_signals - expected_signals)
            raise MalformedOutput(f"signal disposition 불일치: missing={missing}, extra={extra}")
        self.last_signal_dispositions = dispositions
        picked = parsed.get(SELECTION_BODY_FIELD)
        if not isinstance(picked, list):
            raise MalformedOutput(
                f"{SELECTION_BODY_FIELD} 가 목록이 아님: {type(picked).__name__}"
            )
        selected = [item for item in picked if isinstance(item, dict)]
        records_by_ref = {record.get("ref"): record for record in records}
        for item in selected:
            source = records_by_ref.get(item.get("ref"), {})
            if source.get("packet_id"):
                item["packet_id"] = source["packet_id"]
            if source.get("attention_signals"):
                item["attention_signals"] = list(source["attention_signals"])
            if source.get("attention_context"):
                item["attention_context"] = dict(source["attention_context"])
            if source.get("attention_requirements"):
                item["attention_requirements"] = dict(source["attention_requirements"])
        selected_refs = {item.get("ref") for item in selected}
        signal_records = {
            f"{record['ref']}:{signal}": record
            for record in records
            for signal in (record.get("attention_signals") or [])
            if record.get("ref")
        }
        # A model-selected mandatory signal must become a finding even when the
        # model omitted the same ref from suspicious_records.  The reason and
        # evidence fields still come from the model; Python only preserves its
        # explicit disposition.
        for signal_id, disposition in dispositions.items():
            ref = signal_id.split(":", 1)[0]
            if disposition.get("disposition") != "selected" or ref in selected_refs:
                continue
            source_record = signal_records.get(signal_id, {})
            selected.append({
                "ref": ref,
                **({"packet_id": source_record["packet_id"]} if source_record.get("packet_id") else {}),
                "technique": None,
                "reason": disposition.get("reason") or signal_id,
                "severity": "info",
                "evidence_fields": disposition.get("evidence_fields") or [],
                "attention_signals": list(source_record.get("attention_signals") or []),
                "attention_context": dict(source_record.get("attention_context") or {}),
                "attention_requirements": dict(source_record.get("attention_requirements") or {}),
                # **assertion 을 파이썬이 지어 넣지 않는다.** 특정 시그널
                # 이름과 특정 아티팩트 필드를 여기 적으면, 모델이 만든 적 없는
                # 검산식이 모델 출력인 것처럼 findings 에 실린다.
                "assertions": [],
            })
            selected_refs.add(ref)
        return selected

    def _trim_notice(self) -> str:
        """목록이 잘렸다는 사실을 모델에게 말한다.

        말하지 않으면 모델이 "적재 파일은 20개였다"고 쓸 수 있고, 그것은
        우리가 **유발한** 환각이다. 전체 개수는 레코드의 ``*_count`` 필드에
        원본 그대로 실려 있다(프리패치의 ``loaded_file_count`` 등).

        **"앞에서"라고 말하지 않는다.** ``allocation.for_prompt``가
        눈여겨볼 자리를 먼저 골라 넣으므로 실린 것이 앞머리가 아닐 수
        있다(``mappings/_flags.yaml`` 의 ``prompt_keep_paths``). 앞에서
        잘랐다고 말해 두면 모델이 "그 뒤는 못 봤다"를 잘못된 근거로 쓴다.
        """
        notices = []
        if self.max_list_items is not None:
            notices.append(
                f"fields 안의 목록은 {self.max_list_items}개까지만 실려 있고 "
                "원래 순서를 지킨 부분집합이니, 전체 개수는 함께 있는 개수 필드를 "
                "보고 말하십시오"
            )
        # 뺀 필드가 있으면 그 사실도 말한다. 같은 이유다 — 말하지 않으면
        # 모델이 "해시 정보가 없다"를 근거로 쓴다. **어느 이름을 뺐는지까지는
        # 적지 않는다.** 부류만 말하면 "못 본 것으로는 말하지 말라"가 되고,
        # 이름을 열거하면 그 필드들을 두고 추측할 거리를 만들어 준다.
        if prompt_drop_fields():
            notices.append(
                "해시·상관용 GUID·파일 버전 정보는 프롬프트에서 제외했으니, "
                "그 값이 보이지 않는다는 사실 자체를 근거로 삼지 마십시오"
            )
        return (". " + ". ".join(notices)) if notices else ""

    def user_prompt(
        self,
        scenario: dict[str, Any],
        records: list[dict[str, Any]],
        feedback: str | None = None,
    ) -> str:
        techniques = ", ".join(
            f"{t['id']}({t['name']})" for t in scenario.get("techniques", [])
        )
        time_range = scenario.get("time_range", {})

        parts = [
            "### 시나리오\n"
            f"- 대상 OS: {scenario.get('target_os', '?')}\n"
            f"- 사건 서술에서 나온 기법: {techniques or '없음'}\n"
            f"- 붙일 수 있는 기법 라벨(이 중에서만 고릅니다): {self._technique_labels(scenario)}\n"
            f"- 분석 기간: {time_range.get('start', '?')} ~ {time_range.get('end', '?')}",
            # 레코드를 JSONL로 준다. 한 줄이 한 레코드라 모델이 경계를
            # 헷갈리지 않고, 토큰도 들여쓰기 JSON보다 적게 든다.
            "### 레코드 ("
            f"{len(records)}건, 이 목록에 없는 ref를 쓰면 기각됩니다{self._trim_notice()})\n"
            + "\n".join(
                json.dumps(for_prompt(record, self.max_list_items), ensure_ascii=False)
                for record in records
            ),
        ]

        if feedback:
            parts.append(
                "### 직전 출력의 문제\n"
                f"{feedback}\n"
                "이 점만 고쳐서 JSON 객체 하나를 다시 출력하십시오."
            )

        parts.append("### 출력")
        return "\n\n".join(parts)

    def prompt_overhead_chars(self, scenario: dict[str, Any]) -> int:
        """레코드를 빼고 프롬프트가 이미 차지하는 글자 수.

        토큰 예산이 레코드에 얼마를 쓸 수 있는지 정할 때 씁니다
        (``allocation.char_budget``). **추정하지 않고 실제로 조립해 잽니다** —
        시스템 프롬프트가 길어지거나 머리말에 줄이 늘면 그만큼 예산이
        자동으로 줄어야 하고, 상수로 적어 두면 그 순간 어긋납니다.

        재시도의 ``feedback`` 은 빠져 있습니다. 길이가 지적 하나만큼이라
        작고, 예산은 첫 시도 기준으로 잡습니다.
        """
        return len(self.system_prompt()) + len(self.user_prompt(scenario, []))

    def propose_findings(
        self,
        scenario: dict[str, Any],
        records: list[dict[str, Any]],
        feedback: str | None = None,
    ) -> dict[str, Any]:
        """모델을 호출해 해석 본문을 받는다.

        스텁 응답은 헤더와 ``input_refs``가 포함된 완성 문서일 수 있으므로
        본문 필드만 골라낸다.
        """
        system, user = self.system_prompt(), self.user_prompt(scenario, records, feedback)
        self.last_system, self.last_user = system, user
        raw = self.backend.complete(
            system,
            user,
            fmt=constrained_schema(scenario, records, mappings=self.mappings) if self.constrain else None,
        )
        self.last_raw = raw
        self._note_prompt(
            len(self.system_prompt())
            + len(self.user_prompt(scenario, records, feedback))
        )
        parsed = extract_json(raw)
        return {key: parsed.get(key, []) for key in FINDINGS_BODY_FIELDS}
