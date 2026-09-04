# schemas/ — 단계 간 데이터 계약

`src/common/`과 함께 단계들의 유일한 접점입니다. **변경은 전체 공지 대상입니다.**

스키마는 상상해서 쓴 것이 아니라 `benchmark/fixtures/C-001-webshell/`의
실제 파일에서 역산했습니다. `tests/test_schemas.py`가 목업이 여전히 통과하는지
확인합니다. 통과하는 인스턴스가 존재하지 않는 스키마를 동결하면 담당자들이
각자 다른 해석으로 구현하게 됩니다.

## 파일

| 스키마 | 검증 대상 | 생성 주체 |
|---|---|---|
| `input.schema.json` | `01_input.json` | 사람/수집 스크립트 |
| `scenario.schema.json` | `02_scenario.json` | sLLM |
| `selection.schema.json` | `03_selection.json` | `select.py` |
| `parsed_record.schema.json` | `04_parsed/*.jsonl`의 **한 줄** | `parse.py` |
| `findings.schema.json` | `05_findings.json` | sLLM |
| `verified.schema.json` | `06_verified.json` | `verify.py` |

`04_parsed/_manifest.json`은 스키마를 두지 않았습니다. 파싱 산출물의 목록일 뿐
단계 간 계약이 아니며, 값의 정합성(`record_count == wc -l`)은 스키마로
표현할 수 없어 테스트가 봅니다.

## 사용법

```python
from src.common import io, schema

doc = io.read_json("cases/C-001/02_scenario.json")
schema.validate(doc, "scenario")        # 첫 위반에서 SchemaViolation
schema.validate_stage(doc)              # 헤더의 stage를 보고 스키마를 고름
```

`SchemaViolation.as_detail()`을 `ErrorLog.record(detail=...)`에 그대로 넘기면
`errors.jsonl`의 형식이 맞습니다.

```python
try:
    schema.validate(doc, "scenario")
except schema.SchemaViolation as v:
    log.record("02_normalize", "schema_violation", v.as_detail(), action="retry", attempt=1)
```

`validate()`가 첫 위반만 던지는 것은 의도입니다. 재시도 프롬프트에 넣을 지적이
하나여야 sLLM이 그것을 고칩니다. 열 건을 한꺼번에 주면 대개 더 나빠집니다.
전수 목록이 필요하면 `iter_violations()`를 씁니다.

---

## 스펙 문서에 없어서 여기서 정한 것

`docs/pipeline-io-spec.md`를 파일로 옮기는 과정에서 드러난 미결정 사항입니다.
**이견이 있으면 지금 제기해 주세요. 동결 후에는 `schema_version`을 올려야 합니다.**

### 1. `01_input.json`의 `generator`는 선택 항목

공통 헤더 규약은 `generator`를 필수로 두지만, 스펙의 `01_input` 예시에는 없습니다.
사람이 손으로 쓰는 파일이라 생성 주체를 적을 수 없는 경우가 있어
**`input.schema.json`에서만 선택 항목**으로 두었습니다. 나머지 다섯은 필수입니다.

코드에서는 `io.check_header(doc, require_generator=False)`로 이 경로를 씁니다.

### 2. `generator` 표기는 `"<스크립트> / <모델>"`

스펙의 공통 헤더 예시는 `"normalize.py / qwen2.5-7b-instruct-q4"`인데
`02_scenario` 예시는 `"qwen2.5-7b-instruct-q4"`뿐입니다.

스키마는 둘 다 통과시키되(문자열이면 됨), **새로 만드는 문서는
`io.make_generator(script, model)`을 경유**해 앞의 형식으로 통일합니다.
스키마로 강제하지 않은 이유는 기존 목업을 깨지 않기 위해서고, 실제 통일은
헬퍼 함수 하나만 쓰면 되기 때문입니다.

### 3. 검증기 실행 순서: `ref_exists` → `ref_in_input` → `value_match` → `technique_supported`

스펙의 기각 예시에서 `MFT#99999`는 파싱 결과에도 `input_refs`에도 없는데
`ref_not_found`로 판정됩니다. 즉 **`ref_exists`가 먼저 돌아야** 합니다.
순서가 반대면 같은 상황이 `ref_not_in_input`으로 집계되어 환각 유형 분포가
왜곡됩니다.

이것은 `--checkers` 조합 실험(work-guide 8.2)에도 영향을 줍니다.
`ref_exists`를 끄면 존재하지 않는 레코드가 `ref_not_in_input`으로 넘어가므로,
실험 결과를 읽을 때 이 점을 감안해야 합니다.

### 4. 기각 사유에 `field_not_found` 추가

스펙에는 세 가지(`ref_not_found` / `value_mismatch` / `ref_not_in_input`)만
있습니다. 여기에 하나를 더 두었습니다: 레코드는 실재하는데 `claims`가
**없는 필드**를 주장하는 경우입니다.

`value_mismatch`로 뭉뚱그리면 "값을 틀리게 말한 것"과 "필드 자체를 지어낸 것"이
같은 통계에 섞입니다. 후자가 더 심각한 환각이므로 나눠서 셉니다.

### 4-2. 기각 사유에 `technique_unsupported` 추가 (2026-09-03)

앞의 넷은 전부 **값과 존재**를 봅니다. 이것만 **함의**를 봅니다 — 인용한
레코드의 아티팩트가 그 기법의 근거로 `mappings/*/T*.yaml`에 등재돼 있는가.

**05단계가 `claims`를 파이썬으로 조립하게 되면서 필요해졌습니다.** 우리가
원본에서 복사한 값을 우리가 원본과 대조하면 `value_match`는 항등식이고,
`ref`는 출력 문법의 `enum`이 이미 막습니다. 그러면 06단계가 실제로 판정하는
것이 하나도 남지 않고, 통과율 100%는 성과가 아니라 측정의 소멸입니다.

**새 판단 기준을 만드는 것이 아닙니다.** 03단계가 선별에 쓰는 바로 그 표를
거꾸로 적용해 "이미 선언된 것을 지켰는가"를 볼 뿐입니다. 판정할 수 없는
것(기법이 `null`, 매핑 결손, 인용 없음)은 통과시키고, 인용한 것 중
**하나라도** 근거 아티팩트이면 통과입니다 — 과엄격은 환각률이 실제 환각이
아니라 우리 무지를 세게 만듭니다.

### 4-1. `claims`가 비었는데 참조가 틀린 문장은 기각이 우선

스펙의 판정 규칙 표는 `claims`가 빈 배열이면 `unverifiable`, `refs`가
`input_refs` 밖이면 `rejected`라고만 합니다. 두 조건이 동시에 걸리는 경우가
명시되어 있지 않습니다.

**기각이 우선합니다.** 종합 판단 문장이라도 지어낸 근거를 달았다면 그것은
환각입니다. 구현상 ref 체커가 먼저 돌고, 통과한 뒤에야 빈 `claims`를 보고
`unverifiable`로 분류합니다.

### 5. `case_id`는 경로 안전 문자만 허용

`^[A-Za-z0-9][A-Za-z0-9_-]*$` — 점과 경로 구분자를 막습니다.
`case_id`가 `cases/<case_id>/` 경로에 그대로 들어가므로, `../` 같은 값이
들어오면 산출물이 리포지토리 밖에 쓰입니다.

### 6. `claims[].value`의 타입을 좁히지 않음

`string | number | boolean`을 모두 허용합니다. 크기를 `4821`로 쓰든 `"4821"`로
쓰든 주장하는 사실은 같습니다. 표기 차이를 스키마 위반으로 잡으면 **환각률이
형식 문제로 부풀려집니다.** 타입 정규화는 `stage06_verify/comparators.py`가 맡습니다.

같은 이유로 타임스탬프는 `tolerance.timestamp_seconds` 범위 내 오차를 허용합니다.

### 7. `parsed_record`의 속성은 전부 최상위에 선언

MFT 레코드와 EVTX 레코드는 필드가 다르지만, `if/then`으로는 `required`만 늘리고
속성 선언과 `additionalProperties: false`는 최상위에 둡니다.

`if/then` 안에 `additionalProperties: false`를 쓰면 **다른 분기에서 선언한
속성까지 거부합니다.** JSON Schema에서 가장 흔히 밟는 함정이라 명시해 둡니다.

---

## 알려진 중복

여섯 파일이 공통 헤더 정의를 각자 들고 있습니다. `$ref`로 외부 파일을 참조하면
`jsonschema`에 레지스트리를 붙여야 하고, 팀원이 `jsonschema.validate()`를 직접
호출했을 때 동작하지 않습니다. 계약을 동결할 것이므로 **자기완결성을 택했습니다.**

쓰는 쪽의 단일 진실 공급원은 `io.new_document()` 하나입니다.
