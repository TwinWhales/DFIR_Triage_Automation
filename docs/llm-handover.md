# LLM 파이프라인 인계 문서

**대상**: 02 정규화 · 05 해석의 모델 연결을 맡는 담당자
**문서 목적**: 무엇이 되어 있고, 무엇을 하면 되고, **무엇을 건드리면 안 되는지**

데이터 형식은 이 문서에 다시 적지 않습니다. `schemas/` 6개와
[`schemas/README.md`](../schemas/README.md)가 그 역할입니다. 여기 또 쓰면
진실이 두 개가 되고, 갈라지는 순간 어느 쪽이 맞는지 알 수 없게 됩니다.

---

## 1. 5분 안에 직접 돌려보기

파이프라인은 이미 01→07 전 구간이 돌아갑니다. 모델만 스텁입니다.

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe -m pytest          # 253 passed
```

```bash
.venv/Scripts/python.exe tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01 \
  --input benchmark/datasets/C-001-webshell/input.json \
  --seed-parsed benchmark/datasets/C-001-webshell/mock/04_parsed
```

```bash
PYTHON=.venv/Scripts/python.exe bash run_pipeline.sh C-001 /mnt/evidence/WEB01 benchmark/datasets/C-001-webshell/mock
```

`cases/C-001/`에 01부터 07까지 쌓이고 `07_report.md`가 나옵니다.
세 번째 인자가 **replay 디렉터리**입니다. 이걸 빼면 스텁 대신 Ollama를 부릅니다.

먼저 이걸 돌려서 정상 동작을 눈으로 확인하십시오. 이후 무엇을 바꾸든
이 결과와 비교하면 됩니다.

---

## 2. 지금 되는 것 / 안 되는 것

### 되는 것

| | 상태 |
|---|---|
| 프롬프트 조립 | 시스템 프롬프트 + few-shot + 증거 요약 + 재시도 피드백 |
| 응답 파싱 | 코드펜스 제거, 앞뒤 산문 제거, 중첩 중괄호 스캔 |
| 스키마 검증 | 위반 시 `errors.jsonl` 기록 후 재시도 (기본 3회) |
| ATT&CK ID 검사 | 형식 + 실재 여부를 **따로** 검사 |
| 재시도 피드백 | 직전 위반을 다음 프롬프트에 실어 보냄 |
| EDR 알럿 경로 | LLM 없이 결정론적 변환 (`alert_adapter.py`) — **완성** |
| 실험 조건 기록 | `generator` 필드에 스크립트 + 모델명 |

### 안 되는 것

| | 비고 |
|---|---|
| **실제 모델 호출** | `--llm ollama` 코드는 있으나 **한 번도 실행된 적 없음** |
| **2회 호출 분리** | `prompts/claims_extract.txt`는 작성돼 있으나 **배선 안 됨** |
| 프롬프트 튜닝 | 실측 없이 쓴 초안. 지금 값에 근거 없음 |
| 모델 선택 | 기본값은 가정일 뿐 |

**`--llm ollama` 경로는 미검증입니다.** 첫 실행에서 응답 파싱이나 프롬프트가
걸릴 가능성이 있습니다. 그게 이 일의 첫 번째 과제입니다.

---

## 3. 담당 범위

### 3-1. 실제 모델 붙이기 (먼저)

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M
```

```bash
.venv/Scripts/python.exe -m src.stage02_normalize.normalize \
  --in cases/C-001/01_input.json --out cases/C-001/02_scenario.json \
  --llm ollama --model qwen2.5:7b-instruct-q4_K_M
```

02단계는 04 파서와 무관하게 **지금 완전히 검증 가능합니다.** 05단계는
실제 레코드가 있어야 제대로 시험되므로 04 파서 완성 후에 봅니다.

기본 모델 태그는 `src/stage02_normalize/llm_client.py`와
`src/stage05_interpret/llm_client.py`의 `DEFAULT_MODEL`에 있습니다.
두 단계가 상수를 공유하지 않는 것은 **의도**입니다 — 해석만 큰 모델로
바꾸는 실험이 잦습니다.

### 3-2. 프롬프트 튜닝

| 파일 | 역할 |
|---|---|
| `src/stage02_normalize/prompts/normalize_system.txt` | 정규화 시스템 프롬프트 |
| `src/stage02_normalize/prompts/normalize_fewshot.json` | few-shot 예시 2개 |
| `src/stage05_interpret/prompts/interpret_system.txt` | 해석 시스템 프롬프트 |
| `src/stage05_interpret/prompts/claims_extract.txt` | 2회 호출용 (**미배선**) |

`--no-fewshot` 옵션이 있어 few-shot 유무 비교를 바로 할 수 있습니다.

**튜닝은 반드시 수치로 판단하십시오.** 눈으로 보고 "좋아진 것 같다"는
근거가 되지 않습니다. 측정 방법은 5절에 있습니다.

### 3-3. 2회 호출 분리 (여유 있으면)

7B급 모델은 자연어 문장과 구조화 출력을 한 번에 요구받으면 한쪽을 대충
처리합니다. 대개 문장은 그럴듯하게 쓰고 `claims`를 빈약하게 채웁니다.

`claims_extract.txt`는 그 대비책으로 미리 써 둔 프롬프트입니다.
`InterpretClient`에 두 번째 호출을 추가하고 `interpret.py`에 `--two-pass`
같은 옵션을 두면 됩니다. **단일 호출과 비교 측정이 가능하도록 옵션으로
두십시오.** 바꿔치기하면 효과를 알 수 없습니다.

---

## 4. 건드리면 안 되는 것

**이 절이 이 문서에서 가장 중요합니다.** 아래는 전부 자연스러운 개선처럼
보이지만, 하는 순간 이 도구의 존재 이유가 사라집니다.

### 4-1. 07단계에 LLM을 넣지 마십시오

가장 빠지기 쉬운 함정입니다. 보고서 문장이 딱딱해 보여서 모델로 다듬고
싶어집니다.

그 순간 **검증을 통과한 문장이 검증되지 않은 문장으로 바뀝니다.** 06단계가
`claims`를 대조해 통과시킨 것은 그 문장이지 재작성된 문장이 아닙니다.
앞의 모든 검증이 무의미해집니다.

07은 Jinja2 템플릿으로 렌더링합니다. "검증 통과분만 실린다"를 코드가 아니라
**구조로** 보장하기 위해서입니다.

문장을 다듬는 게 아니라 **요약을 추가**하고 싶다면
`src/stage07_report/prompts/report_system.txt`에 용도와 제약을 적어 뒀습니다.
그 경우에도 통과한 문장 자체는 손대지 않습니다.

### 4-2. `input_refs`를 모델에게 묻지 마십시오

```python
# src/stage05_interpret/llm_client.py
FINDINGS_BODY_FIELDS = ("findings", "timeline")   # input_refs 없음
```

`input_refs`는 `record_filter`가 실제로 전달한 레코드 목록으로 채웁니다.
모델이 보고하게 바꾸면, 모델이 받지도 않은 레코드를 목록에 넣어
**`ref_not_in_input` 검사를 스스로 무력화**할 수 있습니다.

이 검사가 잡는 게 실무에서 가장 흔한 환각 유형입니다.

### 4-3. 검증 실패를 조용히 넘기지 마십시오

재시도가 소진되면 `errors.jsonl`에 기록하고 **비정상 종료**합니다.
빈 결과를 만들어 다음 단계로 넘기지 않습니다.

폴백은 **아직 넣지 않습니다.** 선형 경로가 안정되기 전에 폴백을 넣으면
"폴백이 잘못 걸린 것인지 원래 로직이 틀린 것인지" 구분할 수 없습니다.
누적된 실패 유형을 보고 나중에 판단합니다.

### 4-4. `schemas/`를 고치지 마십시오

동결 대상입니다. 모델이 자꾸 어떤 필드를 틀린다고 해서 스키마를 느슨하게
하면, 그 틀림이 통계에서 사라집니다. **틀리는 것을 기록하는 게 목적입니다.**

정말 필요하면 `schema_version`을 올리고 전체 공지를 거칩니다.
결정 배경은 [`schemas/README.md`](../schemas/README.md)에 8건 적혀 있습니다.

### 4-5. `errors.jsonl`의 고정 어휘를 늘리지 마십시오

`type`은 `schema_violation` / `parse_error` / `malformed_output` /
`empty_result` / `timeout`, `action`은 `retry` / `skip` / `abort`뿐입니다.
발표 통계가 여기서 직접 산출되므로 어휘가 갈라지면 집계가 깨집니다.

`src/common/errors.py`가 쓰는 시점에 거부합니다. 정말 새 유형이 필요하면
전체 공지 후 추가하십시오.

---

## 5. 완료 조건

"다 됐다"를 눈이 아니라 수치로 판정합니다.

### 5-1. 필수

| 조건 | 확인 방법 |
|---|---|
| 실제 모델로 02가 스키마를 통과 | `--llm ollama` 실행 후 `02_scenario.json` 생성 |
| 실제 모델로 05가 스키마를 통과 | 04 파서 완성 후 |
| 관통 실행이 스텁 없이 완료 | `run_pipeline.sh C-001 <evidence>` (3번째 인자 없이) |
| 회귀 없음 | `python -m pytest` → 253 passed |

### 5-2. 측정해서 보고할 것

```bash
python -c "from src.common.errors import tally; import json; print(json.dumps(tally('cases/C-001/errors.jsonl'), ensure_ascii=False, indent=2))"
```

| 수치 | 어디서 |
|---|---|
| 정규화 실패율 | `errors.jsonl`의 `02_normalize/schema_violation` ÷ 케이스 수 |
| 자주 틀리는 필드 | `tally()`의 `by_field` 분포 |
| 환각률 | `06_verified.json`의 `stats.hallucination_rate` |
| 검증 불가율 | `stats.unverifiable / stats.total_findings` |

**프롬프트를 바꿀 때마다 이 수치를 남기십시오.** "참조 형식을 명시했더니
`rejected`가 18%→6%"가 발표의 핵심 근거가 됩니다. 바꾼 내용과 수치를
같이 적어야 의미가 있습니다.

### 5-3. 지금 알려진 기준선

목업 기준이라 모델 성능이 아니라 **배선이 맞다는 확인**입니다.

```
02 정규화   techniques 2건, 스키마 통과
05 해석     레코드 5건 중 4건 전달, findings 3건
06 검증     passed 2 / rejected 0 / unverifiable 1 (환각률 0.0%)
```

실제 모델을 붙이면 이 수치가 나빠지는 게 정상입니다. **얼마나 나빠지는지가
측정하려는 값입니다.**

---

## 6. 막힐 때

| 증상 | 볼 곳 |
|---|---|
| 어디서 왜 실패했는지 모르겠다 | `cases/<id>/errors.jsonl` — 조용히 넘어가는 실패는 없습니다 |
| 응답에서 JSON을 못 찾는다 | `src/common/llm.py`의 `extract_json` |
| 스키마 위반이 반복된다 | 위반 필드가 `errors.jsonl`의 `detail.field`에 있습니다 |
| 모델 없이 뒷단만 보고 싶다 | `--llm stub --replay <mock 파일>` |
| 데이터가 어떻게 생겼는지 | `schemas/*.schema.json` + `benchmark/datasets/C-001-webshell/mock/` |
| 왜 이렇게 짰는지 | 각 모듈 docstring, `schemas/README.md` |

**중요**: 목업은 손으로 만든 것입니다. 파이프라인이 목업을 재현한다는 것은
배선이 맞다는 뜻이지 도구가 정확하다는 증거가 아닙니다. 실제 데이터에서
처음 나오는 결과를 기준선으로 삼으십시오.

---

## 7. 설계 배경 (읽어 두면 판단이 빨라집니다)

- [`work-guide.md`](../work-guide.md) — 전체 설계 전제. 2.2 설계 원칙 5개
- [`schemas/README.md`](../schemas/README.md) — 스펙에 없어서 정한 것 8건
- [`docs/pipeline-io-spec.md`](pipeline-io-spec.md) — 단계별 입출력 계약
- [`docs/mapping-guide.md`](mapping-guide.md) — 03단계 담당자용

핵심 원칙 하나만 기억하면 됩니다.

> **LLM 출력이 나올 때마다 다음 단계에서 기계적으로 검증된다.**

그래서 LLM 쪽에서 "검증을 편하게 하려는" 변경은 대부분 잘못된 방향입니다.
모델이 틀리는 것은 문제가 아니라 **측정 대상**입니다.
