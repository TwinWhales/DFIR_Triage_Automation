# LLM 파이프라인 인계 문서

**대상**: 02 정규화 · 05 해석의 모델 연결을 맡는 담당자
**전제 지식**: 없음. 이 프로젝트를 처음 보는 상태를 가정하고 씁니다.

## 읽는 순서

| | 절 | 무엇을 알게 되나 | 분량 |
|---|---|---|---|
| **A부** | 1~5 | 이 프로젝트가 뭐고, 어떻게 돌아가고, 지금 어디까지 됐는지 | 15분 |
| **B부** | 6~11 | 당신이 무엇을 하면 되는지 | 15분 |

A부를 건너뛰면 B부의 "건드리면 안 되는 것"이 왜 그런지 납득되지 않습니다.
그 절이 이 문서에서 가장 중요합니다.

데이터 형식(필드 이름, 타입, 제약)은 이 문서에 적지 않습니다.
`schemas/` 6개와 [`schemas/README.md`](../schemas/README.md)가 그 역할입니다.
여기 또 쓰면 진실이 두 개가 되고, 갈라지는 순간 어느 쪽이 맞는지 알 수 없게 됩니다.

---
---

# A부 — 프로젝트 이해

## 1. 이 도구가 무엇인가

### 1-1. 한 줄 정의

침해사고 상황을 자연어로 입력받아, **분석할 아티팩트를 먼저 선별한 뒤**,
선별된 것만 파싱해 sLLM으로 해석하고, **그 해석이 실제 증거에 근거하는지
기계적으로 검증하는** 온프레미스 트리아지 도구.

"아티팩트"는 포렌식 분석 대상이 되는 흔적 데이터입니다. Windows에서는
`$MFT`(파일 생성·삭제 기록), `$UsnJrnl`(변경 이력), `evtx`(이벤트 로그) 등입니다.

### 1-2. 기존 도구와 뭐가 다른가

공개된 AI 기반 DFIR 도구(AIFT, DFIR-Chain 등) 대부분은 이렇습니다.

```
전부 파싱  →  결과를 LLM에 던짐  →  해석
```

이 프로젝트는 **순서를 뒤집습니다.**

```
무엇을 볼지 먼저 결정  →  그것만 파싱  →  해석  →  검증
```

| | 전수 파싱 방식 | 이 프로젝트 |
|---|---|---|
| 컨텍스트 문제 | 수십만 건을 소형 모델에 넣을 수 없음 | 처음부터 대상이 적어 회피 |
| 분석가 사고 모사 | 낮음 | 실무 분석가의 판단 순서와 일치 |
| 리스크 | 느릴 뿐 | **선별 실패 시 증거를 아예 놓침** |

마지막 행이 이 프로젝트의 연구 질문입니다. **선별 방식의 재현율은 얼마인가.**

### 1-3. 발표에서 제시할 세 가지 수치

1. **재현율** — 정답 케이스에서 실제 증거가 담긴 아티팩트를 몇 % 선별했는가
2. **환각률** — LLM 해석 문장 중 근거 검증에서 기각된 비율
3. **효율** — 전수 분석 대비 소요 시간·토큰 절감

"빠르다"가 아니라 **"이만큼 빠른데 이만큼만 놓친다"**를 말하는 것이 목표입니다.

> **당신이 맡은 일이 2번 수치를 직접 만듭니다.** 모델이 틀리는 것은 문제가
> 아니라 측정 대상입니다. 이 문장이 이 문서 전체를 관통하는 원칙입니다.

---

## 2. 파이프라인 7단계

```
[01] 입력          자연어 서술 또는 EDR/SIEM 알럿
   ↓
[02] 시나리오 정규화   ← sLLM          ★ 당신 담당
   ↓
[03] 아티팩트 선별     ← 결정론적 (매핑 테이블)
   ↓
[04] 파싱             ← 결정론적 (바이트 레벨)
   ↓
[05] 해석             ← sLLM          ★ 당신 담당
   ↓
[06] 근거 검증        ← 결정론적 (필터)
   ↓
[07] 결과 보고        ← 템플릿
```

| 단계 | 하는 일 | 산출물 |
|---|---|---|
| 01 | 사람이 상황을 적는다 | `01_input.json` |
| **02** | 자연어 → ATT&CK 기법·시간범위·엔티티로 **구조화** | `02_scenario.json` |
| 03 | 기법을 보고 **어떤 아티팩트의 어디를 읽을지** 결정 | `03_selection.json` |
| 04 | 그 범위만 파싱해 레코드로 만든다 | `04_parsed/*.jsonl` |
| **05** | 레코드를 읽고 **"무엇이 확인되는가"**를 문장으로 | `05_findings.json` |
| 06 | 그 문장이 레코드와 실제로 일치하는지 **대조** | `06_verified.json` |
| 07 | 통과한 것만 모아 보고서 | `07_report.md` |

### 2-1. 왜 LLM과 결정론적 구간을 번갈아 두는가

**LLM 출력이 나올 때마다 다음 단계에서 기계적으로 검증되기 때문입니다.**
오류가 파이프라인 끝까지 증폭되지 않습니다.

- 02(LLM)가 이상한 기법 ID를 내면 → 03이 매핑을 못 찾아 드러남
- 05(LLM)가 없는 증거를 지어내면 → 06이 기각

파싱을 LLM에 맡기지 않는 것도 같은 이유입니다. 환각이 **데이터 계층**에서
발생하면 검증 자체가 불가능해집니다. 무엇과 대조하겠습니까.

---

## 3. 단계 간 통신은 파일로만 한다

각 단계는 **독립 CLI**입니다. 함수 호출로 엮여 있지 않습니다.

```bash
.venv/Scripts/python.exe -m src.stage02_normalize.normalize --in 01_input.json --out 02_scenario.json
.venv/Scripts/python.exe -m src.stage03_select.select       --in 02_scenario.json --out 03_selection.json
...
```

이유가 셋입니다.

1. **팀원이 서로를 기다리지 않습니다.** 파일 계약만 정해두면 앞 단계가
   없어도 목업 입력으로 개발할 수 있습니다. 04 파서가 하나도 없던 초기에도
   목업만으로 05~07을 개발했습니다.
2. **중간 산출물이 남아 디버깅이 쉽습니다.** 어디서 틀어졌는지 파일을
   열어보면 됩니다.
3. **중간부터 재실행이 됩니다.** 파싱은 오래 걸리므로 실험 반복에 필수입니다.

모든 JSON 문서는 최상위에 공통 헤더를 답니다.

```json
{
  "case_id": "C-001",
  "stage": "02_normalize",
  "schema_version": "1.0",
  "generated_at": "2026-08-06T04:12:33Z",
  "generator": "normalize.py / qwen2.5:7b-instruct-q4_K_M"
}
```

`generator`에 **모델명과 양자화 수준까지** 적습니다. 나중에 모델별 비교
실험에서 결과 파일만 보고 조건을 복원하기 위해서입니다.

### 3-1. `ref` — 전 단계를 관통하는 증거 식별자

이 프로젝트에서 가장 중요한 개념입니다. 형식은 `<접두어>#<레코드번호>`.

| 아티팩트 | 접두어 | 예시 |
|---|---|---|
| `$MFT` | `MFT` | `MFT#12345` |
| `$UsnJrnl` | `USN` | `USN#8821004` |
| `Security.evtx` | `EVTX-SEC` | `EVTX-SEC#40912` |
| `System.evtx` | `EVTX-SYS` | `EVTX-SYS#1177` |

레코드 번호는 아티팩트 **내부의 고유 번호**를 그대로 씁니다. 자체 일련번호를
매기면 원본과 대조할 수 없게 됩니다.

**포렌식에서 근거 없는 문장은 가치가 없습니다.** 그래서 05단계가 만드는 모든
문장은 `refs`로 원본 레코드를 가리켜야 하고, 참조가 없거나 틀린 문장은
보고서에서 제거됩니다.

---

## 4. C-001로 실제 데이터 따라가기

말로 설명하는 것보다 값을 보는 게 빠릅니다. 저장소에 들어 있는 예제 케이스
하나를 처음부터 끝까지 따라갑니다. 파일은
`benchmark/datasets/C-001-webshell/mock/` 에 있습니다.

### ① 01_input.json — 사람이 적은 상황

```json
{
  "source_type": "natural_language",
  "raw": "웹서버 WEB01에서 이상한 aspx 파일이 발견됐습니다. 비슷한 시기에
          관리자 그룹에 모르는 계정이 추가된 것 같습니다. 7월 20일 전후로 보입니다.",
  "evidence": { "root": "/mnt/evidence/WEB01", "os_hint": "windows_server_2019" }
}
```

### ② 02_scenario.json — **당신의 첫 담당 구간**

위 자연어를 이렇게 바꿉니다.

```json
{
  "target_os": "windows",
  "techniques": [
    { "id": "T1505.003", "name": "Web Shell", "confidence": 0.85,
      "evidence_text": "이상한 aspx 파일이 발견됐습니다" },
    { "id": "T1136.001", "name": "Create Account: Local Account", "confidence": 0.70,
      "evidence_text": "관리자 그룹에 모르는 계정이 추가된 것 같습니다" }
  ],
  "time_range": { "start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z",
                  "basis": "사용자가 7월 20일 전후로 언급, ±2일 확장" },
  "entities": { "hosts": ["WEB01"], "paths": ["C:\\inetpub\\wwwroot"], ... }
}
```

몇 가지 설계 의도가 있습니다.

- `evidence_text` — 입력 원문 중 **그 기법이라고 판단한 근거 구간**. 오분류
  원인을 되짚을 때 필요합니다. 요약하지 말고 그대로 인용해야 합니다.
- `time_range.basis` — 범위를 어떻게 정했는지. 범위가 틀렸을 때 원인이 드러납니다.
- `confidence` — 낮으면 선별 단계에서 범위를 넓히는 신호로 씁니다.
- `entities.paths[0]` — 03단계가 이걸 웹루트로 씁니다. 순서가 의미를 가집니다.

### ③ 03_selection.json — 무엇을 볼지 결정 (결정론적)

02의 기법 ID로 `mappings/windows/T1505.003.yaml` 같은 매핑 테이블을 찾아
읽을 범위를 정합니다. **LLM은 관여하지 않습니다.**

```json
{
  "selected": [
    { "artifact": "$MFT", "tier": 1,
      "scope": { "path_prefix": ["C:\\inetpub\\wwwroot"],
                 "extensions": [".aspx", ".asp", ".ashx", ".asmx"],
                 "time_range": { "start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z" } },
      "reason": { "technique": "T1505.003", "rationale": "웹셸 파일 생성 흔적" } },
    { "artifact": "evtx:Security", "tier": 1,
      "scope": { "event_ids": [4720, 4728, 4732], ... },
      "reason": { "technique": "T1136.001", "rationale": "계정 생성 및 권한 그룹 추가" } }
  ],
  "deferred": [ ... ],
  "excluded": [
    { "artifact": "prefetch", "reason": "Windows Server 기본 설정에서 비활성화되어 수집 불가" },
    { "artifact": "$LogFile", "reason": "본 버전 미지원 (파싱 모듈 범위 외)" }
  ]
}
```

`excluded`가 왜 있는지가 중요합니다. **보지 않기로 한 것과 그 이유를 최종
보고서까지 전달합니다.** 이것이 선별 방식의 리스크를 "방법론적 결함"에서
"문서화된 판단"으로 바꿉니다.

### ④ 04_parsed/*.jsonl — 파싱 결과 (한 줄이 한 레코드)

```jsonl
{"ref":"MFT#12345","artifact":"$MFT","record_num":12345,"offset":"0x1E000",
 "path":"C:\\inetpub\\wwwroot\\upload\\shell.aspx","size":4821,
 "si_ctime":"2026-07-20T03:14:22.1234567Z","fn_ctime":"2026-07-21T09:02:11.7654321Z",
 "flags":["timestamp_mismatch"]}
```

- `offset` — 원본 바이트 위치. 기존 파서를 안 쓰고 직접 구현하는 이유가
  이 필드입니다. 나중에 "우리 도구가 이 오프셋을 실제로 읽었다"를 보일 수 있습니다.
- `flags` — 룰 기반으로 붙인 표시. **고정 어휘**입니다.
  `timestamp_mismatch`(=$SI와 $FN 불일치, 조작 정황), `deleted`,
  `account_created`(EVTX 4720), `privileged_group_add` 등.

`flags`가 중요한 이유: **05단계에 전달할 레코드를 추리는 필터로 쓰입니다.**
수천 건에서 수십 건으로 줄이는 기준입니다.

### ⑤ 05_findings.json — **당신의 두 번째 담당 구간**

```json
{
  "input_refs": ["MFT#12345", "MFT#12346", "EVTX-SEC#40912", "EVTX-SEC#40915"],
  "findings": [
    {
      "id": "F1",
      "statement": "웹루트 하위 upload 디렉터리에 shell.aspx가 2026-07-20 03:14:22에
                    생성되었으며, $SI와 $FN 타임스탬프가 일치하지 않아 타임스탬프 조작
                    정황이 확인됩니다.",
      "refs": ["MFT#12345"],
      "claims": [
        { "ref": "MFT#12345", "field": "path",  "value": "C:\\inetpub\\wwwroot\\upload\\shell.aspx" },
        { "ref": "MFT#12345", "field": "si_ctime", "value": "2026-07-20T03:14:22Z" },
        { "ref": "MFT#12345", "field": "flags", "value": "timestamp_mismatch" }
      ],
      "technique": "T1505.003",
      "severity": "high"
    },
    {
      "id": "F3",
      "statement": "전반적으로 웹셸을 통한 초기 침투 이후 계정 생성으로 지속성을
                    확보한 전형적인 공격 흐름으로 판단됩니다.",
      "refs": [], "claims": [], "technique": null, "severity": "info"
    }
  ],
  "timeline": [ { "ts": "...", "event": "shell.aspx 생성", "refs": ["MFT#12345"] } ]
}
```

**`claims`가 이 프로젝트의 핵심 장치입니다.**

`statement`는 자연어라 기계가 검증할 수 없습니다. 그래서 문장이 주장하는
사실을 `(ref, field, value)` 삼중항으로 **따로 분해**하게 합니다.
검증기는 `claims`만 대조하면 됩니다.

`F3`처럼 종합 판단은 특정 레코드로 뒷받침되지 않으므로 `claims`를 빈 배열로
둡니다. **억지로 ref를 붙이면 안 됩니다.** 다음 단계에서 별도 분류됩니다.

`input_refs`는 **모델에게 전달한 레코드 목록**입니다. 이게 왜 필요한지는
바로 다음에 나옵니다.

### ⑥ 06_verified.json — 기계적 대조

```json
{
  "tolerance": { "timestamp_seconds": 1 },
  "passed":       [ { "id": "F1", "checks": 3, "checks_passed": 3 },
                    { "id": "F2", "checks": 3, "checks_passed": 3 } ],
  "rejected":     [],
  "unverifiable": [ { "id": "F3", "reason": "claims 없음 (종합 판단 문장)" } ],
  "stats": { "total_findings": 3, "passed": 2, "rejected": 0,
             "unverifiable": 1, "hallucination_rate": 0.0 }
}
```

판정 규칙:

| 조건 | 판정 |
|---|---|
| `claims` 전부가 실제 레코드와 일치 | `passed` |
| `claims` 중 **하나라도** 불일치 | `rejected` — 부분 통과 없음 |
| `claims`가 빈 배열 | `unverifiable` |
| `refs`가 `input_refs` 밖 레코드를 포함 | `rejected` |

기각 사유는 네 가지로 나뉩니다.

| 사유 | 무엇을 잡는가 |
|---|---|
| `ref_not_found` | 파싱 결과에 없는 레코드를 지어냄 |
| `value_mismatch` | 레코드는 맞는데 값을 틀리게 말함 |
| **`ref_not_in_input`** | **전달받지 않은 레코드를 언급** ← 실무에서 가장 흔함 |
| `field_not_found` | 없는 필드를 주장 |

`ref_not_in_input`이 `input_refs`가 필요한 이유입니다. 모델이 파일 이름이나
번호 패턴에서 **그럴듯하게 추측해 낸** 경우를 잡습니다. 레코드는 실재하므로
`ref_not_found`로는 안 걸립니다.

### ⑦ 07_report.md — 통과한 것만

`passed` 항목만 실립니다. 그리고 두 개의 고정 섹션이 반드시 들어갑니다.

- **미검증 항목** — `unverifiable`로 분류된 종합 판단
- **분석 범위 한계** — `excluded` + 발동하지 않은 `deferred`

이 두 섹션이 이 도구의 신뢰성 근거입니다. 자동 생성에서 누락되지 않도록
템플릿에 고정해 두었습니다.

---

## 5. 지금 어디까지 됐는가

### 5-1. 단계별 상태

| 단계 | 상태 | 설명 |
|---|---|---|
| 01 입력 | ✅ | `tools/make_case.py` |
| **02 정규화** | ⚠️ **LLM만 스텁** | 알럿 경로는 완성, 재시도 루프 완성 |
| 03 선별 | ✅ 완전 구현 | 매핑 6개 + 아티팩트 카탈로그 |
| 04 파싱 | ✅ 완전 구현 | `$MFT`·`$UsnJrnl`·`evtx` |
| **05 해석** | ⚠️ **LLM만 스텁** | 레코드 추림은 완성 |
| 06 검증 | ✅ 완전 구현 | 체커 3종 |
| 07 보고 | ✅ 완전 구현 | 템플릿, LLM 미사용 |

파이프라인은 **01→07 전 구간이 관통합니다.** 테스트 465건 통과.
알려진 한계는 `docs/limitations.md`에 모아 두었습니다.
남은 대체물은 **02·05의 LLM 하나뿐입니다.**

### 5-2. "스텁"이 무슨 뜻인가

`--llm stub` 모드는 미리 기록해 둔 응답 파일을 그대로 돌려줍니다.
**네트워크 호출만 대체되고 나머지는 실제 경로를 그대로 지나갑니다** —
프롬프트 조립, 응답 파싱, 스키마 검증, 재시도까지.

왜 이렇게 만들었느냐면, LLM을 먼저 붙이면 **파이프라인 버그인지 모델
한계인지 구분되지 않기** 때문입니다. 선형 경로를 먼저 안정시키고 모델을
나중에 끼우는 순서입니다.

그 조건은 이제 충족됐습니다. **당신이 실제 모델을 붙일 차례입니다.**

### 5-3. 반드시 알아야 할 한 가지

**지금 저장소의 04_parsed와 예제 데이터는 사람이 손으로 만든 것입니다.**
실제 디스크 이미지를 파싱한 결과가 아닙니다.

그래서 지금 나오는 "환각률 0%"는 **의미가 없습니다.** 목업을 만들고 그
목업을 통과하도록 코드를 짰으니 통과하는 게 당연합니다. 배선이 맞다는
확인일 뿐입니다.

**실제 모델을 붙이면 이 수치가 나빠지는 게 정상이고, 얼마나 나빠지는지가
우리가 측정하려는 값입니다.**

---
---

# B부 — 당신이 할 일

## 6. 먼저 직접 돌려보기

설명을 더 읽기 전에 한 번 돌려보십시오. 이후 무엇을 바꾸든 이 결과와
비교하면 됩니다.

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe -m pytest
```

`529 passed`가 나와야 합니다. (Linux/macOS면 `.venv/bin/python`)

```bash
.venv/Scripts/python.exe tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01 \
  --input benchmark/datasets/C-001-webshell/input.json \
  --seed-parsed benchmark/datasets/C-001-webshell/mock/04_parsed
```

`--seed-parsed`는 파싱 결과를 미리 넣어 두는 것입니다. 이제 카탈로그의
아티팩트는 전부 파서가 있으므로, 실제 증거가 있으면 필요 없습니다.
증거 없이 배선만 확인할 때 씁니다.

```bash
PYTHON=.venv/Scripts/python.exe bash run_pipeline.sh C-001 /mnt/evidence/WEB01 \
  benchmark/datasets/C-001-webshell/mock
```

```
== 02 정규화 ==  techniques 2 (T1505.003, T1136.001)
== 03 선별 ==    selected 2 / deferred 2 / excluded 2
== 04 파싱 ==    이미 산출물이 있어 건너뜀
== 05 해석 ==    레코드 5건 중 4건 전달, findings 3건
== 06 검증 ==    passed 2 / rejected 0 / unverifiable 1 (환각률 0.0%)
== 07 보고 ==    확인된 사항 2건 / 미검증 1건 / 범위 한계 4건
```

`cases/C-001/`에 01부터 07까지 쌓입니다. **전부 열어 보십시오.** 4절에서
읽은 값들이 실제로 그대로 들어 있습니다.

마지막 인자가 replay 디렉터리입니다. **이걸 빼면 스텁 대신 Ollama를 부릅니다.**

### 6-1. 검증기가 실제로 일하는지 보기

일부러 틀린 findings를 넣어 둔 파일이 있습니다.

```bash
.venv/Scripts/python.exe -m src.stage06_verify.verify \
  --findings benchmark/datasets/C-001-webshell/mock/05_findings.bad.json \
  --parsed cases/C-001/04_parsed/ --out /tmp/06_bad.json
```

→ `passed 0 / rejected 3 (환각률 100.0%)`.
`/tmp/06_bad.json`을 열면 세 가지 기각 사유가 각각 다르게 찍혀 있습니다.

체커를 끄면 판정이 어떻게 달라지는지도 볼 수 있습니다.

```bash
... --checkers value_match
```

→ 환각률 **100% → 66.7%**. `ref_in_input` 검사를 끄자 "전달받지 않은
레코드를 참조한" 문장이 통과합니다.

---

## 7. 되는 것 / 안 되는 것

### 되는 것

| | 상태 |
|---|---|
| 프롬프트 조립 | 시스템 프롬프트 + few-shot + 증거 요약 + 재시도 피드백 |
| 응답 파싱 | 코드펜스 제거, 앞뒤 산문 제거, 중첩 중괄호 스캔 |
| 스키마 검증 | 위반 시 `errors.jsonl` 기록 후 재시도 (기본 3회) |
| ATT&CK ID 검사 | 형식 검사와 실재 여부 검사를 **따로** |
| 재시도 피드백 | 직전 위반을 다음 프롬프트에 실어 보냄 |
| EDR 알럿 경로 | LLM 없이 결정론적 변환 — **완성** |
| 실험 조건 기록 | `generator` 필드에 스크립트 + 모델 태그 |

### 안 되는 것

| | 비고 |
|---|---|
| **실제 모델 호출** | `--llm ollama` 코드는 있으나 **한 번도 실행된 적 없음** |
| **2회 호출 분리** | `prompts/claims_extract.txt`는 작성됐으나 **배선 안 됨** |
| 프롬프트 튜닝 | 실측 없이 쓴 초안. 지금 값에 근거 없음 |
| 모델 선택 | 기본값은 가정일 뿐 |

**`--llm ollama` 경로는 미검증입니다.** 첫 실행에서 응답 파싱이나 프롬프트가
걸릴 수 있습니다. 그게 이 일의 첫 번째 과제입니다.

---

## 8. 담당 범위

### 8-1. 실제 모델 붙이기 (먼저)

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M
```

```bash
.venv/Scripts/python.exe -m src.stage02_normalize.normalize \
  --in cases/C-001/01_input.json --out cases/C-001/02_scenario.json \
  --llm ollama --model qwen2.5:7b-instruct-q4_K_M
```

**02단계는 04 파서와 무관하게 지금 완전히 검증 가능합니다.**
05단계는 실제 레코드가 있어야 제대로 시험되므로 04 완성 후에 봅니다.

기본 모델 태그는 아래 두 곳의 `DEFAULT_MODEL`에 있습니다.

```
src/stage02_normalize/llm_client.py
src/stage05_interpret/llm_client.py
```

**두 단계가 상수를 공유하지 않는 것은 의도입니다.** 정규화는 짧은 구조화
출력이라 작은 모델로도 되지만 해석은 더 큰 모델이 필요할 수 있습니다.
해석만 키우는 실험이 잦습니다.

Ollama 호출은 `src/common/llm.py`의 `OllamaBackend`에 있습니다.
`POST /api/generate`, `temperature=0.0`(재현성), 타임아웃 120초.

### 8-2. 프롬프트 튜닝

| 파일 | 역할 |
|---|---|
| `src/stage02_normalize/prompts/normalize_system.txt` | 정규화 시스템 프롬프트 |
| `src/stage02_normalize/prompts/normalize_fewshot.json` | few-shot 예시 2개 |
| `src/stage05_interpret/prompts/interpret_system.txt` | 해석 시스템 프롬프트 |
| `src/stage05_interpret/prompts/claims_extract.txt` | 2회 호출용 (**미배선**) |

`--no-fewshot` 옵션이 있어 few-shot 유무 비교를 바로 할 수 있습니다.

정규화 프롬프트에는 **사용 가능한 ATT&CK ID 목록이 자동으로 실립니다**
(`src/common/attack.py`의 `KNOWN_TECHNIQUES`, 현재 17개). 이 목록이 없으면
모델이 그럴듯한 ID를 지어내고, 그게 가장 흔한 스키마 위반이 됩니다.

**튜닝은 반드시 수치로 판단하십시오.** 눈으로 보고 "좋아진 것 같다"는
근거가 되지 않습니다. 측정 방법은 10절에 있습니다.

### 8-3. 2회 호출 분리 (여유 있으면)

7B급 모델은 자연어 문장과 구조화 출력을 한 번에 요구받으면 한쪽을 대충
처리합니다. 대개 문장은 그럴듯하게 쓰고 `claims`를 빈약하게 채웁니다.

`claims_extract.txt`는 그 대비책으로 미리 써 둔 프롬프트입니다.
`InterpretClient`에 두 번째 호출을 추가하고 `interpret.py`에 `--two-pass`
옵션을 두면 됩니다.

**바꿔치기하지 말고 옵션으로 두십시오.** 단일 호출과 비교할 수 없으면
효과를 측정할 수 없습니다.

---

## 9. 건드리면 안 되는 것

**이 절이 이 문서에서 가장 중요합니다.** 아래는 전부 자연스러운 개선처럼
보이지만, 하는 순간 이 도구의 존재 이유가 사라집니다.

### 9-1. 07단계에 LLM을 넣지 마십시오

가장 빠지기 쉬운 함정입니다. 보고서 문장이 딱딱해 보여서 모델로 다듬고
싶어집니다.

그 순간 **검증을 통과한 문장이 검증되지 않은 문장으로 바뀝니다.**
06단계가 `claims`를 대조해 통과시킨 것은 **그 문장**이지 재작성된 문장이
아닙니다. 앞의 모든 검증이 무의미해집니다.

07은 Jinja2 템플릿으로 렌더링합니다. "검증 통과분만 실린다"를 코드가 아니라
**구조로** 보장하기 위해서입니다.

문장을 다듬는 게 아니라 **요약을 추가**하고 싶다면
`src/stage07_report/prompts/report_system.txt`에 용도와 제약을 적어 뒀습니다.
그 경우에도 통과한 문장 자체는 손대지 않습니다.

### 9-2. `input_refs`를 모델에게 묻지 마십시오

```python
# src/stage05_interpret/llm_client.py
FINDINGS_BODY_FIELDS = ("findings", "timeline")   # input_refs 없음
```

`input_refs`는 `record_filter`가 **실제로 전달한** 레코드 목록으로 채웁니다.
모델이 보고하게 바꾸면, 모델이 받지도 않은 레코드를 목록에 넣어
**`ref_not_in_input` 검사를 스스로 무력화**할 수 있습니다.

4절 ⑥에서 본, 실무에서 가장 흔한 환각 유형을 잡는 검사입니다.

### 9-3. 검증 실패를 조용히 넘기지 마십시오

재시도가 소진되면 `errors.jsonl`에 기록하고 **비정상 종료**합니다.
빈 결과를 만들어 다음 단계로 넘기지 않습니다.

폴백은 **아직 넣지 않습니다.** 선형 경로가 안정되기 전에 폴백을 넣으면
"폴백이 잘못 걸린 것인지 원래 로직이 틀린 것인지" 구분할 수 없습니다.
누적된 실패 유형을 보고 나중에 판단합니다.

### 9-4. `schemas/`를 고치지 마십시오

동결 대상입니다. 모델이 자꾸 어떤 필드를 틀린다고 해서 스키마를 느슨하게
하면, **그 틀림이 통계에서 사라집니다.** 틀리는 것을 기록하는 게 목적입니다.

정말 필요하면 `schema_version`을 올리고 전체 공지를 거칩니다.
결정 배경은 [`schemas/README.md`](../schemas/README.md)에 8건 적혀 있습니다.

### 9-5. `errors.jsonl`의 고정 어휘를 늘리지 마십시오

`type`은 `schema_violation` / `parse_error` / `malformed_output` /
`empty_result` / `timeout`, `action`은 `retry` / `skip` / `abort`뿐입니다.
발표 통계가 여기서 직접 산출되므로 어휘가 갈라지면 집계가 깨집니다.

`src/common/errors.py`가 쓰는 시점에 거부합니다.

---

## 10. 완료 조건

"다 됐다"를 눈이 아니라 수치로 판정합니다.

### 10-1. 필수

| 조건 | 확인 방법 |
|---|---|
| 실제 모델로 02가 스키마를 통과 | `--llm ollama` 실행 후 `02_scenario.json` 생성 |
| 실제 모델로 05가 스키마를 통과 | 04 파서 완성 후 |
| 관통 실행이 스텁 없이 완료 | `run_pipeline.sh C-001 <evidence>` (3번째 인자 없이) |
| 회귀 없음 | `.venv/Scripts/python.exe -m pytest` → 529 passed |

### 10-2. 측정해서 보고할 것

```bash
.venv/Scripts/python.exe -c "from src.common.errors import tally; import json; \
  print(json.dumps(tally('cases/C-001/errors.jsonl'), ensure_ascii=False, indent=2))"
```

```json
{
  "by_type":  { "schema_violation": 2, "malformed_output": 1 },
  "by_action": { "retry": 3 },
  "by_field": { "techniques[0].id": 1, "confidence": 1 }
}
```

| 수치 | 어디서 |
|---|---|
| 정규화 실패율 | `02_normalize/schema_violation` ÷ 케이스 수 |
| **자주 틀리는 필드** | `by_field` 분포 ← 프롬프트 개선의 근거 |
| 환각률 | `06_verified.json`의 `stats.hallucination_rate` |
| 검증 불가율 | `stats.unverifiable / stats.total_findings` |

**프롬프트를 바꿀 때마다 바꾼 내용과 수치를 같이 남기십시오.**
"참조 형식을 명시했더니 `rejected`가 18%→6%"가 발표의 핵심 근거가 됩니다.

### 10-3. 지금 기준선

목업 기준이라 모델 성능이 아니라 **배선이 맞다는 확인**입니다.

```
02 정규화   techniques 2건, 스키마 통과
05 해석     레코드 5건 중 4건 전달, findings 3건
06 검증     passed 2 / rejected 0 / unverifiable 1 (환각률 0.0%)
```

실제 모델을 붙이면 나빠지는 게 정상입니다.

---

## 11. 막힐 때

| 증상 | 볼 곳 |
|---|---|
| 어디서 왜 실패했는지 모르겠다 | `cases/<id>/errors.jsonl` — 조용히 넘어가는 실패는 없습니다 |
| 응답에서 JSON을 못 찾는다 | `src/common/llm.py`의 `extract_json` |
| 스키마 위반이 반복된다 | 위반 필드가 `errors.jsonl`의 `detail.field`에 |
| 모델 없이 뒷단만 보고 싶다 | `--llm stub --replay <mock 파일>` |
| 데이터가 어떻게 생겼는지 | `schemas/*.schema.json` + `benchmark/datasets/C-001-webshell/mock/` |
| 왜 이렇게 짰는지 | 각 모듈 최상단 docstring |

모든 단계 CLI에 `--help`가 있습니다.

### 코드 지도

```
src/
├── common/              ← 단계 간 유일한 공용 코드. 여기와 schemas/만 공유
│   ├── io.py            공통 헤더, JSON·JSONL 읽기·쓰기, 타임스탬프 파싱
│   ├── schema.py        스키마 검증 래퍼 (위반 위치를 techniques[0].id 형태로)
│   ├── errors.py        errors.jsonl 기록, 고정 어휘 강제, 집계
│   ├── refs.py          ref 생성·파싱
│   ├── attack.py        ATT&CK ID 검사, KNOWN_TECHNIQUES 카탈로그
│   └── llm.py           ★ 전송 계층 (StubBackend / OllamaBackend, extract_json)
│
├── stage02_normalize/   ★ 당신 담당
│   ├── normalize.py     CLI + 재시도 루프
│   ├── llm_client.py    이 단계의 프롬프트·파라미터
│   ├── alert_adapter.py EDR 알럿 → 시나리오 (LLM 없음, 완성)
│   └── prompts/
│
├── stage05_interpret/   ★ 당신 담당
│   ├── interpret.py     CLI + 재시도 루프
│   ├── llm_client.py    이 단계의 프롬프트·파라미터
│   ├── record_filter.py 전달할 레코드 추림 (완성)
│   └── prompts/
│
├── stage03_select/      선별 (다른 담당)
├── stage04_parse/       파싱 (다른 담당, 완성)
├── stage06_verify/      검증 (완성)
└── stage07_report/      보고 (완성)
```

---

## 12. 더 읽을 것

| 문서 | 언제 |
|---|---|
| [`work-guide.md`](../work-guide.md) | 설계 전제 전체. 2.2 설계 원칙 5개는 읽어 두면 판단이 빨라집니다 |
| [`schemas/README.md`](../schemas/README.md) | 스펙에 없어서 정한 것 8건 |
| [`docs/pipeline-io-spec.md`](pipeline-io-spec.md) | 단계별 입출력 상세 명세 |
| [`benchmark/datasets/C-001-webshell/README.md`](../benchmark/datasets/C-001-webshell/README.md) | 예제 데이터 사용법 |

---

핵심 원칙 하나만 기억하면 됩니다.

> **LLM 출력이 나올 때마다 다음 단계에서 기계적으로 검증된다.**

그래서 LLM 쪽에서 "검증을 편하게 하려는" 변경은 대부분 잘못된 방향입니다.
**모델이 틀리는 것은 문제가 아니라 측정 대상입니다.**
