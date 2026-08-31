# 📊 benchmark — 성능·정확도·신뢰성 측정 체계

이 디렉터리는 **DFIR Triage 파이프라인(01~07단계)의 분석 품질과 성능을 객관적으로 측정하고 검증**하기 위한 독립 평가 계층입니다. 평가는 파이프라인의 일부가 아니라 **파이프라인을 대상으로 하는 별개 작업**이므로, `src/`의 내부 구조를 몰라도 CLI만 호출해 측정할 수 있도록 구성되어 있습니다. (도구 자체는 `src/common`의 입출력·스키마 유틸리티를 재사용합니다 — 읽고 쓰는 형식이 갈라지면 측정값이 파이프라인과 어긋나기 때문입니다.)

---

## 📁 디렉터리 및 파일 구조

```text
benchmark/
├── README.md                  # [본 문서] 벤치마크 구조 및 사용법 가이드
├── collect.py                 # [집계 도구] results/ 에 누적된 실행 기록을 한눈에 표로 종합 출력
├── evaluate.py                # [평가 도구] ATT&CK 기법 및 아티팩트 선별 재현율(Recall) 정밀 채점
├── validator_check.py         # [검증 도구] 06단계 검증기가 과엄격(오탐)하지 않은지 회귀 테스트
├── ground_truth_schema.json   # 정답 데이터셋(ground_truth.json) 규격 스키마
│
├── datasets/<케이스ID>/        # [측정 대상] 공식 입력(input.json)과 정답 기준(ground_truth.json)
│   └── C-001-webshell/
├── fixtures/<케이스ID>/        # [고정 입력] 사람이 손으로 작성한 입력/스텁 데이터 (절대 수정 금지)
│   └── C-001-webshell/        # (01_input, 02_scenario, 04_parsed/, 05_findings)
├── golden/<케이스ID>/          # [모범 답안] 코드가 정상 동작했을 때의 기대 출력 (회귀 테스트 기준)
│   └── C-001-webshell/        # (03_selection, 06_verified, 07_report.md)
├── validator/                 # [검증기 테스트 케이스] cases.json 및 레코드 샘플 데이터
└── results/                   # [실험 로그] live_check.py 실행 시 생성되는 JSON 로그 (git 제외)
```

---

## 🔍 핵심 구성요소 역할 및 책임

| 디렉터리 / 파일 | 주요 역할 | 생성/수정 주체 | 수정 가능 여부 |
|---|---|:---:|:---:|
| **`datasets/<케이스>/`** | 평가의 기준이 되는 **입력 데이터와 전문가 정답(Ground Truth)** | 사람 (분석가) | 신규 케이스 추가 시 작성 |
| **`fixtures/<케이스>/`** | 코드가 만들 수 없는 **사람이 작성한 입력 및 LLM 스텁 응답** | 사람 | **수정 절대 금지** (기준 데이터) |
| **`golden/<케이스>/`** | 코드가 정상일 때 출력되어야 하는 **단계별 모범 답안** | 코드/시스템 | 로직 개선 시 의도적 갱신 (지금은 **손으로** 복사 — 자동 갱신 스크립트는 아래 과제 3번) |
| **`validator/`** | 06단계 검증기가 정상 문장을 기각하지 않는지 테스트하는 케이스 모음 | 사람 | 새로운 검증 규칙 추가 시 확장 |
| **`results/`** | `live_check.py` 실행 시 생성되는 판정·시간·측정치 JSON 로그 | 시스템 실행 | 자동 생성 (`.gitignore`) |
| **`collect.py`** | `results/` 폴더의 모든 실험 결과를 모아 **종합 성적표를 출력** | 시스템 도구 | 상시 실행 가능 |
| **`evaluate.py`** | 식별된 기법/아티팩트가 정답과 얼마나 일치하는지 **재현율 계산** | 시스템 도구 | 상시 실행 가능 |
| **`validator_check.py`** | 06단계 검증기의 **무결성(오탐 0건 여부)**을 검사 | 시스템 도구 | 상시 실행 가능 |

---

## ⚖️ `fixtures/` 와 `golden/`을 엄격히 분리하는 이유

과거에는 두 데이터가 `mock/` 한 폴더에 뒤섞여 있어, 어느 것이 입력이고 어느 것이 기대 출력인지 구분하기 어려웠습니다. 특히 **03_selection.json**은 `03_select` 단계의 '기대 출력'이면서 동시에 `04_parse` 단계 테스트의 **'입력'**으로 사용되는 위험한 이중성을 띠고 있었습니다.

이를 방지하기 위해 **경로 자체가 역할과 권한을 명시**하도록 분리했습니다:

1. **`fixtures/` (재생성 금지)**:
   * 사람이 직접 작성한 불변의 입력 데이터입니다.
   * `--replay` 스텁 응답처럼 모델이 내야 할 정답 대역이 포함되어 있으므로 **자동 스크립트로 재생성하면 안 됩니다.**
2. **`golden/` (의도적 재생성 대상)**:
   * 파이프라인 코드가 정상일 때 만들어내는 기준 산출물입니다.
   * 로직이나 매핑을 의도적으로 개선했을 때 갱신하며, **이전 골든과의 diff가 곧 회귀(Regression) 여부를 증명**합니다. (갱신은 아직 수동입니다 — 과제 3번)
   * 분류 기준은 `tests/casepaths.py`의 `GOLDEN_FILES`에 단일 출처로 정의되어 있습니다.

---

## 📈 3대 핵심 측정 지표

발표 및 성능 평가에서 활용하는 3대 핵심 지표와 산출 출처입니다.

| 지표 | 정의 | 산출 출처 | 측정 명령어 |
|---|---|---|---|
| **1. 재현율 (Recall)** | 정답 증거/기법을 파이프라인이 몇 %나 빠짐없이 선별했는가 | `evaluate.py` | `.venv/Scripts/python.exe benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell` |
| **2. 환각률 (Hallucination)** | AI가 생성한 소견 문장 중 근거 불일치로 기각된 비율 | `06_verified.json`의 `stats.hallucination_rate` | `.venv/Scripts/python.exe tools/live_check.py ...` (자동 산출) |
| **3. 처리 시간 (Efficiency)** | 01~07 전 단계 및 LLM 추론에 소요된 초 단위 시간 | `live_check.json` | `.venv/Scripts/python.exe tools/live_check.py ...` (자동 산출) |

---

## 🚀 사용 방법 (CLI 명령어 가이드)

### 1. 원클릭 실험 결과 종합 집계 (`collect.py`)
`benchmark/results/` 폴더에 쌓인 모든 실물 관통 실행 기록을 하나의 요약 표로 출력합니다.

```bash
# 기본 텍스트 표 출력
.venv/Scripts/python.exe benchmark/collect.py

# JSON 원본 데이터 출력
.venv/Scripts/python.exe benchmark/collect.py --json
```

* **출력 예시**:
```text
케이스              시작                   모델                      판정  findings      환각률     미검증      LLM       전체
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
LC-FIXED         2026-08-31T12:33:16  qwen2.5:latest       11/11         2     0.0%       1    29.9초    40.5초
MY-TEST-02       2026-08-31T13:42:26  qwen2.5:latest       11/11         8     0.0%       0    91.7초   104.6초
MY-TEST-03       2026-08-31T14:05:07  qwen2.5:latest       11/11         2     0.0%       0   103.8초   116.9초
```

---

### 2. 정답 대비 재현율 정밀 평가 (`evaluate.py`)
특정 데이터셋을 대상으로 파이프라인의 기법 식별 및 아티팩트 선별 정확도를 채점합니다.

```bash
# C-001-webshell 데이터셋 평가
.venv/Scripts/python.exe benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell
```

---

### 3. 검증기 무결성/오탐 검사 (`validator_check.py`)
06단계 검증기가 너무 엄격해져서 정상적인 AI 소견 문장을 억울하게 기각하지 않는지 회귀 테스트를 수행합니다.

```bash
.venv/Scripts/python.exe benchmark/validator_check.py
```
* **기준**: `validator/cases.json`의 모든 테스트 케이스가 기대한 판정(PASS/FAIL)과 100% 일치해야 합니다.

---

### 4. 60GB 실물 디스크 + 실제 AI 종합 관통 검증 (`tools/live_check.py`)
스텁 없이 실제 60GB 디스크 이미지와 로컬 Ollama 모델을 연동하여 01→07 전 구간을 실전 검증합니다.

```bash
# 자연어 서술 입력 방식
.venv/Scripts/python.exe tools/live_check.py \
  --case-id MY-TEST-01 \
  --evidence evidence/win10_sysmon_testimage.001 \
  --volume 1 \
  --model qwen2.5:latest \
  --raw "키오스크 단말기에 비인가 USB를 삽입한 후 수상한 서비스가 설치되고 실행된 정황이 발견되었습니다." \
  --force
```
* 실행 결과는 `cases/<케이스ID>/live_check.json` 및 `benchmark/results/`에 자동 저장됩니다.

---

## ➕ 새로운 평가 시나리오(케이스) 추가 절차

새로운 침해사고 시나리오(예: `K-001-kiosk`)를 추가할 때는 다음 4개 위치에 파일을 구성합니다:

1. **`benchmark/datasets/<새케이스ID>/input.json`**:
   * 사건 진입점이 되는 자연어 서술 또는 SIEM 알럿 JSON.
2. **`benchmark/datasets/<새케이스ID>/ground_truth.json`**:
   * 전문가가 증거를 분석하여 확정한 정답 ATT&CK 기법, 타임라인, 필수 아티팩트 목록 (`ground_truth_schema.json` 준수).
3. **`benchmark/fixtures/<새케이스ID>/` (선택)**:
   * AI 모델 없이 고속 단위 테스트를 돌리기 위한 스텁 응답 파일들.
4. **`benchmark/golden/<새케이스ID>/` (선택)**:
   * 코드가 정상 동작했을 때의 기대 출력 파일들 (`03_selection.json` 등).

> 💡 **참고**: `tests/casepaths.py`는 현재 `CASE = "C-001-webshell"` **단일 상수**입니다.
> 두 번째 케이스를 픽스처·골든까지 만들려면 이 파일을 먼저 다중 케이스로 고쳐야 합니다 (과제 4번).
> `datasets/`에 정답만 추가하는 것은 지금도 됩니다 — `evaluate.py`는 `--dataset` 경로를 직접 받습니다.

---

## ⚠️ 현재 한계 및 남은 과제 (Technical Backlog & Roadmap)

벤치마크 체계가 실질적인 평가 가치를 가지기 위해 해결해야 할 **6가지 남은 과제**와 권장 작업 순서입니다.

### 1. 🛑 정답 데이터의 사람 직접 분석 및 확정 (가장 중요한 병목)
* **현상**: 현재 유일한 데이터셋인 `C-001-webshell`의 `ground_truth.json`은 `authored_by: "spec-example"`로 지정되어 있어, `evaluate.py` 실행 시 **"자기채점이라 발표에 쓸 수 없습니다 (cases_missing_human_ground_truth)"**라는 경고를 출력합니다.
* **해결 과제**: 분석가가 증거를 직접 분석해 반드시 나와야 할 실제 레코드 번호(`required_refs`)를 수동으로 확정한 진짜 정답셋을 구축해야 합니다.
* **⚠️ 먼저 알아야 할 것 — C-001 과 손에 있는 이미지는 짝이 아닙니다.**
  * `C-001-webshell`의 정답은 `MFT#12345`(`C:\inetpub\wwwroot\upload\shell.aspx`)와 `EVTX-SEC#40912/40915`(4720·4732)를 요구합니다. 그런데 `win10_sysmon_testimage.001`은 IIS가 없는 Win10 Pro 클라이언트이고, 파싱 결과에서 **`inetpub`·`aspx` 흔적이 0건**으로 확인됐습니다.
  * 즉 이 이미지로 C-001 정답을 채우려 들면 **있지도 않은 증거를 찾게 됩니다.** 둘 중 하나를 골라야 합니다.
    1. 이 이미지에 **실제로 있는 것**(USB 삽입·드라이버/서비스 설치 등)으로 새 케이스를 만들고 그 정답을 사람이 확정한다 → 사실상 과제 2번(K-001)과 같은 일이 됩니다.
    2. C-001을 채점용이 아닌 **스펙 예시**로 남겨 두고, 웹셸 흔적이 있는 이미지를 따로 확보한다.
  * 어느 쪽이든 `authored_by`를 `human`으로 바꾸는 것은 **증거를 실제로 본 뒤**입니다. 그 값이 `evaluate.py`의 자기채점 경고를 끄는 스위치이므로, 확인 없이 바꾸면 경고만 사라지고 문제는 남습니다.

### 2. 🎯 K-001 키오스크 공식 데이터셋 구축
* **현상**: 매핑(`mappings/windows/`), `docs/limitations.md`, `benchmark/validator/cases.json`에는 키오스크 시나리오(`K-001`)가 이미 반영되어 있으나, `benchmark/datasets/`에는 아직 데이터셋으로 패키징되지 않았습니다.
* **해결 과제**: 프로젝트의 최종 타깃인 키오스크 침해사고 시나리오(`K-001-kiosk`)를 `datasets/`에 정식 등록해야 합니다.

### 3. 🛠️ `--update-golden` 자동 갱신 CLI 스크립트 구현
* **현상**: 문서에는 `--update-golden`으로 기대 출력을 갱신한다고 기술되어 있으나, 현재는 해당 CLI 플래그가 구현되어 있지 않아 사람이 수동으로 파일을 복사하고 있습니다.
* **해결 과제**: `tests/casepaths.py`의 `GOLDEN_FILES`에 정의된 파일들만 안전하게 일괄 재생성하는 전용 스크립트가 필요합니다.

### 4. 🧩 `tests/casepaths.py` 다중 케이스 구조로 리팩토링
* **현상**: 현재 `tests/casepaths.py`에 `CASE = "C-001-webshell"` 단일 상수로 하드코딩되어 있어, 두 번째 데이터셋(`K-001`)이 추가되면 테스트 경로가 충돌합니다.
* **해결 과제**: 다중 케이스 목록을 지원하도록 `casepaths.py`를 리팩토링해야 합니다.

### 5. 📐 `ground_truth_schema.json` 정식 규격 확정
* **현상**: 현재 스키마는 초안 상태이며, 특히 `required_refs`(필수 증거)와 `acceptable_artifacts`(허용 아티팩트)의 경계 정의가 재현율 분모를 결정하므로 팀 차원의 규격 확정이 필요합니다.

### 6. 📊 3대 수치(재현율 + 환각률 + 시간) 단일 통합 출력 도구
* **현상**: 현재는 `collect.py`(환각률·시간)와 `evaluate.py`(재현율)가 분리되어 있어 발표 표를 만들 때 두 명령을 각각 돌려야 합니다. 1번(사람 정답셋)이 확정된 후 단일 리포트로 통합하는 것이 바람직합니다.

---

### 🗺️ 권장 작업 우선순위 (Roadmap)

$$\mathbf{5} \xrightarrow{\text{스키마 확정}} \mathbf{1} \xrightarrow{\text{사람 정답 분석}} \mathbf{4} \xrightarrow{\text{다중 케이스 지원}} \mathbf{2} \xrightarrow{\text{K-001 등록}}$$

1. **`5번 (스키마 확정)`** ➡️ 정답의 기준 규격을 먼저 못박습니다.
2. **`1번 (사람 정답셋 구축)`** ➡️ 60GB 이미지의 실제 증거를 분석해 진짜 정답을 만듭니다.
3. **`4번 (casepaths 다중화)`** ➡️ 여러 데이터셋을 받을 수 있게 테스트 코드를 확장합니다.
4. **`2번 (K-001 키오스크 등록)`** ➡️ 최종 목표인 키오스크 벤치마크를 정식 등록합니다.
*(※ 3번 `--update-golden` 스크립트는 독립 작업으로 언제든 추가 가능하며, 6번 통합 출력은 1번 완료 후 진행)*
