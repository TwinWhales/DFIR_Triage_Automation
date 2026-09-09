# dfir-triage — 시나리오 기반 온프레미스 DFIR 트리아지 자동화

침해 시나리오를 바탕으로 **필요한 아티팩트를 먼저 선별**하고, 선별된 데이터만 파싱하여 소형 언어 모델(sLLM)로 해석한 뒤, 그 해석이 실제 포렌식 증거에 부합하는지 **기계적으로 검증(신호등 판정)**하는 엔터프라이즈 침해사고 트리아지 도구입니다.

단일 단말(01~07단계) 분석을 넘어, 키오스크·POS·관리서버 간 횡적 이동(Lateral Movement) 공격 체인을 자동으로 복원하는 **08단계 캠페인 레이어**까지 통합 지원합니다.

---

## 💡 핵심 설계 철학

1. **전수 파싱 대신 "시나리오 기반 선별" (선별 후 파싱)**
   - 수십~수백 GB의 전체 증거를 무작정 파싱해 LLM 컨텍스트에 밀어 넣는 기존 도구의 한계를 탈피했습니다.
   - 02단계(시나리오 정규화)에서 식별된 MITRE ATT&CK 기법을 기반으로, 03단계에서 분석에 꼭 필요한 아티팩트만 스마트하게 선별하여 파싱합니다.
2. **LLM 구간과 결정론적(Python) 구간의 교차 배치**
   - 모델이 추론(02 시나리오, 05 해석)을 수행할 때마다 다음 단계(03 선별, 06 근거 검증)에서 기계적 규칙으로 검증합니다.
   - 07단계 보고서와 08단계 캠페인 상관분석은 **LLM을 전혀 쓰지 않고 100% Jinja2 및 파이썬 결정론**으로 처리하여 환각의 재유입을 원천 차단합니다.
3. **바이트 오프셋(Offset) 기반 포렌식 무결성**
   - 모든 파서 선정의 절대 기준은 **"레코드마다 원본 바이트 오프셋을 제공하는가"**입니다.
   - 보고서의 모든 소견 문장은 원본 아티팩트 레코드(`ref`)와 연결되며, 원본 디스크 바이트까지 1:1로 즉시 역추적할 수 있습니다.

---

## 🔄 전체 파이프라인 (01단계 ~ 08단계)

```
[01 입력] 자연어 서술 / EDR 알럿 / Wazuh SIEM JSON
   ↓
[02 시나리오 정규화]       ← sLLM + 고정 스키마 검증
   ↓                       ↑
[03 아티팩트 선별]         │ (05단계의 2차 조사 요청: LOOP=1 시 활성화)
   ↓                       │ [시간창 확장 · 기법 추가 · 아티팩트 강제 선별]
[04 결정론적 파싱]         │ (--reuse-from 으로 동일 범위 증거 캐시 재사용)
   ↓                       │
[05 sLLM 해석]             └─── 1차 해석 후 추가 조사 요청(05_requests.json) 발행
   ↓                            (--pin-refs 로 1차 인용 레코드 보장 레인 고정)
[06 근거 검증 (신호등)]     ← 결정론적 (🟢Passed / 🟡Warning / 🔴Rejected)
   ↓
[07 단일 결과 보고]         ← 결정론적 (Jinja2 마크다운 리포트 생성, 2차 조사 처리 내역 포함)
   ↓
[08 캠페인 상관분석]       ← 100% 파이썬 결정론 (노드 간 횡적이동 공격 체인 및 Mermaid 복원)
```

### 🚦 신호등 검증 체계 (06단계)
* 🟢 **Passed (확정 사실)**: 소견의 모든 주장(`claims`)이 원본 레코드의 실제 값과 100% 일치.
* 🟡 **Warning (주의 필요)**: 소견의 핵심 팩트는 유효하나 일부 수치/경로 표현 차이 또는 분석가 추가 검토가 필요한 항목.
* 🔴 **Rejected (기각)**: 증거에 존재하지 않는 파일명·IP 날조 또는 명백한 환각. 보고서 본문에서 자동 차단.

---

## 🚀 빠른 시작 (Quick Start)

### 1. 개발 환경 구축
```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # Linux/macOS
.venv/Scripts/python.exe -m pytest -q                        # 1,637건 전체 테스트 통과
```

### 2. Ollama 로컬 sLLM 모델 준비
```bash
ollama pull qwen2.5:latest   # 또는 qwen2.5:7b
```

### 3. 단일 케이스 실행

#### 기본 실행 (1차 단발 분석)
```bash
# 1) 케이스 생성
.venv/Scripts/python.exe tools/make_case.py --case-id C-001 --evidence evidence/WEB01

# 2) 01~07 파이프라인 관통 실행
PYTHON=.venv/Scripts/python.exe ./run_pipeline.sh C-001 evidence/WEB01
```

#### 루프백 실행 (ReAct 피드백 활성화 — 심층 2차 조사)
1차 분석 후 모델이 스스로 단서를 되짚어 유예된 증거(`$MFT` 등)를 추가 수집하고 소견을 심화합니다:
```bash
# bash 환경
LOOP=1 PYTHON=.venv/Scripts/python.exe ./run_pipeline.sh C-001 evidence/WEB01

# 또는 live_check 도구에서
.venv/Scripts/python.exe tools/live_check.py --case-id C-001 --evidence evidence/WEB01 --loop
```
> [!TIP]
> **실무 권장 (Opt-in 원칙)**: 루프백은 2차 LLM 심층 해석을 거치므로 실행 시간이 약 2배 소요됩니다 (실측 215초 ➔ 495초). 모든 단말에 무조건 켜기보다는, **1차 분석에서 공격 축을 놓친 것으로 의심되거나 증거가 부족한 단말에 선택적(Opt-in)으로 적용**하는 것이 시간과 분석 품질 면에서 가장 효율적입니다.

### 4. Wazuh SIEM 실시간 알럿 연동
```bash
# alerts/ 폴더의 Wazuh 알럿 JSON을 수신하여 즉시 케이스 생성 및 실행
.venv/Scripts/python.exe tools/make_case.py --case-id C-004 \
  --evidence evidence/WEB04 --alert alerts/wazuh-alert.json
```

### 5. 08단계 멀티 노드 캠페인 상관분석 실행
```bash
# 3개 노드(키오스크, POS, 서버)의 완주된 결과를 엮어 전사 공격 체인 리포트 생성
.venv/Scripts/python.exe -m src.stage08_campaign.campaign \
  --in benchmark/fixtures/campaign-3node/campaign.json \
  --cases benchmark/fixtures/campaign-3node/cases \
  --out campaigns/CAMP3/
```
*(실행 즉시 `campaigns/CAMP3/08_campaign.md`에 Mermaid 다이어그램과 신호등 횡적이동 체인이 렌더링됩니다.)*

---

## 🔍 포렌식 검증 및 역추적 도구

### 1. 04단계 파싱 산출물 자체 검증
```bash
.venv/Scripts/python.exe tools/inspect_jsonl.py --parsed cases/C-001/04_parsed
```
* 매니페스트 줄 수 일치, `ref` 유일성, 레코드 번호 일치 검사 (불일치 시 exit code 1).
* 특정 플래그나 경로 필터링 지원: `--flag deleted --path "Users\Public"`

### 2. 보고서 문장에서 원본 디스크 바이트 덤프 대조
```bash
.venv/Scripts/python.exe tools/hexdump_record.py MFT#12345 \
  --parsed cases/C-001/04_parsed --evidence evidence/disk.001 --volume 1
```
* 보고서에 기재된 `ref` 식별자를 원본 디스크 이미지 바이트와 즉시 1:1 대조합니다.

---

## 📊 벤치마크 및 정량 평가 지표

본 도구는 **"얼마나 빠른데, 얼마나 놓치지 않는가"**를 정량적으로 측정합니다.

```bash
# 1) 전체 벤치마크 평가 실행
.venv/Scripts/python.exe benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell

# 2) 검증기 회귀 방지 테스트 (표기 오류를 환각으로 세지 않는지 검사)
.venv/Scripts/python.exe benchmark/validator_check.py
```

* **4단계 증거 도달률**: 정답 레코드가 `파싱 ➔ 전달 ➔ 인용 ➔ 검증통과` 중 어느 지점에서 탈락했는지 정밀 추적.
* **환각률 (Hallucination Rate)**: `rejected / (passed + rejected)` (06단계 기각 소견 비율 집계).

---

## 📁 프로젝트 구조 요약

```
dfir-triage/
├── src/                      # 파이프라인 소스코드 (02단계 ~ 08단계)
│   ├── common/               # 공용 모듈 (io, schema, refs, attack, llm 등)
│   ├── stage02_normalize/    # 시나리오 정규화 (sLLM)
│   ├── stage03_select/       # 아티팩트 우선순위 선별 (결정론)
│   ├── stage04_parse/        # 결정론적 파서 (MFT, USN, EVTX, Registry, Prefetch 등)
│   ├── stage05_interpret/    # sLLM 타깃 해석 및 의심 레코드 추출
│   ├── stage06_verify/       # 신호등 근거 검증 (Passed / Warning / Rejected)
│   ├── stage07_report/       # 단일 케이스 보고서 템플릿 렌더링 (Jinja2)
│   └── stage08_campaign/     # 멀티 노드 캠페인 상관분석 엔진
├── schemas/                  # 데이터 입출력 계약 스키마 (JSON Schema)
├── mappings/                 # MITRE ATT&CK ➔ 아티팩트 매핑 지식 (YAML)
├── benchmark/                # 가상 픽스처, 정답셋(Ground Truth), 평가 스크립트
├── tools/                    # 검증/대조/실행 유틸리티 스크립트
└── docs/                     # 시스템 상세 스펙 및 한계 문서
```

---

## 📌 문서 가이드 및 제약 사항

* **시스템 층위의 알려진 한계**: [docs/limitations.md](docs/limitations.md) (인과관계 단정 불가, 베이스라인 부재 등)
* **해결된 엔지니어링 기록**: [docs/limitations-log.md](docs/limitations-log.md)
* **단계별 입출력 상세 명세**: [docs/pipeline-io-spec.md](docs/pipeline-io-spec.md)
* **팀 협업 및 일정 관리**: 팀 Notion 대시보드로 통합 이관 관리
