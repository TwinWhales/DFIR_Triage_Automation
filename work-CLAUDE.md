# work-CLAUDE.md — 클로드(Claude) 진행 중 과제

## 🎯 현재 진행 중 과제: 5단계(해석) ➔ 2단계(정규화) 자율 루프백 로직 구현 (Agentic ReAct Loop)

- **설계서**: [docs/proposals/stage05-investigation-loopback.md](docs/proposals/stage05-investigation-loopback.md)
- **배경 및 핵심 목표**:
  - 일방통행(01 ➔ 07) 분석의 한계를 극복하고, LLM이 포렌식 분석관처럼 "의심스러운 단서를 발견하면 스스로 추가 증거를 재요청하는 자율 피드백 루프(ReAct Loop)" 확립.
  - 05단계 LLM 해석 과정에서 미진한 단서 발견 시 구조화된 `investigation_requests`를 출력하고, 이를 오케스트레이터가 수신하여 02단계(시간/기법 확장) ➔ 03단계(추가 선별) ➔ 04단계(2차 타겟 파싱)를 재트리거.
  - 무한 루프 방지(최대 1회 루프백 가드레일) 및 1차+2차 증거 통합을 통한 최종 서사 및 신호등 소견 완결.

### 확정된 설계 결정 (사용자 합의, 2026-09-09)

| # | 결정 | 이유 |
| :-: | :--- | :--- |
| 1 | 요청은 **`05_requests.json` 별도 파일** + `schemas/investigation.schema.json` 신설 | `findings.schema.json`은 동결이고 `additionalProperties: false`다. `campaign.schema.json` 추가와 같은 부류 |
| 2 | 기각된 요청은 **`errors.jsonl`에도** 기록 (`investigation_rejected`, `action="record"`) | `ungrounded_entity`와 같은 부류 — 실패가 아니라 **측정**이다 |
| 3 | 루프백은 **기본 OFF**, `LOOP=1`로 켠다 | `--mode`·`--no-constrain`과 같은 측정용 스위치 규약. 켜고/끄고 돌려야 효과를 잰다 |
| 4 | 2차 파싱은 **범위가 바뀐 아티팩트만** 읽는다 (`--reuse-from`) | 60GB 이미지 전체 재파싱은 4~5분을 통째로 다시 쓴다 |

- **2차 02단계는 LLM을 다시 부르지 않는다.** 요청 반영(시간 합집합·기법 추가·아티팩트 강제)은 전부 결정론이다. 모델을 다시 부르면 "축을 통째로 빠뜨리는" 02단계의 실패 방식(`limitations.md` 3-6)이 2차에서 재현되어, 넓히러 갔다가 1차 결과를 파괴한다. 2차 시나리오가 **1차의 상위집합**임을 코드로 보장한다.
- **모델이 요청할 수 있는 것은 열거형으로 묶는다.** `based_on_ref`는 `input_refs`, `technique_id`는 매핑 YAML이 있는 것, `artifact`는 **카탈로그에서 `supported: true`이면서 이번 03의 `selected`가 아닌 것**. `psreadline_history`처럼 `parser: null`인 아티팩트는 요청해도 03단계 `_force_select`가 올리지 않으므로 목록에서 뺀다.
- **무한 루프 방지는 카운터가 아니라 구조로 건다.** 2차 05 실행에 `--investigate`를 주지 않는다 — 묻지 않으므로 3차 요청이 생길 자리가 없다.
- **1차가 인용한 레코드는 2차 프롬프트에 핀으로 고정한다**(`--pin-refs`). 그러지 않으면 늘어난 레코드가 같은 토큰 예산을 나눠 가지며 **1차 소견이 최종 보고서에서 사라질 수 있다.**

### 구현 순서 (1~3은 모델 없이 끝난다)

- [x] **1단계 — 모델 없이 되는 절반** (2026-09-09, 브랜치 `feat/investigation-loopback`)
  - [x] `schemas/investigation.schema.json` 신설 (`stage: "05_investigate"`, `round: {"const": 1}`로 G1을 파일에서도 드러낸다)
  - [x] `src/common/schema.py`의 `STAGE_SCHEMA`에 `"05_investigate": "investigation"` 한 줄
  - [x] `src/common/errors.py`의 `ERROR_TYPES`에 `investigation_rejected` 한 줄 (근거 주석 포함)
  - [x] `src/stage02_normalize/expand.py` 신설 — 요청 → 2차 시나리오 + `disposition` 기록. **LLM 없음**
  - [x] `tests/test_loopback.py` 25건 — 상위집합 불변식·시간 합집합·수집 시각 상한·기각 사유 일곱·CLI 세 갈래
  - [x] `tests/test_schemas.py` — `ref`를 제약하는 스키마 목록에 `investigation` 추가 (기존 시험이 새 스키마를 잡아냈다)
  - **구현하며 하나 더 막았다**: 수집 시각 **뒤**를 축(`pivot_time`)으로 잡은 요청. 상한 클램프만으로는 1차의 끝과 수집 시각 사이 몇 초를 얻자고 재파싱을 통째로 돌리게 된다. 축이 증거 밖이면 `out_of_evidence`로 기각한다.
  - **관통 확인**: `T1041` 요청 하나가 03단계에서 `srum:NetworkUsage`를 새로 열었고 1차가 고른 셋은 그대로다. `psreadline_history` 요청은 `unsupported_artifact`로 기각됐다.
- [x] **2단계 — 04 부분 재사용** (2026-09-09)
  - [x] `src/stage04_parse/parse.py`에 `--reuse-from`, `scope_key()`(재귀 정규화 후 비교), `reusable_entries()`, 매니페스트 항목 `"reused": true`
  - [x] `--skip-existing`과 동시 사용은 argparse 단계에서 거부 (두 "건너뛰기"의 뜻이 다르다)
  - [x] `tests/test_parse_scaffold.py` 9건 — `scope_key` 순서 무관·구분 유지·모르는 키, 판정 네 갈래(같음/넓어짐/신규/1차 스킵) + 산출물 유실
  - [x] `tests/test_pipeline_e2e.py` — CLI 관통 1건. **재사용한 파일이 한 바이트도 안 바뀐다**를 증거 없는 디렉터리로 증명한다
  - **재사용 조건은 셋 다 만족해야 한다**: 1차가 실제로 읽었고(매니페스트 `files`), 범위가 그대로이며, `.jsonl`이 실재한다. 1차 `skipped`는 재시도한다 — 파일을 못 연 것이라 파싱 비용이 없고 그 사이 증거를 다시 뽑았을 수 있다.
  - **관통 확인**: 2차 선별(=1차 + `srum:NetworkUsage`)로 돌리니 `$MFT`·`evtx:Security`는 재사용, 나머지 둘만 다시 읽었고 `tools/inspect_jsonl.py` 네 대조가 전부 통과했다.
- [ ] **3단계 — 05 후속 질의**
  - `src/stage05_interpret/llm_client.py`에 `investigation_schema()` + `propose_investigation()`
  - `src/stage05_interpret/prompts/investigate_system.txt` 신설
  - `src/stage05_interpret/interpret.py`에 `--investigate` — findings를 쓴 **직후** 한 곳이라 `--mode` 두 경로가 갈라지지 않는다
  - 픽스처에 `investigation_requests` 키를 얹는다 (`StubBackend`가 호출마다 같은 파일을 돌려주는 성질을 조립 경로와 똑같이 이용)
  - `tests/test_pipeline_e2e.py`에 스텁 관통 루프
- [ ] **4단계 — 오케스트레이터**
  - `tools/react_loop.py` 신설 — expand → 03 → 04(`--reuse-from`) → 05(`--pin-refs`, `--investigate` 없이)
  - `src/stage05_interpret/allocation.py`에 `pinned_refs` (기존 `must_review` 보장 레인에 합류)
  - `run_pipeline.sh`의 05와 06 **사이**에 `LOOP=1`일 때 한 줄
- [ ] **5단계 — 보고서와 관문**
  - `src/stage07_report/report.py` + 템플릿에 "2차 조사 요청" 절 (요청·근거 `ref`·수용/기각 사유)
  - `tools/live_check.py`에 `--loop` 관문: 2차 `input_refs` ⊇ 1차 / 시간·기법 상위집합 / 재사용 아티팩트의 `record_count` 동일 / `05_requests.json` 단 한 번
- [ ] **6단계 — 실물 1회**
  - `ollama list`로 태그를 먼저 확인한다 (`CLAUDE.md`의 경고 — 적힌 것을 믿지 않는다)
  - 같은 케이스를 루프 켜고/끄고 두 번. 2차 소요 시간과 재사용으로 아낀 시간을 `benchmark/collect.py`에 남긴다
- [ ] **7단계 — 문서**
  - `docs/pipeline-io-spec.md` — `05_requests.json` 계약, `.round1` 이름 규약, 매니페스트 `reused`
  - `README.md` — 05 ➔ 02 루프백(Tier 2 아티팩트 재수집) 기능 명시 (work-guide.md는 이미 삭제됨)
  - `docs/limitations.md` 3-1 — **범위 축소.** 닫힌 것은 "2차에 열 수단이 없다"이고, 남는 것은 "`trigger` 문자열의 자동 재평가"다. 통째로 `limitations-log.md`로 옮기지 않는다
  - `docs/llm-handover.md`(네 번째 질의), `CLAUDE.md`(`LOOP=1` 실행 예·새 어휘), `benchmark/README.md`

### 전체 공지 대상

- `schemas/`에 파일 추가 (동결된 6개는 건드리지 않는다)
- `src/common/schema.py`의 `STAGE_SCHEMA` 한 줄 — `08_campaign` 때와 같은 부류
- `src/common/errors.py`의 `ERROR_TYPES` 한 줄
- `docs/limitations.md` 3-1 범위 축소 — **이 과제는 프로젝트가 명시적 비목표로 적어 둔 판단을 뒤집는다**

---

## ✅ 직전 완료 과제: 멀티 노드 상관분석 및 캠페인 레이어 (Stage 08)

- **설계서**: [docs/proposals/multi-node-campaign.md](docs/proposals/multi-node-campaign.md) (PR #84)
- **반영 커밋**: `82e3d8b`, `c2734d2`, `ebbb9d2` (전체 완료, 코덱스/GPT 검증 대기 중)
- **세부 완료 내역**:
  1. `canonical.py` 네트워크 축 필드 보강 (`remote_ip`, `remote_port`)
  2. `schemas/campaign.schema.json` & `src/stage08_campaign/` 뼈대 구축
  3. 5대 피벗 상관분석 엔진 (`correlate.py`)
  4. 신호등 판정 연계 및 신뢰도 링크 부여
  5. 전사 캠페인 통합 보고서 렌더링 (`08_campaign.md`)
  6. 픽스처 E2E 관통 테스트 (23개 테스트 통과)
