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
- [x] **3단계 — 05 후속 질의** (2026-09-09)
  - [x] `src/stage05_interpret/llm_client.py`에 `investigation_schema()` + `propose_investigation()`
  - [x] `src/stage05_interpret/investigation.py` 신설 — 요청 가능 목록·축(pivot) 표·문서 조립
  - [x] `src/stage05_interpret/prompts/investigate_system.txt` 신설
  - [x] `src/stage05_interpret/interpret.py`에 `--investigate` / `--requests-out` — findings를 쓴 **직후** 한 곳이라 `--mode` 두 경로가 갈라지지 않는다
  - [x] 픽스처 `05_selection.json`에 `investigation_requests` 키 (`StubBackend`가 호출마다 같은 파일을 돌려주는 성질을 조립 경로와 똑같이 이용). **`05_findings.json`에는 넣지 않았다** — 그 픽스처는 findings 스키마(`additionalProperties: false`)로 검증되는 자리가 여럿이라 키 하나가 그것들을 깬다
  - [x] `tests/test_investigation_query.py` 16건 + `tests/test_pipeline_e2e.py`에 스텁 관통 루프 1건
  - **`pivot_time`을 모델에게 묻지 않기로 했다**(설계서와 달라진 점). 근거 레코드만 받으면 그 시각은 우리가 안다 — `input_refs`를 묻지 않는 것과 같은 규약이고, 타임스탬프를 지어낼 토큰 경로가 사라진다. 그래서 `expand_time_range`의 `based_on_ref` 열거형만 다르다(시각을 뽑을 수 있는 레코드만). 파일 형식은 설계 그대로다.
  - **질의가 실패해도 05단계는 성공이다.** findings는 이미 쓰였고, 요청은 그 위에 얹는 것이라 사유를 남기고 2차 없이 끝낸다(내러티브 critic과 같은 처리).
  - **관통 확인**: 스텁으로 05 → `05_requests.json`(요청 2건, `pivot_time` 채워짐) → `expand` → 03 재선별에서 아티팩트가 늘었다. 질의 내역은 `05_llm_queries/03_investigation.txt`에 남는다.
- [x] **4단계 — 오케스트레이터** (2026-09-09)
  - [x] `tools/react_loop.py` 신설 — expand → 03(`--force-artifacts`) → 04(`--reuse-from`) → 05(`--pin-refs`, **`--investigate` 없이**)
  - [x] `src/stage05_interpret/allocation.py`에 `pinned_refs` (기존 `must_review` 보장 레인에 합류 — 자릿수 상한을 받지 않는다)
  - [x] `src/stage05_interpret/interpret.py`에 `--pin-refs`. 1차 소견의 `findings[].refs`와 `timeline[].refs`를 **양쪽 다** 모은다
  - [x] `run_pipeline.sh` — `LOOP=1`일 때 05에 `--investigate`, 05와 06 **사이**에 루프백. 기본은 꺼짐
  - [x] `tests/test_react_loop.py` 9건 + `tests/test_allocation.py` 3건
  - **끝난 뒤 정규 이름이 2차를 가리킨다.** 06·07은 루프가 돌았는지 모른 채 평소대로 읽는다. 1차는 `.round1`로 남고, **돌 이유가 없었으면 `.round1`을 남기지 않는다** — 남으면 사람도 도구도 "2차가 돌았다"로 읽는다
  - **종료 코드 3은 실패가 아니다** (요청 0건·전부 기각·2차 선별이 1차와 같음). `run_pipeline.sh`가 그것을 정상으로 받는다
  - **관통 확인**: `LOOP=1`로 01→07 완주. 2차 질의 내역(`05_llm_queries_round2`)에 조사 요청 질의가 **없다**(G1이 구조로 걸린 증거). 04는 `$MFT`·`evtx:Security`를 재사용했고, 07 보고서의 기법 표에 `T1041`이 `2차 조사 요청(EVTX-SEC#40912): …`로 실렸다
- [x] **5단계 — 보고서와 관문** (2026-09-09)
  - [x] `src/stage07_report/report.py` + 템플릿에 "2차 조사 요청과 그 처리" 절 — **미확인 사항** 아래에 둔다. 기각된 요청이 그 절의 요지다(모델이 더 보자고 했는데 안 본 자리). `--requests`가 없으면 절 자체가 안 실린다
  - [x] `run_pipeline.sh`가 `05_requests.json`이 있을 때만 07에 넘긴다
  - [x] `tools/live_check.py`에 `--loop` — 12번째 관문이 05와 06 **사이**에 낀다
  - [x] `tests/test_report.py` 6건 + `tests/test_react_loop.py`에 배선 3건
  - **관문이 보는 것 여섯**: 2차 `input_refs` ⊇ 1차 / 기법 상위집합 / 시간 범위 상위집합 / 재사용 아티팩트의 `record_count`가 1차와 동일 / 총 레코드 감소 없음 / 2차 질의 내역에 조사 요청 질의 없음. 종료 코드 3(돌 이유 없음)은 **PASS**이며, 그때 `.round1`이 남아 있으면 FAIL이다
  - **어휘 표류 시험 둘**: 스키마의 기각 사유·요청 종류가 늘었는데 보고서가 모르면 코드값이 그대로 인쇄된다. `REJECTION_LABELS`·`REQUEST_LABELS`가 스키마 enum과 정확히 같은지 검사한다
  - **`live_check.py`에 첫 시험이 생겼다**: 모든 단계 키에 `do_<key>` 핸들러가 있는가. 오타는 import에서도 문법 검사에서도 안 걸리고 5분짜리 실물 실행 중간에 터진다
- [x] **6단계 — 실물 1회** (2026-09-09, `evidence/KAPE_Results/snapshot1/C`, `qwen2.5:latest`)
  - [x] `ollama list` 확인 — **`qwen2.5:7b`이 다시 생겼다**(6시간 전). `CLAUDE.md`의 "없다"가 또 낡았다 (7단계에서 고칠 것)
  - [x] 같은 서술로 루프 끄고/켜고 실행. 기록은 `benchmark/results/K-LOOP-0909-*.json`

  | | 루프 끔 (`off`) | 루프 켬 (`on3`) |
  | :-- | --: | --: |
  | 관문 | 11/11 PASS | **12/12 PASS** |
  | 기법 | 1 (T1091) | 2 (**+T1059.001**) |
  | 04 레코드 | 45,137 (3개) | 93,997 (5개) |
  | 소견 | 4 | 17 |
  | passed / rejected / unverifiable | 4 / 0 / 0 | 14 / 2 / 1 |
  | 환각률 | 0.0% | 12.5% |
  | 전체 | 214.9초 | 495.5초 (루프백 단계 313.2초) |

  - **02가 놓친 축을 루프백이 되찾았다.** 입력이 "어떤 경로로 실행됐는지는 아직 확인하지 못했습니다"라고 적어 02는 `T1091` 하나만 골랐고, 03은 `$MFT`를 Tier 2로 유예했다 — `518_Test_0907`과 같은 모양이다. 05가 `T1059.001`과 **`$MFT`를 요청**했고 둘 다 수용됐다. `limitations.md` 3-1이 "영구 미수집"이라 적은 자리가 실물에서 열렸다.
  - **`--reuse-from`이 세 갈래를 실물로 다 보여 줬다**: `$UsnJrnl`(41,207) · `registry:SYSTEM`(303)은 범위가 같아 **재사용**, `evtx:Sysmon`은 새 기법이 다른 `event_id`를 요청해 **다시 읽었고**(3,627→3,732), `$MFT`(48,330)·`evtx:PowerShell`(425)은 **새로** 읽었다.
  - **환각률 0%→12.5%를 개선 실패로 읽지 않는다.** 기준선의 0%는 소견이 4건뿐이라 나온 수다(`limitations.md` 3-5). 소견이 17건으로 늘자 `technique_unsupported` 2건이 걸렸다 — 검증기가 넓어진 표면에서 일한 것이다.
  - **실물이 관문 결함 둘을 잡았다. 스텁으로는 나올 수 없는 종류였다** (아래 별도 항목)
- [x] **7단계 — 문서 완성** (2026-09-09)
  - [x] `docs/pipeline-io-spec.md` — `05_requests.json` 계약, 디렉터리 트리, `investigation.schema.json`
  - [x] `README.md` — 05 ➔ 02 루프백 ReAct 피드백 경로 다이어그램, `LOOP=1` / `--loop` 실행법, Opt-in 실무 권장 가이드
  - [x] `docs/limitations.md` 3-1 — **범위 축소 및 신규 트레이드오프 기록.** 영구 결손 해소 + 서사(`incident_story`) 스킵 현상 및 기법 라벨 오배정 위험 구조적 증가 명시
  - [x] `docs/limitations-log.md` — 05단계 조사 피드백 루프백 완성 기록 이전
  - [x] `docs/llm-handover.md` — `investigate_system.txt` 4번째 질의 프롬프트 명세 반영
  - [x] `CLAUDE.md` — 모델 태그 최신화 (`qwen2.5:7b` 및 `qwen2.5:latest` 사용 가능 반영)
  - [x] `benchmark/README.md` — 루프백 관측 지표(소견 4➔17건, 환각률 12.5%, 소요 시간 ~495초) 반영


### 실물이 잡은 관문 결함 둘 (2026-09-09)

1. **관문이 설계서보다 엄격했다** (`K-LOOP-0909-on`, 8/12에서 FAIL). 관문을 "2차 `input_refs` ⊇ 1차 `input_refs`"로 걸었는데, 2차는 레코드가 늘어난 상태에서 **같은 자릿수 예산**으로 배분하므로 아무도 인용하지 않은 레코드가 새 증거에 밀린다(61건 중 24건). 인용된 12건은 전부 남아 있었다 — **핀은 일했고 관문이 틀렸다.** 설계서 §7은 핀의 대상을 "인용한 레코드"로, §9는 관문을 "전달한 레코드"로 적어 둔 내 불일치였다. 전달 목록의 단조 증가는 예산이 고정인 한 성립할 수 없는 불변식이라, 관문을 인용 레코드 기준으로 고치고 밀린 수는 측정으로 남겼다. **약화가 아니라 정정이다.**
2. **05가 06으로 넘긴 값이 루프백 때문에 낡았다** (`K-LOOP-0909-on2`, 10/12에서 FAIL). `live_check`가 05단계에서 센 `findings_count`(1차 2건)를 06 관문이 쓰는데, 그 사이에 루프백이 돌아 최종 findings가 17건이 됐다. 06 이후의 판정은 전부 최종 산출물을 봐야 하므로 루프백 단계가 그 값을 2차 것으로 바꾼다.

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
