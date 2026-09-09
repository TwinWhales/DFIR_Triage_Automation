# 05단계 추가 조사 요청과 자율 루프백 — 설계

> `work.md` 2번의 상세입니다. **무엇을 할 차례인가**는 `work-CLAUDE.md` 에 있고,
> 여기에는 다음 세션이 바로 집을 수 있게 적어 둔 배선이 있습니다.
> 사용자와 합의된 것은 4장 넷(요청 파일 분리 · `errors.jsonl` 기록 ·
> `LOOP=1` opt-in · **범위가 안 바뀐 아티팩트는 재사용**)이고, 나머지는 제안입니다.

지금 파이프라인은 일방통행입니다. 05단계가 레코드를 보다가 "이 시각 앞뒤를 더
봐야 한다" 또는 "이 아티팩트를 열어야 한다"고 판단해도, 그 판단을 **되돌려 보낼
통로가 없습니다.** 03단계가 Tier 2 로 유예한 것은 영영 유예된 채 끝납니다.

`518_Test_0907` 이 그 자리에서 나온 실측입니다 — 사람이 `prefetch` 를 지정했는데
02단계가 고른 `T1059.003` 매핑이 그것을 Tier 2 로 두는 바람에 유예됐고,
`518.EXE-71CD1C31.pf` 의 실행 3회가 보고서에 한 줄도 오르지 않았습니다. 그때
막은 방법은 사람이 `--force-artifacts` 로 직접 올리는 것이었습니다. 이 문서는
**그 손을 모델이 대신 쓰게 하되, 모델이 지어낼 수 없는 자리만 쓰게 하는** 배선입니다.

---

## 1. 이 문서가 뒤집는 판단, 그리고 뒤집지 않는 판단

`work-guide.md` 1.4 는 **Tier 2 루프백을 명시적 비목표**로 적었고
`docs/limitations.md` 3-1 이 같은 말을 반복합니다. 이번 과제는 그 판단을
뒤집으므로 두 문서를 함께 고칩니다.

**다만 3-1 이 통째로 닫히지는 않습니다.** 매핑 YAML 의 `trigger` 는

```yaml
- name: "psreadline_history"
  tier: 2
  trigger: "대화형 PS 콘솔(리버스쉘 세션 등) 사용 시"
```

처럼 **자연어 문장**이고, 이번 구현도 그 문장을 기계가 평가하지 않습니다. 열리는
조건은 오직 "모델이 1차 레코드를 보고 요청했는가" 입니다. 그래서 3-1 은
`limitations-log.md` 로 옮기는 것이 아니라 **범위를 좁혀 다시 씁니다** — 닫힌 것은
"유예된 아티팩트를 2차에 열 수단이 아예 없다" 이고, 남는 것은 "`trigger` 조건의
자동 재평가" 입니다. 두 문서를 가르는 기준은 날짜가 아니라 지금도 참인가입니다.

---

## 2. A안을 택하지 않은 이유 — 2차에 02를 다시 부르지 않는다

"02단계 재트리거" 라는 말을 곧이곧대로 읽으면 **모델에게 시나리오를 다시 쓰게
하는 것**이 됩니다. 검토했고, 택하지 않았습니다.

- 02단계의 실패 방식이 **축을 통째로 빠뜨리는 것**입니다(2026-09-04 실측,
  `limitations.md` 3-6). 2차에서 그것이 재현되면 루프백이 증거를 넓히는 것이
  아니라 **1차 결과를 파괴합니다.** 넓히러 갔다가 좁혀 오는 경로를 만들 이유가 없습니다.
- 같은 입력에 같은 모델을 다시 물으면 `temperature` 가 0 일 때 같은 답이,
  0 이 아닐 때 **다른 기법 목록**이 옵니다. 어느 쪽도 2차의 근거가 되지 못합니다.
- 요청을 시나리오에 반영하는 일 자체가 결정론입니다 — 시간 범위 합집합, 기법
  추가, 아티팩트 강제. 결정론으로 되는 것을 모델에게 맡기면 검증할 것이 늘어납니다.

**B안 — 요청은 모델이 내고, 반영은 파이썬이 한다.** 2차 시나리오는 코드로
**1차의 상위집합임이 보장됩니다**: 기법은 추가만, 시간 범위는 합집합만,
`entities` 는 그대로. 04·06·07 을 결정론 구간으로 둔 판단과 같은 결입니다.

이 문서는 B안의 배선입니다.

---

## 3. 라운드 배치 — 무엇이 남는가

```
cases/C-001/
  01_input.json
  02_scenario.round1.json   03_selection.round1.json   05_findings.round1.json  ← 1차 보존
  05_requests.json          ← 요청 + 처리 결과(수용/기각과 사유)
  02_scenario.json          ← 2차(최종). 이름은 그대로
  03_selection.json         ← 2차(최종). 1차의 상위집합
  04_parsed/                ← 1차 산출물 + 2차에서 새로 읽은 것 (§6)
  05_findings.json          06_verified.json   07_report.md    ← 최종
```

**최종 결과가 정규 이름을 갖습니다.** `benchmark/evaluate.py`·`tools/live_check.py`·
`pipeline_worker.py` 가 `02_scenario.json` 같은 이름을 하드코딩하고 있어서,
2차를 `.r2` 로 두면 그 도구들이 전부 1차를 보게 됩니다. 1차를 `.round1` 로 미는
쪽이 손대는 곳이 적고, `05_requests.json` + `.round1` + `errors.jsonl` 셋이
감사 추적을 온전히 남깁니다.

루프백이 돌지 않으면(요청 0건이거나 전부 기각) `.round1` 파일은 **만들지 않습니다.**
있으면 2차가 돌았다는 뜻이고, 없으면 1차로 끝났다는 뜻입니다.

---

## 4. 사용자와 합의된 넷

| # | 결정 | 근거 |
|---|---|---|
| 1 | 요청은 **`05_requests.json` 별도 파일**, `schemas/investigation.schema.json` 신설 | `findings.schema.json` 은 동결이고 `additionalProperties: false` 다. `campaign.schema.json` 추가와 같은 부류 |
| 2 | 기각된 요청은 **`errors.jsonl` 에도** 적는다 (`investigation_rejected`, `action="record"`) | `ungrounded_entity` 와 같은 부류 — **실패가 아니라 측정**이다. 프롬프트를 고쳤을 때 나아졌는지 볼 자리 |
| 3 | 루프백은 **기본 OFF**, `LOOP=1` 로 켠다 | `--mode`·`--no-constrain` 과 같은 측정용 스위치 규약. 같은 케이스를 켜고/끄고 돌려야 무엇이 달라졌는지 말할 수 있다 |
| 4 | 2차 파싱은 **범위가 바뀐 아티팩트만** 읽는다 | 60GB 이미지에서 전체 재파싱은 4~5분을 통째로 다시 쓴다 (§6) |

---

## 5. 요청 — 무엇을 물을 수 있는가

### 5-1. 별도 질의로 묻는다

`--mode assemble` 은 Map(선별) → Reduce(종합) → Critic 으로 이미 질의를 나눠
보냅니다. 요청은 **그 뒤에 붙는 네 번째 질의**입니다. 기존 두 출력 스키마
(`selection_schema`·`connection_schema`)를 건드리지 않는 이유가 여기 있습니다 —
둘은 토큰 예산이 촘촘히 잡혀 있고, 거기에 필드를 얹으면 레코드 자릿수가 줄어듭니다.

질의 하나가 더 붙지만 **작습니다.** 레코드 원본을 다시 싣지 않고 1차 소견의
문장·인용 `ref`·현재 시간 범위·요청 가능한 목록만 보냅니다.

`--mode model`(모델이 문장을 직접 쓰는 경로)에서도 같은 함수를 부릅니다.
`interpret.py` 의 `main()` 에서 findings 를 쓴 **직후** 한 곳에 있으므로 두 경로가
갈라지지 않습니다.

### 5-2. 지어낼 수 없게 만든다 — 열거형이 곧 가드

`constrained_schema` 가 `ref` 를 enum 으로 묶어 **"없는 ref 를 만들 토큰 경로가
사라진다"** 고 한 것과 같은 규약입니다. 걸러 낼 것이 아니라 나오지 않게 합니다.

| 필드 | enum 의 출처 | 막는 것 |
|---|---|---|
| `based_on_ref` | 이번에 전달한 레코드의 `ref` (`input_refs`) | 근거 없는 요청 |
| `technique_id` | `attack.mapped_techniques()` − 이미 선별된 기법 | 매핑이 없어 03이 아무것도 못 고르는 요청 |
| `artifact` | 카탈로그에서 `supported: true` 이면서 이번 03의 `selected` 가 **아닌** 것 | 파서 없는 아티팩트 요청 |
| `pivot_time` | 전달한 레코드의 타임스탬프 | 증거에 없는 시각을 축으로 삼는 것 |
| `window_hours` | 정수 1–24 | 증거 전체를 다시 읽게 만드는 폭주 |
| 요청 수 | `maxItems: 3` | 2차 파싱이 1차보다 커지는 것 |

**`artifact` 의 enum 에서 미지원 아티팩트를 빼는 것이 핵심입니다.**
`psreadline_history` 는 `mappings/_artifacts.yaml` 에서 `parser: null,
supported: false` 라, 요청해도 03단계 `_force_select` 가 `unusable_reason` 을 보고
올리지 않습니다(`select.py:406`). 목록에 넣으면 모델이 요청은 하는데 2차가
아무것도 못 가져오고, 4~5분짜리 재파싱이 헛돕니다. 그것을 정말 읽고 싶으면
루프백 과제가 아니라 `add-parser` 과제입니다.

Tier 2 로 유예되는 18개 중 실제로 깨울 수 있는 것은 17개입니다 —
`$UsnJrnl`·`$MFT`(각 9개 기법), `prefetch`(7), `registry:SOFTWARE`(4),
`evtx:Sysmon`·`evtx:NetworkProfile`·`evtx:Security`(각 3) 등.

### 5-3. `05_requests.json`

```json
{
  "case_id": "C-001",
  "stage": "05_investigate",
  "schema_version": "1.0",
  "generated_at": "2026-09-09T04:31:12Z",
  "generator": "interpret.py / qwen2.5:latest",
  "round": 1,
  "requests": [
    {
      "type": "expand_time_range",
      "based_on_ref": "SYSMON#4412",
      "rationale": "C2 아웃바운드 직전 유입 경로를 못 봤다",
      "pivot_time": "2026-09-07T13:37:00Z",
      "window_hours": 2,
      "disposition": {
        "verdict": "accepted",
        "reason": "applied",
        "detail": "time_range 를 2026-09-07T11:37:00Z 까지 앞으로 넓혔다"
      }
    },
    {
      "type": "request_artifact",
      "based_on_ref": "SYSMON#4412",
      "rationale": "실행 흔적을 프리패치로 교차 확인",
      "artifact": "prefetch",
      "disposition": {"verdict": "accepted", "reason": "applied", "detail": "Tier 2 승격"}
    }
  ],
  "applied": {
    "time_range": {"start": "2026-09-07T11:37:00Z", "end": "2026-09-07T14:00:00Z"},
    "techniques": [],
    "artifacts": ["prefetch"]
  }
}
```

`disposition` 은 **05가 쓰지 않습니다.** 05는 요청만 적고, `expand.py` 가 처리한
뒤 같은 파일에 판정을 채웁니다. 요청과 판정이 한 파일에 있어야 "무엇을 물었고
무엇이 받아들여졌나"를 한 번에 봅니다.

기각 사유 어휘 — `ungrounded_ref` · `unknown_technique` · `unmapped_technique` ·
`already_selected` · `unsupported_artifact` · `out_of_evidence` · `no_widening`.
전부 `errors.jsonl` 에 `investigation_rejected` 로도 남습니다(합의 2).

---

## 6. 04단계 부분 재사용 — `--reuse-from` (합의 4)

2차는 시나리오가 넓어졌으므로 03이 **상위집합**을 냅니다. 그렇다고 전부 다시
읽을 이유는 없습니다. `$MFT` 의 범위가 그대로인데 다시 파는 것은 60GB 에서
4~5분입니다.

```bash
python -m src.stage04_parse.parse \
    --in cases/C-001/03_selection.json --out cases/C-001/04_parsed/ \
    --evidence <이미지> --volume 1 \
    --reuse-from cases/C-001/03_selection.round1.json
```

**판정 규칙** — 아티팩트마다 이렇게 가릅니다.

| 1차와 비교해서 | 2차의 행동 |
|---|---|
| 범위가 **같다** + 1차 매니페스트의 `files` 에 있다 + `.jsonl` 이 실재한다 | **재사용.** 파일을 그대로 두고 1차 매니페스트 항목을 옮겨 적는다 |
| 범위가 **넓어졌다** | 다시 읽는다 (같은 파일명을 덮어쓴다 → `ref` 유일성 유지) |
| 1차에 **없던 아티팩트** | 읽는다 |
| 1차에서 `skipped` 였다 | **다시 시도한다.** 파일을 못 열어 실패한 것이라 파싱 비용이 없고, 재시도가 더 정직하다 |

**범위 비교는 정렬 후에 합니다.** `merge_scopes` 는 값의 등장 순서를 보존하므로
(`dict.fromkeys`), 기법이 하나 늘면 같은 `path_prefix` 가 다른 순서로 나올 수
있습니다. `path_prefix`·`extensions`·`event_ids` 는 전부 "이 중 아무거나" 조건이라
순서에 뜻이 없습니다. `scope_key(scope)` 로 목록을 정렬해 정규화한 뒤 비교합니다.

**재사용한 항목은 매니페스트에 표시합니다** — `"reused": true`. 매니페스트는
04단계가 **자기가 한 일을 적는 곳**이므로, 이번 실행이 읽지 않은 것을 읽은 것처럼
적으면 안 됩니다. `record_count`·`source_path`·`parse_errors` 는 1차 값을 그대로
옮기므로 `total_records` 합계와 `tools/inspect_jsonl.py` 대조가 그대로 성립합니다.

**`--skip-existing` 과 함께 쓸 수 없습니다.** 둘 다 "건너뛴다" 지만 뜻이 다릅니다 —
앞은 "산출물이 있으면 통째로 안 읽는다"(목업·리플레이용), 뒤는 "범위가 같은 것만
안 읽는다". 한 실행에서 두 뜻이 섞이면 무엇을 읽었는지 말할 수 없으므로 argparse
단계에서 거부합니다.

**잔재는 `inspect_jsonl.py` 가 잡습니다.** 매니페스트에 없는 `.jsonl` 이 디렉터리에
남으면 `total_records` 합계가 어긋나 종료 코드 1 이 됩니다. 이미 있는 안전망입니다.

---

## 7. 2차 해석 — 1차가 인용한 레코드를 핀으로 고정한다

2차는 레코드가 늘어난 상태에서 **같은 토큰 예산**으로 다시 배분합니다. 그냥 두면
1차가 인용했던 레코드가 자리를 잃고, 최종 보고서에서 **1차 소견이 사라질 수
있습니다.** "2차를 돌렸더니 1차보다 얇아졌다"는 결과는 루프백의 실패입니다.

`allocation.allocate_records` 에 `pinned_refs` 를 넣어 기존 보장 레인
(`must_review`)에 합류시킵니다 — `guaranteed` dict 에 `setdefault` 하는 세 줄입니다.
`react_loop.py` 가 `05_findings.round1.json` 의 모든 `findings[].refs` 와
`timeline[].refs` 를 모아 `--pin-refs` 로 넘깁니다.

이것이 "1차+2차 통합" 이 말이 되게 하는 자리이고, 9장의 첫 관문이 이것을 증명합니다.

---

## 8. 가드레일

| # | 무엇을 막나 | 어떻게 |
|---|---|---|
| G1 | 무한 루프 | 2차 05 실행에 **`--investigate` 를 주지 않는다.** 카운터가 아니라 구조 — 묻지 않으므로 3차 요청이 생길 자리가 없다 |
| G2 | 근거 없는 요청 | `based_on_ref` enum = `input_refs` (§5-2) |
| G3 | 헛도는 2차 | 수용된 요청이 0건이면 **2차를 아예 시작하지 않는다.** `.round1` 파일도 만들지 않는다 |
| G4 | 헛도는 2차 ② | 2차 03 산출물이 1차와 **같으면** 거기서 멈춘다 (04·05를 돌리지 않는다) |
| G5 | 증거 밖으로 넓히기 | `timeband.clamp_to_collection` — 수집 시각 뒤로는 증거가 없다. 이미 있는 기계를 그대로 쓴다 |
| G6 | 범위 폭주 | `window_hours` ≤ 24, 요청 ≤ 3건 |
| G7 | 1차 소견 유실 | `--pin-refs` (§7) |
| G8 | 2차가 1차를 좁히기 | `expand.py` 는 추가·합집합만 한다. 시험이 상위집합을 검사한다 |

---

## 9. 관문 — `live_check.py` 의 12번째 판정 (`--loop` 일 때만)

내용이 맞는지가 아니라 **구조 불변식**만 봅니다. 기존 11개와 같은 규약입니다 —
모델이 무엇을 요청했든 성립해야 하는 것만 판정하고, 깨지면 모델 사정이 아니라
우리 회귀입니다.

- 2차 `input_refs` ⊇ 1차 `input_refs` — **1차가 본 것을 2차가 잃지 않았는가** (§7의 증명)
- 2차 `time_range` ⊇ 1차, 2차 `techniques` ⊇ 1차 — 넓히기만 했는가
- 2차 `04_parsed` 총 레코드 ≥ 1차, 재사용한 아티팩트의 `record_count` 는 1차와 **같은가**
- 수용된 요청의 `based_on_ref` 가 전부 1차 `input_refs` 안에 있는가
- `05_requests.json` 이 정확히 한 번만 생겼는가 (G1)

환각률·2차 소요 시간은 **측정**이며 종료 코드를 바꾸지 않습니다.

---

## 10. 손대는 파일

| 파일 | 하는 일 |
|---|---|
| `schemas/investigation.schema.json` **(신규)** | `05_requests.json` 의 계약 |
| `src/common/schema.py` | `STAGE_SCHEMA` 에 `"05_investigate": "investigation"` 한 줄 |
| `src/common/errors.py` | `ERROR_TYPES` 에 `investigation_rejected` (합의 2) |
| `src/stage05_interpret/llm_client.py` | `investigation_schema()` + `propose_investigation()` |
| `src/stage05_interpret/prompts/investigate_system.txt` **(신규)** | "무엇이 더 필요한가"만 묻는다 |
| `src/stage05_interpret/interpret.py` | `--investigate` / `--pin-refs`. findings 를 쓴 직후 한 곳 |
| `src/stage05_interpret/allocation.py` | `pinned_refs` (§7) |
| `src/stage02_normalize/expand.py` **(신규)** | 요청 → 2차 시나리오 + `disposition` 기록. **LLM 없음** |
| `src/stage04_parse/parse.py` | `--reuse-from`, `scope_key()`, 매니페스트 `reused` (§6) |
| `tools/react_loop.py` **(신규)** | 오케스트레이터. expand → 03 → 04 → 05 |
| `run_pipeline.sh` | 05와 06 **사이**에 `LOOP=1` 일 때 한 줄 |
| `tools/live_check.py` | `--loop` 관문 (§9) |
| `src/stage07_report/report.py` + `templates/report.md.j2` | "2차 조사 요청" 절 — 요청·근거 `ref`·수용/기각 사유 |

시나리오 확장을 `src/stage02_normalize/` 에 두는 이유는 **시나리오 문서의 주인이
02단계**이기 때문입니다. 새 단계 번호를 만들면 "02 재트리거" 가 아니라 "09단계"가
됩니다.

### 전체 공지 대상

- `schemas/` 에 파일 추가 (동결된 6개는 안 건드립니다)
- `src/common/schema.py` 의 `STAGE_SCHEMA` 한 줄 — `08_campaign` 때와 같은 부류
- `src/common/errors.py` 의 `ERROR_TYPES` 한 줄
- `work-guide.md` 1.4 비목표 수정, `limitations.md` 3-1 범위 축소

---

## 11. 시험

- `tests/test_loopback.py` **(신규)**
  - 시간 합집합·`clamp_to_collection`·`window_hours` 상한
  - 기법 추가 후 `scenario` 스키마 통과, 매핑 없는 기법 기각
  - `based_on_ref` 가 `input_refs` 밖이면 기각
  - **상위집합 시험** — 2차 시나리오가 1차의 기법·시간을 잃지 않는다 (G8)
  - 수용 0건이면 2차를 시작하지 않는다 (G3), 03 산출물이 같으면 멈춘다 (G4)
- `tests/test_pipeline_e2e.py` — 스텁 관통 루프. `StubBackend` 가 호출마다 같은
  파일을 돌려주므로, 조립 경로가 `05_selection.json` 하나에 선별·종합을 같이 담은
  것과 **똑같은 방식으로** `investigation_requests` 키를 픽스처에 얹는다
- `tests/test_parse_scaffold.py` — `--reuse-from` 판정 넷(§6 표), 정렬 후 비교,
  `--skip-existing` 과 동시 사용 거부
- `tests/test_allocation.py` — `pinned_refs` 가 예산을 넘겨도 자리를 지키는가
- `tests/test_schemas.py`·`test_command_line_flags.py` 갱신

---

## 12. 문서

| 문서 | 무엇을 적나 |
|---|---|
| `docs/pipeline-io-spec.md` | `05_requests.json` 계약, `.round1` 이름 규약, 매니페스트 `reused` |
| `work-guide.md` 1.4 | 비목표에서 "Tier 2 루프백" 삭제 |
| `docs/limitations.md` 3-1 | 범위 축소 — 남는 것은 `trigger` 자동 재평가 (§1) |
| `docs/limitations-log.md` | 닫힌 부분(2차에 열 수단이 없다) 이관 |
| `docs/llm-handover.md` | 네 번째 질의 |
| `CLAUDE.md` | `LOOP=1` 실행 예, `investigation_rejected` 어휘 |
| `benchmark/README.md` | 2차가 돈 실행의 수치를 어떻게 읽나 |

---

## 13. 구현 순서

1. **모델 없이 되는 절반** — `investigation.schema.json` + `expand.py` + `test_loopback.py`
2. **04 부분 재사용** — `--reuse-from` + 시험. 1번과 독립이라 순서를 바꿔도 된다
3. **05 후속 질의** — `propose_investigation` + 프롬프트 + 픽스처 + 스텁 E2E
4. **오케스트레이터** — `react_loop.py` + `run_pipeline.sh` + `--pin-refs`
5. **07 보고서 절 + `live_check.py` 관문**
6. **실물 1회** — `ollama list` 로 태그를 먼저 보고(`CLAUDE.md` 의 경고), 루프 켜고/끈
   같은 케이스 두 번. 2차 소요 시간과 재사용으로 아낀 시간을 `benchmark/collect.py` 에 남긴다
7. **문서** (§12)

1~3 은 모델 없이 끝나고, 4~5 에서 처음으로 실제 모델이 필요합니다.
