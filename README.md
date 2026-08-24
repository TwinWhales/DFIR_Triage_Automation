# dfir-triage

시나리오 기반 아티팩트 선별과 sLLM 해석을 결합한 침해사고 트리아지 도구.

## 파이프라인

입력(자연어 또는 EDR/SIEM 알럿) -> 시나리오 정규화 -> 아티팩트 우선순위 선별
-> 결정론적 파싱 -> sLLM 해석 -> 근거 검증 -> 결과 보고

각 단계는 독립 CLI이며 파일로 입출력을 주고받습니다. 상세 계약은
`docs/pipeline-io-spec.md`를 참조하세요.

## 개발 환경

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # Linux/macOS
.venv/Scripts/python.exe -m pytest
```

아래 예시는 전부 **가상환경의 파이썬을 명시적으로** 부릅니다. Windows에서
맨 `python`은 다른 인터프리터로 잡히는 일이 흔하고, 버전이 같으면 조용히
실행되다가 `Evtx`·`Registry` import에서야 터집니다. Linux/macOS라면
`.venv/bin/python`으로 바꿔 읽으세요.

## 실행

```bash
.venv/Scripts/python.exe tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01
PYTHON=.venv/Scripts/python.exe ./run_pipeline.sh C-001 /mnt/evidence/WEB01
```

## 평가

```bash
.venv/Scripts/python.exe benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell
```

수치만 내지 않고 **어느 단계에서 놓쳤는지**를 가릅니다. 정답 레코드마다
`파싱 → 전달 → 인용 → 검증통과` 네 단계를 따로 세므로, 고칠 곳이 파서인지
매핑인지 프롬프트인지 바로 보입니다.

```bash
.venv/Scripts/python.exe benchmark/validator_check.py
```

검증기가 과엄격해지는 것을 막는 장치입니다. 사람이 옳다고 판단한 문장
33건을 넣어 몇 건이 통과하는지 봅니다. 하나라도 기각되면 환각률이 실제
환각이 아니라 표기 차이를 세고 있다는 뜻입니다.

---

## 현재 상태

파이프라인은 **01→07 전 구간이 관통합니다.** 카탈로그의 아티팩트에는
전부 파서가 있습니다. 남은 대체물은 하나 — **LLM 호출이 스텁입니다.**
알려진 한계 전체는 [`docs/limitations.md`](docs/limitations.md)에 있습니다.

| | 상태 |
|---|---|
| `schemas/` 6개 | 확정 (동결 대상) |
| `src/common/` | 구현 완료 — `io` `schema` `errors` `refs` `attack` |
| C-001 목업 세트 | 작성 완료 |
| 02 시나리오 정규화 | 구현 완료 — 알럿 어댑터는 실동작, LLM은 **스텁** |
| 03 아티팩트 선별 | 구현 완료 — 매핑 9개 + 카탈로그 (`mapping_table_version` 0.6) |
| **04 파싱** | 구현 완료 — `$MFT`(analyzeMFT 기반, MIT), `$UsnJrnl`(자체 구현), `evtx`(python-evtx 기반), `registry`(python-registry 기반) |
| 05 sLLM 해석 | 구현 완료 — 아티팩트별 자릿수 배분은 실동작, LLM은 **스텁** |
| 06 근거 검증 | 구현 완료 — 체커 3종 + `--checkers` 조합 |
| 07 결과 보고 | 구현 완료 — Jinja2 템플릿 (LLM 미사용) |
| **평가 (`benchmark/`)** | **구현 완료** — 단계별 진단 + 검증기 오탐 확인 |

수치를 낼 준비는 끝났지만 **정답 데이터가 없습니다.** 지금 있는
`ground_truth.json`은 스펙 예시에서 역산한 것이라 자기채점이고,
`evaluate.py`가 그 사실을 경고로 띄웁니다. 발표에 쓸 수치는 사람이
실제 증거를 보고 만든 정답에서 나와야 합니다.

### 한 실행은 한 볼륨

`--evidence`는 **볼륨 루트**를 가리킵니다. KAPE 출력이면 `<수집폴더>/C`이지
`<수집폴더>`가 아닙니다. 볼륨이 여럿이면 케이스를 나눕니다.

```
cases/C-001-C/   ← 시스템 볼륨
cases/C-001-D/   ← 데이터 볼륨
```

도구가 어느 볼륨인지 추측하지 않게 하려는 것입니다. 덤으로 `ref`가
유일해집니다 — 두 볼륨을 한 번에 읽으면 `MFT#12345`가 양쪽에 존재해
06단계가 어느 레코드를 검증했는지 알 수 없게 됩니다.

볼륨들을 담은 폴더를 지정하면 어느 볼륨인지 안내하고 멈춥니다.

**파이프라인은 01→07 전 구간이 관통됩니다.** 다만 02·05의 LLM이 아직
대체물입니다.

- **04 파싱** — `$MFT`는 메인 파서([analyzeMFT](third_party/README.md) 기반,
  MIT)가 실제로 읽습니다. `native`(기본)와 `--parser reference` 어느 쪽으로
  불러도 같은 파서를 씁니다.
- **02·05의 LLM** — `--llm stub`이 기록된 응답을 재생합니다. 프롬프트 조립,
  응답 파싱, 스키마 검증, 재시도까지 실제 경로를 그대로 지나가고 네트워크
  호출만 대체됩니다.

- **evtx** — 온디스크 계층은 [python-evtx](docs/artifact-notes.md)가 맡고,
  청크 순회 감사·필드 추출·`ref`/`offset` 규약은 우리 어댑터가 합니다.

- **registry** — `SYSTEM`·`SOFTWARE` 하이브. 온디스크 계층은 python-registry가
  맡고, 경로 재구성·`CurrentControlSet` 해석·범위 밖 서브트리 가지치기는
  우리 어댑터가 합니다. 신호가 04단계 플래그가 아니라 **선별에서** 나오는
  아티팩트라 카탈로그에 `signal_source: scope`로 표시돼 있고, 05단계 배분이
  그것을 보고 자리를 줍니다([`limitations.md`](docs/limitations.md) 6-7).

`$MFT` 파싱 회귀는 `tools/compare_mft.py`와 합성 레코드 테스트
(`tests/test_mft_parser.py`)로 MFTECmd 없이 `pytest` 안에서 검증합니다.

evtx는 **외부 도구 대조를 실제로 마쳤습니다.** `wevtutil`(Windows 기본
탑재, 마이크로소프트 자체 파서)과 8,257레코드를 대조해 레코드 수·
`EventRecordID`·`event_id`·`computer`·타임스탬프가 전부 일치했습니다.
기록은 [`docs/artifact-notes.md`](docs/artifact-notes.md)에 있습니다.

레지스트리는 **커버리지 대조를 마쳤습니다.** `tools/scan_hive_cells.py`가
서브키 목록을 따라가지 않고 셀을 직접 걸어 `nk`를 세는데, 파서 결과와
SYSTEM 34,855건·SOFTWARE 156,716건이 정확히 일치했습니다. 값 대조는
`reg load`로 남아 있습니다.

```bash
.venv/Scripts/python.exe tools/scan_hive_cells.py --hive <volume>/Windows/System32/config/SYSTEM   --ours cases/C-001/04_parsed/registry_system.jsonl
```

### 관통 실행해 보기

```bash
.venv/Scripts/python.exe tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01 \
  --input benchmark/datasets/C-001-webshell/input.json \
  --seed-parsed benchmark/datasets/C-001-webshell/mock/04_parsed

PYTHON=.venv/Scripts/python.exe ./run_pipeline.sh C-001 /mnt/evidence/WEB01 benchmark/datasets/C-001-webshell/mock
```

`cases/C-001/`에 01부터 07까지 쌓이고 `07_report.md`가 나옵니다.
세 번째 인자를 빼면 스텁 대신 Ollama를 호출합니다.

### 먼저 읽을 것

1. `work-guide.md` — 설계 전제와 팀 분담
2. `schemas/README.md` — 데이터 계약, **스펙에 없어서 정한 것 8건**
3. `benchmark/datasets/C-001-webshell/README.md` — 목업 사용법
4. [`docs/agent-harness.md`](docs/agent-harness.md) — `.claude/`가 무엇이고
   pull 하면 무엇이 달라지는지. Claude Code를 쓰든 안 쓰든 1절은 보세요

담당별로 이어서 읽을 것:

| 담당 | 문서 |
|---|---|
| LLM 파이프라인 (02·05) | `docs/llm-handover.md` |
| 선별·매핑 (03) | `docs/mapping-guide.md` |

### 착수하는 사람에게

담당 단계의 앞 단계가 아직 없어도 목업을 입력 삼아 바로 시작할 수 있습니다.
`mock/`은 `cases/C-001/`과 같은 레이아웃이라 CLI 인자만 바꿔 끼우면 됩니다.

```bash
.venv/Scripts/python.exe -m src.stage04_parse.parse \
  --in benchmark/datasets/C-001-webshell/mock/03_selection.json \
  --out /tmp/out/ --evidence <evidence_root>
```

검증 담당자는 `mock/05_findings.bad.json`을 넣으면
`mock/06_verified.bad.json`이 나와야 합니다. 기각 3유형이 들어 있습니다.
