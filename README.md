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
python -m pytest
```

## 실행

```bash
python tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01
./run_pipeline.sh C-001 /mnt/evidence/WEB01
```

## 평가

```bash
python benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell
```

수치만 내지 않고 **어느 단계에서 놓쳤는지**를 가릅니다. 정답 레코드마다
`파싱 → 전달 → 인용 → 검증통과` 네 단계를 따로 세므로, 고칠 곳이 파서인지
매핑인지 프롬프트인지 바로 보입니다.

```bash
python benchmark/validator_check.py
```

검증기가 과엄격해지는 것을 막는 장치입니다. 사람이 옳다고 판단한 문장
33건을 넣어 몇 건이 통과하는지 봅니다. 하나라도 기각되면 환각률이 실제
환각이 아니라 표기 차이를 세고 있다는 뜻입니다.

---

## 현재 상태

파이프라인 단계는 **아직 구현되지 않았습니다.** 위 실행/평가 명령은 목표
인터페이스이며, 지금 돌리면 빈 스크립트입니다.

| | 상태 |
|---|---|
| `schemas/` 6개 | 확정 (동결 대상) |
| `src/common/` | 구현 완료 — `io` `schema` `errors` `refs` `attack` |
| C-001 목업 세트 | 작성 완료 |
| 02 시나리오 정규화 | 구현 완료 — 알럿 어댑터는 실동작, LLM은 **스텁** |
| 03 아티팩트 선별 | 구현 완료 — 매핑 5개 + 카탈로그 |
| **04 파싱** | 구현 완료 — `$MFT` 메인 파서 (analyzeMFT 기반, MIT) |
| 05 sLLM 해석 | 구현 완료 — 레코드 추림은 실동작, LLM은 **스텁** |
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

`$MFT` 파싱 회귀는 `tools/compare_mft.py`와 합성 레코드 테스트
(`tests/test_mft_parser.py`)로 MFTECmd 없이 `pytest` 안에서 검증합니다.

### 관통 실행해 보기

```bash
python tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01 \
  --input benchmark/datasets/C-001-webshell/input.json \
  --seed-parsed benchmark/datasets/C-001-webshell/mock/04_parsed

./run_pipeline.sh C-001 /mnt/evidence/WEB01 benchmark/datasets/C-001-webshell/mock
```

`cases/C-001/`에 01부터 07까지 쌓이고 `07_report.md`가 나옵니다.
세 번째 인자를 빼면 스텁 대신 Ollama를 호출합니다.

### 먼저 읽을 것

1. `work-guide.md` — 설계 전제와 팀 분담
2. `schemas/README.md` — 데이터 계약, **스펙에 없어서 정한 것 8건**
3. `benchmark/datasets/C-001-webshell/README.md` — 목업 사용법

담당별로 이어서 읽을 것:

| 담당 | 문서 |
|---|---|
| LLM 파이프라인 (02·05) | `docs/llm-handover.md` |
| 선별·매핑 (03) | `docs/mapping-guide.md` |

### 착수하는 사람에게

담당 단계의 앞 단계가 아직 없어도 목업을 입력 삼아 바로 시작할 수 있습니다.
`mock/`은 `cases/C-001/`과 같은 레이아웃이라 CLI 인자만 바꿔 끼우면 됩니다.

```bash
python -m src.stage04_parse.parse \
  --in benchmark/datasets/C-001-webshell/mock/03_selection.json \
  --out /tmp/out/ --evidence <evidence_root>
```

검증 담당자는 `mock/05_findings.bad.json`을 넣으면
`mock/06_verified.bad.json`이 나와야 합니다. 기각 3유형이 들어 있습니다.
