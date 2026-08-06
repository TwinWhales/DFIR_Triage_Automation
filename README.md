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
python benchmark/validator_check.py
```

---

## 현재 상태

파이프라인 단계는 **아직 구현되지 않았습니다.** 위 실행/평가 명령은 목표
인터페이스이며, 지금 돌리면 빈 스크립트입니다.

| | 상태 |
|---|---|
| `schemas/` 6개 | 확정 (동결 대상) |
| `src/common/` | 구현 완료 — `io` `schema` `errors` `refs` `attack` |
| C-001 목업 세트 | 작성 완료 |
| **06 근거 검증** | **구현 완료** — 체커 3종 + `--checkers` 조합 |
| 02·03·04·05·07 단계 | 미착수 |

```bash
python -m src.stage06_verify.verify \
  --findings benchmark/datasets/C-001-webshell/mock/05_findings.json \
  --parsed   benchmark/datasets/C-001-webshell/mock/04_parsed/ \
  --out      /tmp/06_verified.json
```

### 먼저 읽을 것

1. `work-guide.md` — 설계 전제와 팀 분담
2. `schemas/README.md` — 데이터 계약, **스펙에 없어서 정한 것 7건**
3. `benchmark/datasets/C-001-webshell/README.md` — 목업 사용법

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
