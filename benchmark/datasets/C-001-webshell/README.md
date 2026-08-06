# C-001 — 웹셸 침해 케이스 (목업 데이터셋)

`docs/pipeline-io-spec.md`의 C-001 예시를 실제 파일로 옮긴 것입니다.
**아직 어떤 코드도 이 파일들을 생성하지 않았습니다. 전부 손으로 작성한 목업입니다.**

목적은 하나입니다: 각 담당자가 앞 단계의 완성을 기다리지 않고 착수할 수 있게 하는 것.

## 구성

| 경로 | 용도 |
|---|---|
| `input.json` | 벤치마크 진입점 (`mock/01_input.json`과 동일 내용) |
| `ground_truth.json` | 정답. 재현율 계산의 기준 |
| `evidence/` | 실제 증거 이미지 위치 (Git 제외) |
| `mock/` | 전 단계 목업 세트. `cases/C-001/`과 동일한 레이아웃 |

`mock/`이 `cases/C-001/`과 같은 구조인 이유는 CLI 인자를 그대로 바꿔 끼울 수 있게 하기 위함입니다.

```bash
# 아직 select.py가 없어도, 03 목업을 입력 삼아 파싱 단계를 개발할 수 있습니다
python -m src.stage04_parse.parse \
  --in benchmark/datasets/C-001-webshell/mock/03_selection.json \
  --out /tmp/out/ --evidence <evidence_root>
```

## 정상 경로

`01_input` → `02_scenario` → `03_selection` → `04_parsed/` → `05_findings` → `06_verified` → `07_report`

`06_verified.json`은 passed 2건 / unverifiable 1건 / rejected 0건입니다.

## 음성 픽스처 (기각 케이스)

검증 담당자용입니다. `05_findings.bad.json`을 넣으면 `06_verified.bad.json`이 나와야 합니다.

| finding | 기각 사유 | 재현하는 상황 |
|---|---|---|
| F4 | `ref_not_found` | 파싱 결과에 아예 없는 `MFT#99999`를 참조 |
| F5 | `value_mismatch` | `MFT#12345`의 `si_ctime`을 다른 값으로 주장 |
| F6 | `ref_not_in_input` | 파싱은 됐지만 LLM에 전달되지 않은 `MFT#12400`을 참조 |

F6이 성립하려면 `mft.jsonl`에는 있으나 `input_refs`에는 없는 레코드가 필요합니다.
`MFT#12400`(`health.aspx`)이 그 역할입니다 — 선별 범위에는 들어오지만 flag가 없어
`record_filter.py`의 상위 N건 추림에서 빠진 레코드를 가정한 것입니다.

## 스펙 문서와 의도적으로 다른 부분

`docs/pipeline-io-spec.md`의 `_manifest.json` 예시는 `record_count`가 1842 / 517입니다.
여기서는 실제 `.jsonl` 줄 수(3 / 2)에 맞췄습니다. 스펙의 숫자는 실제 규모를 보여주는
예시일 뿐이고, 목업은 **파일 간 정합성이 깨지지 않는 것**이 더 중요하기 때문입니다.
`record_count == wc -l` 을 단언하는 테스트를 짤 수 있어야 합니다.

## 확정되지 않은 것

`ground_truth.json`의 스키마는 초안입니다. `work-guide.md` 8장의 지표 정의
(재현율 = 정답 아티팩트 중 selected 비율)에서 역산했으나,
`benchmark/ground_truth_schema.json` 작성 시 팀 합의가 필요합니다.
