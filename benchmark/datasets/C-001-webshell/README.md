# C-001 — 웹셸 침해 케이스

`docs/pipeline-io-spec.md`의 C-001 예시를 실제 파일로 옮긴 것입니다.
목적은 하나였습니다: 각 담당자가 앞 단계의 완성을 기다리지 않고 착수하는 것.

## 구성

| 경로 | 용도 |
|---|---|
| `input.json` | 벤치마크 진입점 (`fixtures/…/01_input.json`과 동일 내용) |
| `ground_truth.json` | 정답. 재현율 계산의 기준 |
| `evidence/` | 실제 증거 이미지 위치 (Git 제외) |

파이프라인 산출물은 이 폴더에 없습니다. 손으로 쓴 것은
`benchmark/fixtures/C-001-webshell/`에, 코드의 기대 출력은
`benchmark/golden/C-001-webshell/`에 있습니다. 둘 다 `cases/C-001/`과 같은
파일 이름을 쓰므로 CLI 인자를 그대로 바꿔 끼울 수 있습니다.

```bash
# 03 골든을 입력 삼아 파싱 단계만 돌릴 수 있습니다
.venv/Scripts/python.exe -m src.stage04_parse.parse \
  --in benchmark/golden/C-001-webshell/03_selection.json \
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

## 어느 파일이 "기대 출력"인가 — 이제 경로가 답합니다

전에는 이 자리에 파일별 성격을 적은 표가 있었습니다. **표가 필요하다는 것이
신호였습니다** — 역할이 다른 파일이 한 폴더(`mock/`)에 있으면 갱신해도 되는지를
매번 물어야 합니다. 지금은 갈라져 있습니다.

| 어디 | 성격 | 갱신 |
|---|---|---|
| `benchmark/fixtures/C-001-webshell/` | 손으로 쓴 입력·스텁 응답 | **재생성하지 않습니다.** 손으로 고치고 이유를 남깁니다 |
| `benchmark/golden/C-001-webshell/` | 코드가 만든 기대 출력 | 의도적으로 재생성합니다. diff가 곧 회귀입니다 |

테스트가 생성 결과와 대조합니다 (`generated_at`, `generator` 제외). 분류의
유일한 출처는 `tests/casepaths.py`의 `GOLDEN_FILES`이고, 자세한 근거는
[`benchmark/README.md`](../../README.md)에 있습니다.

`07_report.md`의 제목이 `F1 — T1505.003 Server Software Component: Web Shell`처럼
기법명인 것은 의도입니다. findings에는 제목 필드가 없고, 문장에서 요약 제목을
만들어 내면 **그것이 검증되지 않은 새 문장**이 됩니다. 이미 검증된 값인
기법 ID만 씁니다.

## 스펙 문서와 의도적으로 다른 부분

`docs/pipeline-io-spec.md`의 `_manifest.json` 예시는 `record_count`가 1842 / 517입니다.
여기서는 실제 `.jsonl` 줄 수(3 / 2)에 맞췄습니다. 스펙의 숫자는 실제 규모를 보여주는
예시일 뿐이고, 목업은 **파일 간 정합성이 깨지지 않는 것**이 더 중요하기 때문입니다.
`record_count == wc -l` 을 단언하는 테스트를 짤 수 있어야 합니다.

같은 이유로 F5 기각 사유의 `actual`을 `2026-07-20T03:14:22.1234567Z`로 적었습니다.
스펙 예시는 `2026-07-20T03:14:22Z`로 줄여 썼지만, 기각 사유의 `actual`은 분석가가
원본을 되짚는 값이므로 레코드에 저장된 그대로여야 합니다.

## 이 정답은 채점에 쓸 수 없습니다

`provenance`가 `derived_from_spec`입니다 — `docs/pipeline-io-spec.md`의 예시에서
역산한 것이라, 우리가 만든 답을 우리가 맞히는 자기채점입니다. `evaluate.py`가
결과 끝에 그 사실을 경고로 찍습니다. **발표에 쓸 수치는 사람이 실제 증거를
외부 도구로 보고 만든 정답(`provenance: human_analysis`)에서 나와야 합니다** —
절차는 노션 페이지에 있습니다 (`work.md` 8번에 링크).

## 확정되지 않은 것

스키마의 **지표 쪽**은 아직 초안입니다. `work-guide.md` 8장의 정의(재현율 =
정답 아티팩트 중 selected 비율)에서 역산했고, 팀 합의가 남아 있습니다.
정답의 출처(`provenance`)와 `ref` 접두어는 2026-09-02에 정해졌습니다.
