# 프로젝트 디렉터리 구조

## 전체 트리

```
dfir-triage/
├── README.md
├── requirements.txt
├── run_pipeline.sh
│
├── src/
│   ├── common/
│   │   ├── __init__.py
│   │   ├── io.py                  # 공통 헤더 생성/검증, JSON·JSONL 읽기·쓰기
│   │   ├── schema.py              # JSON Schema 로드 및 검증 래퍼
│   │   ├── errors.py              # errors.jsonl 기록 인터페이스
│   │   ├── refs.py                # ref 문자열 생성·파싱 (MFT#12345 등)
│   │   └── attack.py              # ATT&CK ID 유효성 검사, 기법명 조회
│   │
│   ├── stage02_normalize/
│   │   ├── normalize.py           # CLI 진입점
│   │   ├── prompts/
│   │   │   ├── normalize_system.txt
│   │   │   └── normalize_fewshot.json
│   │   ├── llm_client.py          # Ollama/llama.cpp 호출 래퍼
│   │   └── alert_adapter.py       # EDR·SIEM 알럿 → 스키마 직결 변환 (LLM 미사용)
│   │
│   ├── stage03_select/
│   │   ├── select.py              # CLI 진입점
│   │   ├── mapping_loader.py      # mappings/ YAML 로드 및 병합
│   │   └── scope_resolver.py      # scope_template 변수 치환 ({web_root} 등)
│   │
│   ├── stage04_parse/
│   │   ├── parse.py               # CLI 진입점, 선별 결과에 따라 파서 디스패치
│   │   ├── evidence.py            # 아티팩트 이름 → 바이트 스트림 (파일/폴더)
│   │   ├── parsers/
│   │   │   ├── base.py            # 파서 공통 인터페이스
│   │   │   ├── mft.py             # $MFT 바이트 레벨 파싱
│   │   │   ├── usnjrnl.py         # $UsnJrnl:$J 파싱
│   │   │   ├── evtx.py            # EVTX 파싱
│   │   │   ├── registry.py        # SYSTEM/SOFTWARE/Amcache 하이브 파싱
│   │   │   ├── recentfilecache.py # RecentFileCache.bcf 파싱 (Windows 7 전용)
│   │   │   └── prefetch.py        # Windows/Prefetch/*.pf 파싱
│   │   ├── structs/
│   │   │   ├── mft_record.py      # MFT 레코드 헤더, $SI, $FN, $DATA 구조체
│   │   │   ├── usn_record.py      # USN_RECORD_V2 구조체
│   │   │   ├── prefetch_record.py # .pf 헤더·파일 정보·메트릭·볼륨 구조체
│   │   │   ├── recentfilecache_record.py  # .bcf 헤더·항목 구조체
│   │   │   └── xpress_huffman.py  # MAM(LZXPRESS Huffman) 압축 해제
│   │   ├── osinfo.py              # 증거의 Windows 버전 판정, 버전별 아티팩트 가용성
│   │   └── flagging.py            # flags 어휘 룰 적용
│   │
│   ├── stage05_interpret/
│   │   ├── interpret.py           # CLI 진입점
│   │   ├── prompts/
│   │   │   ├── interpret_system.txt
│   │   │   └── claims_extract.txt # 문장→claims 분리 시 2차 호출용
│   │   ├── record_filter.py       # 신호 판정·활동 시각
│   │   ├── allocation.py          # 아티팩트별 자릿수 배분(쿼터)
│   │   └── llm_client.py
│   │
│   ├── stage06_verify/
│   │   ├── verify.py              # CLI 진입점
│   │   ├── checkers/
│   │   │   ├── ref_exists.py      # 참조 존재 검증
│   │   │   ├── ref_in_input.py    # input_refs 범위 검증
│   │   │   └── value_match.py     # 값 일치 검증 (필드 타입별 비교기)
│   │   └── comparators.py         # 타임스탬프·경로·문자열 비교 규칙
│   │
│   └── stage07_report/
│       ├── report.py              # CLI 진입점
│       ├── prompts/
│       │   └── report_system.txt
│       └── templates/
│           └── report.md.j2       # 고정 섹션 포함 Jinja2 템플릿
│
├── schemas/
│   ├── input.schema.json
│   ├── scenario.schema.json
│   ├── selection.schema.json
│   ├── parsed_record.schema.json
│   ├── findings.schema.json
│   └── verified.schema.json
│
├── mappings/
│   ├── _flags.yaml                # flags 어휘 정의
│   ├── _artifacts.yaml            # 아티팩트 카탈로그 (경로, 파서, OS별 가용성)
│   ├── windows/
│   │   ├── T1505.003.yaml         # Web Shell
│   │   ├── T1136.001.yaml         # Create Account
│   │   ├── T1543.003.yaml         # Windows Service
│   │   ├── T1053.005.yaml         # Scheduled Task
│   │   └── T1070.006.yaml         # Timestomp
│   └── linux/
│       └── .gitkeep
│
├── benchmark/
│   ├── datasets/
│   │   ├── C-001-webshell/
│   │   │   ├── input.json
│   │   │   ├── evidence/          # 실제 이미지는 Git 제외, 경로만 기록
│   │   │   └── ground_truth.json
│   │   └── C-002-ransomware/
│   ├── ground_truth_schema.json
│   ├── evaluate.py                # 재현율·환각률·소요시간 산출
│   ├── validator_check.py         # 검증기 자체 오탐 확인용 정답 문장 30건 테스트
│   └── results/
│       └── .gitkeep
│
├── cases/                         # 실행 산출물 (Git 제외)
│   └── .gitkeep
│
├── tests/
│   ├── test_mft_parser.py
│   ├── test_usn_parser.py
│   ├── test_evtx_parser.py
│   ├── test_mapping_loader.py
│   ├── test_verify_checkers.py
│   └── fixtures/
│       ├── mft_sample.bin         # 소형 테스트 이미지 조각
│       └── expected_mft.jsonl
│
├── docs/
│   ├── pipeline-io-spec.md        # 단계별 입출력 계약
│   ├── mapping-guide.md           # 매핑 테이블 작성 규칙
│   ├── artifact-notes.md          # 파싱 중 확인한 온디스크 구조 메모
│   ├── limitations.md             # 미지원 범위, 알려진 한계
│   └── meeting-notes/
│
└── tools/
    ├── make_case.py               # 신규 케이스 디렉터리 생성
    ├── sync_flag_enum.py          # _flags.yaml → 스키마 enum 생성
    ├── compare_mft.py             # $MFT 파싱 회귀 대조
    ├── scan_hive_cells.py         # 하이브 nk 셀 직접 계수 (커버리지 정답지)
    ├── decode_hive_values.py      # 하이브 값을 명세대로 직접 디코딩
    ├── scan_prefetch.py           # .pf를 파서와 다른 길로 읽어 대조
    ├── scan_recentfilecache.py    # .bcf를 길이 필드 없이 읽어 대조
    ├── inspect_jsonl.py           # 04 산출물 요약·조회 + 매니페스트 대조
    └── hexdump_record.py          # ref의 원본 바이트를 되짚어 덤프하고 대조
```

---

## 설계 근거

### 단계별 디렉터리 분리

`stage02_` ~ `stage07_` 접두어를 붙여 실행 순서가 디렉터리명에 드러나게 했습니다. 팀원이 자기 담당 디렉터리 안에서만 작업하면 되고, 다른 단계의 코드를 건드릴 일이 없습니다. 단계 간 유일한 접점은 `src/common/`과 `schemas/`입니다.

`llm_client.py`가 02와 05에 중복으로 있는 것은 의도적입니다. 두 단계가 서로 다른 모델·파라미터를 쓸 수 있어야 하기 때문입니다. 정규화는 짧은 구조화 출력이라 작은 모델로도 되지만, 해석은 더 큰 모델이 필요할 수 있습니다.

### `alert_adapter.py`를 02 단계에 둔 이유

EDR·SIEM 알럿은 이미 구조화되어 있으므로 LLM 없이 스키마로 직결 변환됩니다. 하지만 출력 형식은 자연어 경로와 동일해야 하므로 같은 단계 안에 둡니다. `normalize.py`가 `source_type`을 보고 둘 중 하나로 분기합니다.

이 구조 덕분에 LLM이 준비되지 않은 상태에서도 03단계 이후를 개발·테스트할 수 있습니다.

### `parsers/`와 `structs/` 분리

`structs/`는 온디스크 구조를 그대로 옮긴 정의(오프셋, 크기, 필드 타입)이고, `parsers/`는 그것을 읽어 레코드를 만드는 로직입니다. 구조 정의를 분리해 두면 스펙 문서와 대조하기 쉽고, 나중에 `docs/artifact-notes.md`와 함께 팀의 학습 성과물로 제출할 수 있습니다.

### `checkers/` 개별 파일

검증 항목마다 파일을 나눈 것은 각각이 독립적으로 켜고 끌 수 있어야 하기 때문입니다. 검증 강도별로 실험할 때 `--checkers ref_exists,value_match` 같은 옵션으로 조합을 바꿔가며 통과율 변화를 측정할 수 있습니다.

### `benchmark/`를 별도 최상위로

평가는 파이프라인의 일부가 아니라 파이프라인을 대상으로 하는 별개 작업입니다. 담당자가 `src/`를 몰라도 CLI만 호출해서 평가할 수 있어야 하므로 분리했습니다.

`validator_check.py`는 앞서 논의한 "검증기 자체의 오탐 확인" 절차입니다. 사람이 직접 옳다고 판단한 문장 30건을 넣었을 때 몇 건이 통과하는지 측정합니다. 검증기가 너무 엄격해지는 것을 막는 안전장치입니다.

### `cases/`는 Git에서 제외

실행 산출물은 케이스당 수백 MB가 될 수 있고 증거 데이터를 포함하므로 커밋하지 않습니다. `.gitignore`에 `cases/*`와 `benchmark/datasets/*/evidence/`를 넣습니다. 대신 발표용으로 선별한 산출물은 `docs/`에 별도 복사합니다.

### `tools/inspect_jsonl.py`

`04_parsed/`는 파일이 스무 개가 넘고 `$MFT`·`$UsnJrnl`은 수십 MB입니다.
"뭐가 몇 건 나왔나", "이 경로가 걸린 레코드가 있나"를 보는 자리이고, 팀
기계는 Windows라 `jq`가 있다고 가정할 수 없습니다.

**요약은 `_manifest.json`을 그대로 옮기지 않고 파일을 세어 맞춰 봅니다.**
매니페스트의 `record_count`는 07단계 보고서가 싣는 값인데, 실물 실행에서
그것이 파일과 같은지 아무도 보지 않았습니다(벤치마크 데이터셋만 테스트가
대조합니다). `ref` 유일성과 `record_num`—`ref` 일치도 함께 봅니다. 앞의
것은 05·06단계에 가서야 터지고, 뒤의 것은 스키마가 보지 않는 불변식입니다.
하나라도 어긋나면 종료 코드가 1입니다.

원본 바이트가 필요하면 `hexdump_record.py`로 넘깁니다. 흉내 내면 진실이
둘이 됩니다.

### `tools/hexdump_record.py`

`ref`를 주면 그 레코드의 원본 바이트를 덤프합니다. **덤프만 하지 않고
거기 있는 바이트가 정말 그 레코드인지 대조합니다** — 그러지 않으면 "봤다"와
"맞다"가 구별되지 않습니다.

대조는 파서로 다시 파싱해서 하지 않습니다. 레코드가 **자기 안에 들고 있는
식별자**로 합니다(`$MFT` 헤더의 레코드 번호와 업데이트 시퀀스, USN 레코드의
USN, evtx 의 EventRecordID). 그 값을 쓴 것은 Windows 이므로 우리 해석과
독립이고, 파서가 틀렸다면 어긋나야 정상입니다.

`offset` 은 동결된 스키마의 필수 필드이고 직접 구현의 이유이기도 합니다
(`work-guide.md` 3.1). 그 주장을 시연으로 바꾸는 자리가 이 도구입니다 —
발표에서 "우리 도구가 이 오프셋을 실제로 읽었다"를 보여 주는 것도 여기입니다.

---

## 팀 분담 매핑

| 영역 | 디렉터리 | 의존 관계 |
|---|---|---|
| 파싱 계층 | `src/stage04_parse/`, `src/common/refs.py`, `tests/` | `03_selection.json` 목업만 있으면 즉시 착수 가능 |
| LLM 파이프라인 | `src/stage02_normalize/`, `src/stage05_interpret/`, `src/stage07_report/` | 스키마 확정 후 착수 |
| 선별·매핑 | `src/stage03_select/`, `mappings/` | 스키마 확정 후 즉시 착수, 도메인 조사 비중 큼 |
| 검증·평가 | `src/stage06_verify/`, `benchmark/` | 04·05 출력 목업으로 선행 개발 가능 |

`src/common/`과 `schemas/`는 공용이므로 변경 시 전체 공지가 필요합니다. 초기에 한 명이 골격을 잡고 확정한 뒤 동결하는 편이 낫습니다.

---

## 착수 순서

1. `schemas/` 6개 파일 작성 및 확정
2. `src/common/` 골격 구현 (io, schema, errors, refs)
3. 각 단계 목업 입출력 파일을 `benchmark/datasets/C-001-webshell/`에 손으로 작성
4. 이후 각 담당자가 목업을 입력 삼아 병렬 착수

3번을 건너뛰면 담당자들이 서로를 기다리게 됩니다. 손으로 만든 예시 파일 한 세트가 전체 병렬화의 조건입니다.
