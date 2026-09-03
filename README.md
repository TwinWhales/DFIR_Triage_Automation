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

`requirements.txt`의 `dissect.target`은 **raw 디스크 이미지를 직접 열
때만** 필요합니다. 추출된 아티팩트 폴더만 쓴다면 없어도 동작하고,
없을 때는 이미지를 열려는 순간에만 설치 안내와 함께 실패합니다.

02·05단계를 실제 모델로 돌리려면 [Ollama](https://ollama.com)가 필요합니다.

```bash
ollama pull qwen2.5:7b
```

## 실행

```bash
.venv/Scripts/python.exe tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01
PYTHON=.venv/Scripts/python.exe ./run_pipeline.sh C-001 /mnt/evidence/WEB01
```

## 산출물 확인 — 실제 사건에서 거치는 두 자리

**아래 "평가"는 벤치마크용입니다.** 실제 케이스에서 보는 것은 이 둘입니다.

### 04단계 직후 — 산출물이 스스로와 맞는가

```bash
.venv/Scripts/python.exe tools/inspect_jsonl.py --parsed cases/C-001/04_parsed
```

`_manifest.json`이 적은 건수가 실제 줄 수와 같은지, `ref`가 유일한지,
`record_num`이 `ref`와 같은지, 레코드가 제 파일에 있는지를 봅니다.
**하나라도 어긋나면 종료 코드가 1입니다.**

앞의 둘을 여기서 안 보면 05단계에 가서야 터지고, 매니페스트의 건수는
**07단계 보고서가 그대로 싣는 값**입니다. 60GB 이미지를 돌린 결과에는
이 대조 상대가 달리 없습니다.

경로·플래그·`event_id`로 걸러 보는 것도 같은 도구입니다.

```bash
.venv/Scripts/python.exe tools/inspect_jsonl.py --parsed cases/C-001/04_parsed \
  --flag deleted --path "Users\Public" --limit 20
```

### 보고서를 받은 뒤 — 문장에서 원본 바이트로

`07_report.md`의 타임라인은 항목마다 `ref`를 답니다. 그 `ref`를 그대로
넘기면 디스크의 원본 바이트가 나옵니다.

```bash
.venv/Scripts/python.exe tools/hexdump_record.py MFT#12345 \
  --parsed cases/C-001/04_parsed --evidence evidence/<image>.001 --volume 1
```

덤프만 하지 않고 **거기 있는 바이트가 정말 그 레코드인지 대조합니다** —
`$MFT`는 헤더의 레코드 번호와 업데이트 시퀀스, evtx는 EventRecordID처럼
**레코드가 자기 안에 들고 있는 값**으로 맞춥니다. 우리가 해석해 넣은 값이
아니라 Windows가 쓴 값이라, 파서가 틀렸다면 어긋나야 정상입니다.

보고할 사실을 원본으로 뒷받침해야 할 때 여기서 끝납니다. 파서를 고친
뒤라면 아티팩트마다 20건씩 뽑아 한 번에 봅니다(`--sample 20`).

---

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
35건을 넣어 몇 건이 통과하는지 봅니다. 하나라도 기각되면 환각률이 실제
환각이 아니라 표기 차이를 세고 있다는 뜻입니다.

**이 장치에도 구멍이 생깁니다.** 새로 생긴 표기 부류가 사례에 없으면
33건 전부 통과를 보고하면서 실제로는 정상 문장을 기각합니다. 실제로
겪었습니다([`limitations.md`](docs/limitations.md) "06단계가 표기 오류를
환각으로 셌다"). 검증기를 손대면 사례부터 추가하세요.

---

## 현재 상태

파이프라인은 **01→07 전 구간이 관통합니다.** 카탈로그의 아티팩트에는
전부 파서가 있고, **실물 디스크 이미지와 실제 sLLM으로 관통을
확인했습니다**(2026-08-24, 60GB 물리 디스크 + Ollama `qwen2.5:7b`).

**단, 기본값 그대로는 아닙니다.** 아티팩트가 여럿 걸린 실제 케이스에서는
05단계 프롬프트가 모델의 컨텍스트 창을 넘겨 중단됩니다. `--limit` 을
낮춰야 통과합니다 — 실측과 원인은
[`limitations-log.md`](docs/limitations-log.md) "05단계 프롬프트가 컨텍스트
창을 넘었다" 절에 있습니다(2026-08-26 해결됨). 알려진 한계 전체는
[`limitations.md`](docs/limitations.md) 입니다.

| | 상태 |
|---|---|
| `schemas/` 6개 | 확정 (동결 대상) |
| `src/common/` | 구현 완료 — `io` `schema` `errors` `refs` `attack` `llm` |
| C-001 목업 세트 | 작성 완료 |
| 02 시나리오 정규화 | 구현 완료 — 알럿 어댑터·스텁·Ollama 전부 실동작 |
| 03 아티팩트 선별 | 구현 완료 — 매핑 30개 + 카탈로그 22종 (`mapping_table_version` 1.1) |
| **04 파싱** | 구현 완료 — `$MFT`(analyzeMFT 기반, MIT), `$UsnJrnl`(자체 구현), `evtx` 14채널(python-evtx 기반), `registry` 3하이브(python-registry 기반), `prefetch`·`recentfilecache`(자체 구현). 증거의 Windows 버전을 판정해 그 버전에 없는 아티팩트를 가려 냅니다 |
| 05 sLLM 해석 | 구현 완료 — 아티팩트별 자릿수 배분·스텁·Ollama 전부 실동작 |
| 06 근거 검증 | 구현 완료 — 체커 3종 + `--checkers` 조합 |
| 07 결과 보고 | 구현 완료 — Jinja2 템플릿 (LLM 미사용) |
| **평가 (`benchmark/`)** | **구현 완료** — 단계별 진단 + 검증기 오탐 확인 |

### 남은 것 셋

**검증기가 정상 문장을 환각으로 셉니다.** 2026-08-26 실측 — 실물 이미지
케이스에서 06단계가 소견 4건을 전부 기각해 환각률 100%를 냈는데, 사람이
열어 보니 **진짜 환각은 1건**이고 셋은 표기 차이였습니다(대소문자,
프리패치 볼륨 GUID). `benchmark/validator_check.py` 는 같은 시점에
"오탐 없음 35/35"를 보고했습니다 — 사례에 없는 표기 부류라 못 잡았습니다.
**이 상태의 환각률 수치는 쓸 수 없습니다.** 원인과 재현은
[`limitations.md`](docs/limitations.md) "검증기가 경로 표기 차이를
환각으로 센다" 절.

**정답 데이터가 없습니다.** `ground_truth.json`은 스펙 예시에서 역산한
것이라 자기채점이고, `evaluate.py`가 그 사실을 경고로 띄웁니다. 발표에
쓸 수치는 사람이 실제 증거를 보고 만든 정답에서 나와야 합니다.

**"환각 없이 동작한다"고 말할 수 없습니다.** 실물 실행에서 나온 환각률
0%는 `0 / 1` — findings 한 건으로 나온 값입니다. 게다가 그 실행에서
실제로 관측된 환각(없는 하위기법 `T1200.001` 5회, `entities.paths`에
없는 경로 3회/3회, 호스트명 언어 드리프트)은 **전부 02단계에서 나왔고
02에는 검증 계층이 없어 집계에 들어가지 않습니다.** 06단계가 보는 것은
05단계의 `claims` 삼중항뿐입니다.

### 실측 소요 시간 (60GB 이미지, `qwen2.5:7b`)

| 단계 | 초 |
|---|---|
| 02 정규화 (실제 추론) | 108.7 |
| 03 선별 | 0.5 |
| 04 파싱 | 4.2 |
| 05 해석 (실제 추론) | 215.4 |
| 06 검증 / 07 보고 | 0.7 |
| **합계** | **329.5** |

**시간을 지배하는 것은 이미지 크기가 아니라 모델 호출 두 번입니다** —
전체의 98%. 04단계는 선별 범위에 좌우됩니다(`$MFT` 98,151건이 걸린
실행은 약 4분).

**위 표는 기법 3개짜리 케이스입니다.** 기법 8개가 걸려 아티팩트 10종이
파싱된 케이스에서는 05단계가 프롬프트 크기 때문에 3회 재시도 끝에
중단됐습니다(약 25분 소모, 소견 0건). `--limit 15` 로 낮추면 한 번에
통과합니다. 05단계 시간은 레코드 수가 아니라 **프롬프트 토큰 수**를
따라갑니다.

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

### 디스크 이미지를 바로 줘도 됩니다

`--evidence`에 폴더 대신 **raw 이미지 파일**을 주면 `dissect.target`이
볼륨 계층을 맡습니다. 추출 단계가 필요 없습니다.

```bash
.venv/Scripts/python.exe -m src.stage04_parse.parse \
  --in cases/K-001/03_selection.json --out cases/K-001/04_parsed/ \
  --evidence evidence/0824test.001 --volume 1
```

**NTFS가 여럿이면 `--volume N`으로 사람이 고릅니다.** 지정하지 않으면
후보를 크기·이름과 함께 보여 주고 멈춥니다 — 도구가 크기로 추측하면
복구 파티션과 시스템 볼륨을 바꿔 골라도 "아티팩트 없음"이 아니라
**다른 볼륨의 결과가 조용히 나옵니다.**

```
evidence/0824test.001: NTFS 파일시스템이 2개 발견됐습니다. ...
    --volume 0    0.4GiB  Basic data partition
    --volume 1    59.4GiB  Basic data partition
```

일반적인 Win10/11 물리 디스크는 **복구 파티션도 NTFS라 거의 항상 이
분기를 탑니다.** 논리 드라이브만 뜬 이미지가 예외입니다. E01은 같은
경로를 타도록 돼 있으나 실물로 확인하지 않았습니다.

### 파서별 메모

- **04 파싱** — `$MFT`는 메인 파서([analyzeMFT](third_party/README.md) 기반,
  MIT)가 실제로 읽습니다. `native`(기본)와 `--parser reference` 어느 쪽으로
  불러도 같은 파서를 씁니다.
- **02·05의 LLM** — `--llm ollama`가 실제 호출이고, `--llm stub`은 기록된
  응답을 재생합니다. 스텁도 프롬프트 조립·응답 파싱·스키마 검증·재시도까지
  실제 경로를 그대로 지나가고 네트워크 호출만 대체됩니다.

  실행할 때 **`--num-ctx`와 `--timeout`을 의식하세요.** Ollama 기본
  컨텍스트는 4,096이라 05단계 프롬프트가 **말없이 잘립니다.** 기본값을
  32,768로 두었지만 그것도 넘으면 같은 일이 벌어집니다 — 넘는지는
  아무도 검사하지 않습니다([`limitations.md`](docs/limitations.md) 5장).

- **evtx** — 채널 14종. 기본 탑재 로그(`Security`·`System`·`Application`·
  `Firewall`·`BITS`·`NetworkProfile`), 장치 연결(`DriverFrameworks`·
  `KernelPnP`), 키오스크 제한환경(`AssignedAccess` 3종), 원격 세션
  (`RDPConnection`·`RDPSession`), 그리고 `Sysmon`. **`Sysmon`만 기본
  탑재가 아닙니다** — 대상에 설치돼 있어야 하고, 없으면
  `artifact_not_found`로 빠집니다.
  온디스크 계층은 [python-evtx](docs/artifact-notes.md)가
  맡고, 청크 순회 감사·필드 추출·`ref`/`offset` 규약은 우리 어댑터가 합니다.
  채널이 달라도 형식이 같아 파서는 하나이고, **아티팩트마다 인스턴스를
  따로 만듭니다** — 공유하면 한 채널의 레코드가 다른 접두어로 나가고
  06단계가 그것을 환각으로 셉니다.

  **`EventID`는 제공자 안에서만 유일합니다.** 채널을 늘리면서 실제로
  겹쳤습니다(NetworkProfile의 `10000`과 Kernel-PnP의 `10000`). 플래그 룰을
  쓸 때 `evtx:*` 대신 정확한 아티팩트 이름을 거는 이유입니다.

- **registry** — `SYSTEM`·`SOFTWARE`·`Amcache` 하이브. 온디스크 계층은 python-registry가
  맡고, 경로 재구성·`CurrentControlSet` 해석·범위 밖 서브트리 가지치기는
  우리 어댑터가 합니다. 신호가 04단계 플래그가 아니라 **선별에서** 나오는
  아티팩트라 카탈로그에 `signal_source: scope`로 표시돼 있고, 05단계 배분이
  그것을 보고 자리를 줍니다([`limitations.md`](docs/limitations.md) 6-7).

- **prefetch** — 폴더 하나가 아티팩트 하나입니다. 온디스크 구조도 Win10
  이후의 MAM(LZXPRESS Huffman) 압축 해제도 **전부 자체 구현**입니다 —
  `ctypes`로 `RtlDecompressBufferEx`를 부르면 Windows에서만 읽히는
  아티팩트가 됩니다. 레지스트리와 같은 이유로 `signal_source: scope`입니다
  ([`limitations.md`](docs/limitations.md) 6-8).

`$MFT` 파싱 회귀는 `tools/compare_mft.py`와 합성 레코드 테스트
(`tests/test_mft_parser.py`)로 MFTECmd 없이 `pytest` 안에서 검증합니다.

evtx는 **외부 도구 대조를 실제로 마쳤습니다.** `wevtutil`(Windows 기본
탑재, 마이크로소프트 자체 파서)과 8,257레코드를 대조해 레코드 수·
`EventRecordID`·`event_id`·`computer`·타임스탬프가 전부 일치했습니다.
기록은 [`docs/artifact-notes.md`](docs/artifact-notes.md)에 있습니다.

레지스트리는 **커버리지와 값 대조를 둘 다 마쳤습니다.**
`tools/scan_hive_cells.py`가 서브키 목록을 따라가지 않고 셀을 직접 걸어
`nk`를 세는데, 파서 결과와 SYSTEM 34,855건·SOFTWARE 156,716건이 정확히
일치했습니다. 값은 `nk`/`vk`를 명세대로 직접 디코딩한 독립 도구와 맞춰
46,147키 중 46,142건이 일치했습니다(나머지 5건은 대조 도구가 big data
레코드를 구현하지 않은 것이라 파서 문제가 아닙니다). `reg load` 대조는
아직입니다.

이 대조로만 드러난 것이 셋 있습니다 — **한글 문자열 절단**,
`MULTI_SZ` 종결자, 타임스탬프 반올림. 셋 다 조용히 틀리는 종류라
대조하지 않았으면 그대로 갔습니다([`limitations.md`](docs/limitations.md)).

프리패치는 외부 도구가 없어 **같은 파일을 다른 경로로 읽는 스캐너**를
만들어 맞췄습니다(`tools/scan_prefetch.py` — 메트릭 배열을 걷지 않고
문자열 블록을 쪼갭니다). 실물 이미지 137건에서 적재 경로 10,195건
일치, 불일치 0건.

```bash
.venv/Scripts/python.exe tools/scan_hive_cells.py --hive <volume>/Windows/System32/config/SYSTEM   --ours cases/C-001/04_parsed/registry_system.jsonl
```

### 관통 실행해 보기

```bash
.venv/Scripts/python.exe tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01 \
  --input benchmark/datasets/C-001-webshell/input.json \
  --seed-parsed benchmark/fixtures/C-001-webshell/04_parsed

PYTHON=.venv/Scripts/python.exe ./run_pipeline.sh C-001 /mnt/evidence/WEB01 benchmark/fixtures/C-001-webshell
```

`cases/C-001/`에 01부터 07까지 쌓이고 `07_report.md`가 나옵니다.
세 번째 인자를 빼면 스텁 대신 Ollama를 호출합니다.

**실물 이미지 + 실제 모델로 돌릴 때는 단계를 직접 부르는 편이 낫습니다.**
`run_pipeline.sh`는 아직 `--volume`·`--num-ctx`·`--timeout`을 넘기지
않습니다.

```bash
C=cases/K-001
.venv/Scripts/python.exe -m src.stage02_normalize.normalize \
  --in $C/01_input.json --out $C/02_scenario.json \
  --llm ollama --model qwen2.5:7b --temperature 0.3 --timeout 900

.venv/Scripts/python.exe -m src.stage03_select.select \
  --in $C/02_scenario.json --out $C/03_selection.json --mappings mappings/

.venv/Scripts/python.exe -m src.stage04_parse.parse \
  --in $C/03_selection.json --out $C/04_parsed/ \
  --evidence evidence/<image>.001 --volume 1

# 04 산출물이 스스로와 맞는지 본다. 어긋나면 여기서 멈춘다 (종료 코드 1)
.venv/Scripts/python.exe tools/inspect_jsonl.py --parsed $C/04_parsed

.venv/Scripts/python.exe -m src.stage05_interpret.interpret \
  --in $C/04_parsed/ --scenario $C/02_scenario.json --selection $C/03_selection.json \
  --out $C/05_findings.json --llm ollama --model qwen2.5:7b \
  --temperature 0.3 --timeout 900 --num-ctx 32768

.venv/Scripts/python.exe -m src.stage06_verify.verify \
  --findings $C/05_findings.json --parsed $C/04_parsed/ --out $C/06_verified.json

.venv/Scripts/python.exe -m src.stage07_report.report \
  --in $C/06_verified.json --findings $C/05_findings.json \
  --selection $C/03_selection.json --scenario $C/02_scenario.json \
  --parsed $C/04_parsed/ --out $C/07_report.md
```

07단계에 `--scenario`·`--parsed`를 빼먹으면 보고서의 개요와 "확인한
아티팩트"가 비어 나옵니다. 실패하지 않고 **그 자리에 이유를 적고**
넘어가므로 눈치채기 어렵습니다.

**`--temperature 0.3`인 이유** — 기본값 0은 결정론적이라 스키마 위반이
나면 **재시도가 같은 답을 반복합니다.** 실측에서 없는 하위기법
`T1200.001`을 다섯 번 연속 냈습니다. 재현성과 재시도가 상충하는
자리이고, 지금은 사람이 고릅니다.

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
  --in benchmark/golden/C-001-webshell/03_selection.json \
  --out /tmp/out/ --evidence <evidence_root>
```

검증 담당자는 `mock/05_findings.bad.json`을 넣으면
`mock/06_verified.bad.json`이 나와야 합니다. 기각 3유형이 들어 있습니다.
