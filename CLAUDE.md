# CLAUDE.md

이 파일은 **매 세션 반복되는 것**만 담는다 — 실행 명령, 환경 함정, 어느 문서가
어느 주제의 권위인지. 설계 근거와 데이터 형식은 여기 옮겨 적지 않는다.
진실이 두 개가 되면 갈라지는 순간 어느 쪽이 맞는지 알 수 없게 된다.

---

## 환경

**파이썬은 반드시 `.venv/Scripts/python.exe`를 부른다.**

맨 `python`은 이 프로젝트의 것이 아니다 — 에이전트 하네스의 venv로 잡힌다.
버전이 똑같은 3.11이라 조용히 실행되다가 `Evtx`·`Registry` import에서 터진다.
문서의 명령 예시는 전부 이 경로로 맞춰 뒀다. 예외는 `python -m venv .venv`
한 줄뿐이다 — 가상환경을 만드는 명령이라 시스템 파이썬이어야 한다.

셸은 Windows지만 `run_pipeline.sh`·`scaffold.sh`는 bash용이다. `PYTHON` 환경
변수로 인터프리터를 넘긴다.

## 자주 쓰는 명령

```bash
# 테스트 — skip 은 evidence/ 이미지와 실제 모델이 없어 빠지는 것이라
#          기계마다 다르다 (2026-09-03: 1,252 통과 + 21 skip)
.venv/Scripts/python.exe -m pytest -q

# 관통 실행 (LLM 스텁, 세 번째 인자가 replay 디렉터리)
# MODE=assemble 이면 05 가 조립 경로로 돈다 (재생 파일이 05_selection.json 이다)
PYTHON=.venv/Scripts/python.exe bash run_pipeline.sh C-001 /mnt/evidence/WEB01 \
  benchmark/fixtures/C-001-webshell

# 단계 하나만
.venv/Scripts/python.exe -m src.stage04_parse.parse \
  --in cases/C-001/03_selection.json --out cases/C-001/04_parsed/ \
  --evidence "evidence/[root]"

# 평가 — 어느 단계에서 놓쳤는지까지 가른다
.venv/Scripts/python.exe benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell

# 검증기가 과엄격해지지 않았는지 확인 (하나라도 기각되면 환각률이 오염된 것)
.venv/Scripts/python.exe benchmark/validator_check.py

# 실물 관통 점검 — 단계마다 판정하고 시간을 잰다 (목업 없음, 판정 실패면 1)
.venv/Scripts/python.exe tools/live_check.py --case-id <케이스> \
  --evidence <이미지> --volume 1 --model <올라마태그> --raw "<상황 서술>"

# 그렇게 쌓인 실행 기록을 한 표로 (환각률·소요 시간)
.venv/Scripts/python.exe benchmark/collect.py

# 매핑을 넓힐 근거가 쌓였나 — technique_unsupported 기각을 조합별로 센다.
# 안 가른 것이 맨 위에 온다. 가른 기록은 benchmark/rejections.yaml 이다.
.venv/Scripts/python.exe benchmark/collect.py --rejections

# 04 산출물 요약 — 매니페스트·ref 유일성까지 대조한다 (어긋나면 1)
.venv/Scripts/python.exe tools/inspect_jsonl.py --parsed cases/<케이스>/04_parsed

# 파서를 고쳤으면 offset 이 여전히 원본을 가리키는지 (어긋나면 1)
.venv/Scripts/python.exe tools/hexdump_record.py --sample 20 \
  --parsed cases/<케이스>/04_parsed --evidence <이미지> --volume 1

# flags 어휘를 고쳤으면 스키마 enum을 맞춘다 (--check 는 확인만, 어긋나면 1)
.venv/Scripts/python.exe tools/sync_flag_enum.py
```

**실제 모델로 02·05 를 불러 보는 시험은 PowerShell 형식이다.** 이 셸은
`VAR=값 명령` 을 안 받는다 — 그것을 명령 이름으로 읽고
`CommandNotFoundException` 을 낸다. 위 코드펜스의 다른 줄들과 달리 이것은
bash 로 옮겨 적으면 안 된다.

```powershell
$env:DFIR_LIVE_MODEL = "qwen2.5:7b"
$env:DFIR_LIVE_TIMEOUT = "600"
.venv/Scripts/python.exe -m pytest tests/test_llm_live.py -v
Remove-Item Env:DFIR_LIVE_MODEL, Env:DFIR_LIVE_TIMEOUT
```

**끝나면 지운다.** 안 지우면 그 세션의 이후 `pytest` 가 전부 모델을 부르고,
10초에 끝나던 스위트가 몇 분이 된다. 스텁으로는 안 나오는 부류를 잡는다 —
프롬프트가 모델에게 말이 되는지, 응답이 파서를 통과하는지, 지어낸 `ref` 를
우리가 거르는지, 그리고 조립 경로에서 claims 가 정말 원본의 복사인지.

## 무엇을 알고 싶으면 어디를 보나

| 알고 싶은 것 | 권위 있는 문서 |
|---|---|
| **다음에 무엇을 할 차례인가** | `work.md` |
| 왜 이렇게 설계했나, 팀 분담, 비목표 | `work-guide.md` |
| 데이터 형식 — 필드·타입·제약 | `schemas/*.json` + `schemas/README.md` |
| **수치가 어디서 나오나**, 픽스처와 골든의 차이 | `benchmark/README.md` |
| 단계별 입출력 계약 | `docs/pipeline-io-spec.md` |
| **지금 안 되는 것과 그 이유** | `docs/limitations.md` |
| 그건 언제 어떻게 고쳤나 (해결된 것의 기록) | `docs/limitations-log.md` |
| 온디스크 구조, 외부 도구 대조 기록 | `docs/artifact-notes.md` |
| 매핑 YAML 작성 규칙, flags 어휘·룰 작성법 | `docs/mapping-guide.md` |
| flags 어휘와 판정 룰 자체 | `mappings/_flags.yaml` |
| **기각을 사람이 가른 기록** (매핑을 넓힐 근거) | `benchmark/rejections.yaml` |
| 02·05 LLM 연결 | `docs/llm-handover.md` |
| 디렉터리별 역할과 근거 | `docs/project-structure.md` |
| 어디까지가 우리 코드인가 | `third_party/README.md` |
| 04단계에 새 파서를 추가하는 절차 | `.claude/skills/add-parser/SKILL.md` |
| 새 시나리오·기법에 대응하게 만드는 절차 | `.claude/skills/add-scenario/SKILL.md` |

작업 전에 해당 문서를 읽는다. 여기 요약본을 만들지 않는다.

## 바꾸면 안 되는 것

- **`schemas/` 6개는 동결됐다.** `src/common/`도 공용이다. 둘 다 변경은 전체
  공지 대상이므로, 고쳐야 할 것 같으면 먼저 사용자에게 말한다.
  예외가 하나 있다 — `parsed_record`의 `flags` enum은 `mappings/_flags.yaml`에서
  **생성되는 값**이다. 손으로 고치지 말고 `tools/sync_flag_enum.py`를 돌린다.
- **flags 어휘와 룰은 `mappings/_flags.yaml`이 원본이다.** `flagging.py`에
  새 이름을 만들지 않는다. `event_id`·USN 사유·필드값 비교로 되는 조건은
  YAML만 고치면 되고, 파이썬이 필요한 것은 `HANDLERS`에 등록된 판정뿐이다.
- **`ref` 문자열은 `src/common/refs.py`를 경유한다.** 직접 조립하지 않는다.
  자체 일련번호를 매기면 원본 대조가 불가능해진다.
- **04·06·07은 결정론적 구간이다.** LLM을 부르지 않는다 (07은 Jinja2 템플릿).
  파싱에 환각이 섞이면 검증 자체가 불가능해진다.
- **폴백을 만들지 않는다.** 실패는 `errors.jsonl`에 기록하고 사유를 출력하며
  중단한다. 조용히 넘어가면 폴백이 틀린 건지 원래 로직이 틀린 건지 못 가린다.
- **한 실행은 한 볼륨이다.** `--evidence`는 볼륨 루트(KAPE라면 `<수집폴더>/C`)다.
  두 볼륨을 한 번에 읽으면 `MFT#12345`가 양쪽에 존재해 `ref`가 깨진다.
- **검증에 부분 통과는 없다.** `claims` 하나라도 불일치면 `rejected`다.

## 작업 규약

- **커밋**: `type(단계): 한국어 서술형` — `feat(04):`, `fix(04·07):`, `docs:`.
  type은 `feat|fix|refactor|test|docs|chore`. 명사 나열이 아니라 무엇을 했는지 쓴다.
- **브랜치**: `feat/<주제>`, `fix/<주제>`. `main`에 직접 커밋하지 않는다.
- **`src/`·`tests/`의 `.py`를 고치면 훅이 자동으로 `pytest -q -x`를 돌린다**
  (`.claude/hooks/pytest-on-source-change.sh`). 통과하면 조용하고, 실패하면
  실패 내역이 돌아온다. 훅이 도는 환경이 아닐 수도 있으니 커밋 전에는 직접 확인한다.
- **커밋 전 `pytest` 통과.** 파서를 고쳤으면 외부 도구나 명세와 대조한 기록을
  `docs/artifact-notes.md`에 남긴다. 대조 없는 파서 변경은 "조용히 틀리는" 쪽이다.
- **라이브러리를 우회했으면 왜 우회했는지 `docs/limitations.md`에 적는다.**
  선례: 레지스트리 값 3건(한글 절단, `MULTI_SZ` 종결자, 타임스탬프 반올림).
- **못 고친 것은 감추지 말고 `docs/limitations.md`에 적는다.** 고쳤으면 그
  기록은 `docs/limitations-log.md`로 옮긴다 — 두 문서를 가르는 기준은 날짜가
  아니라 **지금도 참인가**다. 이 프로젝트에서
  한계 기록은 감점이 아니라 성숙도의 지표다.

## 자주 하는 실수

- `cases/`·`evidence/`·`benchmark/results/`는 gitignore 대상이다. 산출물을
  커밋하려 들지 말 것.
- 문서에 스키마 필드를 복사해 넣지 말 것. `schemas/`가 유일한 출처다.
- 남의 코드는 `src/`가 아니라 `third_party/`에 둔다. 발표에서 "어디까지가 우리
  구현인가"를 가르는 경계다.

## 현재 상태 한 줄

01→07 전 구간이 **실제 모델로** 관통한다. 실측 둘 — 60GB 디스크 이미지
5분 30초, KAPE 수집 디렉터리(`snapshot1/C`) 2분 45초로 11개 관문 전부 PASS
(`K-LIVE-0902-wide`, 2026-09-04). `--llm stub`은 못 만든 자리가 아니라
테스트·리플레이용 백엔드다.

**모델 태그를 먼저 확인한다.** 문서 예시와 `start.bat`은 `qwen2.5:7b`라고
적어 두었는데, **이 기계에 그 태그는 없다** — 있는 것은 `qwen2.5:latest`
(같은 7.6B Q4_K_M)와 `qwen2.5:14b`다. 없는 태그를 넘기면 02단계에서 멈추고,
`start.bat`은 74~89줄의 `findstr /I "qwen2.5:7b"` 관문에서 **GUI 가 아예
뜨지 않는다**(2026-09-04 확인). `ollama list`로 먼저 보고 부른다.

**목표 시나리오는 키오스크다.** `C-001-webshell`은 지금 있는 유일한 벤치마크
데이터셋일 뿐 목표가 아니다 — 매핑·flags·기법 목록을 넓히는 작업은 키오스크를
기준으로 우선순위를 정한다.

**PASS 가 곧 정상은 아니다.** `live_check.py`의 판정은 구조 불변식만 본다
(ref 유일성, offset 이 원본을 가리키는가, 목업이 안 섞였는가). 내용이
맞는지는 판정 대상이 아니다 — 아래 넷이 전부 그 자리에서 나왔다.

남은 것 넷:

- **02단계 출력에 관문이 없다.** 두 방향으로 샌다. 입력에 없는 값을
  지어내고(`entities.hosts`가 `キオスク`로 나와 보고서 첫 줄 "대상 호스트"에
  그대로 실렸다, `work.md` 7번), 있어야 할 축을 빠뜨린다(입력이 "계정 관련
  변경"을 물었는데 계정 기법이 하나도 안 나와 `evtx:Security` 15.8MB 가
  선별조차 되지 않았다, `work.md` 11번). 02 의 기법 목록이 03 의 유일한
  입력이라 **놓친 축은 뒤에서 되살릴 자리가 없다.**
- **문장이 claims 를 뒷받침하는지 아무도 보지 않는다.** `--mode assemble`
  에서 claims 는 파이썬이 원본에서 조립하므로 `value_match`는 항등식이다.
  **환각률 0%를 품질로 인용하지 않는다** (`work.md` 12번).
- **사람이 만든 정답 데이터가 없어 수치가 자기채점**이다 (`work.md` 8번).
- **키오스크 축이 아직 미검증이다.** `AssignedAccess` 3종·`DriverFrameworks`·
  `RDPConnection` 다섯 채널이 손에 있는 어느 증거에도 없다 — **KAPE 수집도
  같은 다섯이 비어 있다**(2026-09-04 확인). 파일 경로 문자열과 `event_id`
  추정값을 실물로 맞춰 본 적이 없다. `unexpected_parent_process`가
  `explorer.exe`를 이상으로 보는 가정도 Assigned Access 를 켠 스냅샷이 있어야
  잰다 (`work.md` 0번).

  다만 `RDPSession`·`KernelPnP`는 이 KAPE 수집에 **있다**. 기법 매핑이
  요청하기만 하면 이 둘은 지금 실물로 잴 수 있다.
