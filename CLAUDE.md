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
# 테스트 — 기준선 529개 전부 통과
.venv/Scripts/python.exe -m pytest -q

# 관통 실행 (LLM 스텁, 세 번째 인자가 replay 디렉터리)
PYTHON=.venv/Scripts/python.exe bash run_pipeline.sh C-001 /mnt/evidence/WEB01 \
  benchmark/datasets/C-001-webshell/mock

# 단계 하나만
.venv/Scripts/python.exe -m src.stage04_parse.parse \
  --in cases/C-001/03_selection.json --out cases/C-001/04_parsed/ \
  --evidence "evidence/[root]"

# 평가 — 어느 단계에서 놓쳤는지까지 가른다
.venv/Scripts/python.exe benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell

# 검증기가 과엄격해지지 않았는지 확인 (하나라도 기각되면 환각률이 오염된 것)
.venv/Scripts/python.exe benchmark/validator_check.py

# flags 어휘를 고쳤으면 스키마 enum을 맞춘다 (--check 는 확인만, 어긋나면 1)
.venv/Scripts/python.exe tools/sync_flag_enum.py
```

## 무엇을 알고 싶으면 어디를 보나

| 알고 싶은 것 | 권위 있는 문서 |
|---|---|
| 왜 이렇게 설계했나, 팀 분담, 비목표 | `work-guide.md` |
| 데이터 형식 — 필드·타입·제약 | `schemas/*.json` + `schemas/README.md` |
| 단계별 입출력 계약 | `docs/pipeline-io-spec.md` |
| **지금 안 되는 것과 그 이유** | `docs/limitations.md` |
| 온디스크 구조, 외부 도구 대조 기록 | `docs/artifact-notes.md` |
| 매핑 YAML 작성 규칙, flags 어휘·룰 작성법 | `docs/mapping-guide.md` |
| flags 어휘와 판정 룰 자체 | `mappings/_flags.yaml` |
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
- **못 고친 것은 감추지 말고 `docs/limitations.md`에 적는다.** 이 프로젝트에서
  한계 기록은 감점이 아니라 성숙도의 지표다.

## 자주 하는 실수

- `cases/`·`evidence/`·`benchmark/results/`는 gitignore 대상이다. 산출물을
  커밋하려 들지 말 것.
- 문서에 스키마 필드를 복사해 넣지 말 것. `schemas/`가 유일한 출처다.
- 남의 코드는 `src/`가 아니라 `third_party/`에 둔다. 발표에서 "어디까지가 우리
  구현인가"를 가르는 경계다.

## 현재 상태 한 줄

01→07 전 구간이 관통한다. 남은 대체물은 **02·05의 LLM 호출이 스텁**인 것과,
**사람이 만든 정답 데이터가 없어 수치가 자기채점**인 것 두 가지다.
