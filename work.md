# work.md — 다음에 할 일

2026-08-26 실측(K-001 랩 환경 대비 완성도 점검)에서 나온 작업 큐다.
**설계 근거와 데이터 형식은 여기 옮겨 적지 않는다** — 각 항목에 붙은 문서가
권위다. 여기 있는 것은 "무엇을, 어디서, 어떻게 확인하며" 뿐이다.

끝낸 항목은 지우고, 그 사실은 `docs/limitations.md`에 남긴다.

**2026-08-26 처리됨** — `run_pipeline.sh` 의 `--volume` 통로,
02·05단계의 실패 응답 원문 보존, Sysmon 세 룰의 EID 제약,
프리패치 장치 경로 두 번째 형태, 05단계 토큰 예산과 레코드 다이어트.
전부 `docs/limitations.md` 에 있다.

**2026-08-27 처리됨** — 프리패치 적재 경로 변환과 프롬프트 keep 목록(옛 1번).
`_to_drive()` 를 `fields.loaded_files` 에도 걸었고(실물 10,109건 전량 변환,
`tools/scan_prefetch.py` 대조 불일치 0건), keep 어휘를 `_flags.yaml` 의
`prompt_keep_paths` 로 선언했다. **"0번 이미지를 기다린다" 는 유보를
풀었다** — 섀도 카피 안전성은 `path` 가 예전부터 쓰던 그 함수의 성질이라
새 가정이 아니고, 실물 대조는 0번 목록으로 옮겼다. 남은 것과 안 넣은 것은
`docs/limitations.md` 의 같은 날 절에 있다.

**2026-08-27 처리됨** — Amcache 숫자 값 이름(옛 2번). 대응표를 공개 자료가
아니라 같은 이미지 안의 조인으로 얻었고, 그 과정에서 `PATH_FIELDS` 에
`lowercaselongpath` 가 없어 Amcache 인용 문장이 **전량** 기각되던 것이
함께 드러나 닫혔다. `validator_check.py` 가 40/40, 아는 구멍 0건.
기록은 `docs/artifact-notes.md` 2026-08-27 절과 `docs/limitations.md`.

---

## 먼저 — 이 큐가 어디서 나왔나

알럿 하나를 만들어 실물 60GB 이미지에 관통시켰다. 결과:

| 구간 | 결과 |
|---|---|
| 02 알럿 → 시나리오 | 기법 8개. 결정론적, LLM 없음 |
| 03 선별 | selected 22 / deferred 4 / excluded 3 |
| 04 파싱 | 10종 1,693건. 못 찾은 6종은 `artifact_not_found`로 정직하게 기록 |
| 05 해석 | **3회 재시도 끝에 중단** (약 25분, 소견 0건) |
| 05 재시도 `--limit 15` | 첫 시도 통과, 소견 4건 |
| 06 검증 | **환각률 100%** — 그런데 진짜 환각은 1건 |

실측 전체는 `docs/limitations.md`의 2026-08-26 절 셋에 있다. **먼저 읽는다.**

### 재현용 케이스 만들기

`cases/`는 gitignore라 K-ALERT가 남아 있지 않다. 다시 만들려면:

```bash
# 01_input.json 을 source_type: "edr_alert" 로 손으로 쓴다.
# raw 에 들어갈 모양은 src/stage02_normalize/alert_adapter.py 의 convert() 참고
#   필수: mitre[], severity, detected_at   선택: host, user, process{}, paths[], ips[]
.venv/Scripts/python.exe -m src.stage02_normalize.normalize \
  --in cases/K-ALERT/01_input.json --out cases/K-ALERT/02_scenario.json
.venv/Scripts/python.exe -m src.stage03_select.select \
  --in cases/K-ALERT/02_scenario.json --out cases/K-ALERT/03_selection.json --mappings mappings/
.venv/Scripts/python.exe -m src.stage04_parse.parse \
  --in cases/K-ALERT/03_selection.json --out cases/K-ALERT/04_parsed/ \
  --evidence evidence/0824test.001 --volume 1
```

`--volume 1`이 필수다. 이 이미지는 NTFS가 둘(0.4GiB 복구 + 59.4GiB 시스템)이다.
`win10_sysmon_testimage.001`도 같은 레이아웃이고, **그쪽에만 Sysmon이 있다.**

관통 스크립트로 돌릴 때는 `VOLUME`으로 넘긴다:

```bash
VOLUME=1 PYTHON=.venv/Scripts/python.exe bash run_pipeline.sh \
  K-ALERT evidence/win10_sysmon_testimage.001
```

---

## 0. 코드 작업이 아닌 것 — 먼저 걸어 둔다

**Assigned Access 를 켠 스냅샷 하나.** `win10_sysmon_testimage.001`
(2026-08-26)로 Sysmon 쪽은 절반이 닫혔다. 남은 것은 **키오스크 모드와
USB·RDP** 다. 침해하지 않아도 된다 — 정상 상태로 충분하다.

닫힌 것:

- ~~`evtx:Sysmon` 의 파일 경로 문자열~~ — 맞았다
- ~~`shell_spawned` 목록이 정상 운영 중 몇 건이나 뜨는가~~ — 5.5분에 5건.
  전부 Windows 서비싱(`sedsvc.exe`·`CompatTelRunner.exe`)이다
- ~~`execution_from_unusual_path`~~ — 3건, 전부 `C:\Windows\Temp\{GUID}\DismHost.exe`
- 덤으로 **세 룰이 EID 5 도 잡던 버그**가 드러나 고쳤다

**여전히 미검증인 것 넷.** 이 다섯 채널은 이미지에 파일 자체가 없었다
(`AssignedAccess` 3종·`DriverFrameworks`·`RDPConnection`).

- 그 다섯의 **파일 경로 문자열**이 맞는가
  (`src/stage04_parse/evidence.py`의 `FILE_LAYOUT`)
- 그 채널들의 **event_id 추정값**이 맞는가 (`mappings/_flags.yaml`)
- `kiosk_restriction_event`가 "로그가 작다"는 전제대로인가 — 수만 건이면
  05단계 쿼터를 혼자 태운다
- `unexpected_parent_process`가 `explorer.exe`를 이상으로 보는 가정이
  맞는가. **이번 이미지로는 못 쟀다** — Assigned Access 를 안 켠 일반
  Win10 이라 explorer 가 정상 셸이다

덤으로 **Stage 0 베이스라인**의 시작이기도 하다.

**섀도 카피가 있는 상태로 뜨면 하나 더 닫힌다.** 프리패치 적재 경로 변환이
섀도 카피 참조를 그대로 두는지는 지금 합성 테스트로만 확인돼 있다(디스크의
두 이미지 모두 섀도 참조 0건). 스냅샷에 섀도 카피가 있으면
`tools/scan_prefetch.py` 대조 한 번으로 실물 확인이 된다 —
`docs/limitations.md` "프리패치 적재 경로와 프롬프트 keep 목록".

**keep 어휘도 그 이미지로 잰다.** `prompt_keep_paths` 는 정상 운영 이미지의
분포로만 골랐다(적중 9.81%, `max_items: 12`). 악성 DLL 이 드롭 자리에 실제로
있는 이미지에서 다시 재야 한다.

실측 전체는 `docs/limitations.md` 의 "실측 — Sysmon 을 켠 실물 이미지".

---

## 2. 파서 넷 — SRUM · 저널링 둘 · SQLite

2026-08-27 에 잡은 트랙이다. 절차는 `.claude/skills/add-parser/SKILL.md`
하나가 권위다 — **등록 지점이 다섯이고 그중 셋은 빠뜨려도 조용하다.**

방침은 `work-guide.md` 3.1 이 이미 정해 놨다 — *"파일시스템 계층은 직접
구현해 오프셋을 보존하고, 로그 계층은 검증된 라이브러리를 사용했다."*
아래 셋이 그 선을 각각 어느 쪽에 두는지가 난이도를 가른다.

### 2-1. SRUM (`SRUDB.dat`) — 로그 계층, 라이브러리

`Windows\System32\sru\SRUDB.dat`. **`0824test.001` 에 실제로 있다**
(`SRU.log`·`SRUDB.jfm` 동반 = 클린 셧다운이 아닌 상태라, 파서가 dirty DB
를 견디는지 확인해야 한다).

ESE 데이터베이스라 직접 구현은 B-tree·long value·다중 페이지 레코드를 전부
짜는 일이다. 위 방침대로 **라이브러리로 간다.** `dissect.esedb` 는 아직
설치돼 있지 않은데, `dissect.target` 이 이미 `requirements.txt` 에 있어
**새 벤더를 들이는 것이 아니다** — evtx 에 python-evtx 를 쓴 것과 같은 자리.

**K-001 에서 값이 큰 이유** — `Network Data Usage` 테이블이 **앱별 송수신
바이트**를 들고 있다. 이미 매핑이 있는 T1041·T1048(유출)에 지금 우리가
가진 것 중 가장 직접적인 증거다.

정할 것 — `signal_source` 를 `flags` 로 할지 `scope` 로 할지. SRUM 은
`path_prefix` 로 걸러지지 않으므로 레지스트리·프리패치와 사정이 다르다.
**틀리면 조용히 실패한다**(파싱은 되는데 05단계에 한 건도 안 간다,
`limitations.md` 6-7).

### 2-2. 저널링 — `$UsnJrnl` 보강 + `$LogFile` 신규

**`$UsnJrnl:$J` 는 이미 있다**(직접 구현, `_artifacts.yaml` 등재됨).
보강 범위를 먼저 재고 시작한다.

`$LogFile` 은 카탈로그에 **`supported: false` 로 자리만 있다**
(`_artifacts.yaml`). 이미지에 64MB 로 존재한다. 파일시스템 계층이라
방침대로면 **직접 구현**이고, LSN 레코드와 redo/undo 연산을 해석해야 한다.
설치된 `dissect.ntfs` 도 `$LogFile` 은 안 건드린다.

**셋 중 값 대비 비용이 가장 나쁘다.** 얻는 것이 이미 있는 `$UsnJrnl` 과
상당히 겹친다. 순서를 마지막에 두는 이유다.

### 2-3. SQLite — **보류. 대상이 생기면 집는다**

지금 만들지 않는다. 이유가 둘인데 **둘 다 코드 문제가 아니다.**

- **대조할 파일이 없다.** `ProgramData\POS` 가 `0824test.001` 에 존재하지
  않는다. `mappings/windows/T1565.001.yaml` 의 `pos_db_root` 가 말하는
  그대로다 — K-001 Mock POS 앱이 개발되지 않아 거래 DB 가 어디 놓일지도
  미정이다(설계서 §9 D1 의 열린 결정). add-parser 절차 9번은 **"대조 없는
  파서는 없는 것과 같다"** 인데, 대조 상대 자체가 없다.
- **팀 분담선을 넘는다.** 같은 매핑이 *"DB 내용은 이 도구가 못 본다.
  SQLite 파일을 열어 레코드를 비교하는 것은 담당 6의 영역"* 이라고 적고
  있다. 가져오려면 그쪽과 먼저 정리한다.

**집을 조건** — 아래 중 하나가 참이 되면 시작한다.

1. Mock POS 앱이 랩에 올라가 `pos_db_root` 의 실제 경로가 정해지고, 그
   상태의 이미지가 생긴다. (0번 스냅샷과 같이 뜨면 가장 싸다)
2. 담당 6 과 경계를 다시 그어 DB 내용 비교를 이쪽으로 가져온다.

**미리 알아 둘 것** — 읽기 자체는 stdlib `sqlite3` 로 끝나서 쉽다. 그런데
**DFIR 에서 값이 나오는 부분(삭제 레코드 복구·WAL/journal 잔재)은 stdlib
에 없다.** 그냥 읽기만 하는 파서라면 만들 값이 크지 않다는 뜻이라, 범위를
정할 때 이것부터 정한다.

---

## 3. Wazuh 알럿을 그대로는 못 받는다

레포 전체에 `wazuh`·`sigma`·`winlogbeat`·`active-response` 참조가 0건이다.
`edr_alert` 경로는 있으나 **자체 형식**을 기대한다. 실측:

```
Wazuh 원본(rule.mitre.id / rule.level / agent.name)  →  AlertAdapterError
평탄화한 자체 형식(mitre / severity / host)          →  정상 변환
```

**할 일 셋.**

- `src/stage02_normalize/alert_adapter.py`에 Wazuh 모양을 평탄화하는 변환
  추가 (약 50줄). `rule.mitre.id`→`mitre`, `rule.level`→`severity`,
  `agent.name`→`host`, `data.win.eventdata.*`→`process.*`
- `tools/make_case.py`에 `--alert` 경로. 지금은 자연어 입력만 만든다
- Wazuh active-response에서 부를 래퍼

**라이브 호스트에서 바로 못 읽는다는 것도 함께 본다.** `open_source()`는
이미지 파일 또는 폴더만 받는다(`\\.\C:` 없음). 알럿이 나면 KAPE가 먼저
돌아 폴더를 만들어야 한다 — 계획서에 KAPE가 있으니 운영으로 메꿔지지만,
그 호출을 감싸는 자리가 지금 없다.

### 다음 세션이 바로 집을 수 있게 — 배선

**먼저 실물 샘플 하나를 `tests/data/` 에 붙이고 시작한다.** 필드 이름을
기억으로 적으면 조용히 틀린다 — Wazuh 는 `alerts.json` 한 줄과 API 응답의
모양이 다르고, `rule.mitre` 는 버전에 따라 `id`/`technique`/`tactic` 이
**전부 배열**이다. 샘플이 붙기 전에는 아래 표를 확정하지 않는다.

**손댈 자리는 하나다.** `convert()` 앞에 평탄화 함수를 세우고, `convert()`
자신은 지금 모양 그대로 둔다.

```
raw(Wazuh)  →  _flatten_wazuh(raw)  →  convert(raw, evidence)  →  시나리오
                     ^ 새로 만드는 것            ^ 안 건드린다
```

`convert()` 를 고쳐 두 모양을 다 받게 하면 **어느 형식이 어느 필드를
채웠는지가 함수 안에서 섞인다.** 지금 `convert()` 는 "기법이 없으면
`AlertAdapterError`" 처럼 실패를 정직하게 내는데, 입력 모양이 둘이 되면 그
메시지가 어느 쪽을 가리키는지 알 수 없게 된다.

**모양을 알아보는 기준**을 먼저 정한다 — `raw` 에 `rule` 이 있고 그것이
객체이면 Wazuh 로 본다. `source_type` 을 새로 만들지 않는다(`edr_alert`
그대로다). 스키마는 동결이고, 이것은 형식 판별이지 새 입력 종류가 아니다.

| Wazuh | 우리 | 주의 |
|---|---|---|
| `rule.mitre.id[]` | `mitre[]` | 배열이다. 하나만 오는 경우도 배열로 온다 |
| `rule.level` (0~15) | `severity` | **숫자→문자열 대응을 정해야 한다.** `SEVERITY_CONFIDENCE` 가 `critical`/`high`/... 를 기대한다 |
| `rule.description` | `rule_name` | |
| `agent.name` | `host` | `agent.ip` 는 `ips[]` 로 |
| `data.win.eventdata.image` | `process.path` | 소문자 키다. Windows 이벤트 경유일 때만 있다 |
| `timestamp` | `detected_at` | Wazuh 는 `+0900` 오프셋을 붙여 보낸다. `_detected_at()` 이 받는지 확인 |

**확인 방법** — 샘플을 넣어 02단계를 돌리고, 지금 자체 형식으로 만든
K-ALERT 시나리오와 `techniques`·`time_range`·`entities` 가 같은지 본다.
같은 사건을 두 입력 형식으로 넣으면 같은 시나리오가 나와야 한다. 다르면
평탄화가 무언가를 흘린 것이다.

**정할 것 하나** — `rule.level` 대응. 12 이상을 `critical` 로 볼지 13
이상으로 볼지에 따라 `overall_confidence` 가 0.9 와 0.95 사이에서 갈리고,
그 값은 보고서에 그대로 실린다. 근거 없이 정하지 말고 Wazuh 문서의 레벨
정의를 인용해 `alert_adapter.py` 주석에 남긴다.

---

## 4. 설계 판단이 필요한 것 둘 — 혼자 정하지 않는다

### 3대 상관분석

한 실행 = 한 볼륨은 `ref` 유일성을 지키려는 **의도된 제약**이다. 깨면
06단계 검증이 흔들린다. K-001 Stage 8(POS→관리서버)처럼 두 호스트에
걸친 사실은 지금 사람이 보고서 3장을 합쳐야 한다.

선택지 셋으로 보인다 — (a) 사람이 합친다 (b) `ref`에 호스트 접두어
(스키마 동결을 건드림) (c) 07단계 위에 병합 리포터를 얹는다.
**어느 쪽인지는 발표에서 무엇을 보여줄 건지에 달렸다.**

### 스냅샷 A/B 베이스라인 비교

계획서의 오프라인 축이 "정상 A와 침해 후 B를 비교"인데 **코드에 개념
자체가 없다.** 키오스크처럼 도는 프로세스가 극히 제한적인 환경에서는
이것이 가장 강한 필터가 된다.

넣지 않은 이유는 `docs/limitations.md`의 "넣지 않은 것 — 화이트리스트
역탐지"에 있다. 필요한 것은 부정 매처 하나와 목록을 04단계에 넘길
통로이고, 둘 다 지금 없다. 범위가 커서 별도 트랙이다.

---

## 5. 분석가용 콘솔 (GUI) — 지금 개념 자체가 없다

레포 전체에 GUI·웹 UI 참조가 0건이다. `work-guide.md` 1.4 비목표에도 없으니
**빼기로 한 것이 아니라 아직 안 만든 것**이다. 새 트랙으로 연다.

덮는 범위는 파이프라인 전체다 — 케이스 생성 → 01~07 실행과 진행 상황 →
07 보고서 열람. 지금 사람이 `run_pipeline.sh` 와 `cases/<id>/` 디렉터리를
번갈아 보며 하는 일 전부다.

### 먼저 읽을 것 — GUI 가 감싸야 하는 것은 CLI 가 아니라 그 성질이다

`run_pipeline.sh` 를 그대로 버튼 하나로 만들면 아래 넷이 전부 깨진다.
**이 넷이 이 트랙의 요구사항이고, 나머지는 화면 배치 문제다.**

- **`--volume` 을 안 주면 04단계가 후보를 보여 주고 멈춘다. 그것이 정상
  동작이다** (`run_pipeline.sh` 주석). GUI 가 이걸 실패로 삼켜 재시도하거나
  크기로 추측해 고르면, "아티팩트 없음" 이 아니라 **다른 볼륨의 결과가
  조용히 나온다.** 볼륨 선택은 화면이 받아야 하는 입력이지 숨길 단계가 아니다.
- **05단계는 오래 걸리고 실패한다.** 실측에서 3회 재시도 끝에 약 25분 만에
  소견 0건으로 중단됐다(`docs/limitations.md` 2026-08-26). 요청-응답 하나로
  감싸면 화면이 25분간 멈춰 있다가 아무것도 없이 끝난다. 단계별 진행과
  중단 사유가 실시간으로 보여야 한다.
- **실패를 삼키지 않는다.** CLAUDE.md 의 "폴백을 만들지 않는다" 가 GUI 에도
  그대로 적용된다. `cases/<id>/errors.jsonl` 이 실패의 원본이고, 화면은
  그것을 감추는 자리가 아니라 **가장 잘 보이게 놓는 자리**다.
- **04단계는 로컬의 60GB 이미지를 직접 읽는다.** 이미지를 업로드받는
  서버 모델은 이 파이프라인과 맞지 않는다. 어느 형태를 고르든 **분석가의
  기계에서 도는 것**을 전제로 한다.

### 정할 것 1 — 형태. 셋 다 장단이 갈린다

| | 로컬 웹 (FastAPI/Flask + 브라우저) | 데스크톱 앱 (PySide/Tkinter) | 정적 뷰어 (파일만 열기) |
|---|---|---|---|
| 새 의존성 | 웹 프레임워크 + ASGI 서버 | GUI 툴킷 (PySide 는 무겁다) | 없음~적음 |
| 07 보고서 표시 | **Markdown 렌더가 따로 필요하다.** 07 출력은 `.md` 이고 `markdown` 라이브러리는 `requirements.txt` 에 없다 | 같은 문제 + 툴킷의 MD 위젯 품질 편차 | 같은 문제 |
| 오래 도는 05단계 | 서버가 상태를 들고 SSE/폴링으로 흘리면 자연스럽다 | 스레드/시그널을 직접 짜야 한다 | **못 한다** — 실행을 안 하므로 |
| 실행 중단·재개 | 서버 프로세스가 살아 있어 붙었다 뗐다 된다 | 창을 닫으면 같이 죽는다 | 해당 없음 |
| 배포·발표 | 브라우저만 있으면 된다. 화면 공유가 쉽다 | 실행 파일 하나. 설치가 필요할 수 있다 | 가장 싸다 |
| 위험 | **로컬에 포트를 연다.** 증거를 다루는 도구라 바인딩을 `127.0.0.1` 로 못 박고 인증 없는 원격 접근이 안 되게 해야 한다 | 스택이 파이썬 밖으로 나간다 | 파이프라인 실행이 여전히 CLI 라 두 도구를 오간다 |

**지금 기울어진 쪽은 로컬 웹이다** — 위 요구사항 넷 중 둘(진행 상황, 중단·재개)이
서버가 상태를 들고 있을 때만 자연스럽고, 스택이 파이썬 안에 남는다. 다만
**포트를 여는 것과 MD 렌더 의존성 하나**가 대가다. 근거 없이 확정하지 말고
이 표를 근거로 고른 뒤, 고른 이유를 이 자리에 한 줄로 남긴다.

### 정할 것 2 — 단계를 subprocess 로 부르나, import 로 부르나

| | subprocess (`python -m src.stageXX...`) | 직접 import |
|---|---|---|
| 진실의 개수 | **하나.** CLI 가 유일한 진입점으로 남고 GUI 는 그것을 부른다 | **둘.** GUI 경로와 CLI 경로가 갈라지고, 나중에 조용히 달라진다 |
| 진행 상황 | stdout 을 흘려 받는다. 단계 경계까지만 보인다 | 단계 안까지 볼 수 있다 |
| 실패 처리 | 종료 코드 + `errors.jsonl`. 지금 규약 그대로다 | 예외를 GUI 가 받아 다시 해석해야 한다 |
| 속도 | 프로세스 기동 비용. 04·05 앞에서는 무시할 수준이다 | 조금 빠르다 |

**subprocess 를 권한다.** 이 프로젝트에서 "폴백을 만들지 않는다" 와 "실패는
`errors.jsonl` 에 남긴다" 가 성립하는 이유는 단계가 독립 프로세스이기
때문이다. import 로 당기면 그 규약을 GUI 안에서 다시 만들어야 한다.

### 정할 것 3 — 코드를 어디에 두나

`src/` 안에 넣으면 파이프라인 코드와 섞인다. 발표에서 "어디까지가 우리
파이프라인 구현인가" 를 가르는 경계가 흐려진다(`third_party/README.md` 가
같은 이유로 존재한다). `ui/` 또는 `app/` 로 최상위에 따로 두는 쪽을 권한다 —
`src/` 를 부르는 방향이 한쪽이라는 것이 디렉터리로 보인다.

### 확인 방법

**같은 케이스를 GUI 로 한 번, `run_pipeline.sh` 로 한 번 돌려
`cases/<id>/` 산출물 일곱이 같은지 본다.** 다르면 GUI 가 인자를 흘렸거나
어딘가에 폴백을 만든 것이다. `--volume` 을 안 준 케이스도 함께 본다 —
GUI 가 04단계의 "후보 보여 주고 멈춤" 을 그대로 보여 주는지가 확인점이다.

**착수 조건은 없다.** 0번 스냅샷이나 3번 Wazuh 와 달리 밖에서 올 것을
기다리지 않는다. 다만 **3번보다 먼저 집으면 알럿 입력 화면을 두 번
만들게 된다** — Wazuh 평탄화가 들어오면 케이스 생성 화면의 입력이 하나
늘기 때문이다. 순서는 3번 뒤가 싸다.

---

## 참고 문서

| 주제 | 문서 |
|---|---|
| **지금 안 되는 것과 그 이유** | `docs/limitations.md` |
| 새 파서 추가 절차 | `.claude/skills/add-parser/SKILL.md` |
| 새 시나리오 대응 절차 (관문 넷) | `.claude/skills/add-scenario/SKILL.md` |
| 매핑 작성 규칙, flags 어휘 | `docs/mapping-guide.md` |
| 온디스크 구조, 외부 도구 대조 기록 | `docs/artifact-notes.md` |
| 데이터 형식 | `schemas/*.json` + `schemas/README.md` |
| 설계 근거, 팀 분담, 비목표 | `work-guide.md` |
