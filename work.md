# work.md — 다음에 할 일

2026-08-26 실측(K-001 랩 환경 대비 완성도 점검)에서 나온 작업 큐다.
**설계 근거와 데이터 형식은 여기 옮겨 적지 않는다** — 각 항목에 붙은 문서가
권위다. 여기 있는 것은 "무엇을, 어디서, 어떻게 확인하며" 뿐이다.

끝낸 항목은 지우고, 그 사실은 `docs/limitations.md`에 남긴다.

**2026-08-26 처리됨** — `run_pipeline.sh` 의 `--volume` 통로,
02·05단계의 실패 응답 원문 보존, Sysmon 세 룰의 EID 제약,
프리패치 장치 경로 두 번째 형태, 05단계 토큰 예산과 레코드 다이어트.
전부 `docs/limitations.md` 에 있다.

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

실측 전체는 `docs/limitations.md` 의 "실측 — Sysmon 을 켠 실물 이미지".

---

## 1. `loaded_files`가 장치 경로라 경로 기준으로 고를 수 없다

> **2026-08-27 — 0번 이미지를 기다린다.** 변환 자체의 근거는 확보했다
> (아래 실측을 `0824test.001` 로 재현했다). 남은 것은 **섀도 카피가
> 여전히 안 바뀌는지**를 실물로 보이는 것인데, 지금 디스크의 두 이미지엔
> 섀도 카피 참조가 0건이다. `win10_sysmon_testimage.001` 과
> `evidence/[root]`(73건 중 17건이 섀도 카피)는 **둘 다 디스크에 없다.**
> 0번의 키오스크 스냅샷을 뜰 때 섀도 카피가 있는 상태로 뜨면 같이 닫힌다.

**왜 지금 하나** — 05단계에 보낼 때 `fields` 안의 목록을 앞에서 20개까지만
자른다(2026-08-26). 앞에서 자르는 이유는 "어느 항목이 중요한지 고르는 근거가
없어서"인데, **근거를 만들 수 있다.** 공격과 연계되는 DLL을 먼저 남기면
같은 20자리로 훨씬 나은 20개를 보낸다.

**막는 것** — `path`는 드라이브 문자로 바뀌는데 `fields.loaded_files`는
`\VOLUME{...}\WINDOWS\...` 그대로다. 그래서 경로 기준이 성립하지 않는다.
실측이 그것을 이렇게 보여 준다:

```
적재 경로 10,109건 (프리패치 127건, win10_sysmon_testimage)

  _flags.yaml 드롭 자리 어휘      378건  3.74%   ← 부분 문자열이라 된다
  Users 폴더 아래                531건  5.25%   ← 같은 이유로 된다
  Windows 폴더 밖             10,109건 100.00%  ← 안 된다. 접두어가 안 맞을 뿐
  실행 파일과 같은 폴더              0건  0.00%   ← 안 된다. 진짜 0이 아니다
```

아래 둘이 **사이드로딩(T1574)의 가장 강한 신호**인데 비교 자체가 성립하지
않는다.

**다른 이미지에서 재현됐다** (2026-08-27, `0824test.001`, 프리패치 137건 /
적재 경로 10,195건). 변환을 흉내 내 재 보면 막힌 둘이 실제로 열린다:

```
                          변환 전            변환 후
  드롭 자리 어휘            240   2.35%       240   2.35%   ← 안 바뀐다(정상)
  Users 폴더 아래           567   5.56%       567   5.56%   ← 안 바뀐다(정상)
  Windows 폴더 밖        10,195 100.00%     1,127  11.05%
  실행 파일과 같은 폴더        0   0.00%     5,101  50.03%
```

**"실행 파일과 같은 폴더"가 50%다.** 단독으로 keep 기준을 삼으면 절반을
통과시켜 자르는 뜻이 없어진다. 정상 앱이 자기 폴더의 DLL을 적재하는 것이
원래 다수이기 때문이다. **`C:\Windows` 밖과 곱해서 좁히는 안**이 있는데
아직 정하지 않았다.

**고칠 자리** — `src/stage04_parse/parsers/prefetch.py`. `_to_drive()`를
`loaded_files`에도 적용한다. **그 함수가 이미 조건부다** — 살아 있는 볼륨이
정확히 하나일 때만 바꾸고(`device_prefixes()`), 섀도 카피는 접두어가 안
맞아 그대로 남는다. 지금 `path` 하나에만 걸려 있는 것을 목록에도 거는 일이다.

**대조가 필요하다.** `artifact-notes.md`가 "원본 경로는 `fields.loaded_files`
에 손대지 않은 채로 남고, 바꾼 값은 `path` 하나뿐"이라고 **명시**하고 있다.
그 결정을 뒤집는 것이므로 왜 뒤집는지와 섀도 카피가 여전히 안 바뀌는지를
실물로 확인해 기록한다. 실측 이미지에는 섀도 카피가 0건이라 **그것을 가진
이미지가 따로 필요하다** — `evidence/[root]` 73건 중 17건이 그랬다(지금
디스크에 없음).

**그다음에 keep 목록을 넣는다** (`allocation.for_prompt`).

- 기준은 `mappings/_flags.yaml`에 **별도 최상위 키로 선언한다**
  (`privileged_groups` 선례). `execution_from_unusual_path`의 `values`를
  직접 빌려 쓰면 그 룰을 Sysmon 사정으로 고쳤을 때 프리패치 자르기가
  조용히 바뀐다.
- **keep 목록도 상한을 받아야 한다.** 드롭 자리 어휘 기준으로 6개 레코드가
  20을 넘고 최대 143건이다.
- 출력은 **원래 순서를 유지한다.** 부분집합이지 재정렬이 아니다.
- 적중이 0인 레코드가 127건 중 101건이라, 대부분은 지금 동작 그대로다.

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
