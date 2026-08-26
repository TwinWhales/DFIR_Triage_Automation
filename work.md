# work.md — 다음에 할 일

2026-08-26 실측(K-001 랩 환경 대비 완성도 점검)에서 나온 작업 큐다.
**설계 근거와 데이터 형식은 여기 옮겨 적지 않는다** — 각 항목에 붙은 문서가
권위다. 여기 있는 것은 "무엇을, 어디서, 어떻게 확인하며" 뿐이다.

끝낸 항목은 지우고, 그 사실은 `docs/limitations.md`에 남긴다.

**2026-08-26 처리됨** — `run_pipeline.sh` 의 `--volume` 통로,
02·05단계의 실패 응답 원문 보존, Sysmon 세 룰의 EID 제약,
프리패치 장치 경로 두 번째 형태, 05단계 토큰 예산.
전부 `docs/limitations.md` 에 있다.

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

## 1. Amcache 값 이름이 숫자라 경로인지 알 수 없다

**증상** — `benchmark/validator_check.py`가 "아는 구멍 1건 (V36)"으로 보고한다.

```
AMCACHE#15044  fields = {"17": 131343442490135143,
                         "15": "c:\windows\system32\sppsvc.exe",
                         "101": "00009b5b7c08..."}
```

`"15"`가 전체 경로인데 **이름이 아무 뜻도 담고 있지 않다.** 06단계의
`is_path_field()`가 이름으로 판단하므로 정확 문자열 비교로 떨어지고,
대소문자 하나로 기각된다.

**06단계에서 풀지 않는다.** `PATH_FIELDS`에 `"15"`를 넣으면 다른 서브키의
`15`까지 경로로 본다. 값의 생김새로 판단하는 것은 `comparators.py`가
처음부터 거부한 방식이다.

**고칠 자리** — `src/stage04_parse/parsers/registry.py`. Amcache의 숫자 값
이름을 뜻 있는 이름으로 옮겨 내보낸다. `HIVE_OF`(110행)가 이미
`registry:Amcache`를 따로 알고 있으니 분기할 자리는 있다.

**이 이미지의 레이아웃은 `Root\File\{GUID}\`** 다 — Win8+ 의
`Root\InventoryApplicationFile\`이 아니다. **둘 다 나올 수 있으므로 어느
쪽을 만났는지 확인하고 시작한다.** 값 이름 대응표는 공개 자료에 있지만,
**추정으로 채운 것은 그 자리에서 `docs/limitations.md`에 적는다.**

**끝나면 `benchmark/validator_cases.json`의 V36에서 `expect`를 `passed`로
되돌리고 `gap`을 지운다.** 안 되돌리면
`tests/test_benchmark.py::test_known_gaps_carry_a_reason_and_are_still_broken`
이 "이제 통과하니 되돌리라"고 실패시킨다 — 일부러 그렇게 만들었다.

---

## 2. Wazuh 알럿을 그대로는 못 받는다

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

## 3. 설계 판단이 필요한 것 둘 — 혼자 정하지 않는다

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
