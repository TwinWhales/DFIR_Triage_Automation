# work.md — 다음에 할 일

2026-08-26 실측(K-001 랩 환경 대비 완성도 점검)에서 나온 작업 큐다.
**설계 근거와 데이터 형식은 여기 옮겨 적지 않는다** — 각 항목에 붙은 문서가
권위다. 여기 있는 것은 "무엇을, 어디서, 어떻게 확인하며" 뿐이다.

끝낸 항목은 지우고, 그 사실은 `docs/limitations.md`에 남긴다.

**2026-08-26 처리됨** — `run_pipeline.sh` 의 `--volume` 통로,
02·05단계의 실패 응답 원문 보존. 둘 다 `docs/limitations.md` 에 있다.

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

---

## 0. 코드 작업이 아닌 것 — 먼저 걸어 둔다

**키오스크 랩 VM 스냅샷 하나.** Sysmon 설치 + Assigned Access 켠 상태로
30분 돌린 뒤 이미지를 뜬다. **침해하지 않아도 된다** — 정상 상태로 충분하다.

이것 하나가 지금 미검증인 것 여섯을 확정한다.

- `evtx:Sysmon`·`AssignedAccess` 3종·`DriverFrameworks`·`RDPConnection`의
  **파일 경로 문자열**이 맞는가 (`src/stage04_parse/evidence.py`의 `FILE_LAYOUT`)
- 그 채널들의 **event_id 추정값**이 맞는가 (`mappings/_flags.yaml`)
- `kiosk_restriction_event`가 "로그가 작다"는 전제대로인가 — 수만 건이면
  05단계 쿼터를 혼자 태운다
- `unexpected_parent_process`가 `explorer.exe`를 이상으로 보는 가정이
  이 랩에서 맞는가
- `shell_spawned` 목록이 정상 운영 중 몇 건이나 뜨는가
- 덤으로 **Stage 0 베이스라인**의 시작

**지금 두 실물 이미지 다 Sysmon이 없다.** 기본 탑재가 아니라서다.
그래서 K-001을 가르는 플래그 셋(`shell_spawned`·`execution_from_unusual_path`·
`unexpected_parent_process`)이 실물에서 한 번도 붙어 본 적이 없다.

---

## 1. 프리패치 볼륨 경로가 드라이브 문자로 안 바뀐다

**증상** — 06단계가 정상 문장을 기각한다.

```
모델 주장 : C:\WINDOWS\SYSTEM32\SVCHOST.EXE
실제 레코드: \VOLUME{01d8e7bd02796420-a202ae01}\WINDOWS\SYSTEM32\SVCHOST.EXE
```

**원인** — `src/stage04_parse/parsers/prefetch.py:87`

```python
DEVICE_VOLUME = re.compile(r"^\\DEVICE\\HARDDISKVOLUME(\d+)$", re.IGNORECASE)
```

`device_prefixes()`(97행)가 이 형태만 찾는다. 실물 이미지의 프리패치는
`\VOLUME{01d8e7bd02796420-a202ae01}` 꼴을 쓴다 — 볼륨 일련번호 형태다.
못 찾으면 `None`을 돌려주고, `_to_drive()`(314행)가 경로를 **그대로 둔다.**
주석대로의 동작이다("바꿀 수 없으면 그대로 둔다").

**고칠 자리** — `DEVICE_VOLUME`이 두 형태를 다 받게 한다. 레코드의
`fields.volumes[].device_path`와 `serial_number`가 짝을 이루고 있으니
거기서 확인할 수 있다.

**함정 둘.**

- **`SHADOWCOPY`는 여전히 빼야 한다.** 지금 정규식이 그것을 막고 있다.
  넓히면서 같이 들어오면 섀도 카피의 경로가 `C:`로 둔갑한다.
- **볼륨이 둘 이상이면 바꾸지 않는다.** 지금 `device_prefixes()`가
  "정확히 하나일 때만" 답하는 이유다. 여기를 무르게 하면 D: 의 실행
  파일이 C: 로 보고된다.

**확인** — 위 재현 절차로 04단계를 다시 돌리고 `prefetch.jsonl`의 `path`가
`C:\`로 시작하는지 본다. 그다음 06단계를 다시 걸면 환각률이 실제로 내려간다
(F2·F3 두 건). **이번 작업이 끝나야 2026-08-26 의 100%가 25%로 내려가는 것을
수치로 볼 수 있다.**

**대조 기록을 `docs/artifact-notes.md`에 남긴다.** 파서 변경은 대조 없이는
"조용히 틀리는" 쪽이다 (CLAUDE.md 작업 규약).

---

## 2. Amcache 값 이름이 숫자라 경로인지 알 수 없다

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

## 3. 05단계 프롬프트가 컨텍스트 창을 넘는다

**증상** — 아티팩트가 여럿 걸린 케이스에서 05단계가 3회 재시도 끝에 중단된다.

```
전달 60건의 JSON   71,476자 ≈ 28,600 토큰 (추정)
시스템 프롬프트     3,002자
--num-ctx 기본값   32,768
qwen2.5:7b 상한    32,768   ← 모델 상한이라 더 열 수 없다
```

출력에 쓸 자리가 2천 토큰도 안 남는다. `--limit 15`로 낮추면 첫 시도에 통과한다.

**고칠 자리** — `src/stage05_interpret/allocation.py`. 배분기가 이미
아티팩트별 자릿수를 계산하므로, 거기에 **토큰 예산**을 넣는다.
`DEFAULT_LIMIT`는 `src/stage05_interpret/record_filter.py:49`에 있다.

**이제 실패한 시도의 모델 응답 원문이 `cases/<id>/05_interpret_raw_attempt*.txt`
에 남는다**(2026-08-26 해결). 위 진단은 크기를 재고 `--limit`을 낮춰
재현한 것이지 원문을 본 것이 아니다. 손대기 전에 한 번 재현해 원문을
확인하고 시작한다 — 정말 잘린 것인지 다른 이유인지부터 가른다.

**`--limit`를 낮추는 것은 우회지 수정이 아니다.** 기본값 60은 카탈로그가
11종이던 시절 값이고, 22종이 된 지금 아티팩트가 또 늘면 같은 자리에서
또 터진다. **넘는데도 조용히 도는 것**이 지금 가장 나쁜 성질이다.

**레코드 다이어트는 이것 다음이다.** 06단계 검증은 `04_parsed/`를 직접
읽으므로 프롬프트만 줄이는 것은 안전하다. 다만 모델이 인용할 수 있는
근거의 폭이 줄어드는 거래라, 토큰 예산을 먼저 넣고 그래도 부족할 때 한다.

---

## 4. Wazuh 알럿을 그대로는 못 받는다

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

## 5. 설계 판단이 필요한 것 둘 — 혼자 정하지 않는다

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
