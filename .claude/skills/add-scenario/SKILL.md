---
name: add-scenario
description: 새 침해 시나리오(웹셸 외 — 키오스크·USB·랜섬웨어 등)에 대응하게 만들 때, ATT&CK 기법을 추가하거나 매핑 YAML·flags 어휘를 고칠 때 쓴다. 관문이 넷이고 어디까지가 YAML만으로 되는지 가른다. 넷 중 flags 관문만 조용히 실패한다 — 03단계는 정상이고 04단계는 파싱까지 하는데 05단계에 레코드가 한 건도 가지 않고 errors.jsonl에도 남지 않는다. event_id 를 적을 때 함께 봐야 할 넷(받을 flag 가 있나·artifact 를 정확히 썼나·채널 전체 요청을 받나·실제로 거르나)도 여기 있다.
---

# 새 시나리오 대응 추가

이 도구는 웹셸 전용이 아니다. 매핑 테이블 기반이라 기법을 넓힐 수 있다.
**다만 "YAML만 추가하면 된다"가 참인 구간과 아닌 구간이 있다.**

| 알고 싶은 것 | 볼 곳 |
|---|---|
| 매핑 YAML 문법, `scope_template` 변수, flags `rule` 문법 | `docs/mapping-guide.md` |
| 아티팩트 카탈로그에 없는 것을 추가 | `.claude/skills/add-parser/SKILL.md` |
| 지금 안 되는 것과 그 이유 | `docs/limitations.md` |

---

## 관문 넷

새 기법 하나가 07단계까지 관통하려면 넷을 다 통과해야 한다.

| # | 관문 | 막히면 | 비용 |
|---|---|---|---|
| 1 | `KNOWN_TECHNIQUES`에 ID가 있는가 | 02단계가 스키마 위반으로 기각 | 파이썬 한 줄 |
| 2 | `mappings/<os>/<ID>.yaml`이 있는가 | 03단계가 건너뜀 (`errors.jsonl`에 남음) | **YAML 하나** |
| 3 | 필요한 아티팩트가 카탈로그에 있는가 | 매핑 로드 자체가 실패 | 파서 추가 |
| 4 | 그 아티팩트의 신호가 flags 어휘에 있는가 | **05단계에 한 건도 안 감** | YAML + 생성기 |

**4번만 조용히 실패한다.** 1·2·3은 즉시 멈추거나 `errors.jsonl`에 남는데,
4번은 03단계가 "봤다"고 기록하고 04단계가 실제로 파싱까지 한 뒤 모델에만
안 간다. 보고서에는 그냥 소견이 없는 걸로 보인다.

레지스트리가 그 상태다 — `limitations.md` 6-7에 실측이 있다. 선별이 정확히
골라온 1,754건이 `flagged_count` 0으로 전부 탈락한다.

---

## 순서

**0. 먼저 관문 1·2를 확인한다**

```bash
.venv/Scripts/python.exe -c "
import sys; sys.path.insert(0,'.')
from src.common import attack
have = attack.mapped_techniques('mappings')
for t in ['T1091','T1547.001','T1543.003']:
    print(f'{t:12} KNOWN={attack.is_known(t)!s:5} MAPPING={t in have}')
"
```

기법 목록을 먼저 뽑아 놓고 이 명령에 넣으면, 어디부터 손댈지가 바로 보인다.

**1. 기법 ID를 등재한다** — `src/common/attack.py`의 `KNOWN_TECHNIQUES`

스키마는 `T####.###` 형식만 본다. 실재 여부는 이 dict가 판정하고
`normalize.check_attack_ids`가 기각한다. **여기 없으면 매핑을 아무리 잘
써도 시나리오가 02단계를 못 넘는다.**

주석의 "매핑이 있는 기법 / 아직 없는 기법" 구분은 손으로 유지되는 것이라
쉽게 낡는다. 믿지 말고 `attack.mapped_techniques()`로 확인한다.

**2. 매핑 YAML을 쓴다** — `mappings/<os>/<기법ID>.yaml`

파일명이 곧 기법 ID다. 어긋나면 로더가 거부한다. 문법은 mapping-guide가
권위다. 여기서는 자주 틀리는 것만:

- Tier 1은 `trigger` 금지, Tier 2는 `trigger` 필수 — 반대로 쓰면 로드 실패
- `rationale`은 보고서에 그대로 실린다. `중요함` 같은 평가어 금지
- 아티팩트 이름은 `_artifacts.yaml`과 정확히 일치해야 한다
- `path_prefix`는 **정확히 일치하는 경로도 받는다**(`Scope.matches_prefix`의
  `normalized == prefix`). 파일 하나를 통째로 지정할 수 있다 —
  `C:\Windows\System32\sethc.exe` 처럼. System32 전체를 걸고 05단계
  쿼터(60건)를 태우는 것보다 낫다.
- `scope_template` 변수는 `{web_root}` 등 다섯 개로 닫혀 있지 않다.
  **`defaults`에 값만 주면 새 이름을 써도 된다**(`{system_root}` 같은 것).
  시나리오 `entities`에서 끌어오는 이름만 다섯 개다.

**추정으로 채운 값은 그 자리에서 `docs/limitations.md`에 적는다.**

이벤트 ID, 레지스트리 경로, 서비스 이름, 파일 목록 — 실제 증거로 대조하지
않고 공개 자료나 기억으로 채운 것은 전부 해당한다. **신뢰도가 낮은 순으로**
적고, YAML에도 같은 취지의 주석을 남긴다.

파서와 달리 매핑에는 자동 대조 도구가 없다. 안 적으면 나중에 실증거에서
안 걸렸을 때 그것이 매핑이 틀린 것인지 모델이 못 찾은 것인지 가를 수
없고, 십중팔구 모델 문제로 잘못 집계된다. 선례는 `limitations.md`의
"매핑 — 검증되지 않은 채 채운 항목" 절에 두 묶음이 쌓여 있다.

**3. 아티팩트가 카탈로그에 없으면 먼저 추가한다**

```
MappingError: 카탈로그에 없는 아티팩트: 'evtx:PowerShell'
```

이 메시지가 나오면 `add-parser` 스킬로 간다. 파서 없이 카탈로그에만 넣으면
`supported: false`로 두어야 하고, 그러면 항상 `excluded`로 빠진다.

**4. 신호가 기존 flags 어휘로 표현되는지 본다**

여기가 핵심이다. 아래로 확인한다 — 새 기법이 고른 아티팩트의 대표
레코드를 만들어 실제로 05단계까지 가는지 본다.

```bash
.venv/Scripts/python.exe -c "
import sys; sys.path.insert(0,'.')
from src.stage04_parse import flagging
from src.stage05_interpret import allocation
rec = [{'artifact':'evtx:System','ref':f'EVTX-SYS#{i}','event_id':7045,
        'timestamp':'2026-08-12T03:0%d:00Z'%i,'fields':{}} for i in range(5)]
f = list(flagging.apply_all(rec))
print('플래그:', sum(1 for r in f if r['flags']), '/', len(f))
print('05단계 전달:', len(allocation.allocate_records(f)[0]))
"
```

**0이 나오면 그 기법은 03단계까지만 도는 것이다.** 매핑을 아무리 정확히
써도 모델은 아무것도 못 본다.

**판정은 기법이 아니라 아티팩트 단위로 갈린다.** 한 기법 안에서 evtx는
통과하고 레지스트리는 탈락하는 일이 정상이다. Tier 1 아티팩트를 하나씩
태워 보고 결과를 표로 남긴다(`limitations.md`의 "새 매핑이 05단계에
도달하는지" 절이 그 형식이다).

단, 신호가 **경로에서** 나오는 아티팩트라면 플래그가 0인 것이 정상이다.
그때는 flag를 만들 것이 아니라 `mappings/_artifacts.yaml`에
`signal_source: scope`를 적는다. 레지스트리가 그 경우다 — 위 확인 명령의
`signal_sources` 인자로 그 상태를 재현해 볼 수 있다.

```bash
.venv/Scripts/python.exe -c "
import sys; sys.path.insert(0,'.')
from src.stage05_interpret import allocation
rec = [{'artifact':'registry:SYSTEM','ref':f'REG-SYS#{i}','flags':[],
        'path':r'SYSTEM\ControlSet001\Services\svc%d'%i,'name':'svc',
        'timestamp':'2026-08-12T03:0%d:00Z'%i,'fields':{}} for i in range(5)]
print('flags 로 보면 :', len(allocation.allocate_records(rec)[0]))
print('scope 로 보면 :', len(allocation.allocate_records(
    rec, signal_sources={'registry:SYSTEM':'scope'})[0]))
"
```

**Tier 1이 레지스트리·프리패치뿐인 기법도 이제 작동한다.** 예전에는 6-7의
구조 문제로 선별에는 잡히고 보고서에는 한 줄도 안 나왔고, `T1112`가 그
상태로 들어갔다. 05단계 배분과 `signal_source: scope`로 풀렸으므로 지금은
자리를 배분받는다. **대신 확인 방법이 바뀌었다** — 플래그 수가 아니라 위
명령의 `signal_sources` 인자를 실제 카탈로그로 주고 전달 건수를 본다.

**5. 필요하면 flag를 추가한다** — `mappings/_flags.yaml`

`event_id`·USN 사유·필드값 비교로 표현되면 **YAML만 고치면 된다.**
문법은 mapping-guide의 "flags 어휘" 절이 권위다.

```bash
.venv/Scripts/python.exe tools/sync_flag_enum.py
```

스키마 enum은 이 생성기가 YAML에서 만든다. **`schemas/`를 손으로 고치지
않는다.** 선언으로 표현되지 않는 판정만 `flagging.py`의 `HANDLERS`에
등록하고 YAML에서 이름으로 부른다.

**새 flag는 기존 테스트를 깰 수 있다.** 어느 룰에도 안 걸리는 이벤트를
전제로 쓴 테스트가 있어서다 — `logon_success`(4624)를 만들자
`test_unrelated_event_gets_no_flag`가 4624를 "관계없는 이벤트"로 쓰고
있어 깨졌다. 깨지면 테스트를 고치는 게 맞다. 다만 **왜 그 ID가 더는
중립이 아닌지 주석으로 남긴다.**

**5-1. flag 를 걸었으면 넷을 더 본다**

관문 4를 "플래그가 붙나"로만 확인하면 부족하다. 2026-08-25 에 K-001 매핑을
쓰면서 이 넷을 다 밟았고, 지금은 `tests/test_flag_rules.py` 가 막는다.
**막히니까 안 봐도 된다는 뜻이 아니라, 걸렸을 때 무슨 뜻인지 알아야 한다.**

**① 적은 event_id 를 받을 flag 가 있는가**

매핑에 `event_ids: [11, 22]` 를 적어도 그것을 받는 flag 가 없으면 05단계에
한 건도 가지 않는다. 03단계는 "봤다"고 적고 04단계는 파싱까지 하며
`errors.jsonl` 에도 안 남는다. **관문 4가 조용히 실패하는 자리가 정확히
여기다.** 한 번에 13개를 만든 적이 있다.

메꿀 때는 **새 이름을 만들기 전에 기존 어휘를 먼저 본다.** Sysmon 11
(FileCreate)은 `$UsnJrnl` 의 `file_create` 와 같은 사실이라 절만 더했다.
이름이 갈라지면 05단계가 같은 것을 두 번 찾아야 한다.

**② flag 의 `artifact` 를 정확히 썼는가**

`artifact: evtx:*` 로 쓰면 **카탈로그에 채널을 더할 때마다 사정거리가
조용히 넓어진다.** EventID 는 제공자 안에서만 유일하다 — 실측하면
`System.evtx` 하나에 제공자가 22개다.

채널이 5개에서 14개가 된 날 여섯 룰이 그렇게 됐고, 그중 AssignedAccess
세 채널은 event_id 필터 없이 전량 파싱되던 터라 그 채널의 ID 를 모르는
채로 노출돼 있었다. `evtx:Application` EID 4720 → `account_created` 가
붙는 것을 실제로 확인했다.

**③ 채널 전체를 요구했으면 그것을 받는 절이 있는가**

`scope_template: {}` 로 "이 채널을 다 읽겠다"고 해 놓고, 그 채널의 flag 가
특정 event_id 에만 걸려 있으면 나머지는 모델에 닿지 않는다.

`T1041` 이 `evtx:Firewall` 을 그렇게 걸고 rationale 에 "아웃바운드 연결의
허용·차단 기록"이라고 적었는데 **그 채널에는 그런 기록이 없었다** — 규칙
구성 변경만 담는다. 검사는 "받아 줄 절이 없다"까지만 안다. **rationale 이
틀렸는지는 사람이 채널 내용을 확인해야 나온다.** 걸리면 "고쳐라"가 아니라
"왜 그런지 보라"는 신호로 읽는다.

**④ 그 flag 가 실제로 거르는가**

"붙는가"와 "거르는가"는 다르다. Sysmon EID 1 전체에 붙이면 프로세스 생성이
전량 후보가 돼 쿼터를 혼자 태운다. 반대로 너무 좁히면 겨냥한 대상이 빠진다 —
`shell_spawned` 는 셸만 잡으므로 **USB 에서 실행된 비셸 악성코드는 Sysmon
쪽 근거가 0건이다.** 좁힐 때마다 "그래서 이 기법이 겨냥하는 것이 걸리나"를
되물어야 한다.

붙는 쪽과 안 붙는 쪽을 **같은 비중으로** 확인한다.

**이름으로만 거는 룰은 반쪽이다.** 공격자가 무엇을 실행할지는 모른다.
K-001 Stage 2 가 그 경우였다 — `shell_spawned` 는 셸 이름 목록으로 거는데
USB 로 들여온 `banker.exe` 는 그 목록에 없다. 이름 대신 **맥락**으로 거는
축을 함께 둔다.

| 축 | 무엇을 보나 | 예 |
|---|---|---|
| 무엇이 | 실행 파일의 이름 | `fields.Image` 가 셸·시스템 유틸리티 |
| **어디에** | 실행 파일이 놓인 자리 | 비시스템 볼륨, 쓰기 가능 임시 폴더 |
| **누가** | 부모 프로세스 | `fields.ParentImage` 가 explorer·스크립트 호스트 |

**부정으로 쓰지 않는다.** "정상 목록에 없으면"이 가장 강한 필터지만, 그
목록은 환경마다 다르고 베이스라인(Stage 0)에서 나온다. 전역 어휘인
`_flags.yaml` 에 특정 랩의 목록을 박으면 다른 환경에서 전량이 걸린다.
형식 가정이 틀렸을 때도 마찬가지다 — 긍정은 아무것도 안 걸리고(조용하지만
필터는 산다) 부정은 전부 걸린다(필터가 죽는다).

```bash
.venv/Scripts/python.exe -X utf8 -c "
import sys; sys.path.insert(0,'.')
from src.stage04_parse import flagging
from src.stage05_interpret import allocation
from src.stage03_select.mapping_loader import load_catalog
sigs = {n: s.signal_source for n, s in load_catalog('mappings').artifacts.items()}
def probe(artifact, **extra):
    rec = [{'artifact': artifact, 'ref': f'X#{i}', 'record_num': i, 'offset': '0x0',
            'timestamp': '2026-08-25T09:0%d:00Z' % i, 'fields': {}, **extra} for i in range(5)]
    f = list(flagging.apply_all(iter(rec)))
    return sum(1 for r in f if r['flags']), len(allocation.allocate_records(f, signal_sources=sigs)[0])
print('걸려야 하는 것:', probe('evtx:Sysmon', event_id=3))
print('안 걸려야 하는 것:', probe('evtx:Sysmon', event_id=255))
"
```

**6. 관통 확인**

```bash
.venv/Scripts/python.exe -m pytest -q
```

새 매핑 파일은 따로 손대지 않아도 `tests/test_mapping_loader.py`의 검사
대상에 자동으로 들어간다. Tier 2 `trigger` 유무, 변수 기본값, 카탈로그
등록 여부를 전부 본다.

**다만 두 곳은 손으로 맞춰야 한다.**

- `test_all_shipped_mappings_load`가 기법 ID 집합을 통째로 못박고 있다.
  새 매핑을 넣었으면 여기에도 ID를 더한다. 매핑이 조용히 사라지는 것을
  막으려고 일부러 열거해 둔 것이니, 집합을 지우지 말고 더한다.
- `mapping_table_version`을 올렸으면 **세 곳이 같이 움직인다** —
  `mappings/_artifacts.yaml`, `tests/test_mapping_loader.py`의 값 단언,
  `benchmark/datasets/C-001-webshell/mock/03_selection.json`. 하나만
  고치면 테스트 셋이 한꺼번에 깨진다. 매핑을 의미 있게 늘렸으면 올린다.

시나리오 하나를 실제로 태워 보려면 02단계 산출물을 손으로 써서 03단계에
넣는 것이 가장 빠르다. `benchmark/datasets/C-001-webshell/mock/02_scenario.json`을
복사해 `techniques`만 바꾼다.

```bash
.venv/Scripts/python.exe -m src.stage03_select.select \
  --in <02_scenario.json> --out /tmp/03.json --mappings mappings
```

`매핑 없음: T####`가 뜨면 관문 2, `selected 0`이면 관문 3이다.

---

## 하지 말 것

- **flags 어휘를 남발하지 않는다.** 필터가 일을 안 하게 된다. 기존 어휘로
  될 일이면 새로 만들지 않는다.
- **`match: event_id` 절에 `evtx:*` 를 쓰지 않는다.** 채널을 더할 때마다
  사정거리가 조용히 넓어진다. 정확한 아티팩트 이름으로 건다.
- **테스트가 통과하는 것만 보고 넘어가지 않는다.** 새로 붙인 가드는 **일부러
  되돌려** 실제로 잡는지 확인한다. 안 그러면 가드가 죽어도 모른다 — 실패하지
  않으므로 죽었다는 사실 자체가 안 드러난다.
- **선언으로 되는 조건을 `handler`로 내리지 않는다.** 내리는 순간
  `_flags.yaml`만 읽어서는 무슨 조건인지 알 수 없게 된다.
- **`03_selection.json`이 비었는데 매핑을 늘려서 때우지 않는다.** 원인이
  관문 1인지 3인지 먼저 가른다. `errors.jsonl`에 어느 쪽인지 남는다.
- **리눅스 매핑을 쓰지 않는다.** `mappings/linux/`는 비어 있고 카탈로그
  아티팩트가 전부 `os: [windows]`라 03단계에서 `empty_result`로 멈춘다.
  명시적 비목표다(`work-guide.md` 1.4).

---

## 시나리오가 도구 밖에서 막히는 경우

도구를 고쳐도 안 되는 것이 있다. 판단이 필요하면 `docs/limitations.md`.

- **디스크 이미지는 이제 직접 연다.** `--evidence <이미지> --volume N`.
  볼륨이 여럿이면 도구가 목록을 보여 주고 사람이 고른다.
- **한 실행은 한 볼륨이다.** 볼륨이 여럿이면 케이스를 나눈다.
- **evtx 채널은 11개다**(2026-08-25). Security·System에 Firewall·BITS·
  NetworkProfile·Sysmon·DriverFrameworks·Kernel-PnP·AssignedAccess 셋·
  TerminalServices 둘·Application이 더해졌다. 그 밖의 Operational 로그
  (PowerShell 등)는 여전히 카탈로그에 없다.
- **쓰기 필터(UWF)가 켜진 장비**는 재부팅 시 디스크 변경이 사라진다.
  증거가 없는 것이지 도구가 못 보는 것이 아니다. 이 경우 파이프라인은
  "깨끗함"을 출력하는데 그것이 사실과 다르다 — 보고서에 반드시 적는다.
