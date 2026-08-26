# 매핑 테이블 작성 규칙

`mappings/`는 **코드가 아니라 데이터**입니다. 여러 명이 동시에 채울 수 있고,
개수를 셀 수 있고, 파이썬을 몰라도 작성할 수 있습니다.

여기 담기는 것은 "이 기법을 확인하려면 어떤 아티팩트의 어디를 봐야 하는가"라는
도메인 지식입니다. 이 파일의 품질이 곧 **선별 재현율**입니다.

## 파일 구성

```
mappings/
├── _artifacts.yaml     아티팩트 카탈로그 — 이 도구가 아는 전부
├── _flags.yaml         flags 어휘 정의 (04단계가 사용)
├── windows/
│   └── T1505.003.yaml  기법 하나당 한 파일. 파일명 = 기법 ID
└── linux/
```

**파일명은 반드시 기법 ID와 같아야 합니다.** 로더가 불일치를 거부합니다.
파일명으로 "매핑이 있는 기법" 목록을 세기 때문입니다.

## 기법 매핑 파일

```yaml
technique: T1505.003
name: "Server Software Component: Web Shell"
os: windows

artifacts:
  - name: $MFT              # _artifacts.yaml 에 있는 이름과 정확히 일치
    tier: 1
    priority: 1             # 생략하면 2(중립)
    scope_template:
      path_prefix: ["{web_root}"]
      extensions: [".aspx", ".asp", ".ashx", ".asmx"]
    rationale: 웹셸 파일 생성 흔적

  - name: $UsnJrnl
    tier: 2
    trigger: Tier1 $MFT에서 timestamp_mismatch 또는 deleted 플래그 발견 시
    rationale: 웹셸 파일 삭제/재생성 이력

defaults:
  web_root: 'C:\inetpub\wwwroot'
```

### Tier 1과 Tier 2

| | 의미 | 필수 항목 |
|---|---|---|
| **Tier 1** | 지금 읽는다 | `scope_template` (비어 있어도 됨) |
| **Tier 2** | 조건이 맞으면 읽는다 | `trigger` |

Tier 1에 `trigger`를 쓰거나 Tier 2에 `trigger`를 빠뜨리면 **로드가 실패합니다.**
Tier 2의 핵심은 "언제 보게 되는가"입니다. 조건 없는 유예는 보고서에서
왜 안 봤는지 설명할 수 없습니다.

본 버전은 **Tier 2 루프백을 구현하지 않습니다**(명시적 비목표). `deferred`는
기록만 되고 실제로 파싱되지 않으며, 보고서의 "분석 범위 한계"로 전달됩니다.
그래도 `trigger`를 정확히 쓰세요 — 그 문장이 보고서에 그대로 실립니다.

### priority — 이 기법에서 이 아티팩트의 비중

05단계가 모델에 넘길 자리(기본 60건)를 **아티팩트별로 나눌 때** 쓰는
값입니다. `tier`와 같은 방향으로 **작을수록 강합니다.**

| | 뜻 | 가중치 |
|---|---|---|
| `1` | 판정의 근거 그 자체. 이것이 없으면 그 기법을 말할 수 없다 | 4 |
| `2` | 보조. 다른 아티팩트의 판정을 뒷받침한다. **생략하면 이 값** | 2 |
| `3` | 배경. 있으면 맥락이 넓어지지만 없어도 판정은 선다 | 1 |

**기법의 속성이 아니라 (기법, 아티팩트) 쌍의 속성입니다.** 같은 `$MFT`라도
`T1070.006`(Timestomp)에서는 `$SI`/`$FN` 불일치가 판정 그 자체라 `1`이고,
`T1053.005`(Scheduled Task)에서는 이벤트 로그를 보조하는 자리라 `2`입니다.

한 아티팩트를 여러 기법이 요청하면 **가장 강한 값**이 이깁니다. 합치거나
평균 내면 스치듯 요청한 기법 여럿이 강하게 요청한 기법 하나를 이깁니다.

눈금이 셋뿐인 것은 **사람이 채우는 값**이기 때문입니다. 열 단계를 주면
채우는 사람마다 기준이 달라지고, 검토하는 사람이 3과 4의 차이를 따질 수
없습니다. 눈금 밖의 값(`0`, `4`, `"1"`, `yes`)은 로드가 실패합니다.

> **지금 어떤 매핑도 `priority`를 적지 않았습니다.** 전부 중립이라 배분을
> 가르는 것은 후보 수뿐입니다. 누락이 아니라 **나중에 채우기로 미룬
> 것입니다**(2026-08-24). 이 값은 어떤 자동 규칙에서도 나오지 않습니다 —
> 분석가가 판단해 적고 다른 사람이 검토해야 합니다(`limitations.md` 6-5).
> 새 매핑을 쓰는 사람은 아는 만큼만 적고, 모르면 비워 두십시오. 비워 둔
> 것과 판단해서 2를 적은 것을 구별할 방법은 없으므로, 판단해서 적었다면
> `rationale`에 그 근거가 드러나게 씁니다.

### rationale은 보고서에 실립니다

"왜 이 아티팩트를 봤는가"의 답입니다. 비워 두면 로드가 실패합니다.
`웹셸 파일 생성 흔적`처럼 **무엇을 찾으려는지**를 쓰고, `중요함` 같은
평가어는 쓰지 마세요.

### scope_template 변수

`{변수명}` 형태로 씁니다. 값은 두 곳에서 옵니다.

1. **시나리오의 `entities`** — 사용자가 실제로 언급한 값 (우선)
2. **매핑의 `defaults`** — 언급이 없을 때의 관례적 위치

| 변수 | 시나리오 출처 |
|---|---|
| `{web_root}` | `entities.paths[0]` |
| `{host}` | `entities.hosts[0]` |
| `{account}` | `entities.accounts[0]` |
| `{process}` | `entities.processes[0]` |
| `{ip}` | `entities.ips[0]` |

**모든 변수는 `defaults`에 기본값이 있어야 합니다.** 시나리오가 비어 있어도
치환이 되어야 하며, 치환 실패는 에러입니다(자리표시자가 그대로 실려
파서가 없는 경로를 찾는 것을 막습니다).

`time_range`는 쓰지 마세요. 시나리오에서 자동으로 붙습니다.

### followups — 후속 기법

시나리오에 없는 기법의 아티팩트를 Tier 2로 걸어 둘 수 있습니다.

```yaml
followups:
  - technique: T1543.003
    artifact: evtx:System
    tier: 2
    trigger: Tier1에서 서비스 관련 정황 발견 시
    rationale: 서비스 기반 지속성
```

분석가는 웹셸을 찾으면 관행적으로 서비스 지속성도 확인합니다. 그 판단
순서를 데이터로 옮긴 것입니다. `reason.technique`에는 **후속 기법 ID**가
들어가므로, 보고서를 읽는 사람이 왜 이걸 봐야 하는지 알 수 있습니다.

남용하지 마세요. 후속을 많이 걸수록 `deferred`가 길어지고 보고서의
"분석 범위 한계"가 읽히지 않습니다.

## 아티팩트 카탈로그 (`_artifacts.yaml`)

**이 파일에 없는 아티팩트는 존재하지 않는 것과 같습니다.** 선별될 수도,
제외될 수도 없고, 보고서의 "분석 범위 한계"에도 나타나지 않습니다.

새 아티팩트를 지원하려면 파서보다 이 파일을 **먼저** 고칩니다.

```yaml
  $LogFile:
    parser: null
    os: [windows]
    supported: false
    exclude_reason: 본 버전 미지원 (파싱 모듈 범위 외)
```

제외 사유는 **OS 변종과 무관하게 참이어야 합니다.** `prefetch`가 한때
"Windows Server 기본 비활성화"였는데, 그 문장이 Windows 10 케이스 보고서에
그대로 실려 사실과 달라졌습니다. 수집되지 않은 것은 제외 사유가 아니라
**증거 없음**이고, 04단계가 `artifact_not_found`로 따로 기록합니다.

`supported: false`면 `exclude_reason`이 **필수**입니다. 그 문장이 최종
보고서에 그대로 실리기 때문입니다.

### signal_source — 이 아티팩트의 신호가 어디서 나오는가

05단계가 "볼 만한 레코드"를 가리는 방식이 갈립니다.

| | 뜻 | 05단계 후보 |
|---|---|---|
| `flags` | 04단계가 전부 훑고 재미있는 것에 플래그를 붙인다. **생략하면 이 값** | 플래그가 붙은 것 + 그 주변 시간창 |
| `scope` | 가치가 레코드가 아니라 **경로**에 있다. 03단계 `path_prefix`가 이미 판정을 끝냈다 | **전부** |

레지스트리 두 하이브가 `scope`입니다. `Services\XYZ\ImagePath`는 그 경로가
무엇을 뜻하는지 알아야 의미가 생기므로 04단계가 붙일 플래그가 없고,
`flags`로 두면 선별이 정확히 골라 온 것이 05단계에서 전부 탈락합니다
(`limitations.md` 6-7 — 실측 1,754건이 0건이 됐습니다).

`scope` 아티팩트는 시간창으로도 거르지 않습니다. `Services` 하위 키의
LastWrite는 대개 OS 설치 시각이라 사건 시간창에 걸리지 않기 때문입니다.

`mapping_table_version`은 매핑을 채워 나가면서 재현율이 어떻게 변하는지
추적하는 값입니다. 의미 있게 바뀔 때마다 올리고, `03_selection.json`에
기록되므로 나중에 어느 버전으로 선별했는지 복원할 수 있습니다.

## flags 어휘 (`_flags.yaml`)

`flags`는 04단계가 레코드에 붙이는 "볼 만하다"는 표식이고, **05단계가
sLLM에 전달할 레코드를 고르는 유일한 기준**입니다. 여기서 안 붙으면 그
레코드는 모델 입장에서 존재하지 않습니다.

**이 파일이 어휘와 룰의 원본입니다.** `flagging.py`가 여기서 목록을 읽고,
`schemas/parsed_record.schema.json`의 enum은 `tools/sync_flag_enum.py`가
여기서 생성합니다. 손으로 고치는 파일은 YAML 하나입니다.

```yaml
service_installed:
  artifacts: [evtx:System]
  condition: EVTX 7045 서비스 설치
  rule:
    when:
      - artifact: evtx:*
        match: event_id
        values: [7045]
```

`when`은 절 목록이고 **하나라도 맞으면** 붙습니다. 절이 여럿인 것은 같은
뜻이 아티팩트마다 다르게 나타나기 때문입니다 — `deleted`는 `$MFT`에서
"미할당 상태"로, `$UsnJrnl`에서 "삭제 사유"로 나타납니다.

| `match` | 조건 |
|---|---|
| 생략 | 그 아티팩트의 모든 레코드 |
| `event_id` | `record["event_id"]`가 `values` 안에 있는가 |
| `list_contains` | 리스트 필드 `field`가 `values`와 겹치는가 |
| `field_equals` | `record[field]`가 `value`와 같은가 |
| `field_endswith` | 점 표기 `field`(예: `fields.Image`)의 값이 `values` 중 하나로 끝나는가. 대소문자 무시 |

`artifact`는 `$MFT`처럼 정확히 쓰거나 `evtx:*`로 접두어를, `*`로 전부를
가리킵니다. 카탈로그에 있는 이름이어야 합니다.

**`match: event_id`와 접두어 와일드카드를 함께 쓰지 마세요.** EventID는
제공자 안에서만 유일해서, `evtx:*`로 걸면 **카탈로그에 채널을 더할 때마다
사정거리가 조용히 넓어집니다.** 2026-08-25에 채널이 5개에서 14개가 되면서
여섯 룰이 그렇게 됐습니다(`docs/limitations.md`). `tests/test_flag_rules.py`가
이제 막습니다. `*`는 `match` 없는 전역 표식(`outside_time_range`)에만 씁니다.

`field_endswith`의 값에는 **경로 구분자를 포함시키십시오** — `\cmd.exe`
처럼. `cmd.exe`만 쓰면 `evilcmd.exe`가 함께 걸립니다. 매처가 그 판단을
대신하지 않는 것은, YAML만 읽고도 무엇이 걸리는지 보여야 하기 때문입니다.

### `handler`는 선언으로 안 되는 것만

`flagging.py`의 `HANDLERS`에 등록된 판정을 이름으로 부릅니다. `when`과
함께 쓰면 **둘 다** 만족해야 합니다 — `when`이 대상을 좁히고 `handler`가
판정합니다.

```yaml
privileged_group_add:
  rule:
    when:
      - artifact: evtx:*
        match: event_id
        values: [4728, 4732]
    handler: target_is_privileged_group
```

**선언으로 되는 것을 handler로 넘기지 마세요.** 넘기는 순간 이 파일만
읽어서는 무슨 조건인지 알 수 없게 됩니다. handler는 타임스탬프 비교처럼
근거가 코드 주석에 붙어 있어야 하는 것만 씁니다(`$SI`/`$FN` 비교는 세 쌍을
다 보면 오탐이 59%였다는 실측이 주석에 남아 있습니다).

### 새 flag를 추가하는 절차

1. `mappings/_flags.yaml`에 항목을 쓴다
2. `.venv/Scripts/python.exe tools/sync_flag_enum.py` — 스키마 enum이 따라온다
3. `.venv/Scripts/python.exe -m pytest`

`event_id`·USN 사유·필드값으로 표현되는 조건이면 **1번에서 끝납니다.**
`tests/test_flag_rules.py`가 어긋난 정의를 로드 시점에 잡습니다.

### 특권 그룹 목록

`privileged_groups`는 예전부터 런타임에 읽던 값이라 이름만 추가하면 바로
반영됩니다. 생성기를 돌릴 필요도 없습니다.

## 선별 결과가 만들어지는 순서

1. 시나리오의 각 기법에 대해 매핑을 찾는다. 없으면 `errors.jsonl`에
   `empty_result` / `skip`으로 기록하고 넘어간다 — **매핑 결손 데이터**다
2. 요청된 아티팩트 중 카탈로그가 읽을 수 없다고 한 것은 건너뛴다
3. Tier 1 → `selected`, Tier 2 → `deferred`
4. **이미 Tier 1로 읽는 아티팩트는 `deferred`에서 뺀다** — 보고서에
   "안 봤다"고 적히면 사실과 다르다
5. 카탈로그를 훑어 `excluded`를 만든다
   - 읽을 수 없는 것 → 카탈로그의 사유
   - 아무도 요청하지 않은 것 → `식별된 기법에 매핑된 아티팩트가 아님`

### 같은 아티팩트가 여러 번 나올 수 있습니다

두 기법이 각자의 이유로 `$MFT`를 Tier 1로 요청하면 `selected`에 **두 항목**이
들어갑니다. 합치지 않는 이유는 기법마다 "왜 필요한지"를 보존하기 위해서입니다.

**04단계 계약**: `parse.py`는 `selected`를 아티팩트별로 묶고 `scope`를
합집합으로 읽습니다. 같은 아티팩트를 두 번 파싱하지 않습니다.

## 알려진 한계

### 웹 스택별 변형

`windows/T1505.003.yaml`은 IIS 확장자(`.aspx` `.asp` `.ashx` `.asmx`)만
봅니다. Windows에서도 PHP/JSP는 돌지만 웹루트와 스택이 달라 같은 매핑으로
덮을 수 없습니다.

XAMPP나 Tomcat 환경을 다루게 되면 별도 매핑 변형이 필요합니다. 지금은
**해당 환경의 웹셸을 놓칩니다.** 재현율 측정에서 드러날 지점입니다.

### `{web_root}`를 `entities.paths[0]`에서 가져오는 것

02단계가 웹 침해 시나리오에서 웹루트를 첫 경로로 올린다는 관찰에 기댄
가정입니다. 사용자가 웹루트가 아닌 경로를 먼저 언급하면 엉뚱한 곳을 봅니다.

`defaults`만 쓰는 쪽이 안전해 보이지만 더 위험합니다. 비표준 경로에 설치된
서버를 통째로 놓치는데, **잘못된 곳을 보면 결과가 비어 있어 알아채지만
안 본 것은 드러나지 않기 때문입니다.**

## 새 기법을 추가하는 절차

1. `src/common/attack.py`의 `KNOWN_TECHNIQUES`에 ID와 이름을 넣는다
   (없으면 02단계가 스키마 위반으로 기각한다)
2. `mappings/<os>/<기법ID>.yaml`을 만든다
3. 필요한 아티팩트가 카탈로그에 없으면 `_artifacts.yaml`에 먼저 추가한다
   (파서가 없으면 `.claude/skills/add-parser/SKILL.md`부터 본다)
4. 그 아티팩트의 신호가 기존 flags 어휘로 표현되는지 본다. 안 되면
   위 "새 flag를 추가하는 절차"를 먼저 밟는다 — **매핑이 정확해도 flag가
   없으면 05단계에 레코드가 가지 않는다**
5. `.venv/Scripts/python.exe -m pytest tests/test_mapping_loader.py` 로
   로드되는지 확인한다

`tests/test_mapping_loader.py`는 모든 매핑에 대해 Tier 2의 `trigger` 유무,
변수의 기본값 유무, 카탈로그 등록 여부를 자동으로 확인합니다. 새 파일도
따로 손대지 않아도 검사 대상에 들어갑니다.
