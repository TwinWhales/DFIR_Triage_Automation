# 파이프라인 단계별 파일 입출력 명세

> 예시는 모두 동일 케이스(C-001, 웹셸 침해 의심)를 기준으로 작성되어 파일 간 참조가 실제로 연결됩니다.

## 공통 규약

### 디렉터리 구조

```
cases/
└── C-001/
    ├── 01_input.json
    ├── 02_scenario.json
    ├── 03_selection.json
    ├── 04_parsed/
    │   ├── mft.jsonl
    │   ├── evtx_security.jsonl
    │   └── _manifest.json
    ├── 05_findings.json
    ├── 06_verified.json
    ├── 07_report.md
    └── errors.jsonl
schemas/
├── scenario.schema.json
├── selection.schema.json
└── findings.schema.json
```

### 공통 헤더

모든 JSON 문서(JSONL 제외)는 최상위에 다음 필드를 포함합니다.

```json
{
  "case_id": "C-001",
  "stage": "02_normalize",
  "schema_version": "1.0",
  "generated_at": "2026-08-06T04:12:33Z",
  "generator": "normalize.py / qwen2.5-7b-instruct-q4"
}
```

`generator`에 모델명과 양자화 수준까지 기록해 두면 나중에 모델별 비교 실험에서 결과 파일만 보고 조건을 복원할 수 있습니다.

### 참조자(ref) 규칙

전 단계를 관통하는 증거 식별자입니다. 형식은 `<아티팩트약칭>#<레코드번호>`.

| 아티팩트 | 접두어 | 예시 |
|---|---|---|
| $MFT | `MFT` | `MFT#12345` |
| $UsnJrnl:$J | `USN` | `USN#8821004` |
| Security.evtx | `EVTX-SEC` | `EVTX-SEC#40912` |
| System.evtx | `EVTX-SYS` | `EVTX-SYS#1177` |

레코드 번호는 아티팩트 내부의 고유 번호(MFT 레코드 번호, EVTX RecordId 등)를 그대로 씁니다. 자체 일련번호를 새로 매기면 원본 대조가 어려워집니다.

---

## 01_input.json

원본 입력을 가공 없이 보존합니다. 이 파일은 재실행 시 진입점이므로 절대 덮어쓰지 않습니다.

### 자연어 입력

```json
{
  "case_id": "C-001",
  "stage": "01_input",
  "schema_version": "1.0",
  "generated_at": "2026-08-06T04:10:00Z",
  "source_type": "natural_language",
  "raw": "웹서버 WEB01에서 이상한 aspx 파일이 발견됐습니다. 비슷한 시기에 관리자 그룹에 모르는 계정이 추가된 것 같습니다. 7월 20일 전후로 보입니다.",
  "evidence": {
    "root": "/mnt/evidence/WEB01",
    "os_hint": "windows_server_2019",
    "artifacts_available": ["$MFT", "$UsnJrnl", "evtx"]
  }
}
```

### EDR/SIEM 알럿 입력

```json
{
  "case_id": "C-002",
  "stage": "01_input",
  "schema_version": "1.0",
  "generated_at": "2026-08-06T04:10:00Z",
  "source_type": "edr_alert",
  "raw": {
    "alert_id": "EDR-99213",
    "rule_name": "Suspicious child process from web server",
    "severity": "high",
    "detected_at": "2026-07-20T03:16:40Z",
    "host": "WEB01",
    "process": {
      "name": "cmd.exe",
      "parent": "w3wp.exe",
      "cmdline": "cmd.exe /c whoami"
    },
    "mitre": ["T1505.003"]
  },
  "evidence": {
    "root": "/mnt/evidence/WEB01",
    "os_hint": "windows_server_2019",
    "artifacts_available": ["$MFT", "$UsnJrnl", "evtx"]
  }
}
```

`raw`의 내부 구조는 EDR 제품마다 다르므로 스키마로 강제하지 않습니다. 정규화 단계에서 흡수합니다.

---

## 02_scenario.json

sLLM이 채우는 유일한 구조체입니다. 여기서부터 이후 단계는 이 스키마만 신뢰합니다.

```json
{
  "case_id": "C-001",
  "stage": "02_normalize",
  "schema_version": "1.0",
  "generated_at": "2026-08-06T04:12:33Z",
  "generator": "qwen2.5-7b-instruct-q4",
  "target_os": "windows",
  "techniques": [
    { "id": "T1505.003", "name": "Web Shell", "confidence": 0.85,
      "evidence_text": "이상한 aspx 파일이 발견됐습니다" },
    { "id": "T1136.001", "name": "Create Account: Local Account", "confidence": 0.70,
      "evidence_text": "관리자 그룹에 모르는 계정이 추가된 것 같습니다" }
  ],
  "time_range": {
    "start": "2026-07-18T00:00:00Z",
    "end": "2026-07-22T23:59:59Z",
    "basis": "사용자가 7월 20일 전후로 언급, ±2일 확장"
  },
  "entities": {
    "hosts": ["WEB01"],
    "paths": ["C:\\inetpub\\wwwroot"],
    "processes": [],
    "accounts": [],
    "ips": []
  },
  "overall_confidence": 0.78,
  "unmapped_text": []
}
```

### 필드 설계 근거

| 필드 | 목적 |
|---|---|
| `evidence_text` | 입력 원문 중 해당 기법을 판단한 근거 구간. 오분류 원인 추적에 필수 |
| `confidence` | 낮은 값이면 선별 단계에서 Tier 범위를 넓히는 신호로 사용 |
| `time_range.basis` | 시간 범위를 어떻게 추론했는지. 범위가 틀렸을 때 원인이 드러남 |
| `unmapped_text` | 기법으로 매핑하지 못한 서술. 매핑 테이블의 결손 지점을 찾는 데이터 |

### 검증 규칙

- `techniques[].id`는 사전 정의된 ATT&CK ID 목록에 존재해야 함
- `confidence`는 0.0~1.0
- `techniques`가 빈 배열이면 스키마 위반으로 처리하고 `errors.jsonl`에 기록 후 중단
- `target_os`는 `windows` / `linux` 중 하나

---

## 03_selection.json

무엇을 볼지, 무엇을 보지 않을지에 대한 결정. 결정론적 스크립트가 매핑 테이블을 참조해 생성합니다.

```json
{
  "case_id": "C-001",
  "stage": "03_select",
  "schema_version": "1.0",
  "generated_at": "2026-08-06T04:12:40Z",
  "generator": "select.py",
  "mapping_table_version": "0.3",
  "selected": [
    {
      "artifact": "$MFT",
      "tier": 1,
      "scope": {
        "path_prefix": ["C:\\inetpub\\wwwroot"],
        "extensions": [".aspx", ".asp", ".ashx", ".asmx"],
        "time_range": { "start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z" }
      },
      "reason": { "technique": "T1505.003", "rationale": "웹셸 파일 생성 흔적" }
    },
    {
      "artifact": "evtx:Security",
      "tier": 1,
      "scope": {
        "event_ids": [4720, 4728, 4732],
        "time_range": { "start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z" }
      },
      "reason": { "technique": "T1136.001", "rationale": "계정 생성 및 권한 그룹 추가" }
    }
  ],
  "deferred": [
    {
      "artifact": "$UsnJrnl",
      "tier": 2,
      "trigger": "Tier1 $MFT에서 timestamp_mismatch 또는 deleted 플래그 발견 시",
      "reason": { "technique": "T1505.003", "rationale": "웹셸 파일 삭제/재생성 이력" }
    },
    {
      "artifact": "evtx:System",
      "tier": 2,
      "trigger": "Tier1에서 서비스 관련 정황 발견 시",
      "reason": { "technique": "T1543.003", "rationale": "서비스 기반 지속성" }
    }
  ],
  "excluded": [
    {
      "artifact": "prefetch",
      "reason": "Windows Server 기본 설정에서 비활성화되어 수집 불가"
    },
    {
      "artifact": "$LogFile",
      "reason": "본 버전 미지원 (파싱 모듈 범위 외)"
    }
  ],
  "stats": {
    "selected_count": 2,
    "deferred_count": 2,
    "excluded_count": 2
  }
}
```

`excluded`는 최종 보고서까지 그대로 전달됩니다. "보지 않기로 한 것과 그 이유"를 남기는 것이 이 설계의 핵심이므로 생략하지 않습니다.

### 매핑 테이블 (참고: `mappings/T1505.003.yaml`)

```yaml
technique: T1505.003
name: Web Shell
os: windows
artifacts:
  - name: $MFT
    tier: 1
    scope_template:
      path_prefix: ["{web_root}"]
      extensions: [".aspx", ".asp", ".ashx", ".asmx", ".php", ".jsp"]
    rationale: 웹셸 파일 생성 흔적
  - name: $UsnJrnl
    tier: 2
    trigger: "Tier1 $MFT에서 timestamp_mismatch 또는 deleted 플래그 발견 시"
    rationale: 웹셸 파일 삭제/재생성 이력
defaults:
  web_root: "C:\\inetpub\\wwwroot"
```

---

## 04_parsed/*.jsonl

아티팩트별 개별 파일. 한 줄이 한 레코드입니다.

### mft.jsonl

```jsonl
{"ref":"MFT#12345","artifact":"$MFT","record_num":12345,"offset":"0x1E000","path":"C:\\inetpub\\wwwroot\\upload\\shell.aspx","allocated":true,"is_directory":false,"size":4821,"si_ctime":"2026-07-20T03:14:22.1234567Z","si_mtime":"2026-07-20T03:14:22.1234567Z","si_atime":"2026-07-20T03:14:22.1234567Z","si_btime":"2026-07-20T03:14:22.1234567Z","fn_ctime":"2026-07-21T09:02:11.7654321Z","fn_mtime":"2026-07-21T09:02:11.7654321Z","fn_btime":"2026-07-21T09:02:11.7654321Z","flags":["timestamp_mismatch"]}
{"ref":"MFT#12346","artifact":"$MFT","record_num":12346,"offset":"0x1E400","path":"C:\\inetpub\\wwwroot\\upload\\index.aspx","allocated":true,"is_directory":false,"size":2104,"si_ctime":"2026-03-11T08:00:00.0000000Z","si_mtime":"2026-03-11T08:00:00.0000000Z","si_atime":"2026-07-20T03:15:01.0000000Z","si_btime":"2026-03-11T08:00:00.0000000Z","fn_ctime":"2026-03-11T08:00:00.0000000Z","fn_mtime":"2026-03-11T08:00:00.0000000Z","fn_btime":"2026-03-11T08:00:00.0000000Z","flags":[]}
```

### evtx_security.jsonl

```jsonl
{"ref":"EVTX-SEC#40912","artifact":"evtx:Security","record_num":40912,"offset":"0x2A1000","event_id":4720,"timestamp":"2026-07-20T03:22:15.0000000Z","channel":"Security","computer":"WEB01","fields":{"TargetUserName":"svc_backup","SubjectUserName":"IIS APPPOOL\\DefaultAppPool"},"flags":["account_created"]}
{"ref":"EVTX-SEC#40915","artifact":"evtx:Security","record_num":40915,"offset":"0x2A1D40","event_id":4732,"timestamp":"2026-07-20T03:22:19.0000000Z","channel":"Security","computer":"WEB01","fields":{"TargetUserName":"Administrators","MemberName":"svc_backup"},"flags":["privileged_group_add"]}
```

### _manifest.json

```json
{
  "case_id": "C-001",
  "stage": "04_parse",
  "schema_version": "1.0",
  "generated_at": "2026-08-06T04:18:02Z",
  "generator": "parse.py",
  "files": [
    { "artifact": "$MFT", "path": "mft.jsonl", "record_count": 1842,
      "flagged_count": 3, "parse_errors": 0,
      "source_path": "/mnt/evidence/WEB01/$MFT", "source_method": "volume_path" },
    { "artifact": "evtx:Security", "path": "evtx_security.jsonl", "record_count": 517,
      "flagged_count": 2, "parse_errors": 1, "unreadable_bytes": 4096,
      "source_path": "/mnt/evidence/WEB01/Windows/System32/winevt/Logs/Security.evtx",
      "source_method": "volume_path" }
  ],
  "skipped": [
    { "artifact": "$UsnJrnl", "reason": "empty_artifact",
      "message": "$UsnJrnl: 파일은 있으나 0바이트입니다 ($Extend/$UsnJrnl). ..." }
  ],
  "total_records": 2359,
  "flagged_records": 5
}
```

### `skipped` — 읽지 못한 아티팩트

**매니페스트는 04단계가 자기가 한 일을 적는 곳이므로 "안 한 일"도 여기 적습니다.**

예전에는 스킵이 `errors.jsonl`에만 남아 07단계가 볼 수 없었고, 그 결과 보고서가 읽지 못한 아티팩트를 **언급조차 하지 않았습니다**(`docs/limitations.md` 4-1). `errors.jsonl`은 전 단계가 공유하는 집계용 로그라, 07이 그것을 파싱하면 에러 로그 형식에 묶입니다.

| `reason` | 뜻 | 분석가의 조치 |
|---|---|---|
| `artifact_not_found` | 선별했는데 증거에 없음 | 다시 수집 |
| `empty_artifact` | 파일은 있는데 0바이트 | 다시 추출 |
| `parser_missing` | 이 버전이 못 읽는 아티팩트 | 다른 도구로 확인 |

### `unreadable_bytes` — 못 읽은 규모

`parse_errors`는 **못 읽은 구간의 개수**이고 `unreadable_bytes`는 그 총 크기입니다. 둘을 함께 봐야 규모를 알 수 있습니다 — 구간 1곳이 8바이트인 것과 500KB인 것은 판단이 다릅니다.

연속된 실패를 한 구간으로 묶는 이유는, 걸음마다 세면 비저널 구간 하나가 수만 건으로 부풀어 **"저널이 심하게 손상됐다"고 정반대로 읽히기** 때문입니다(실측 사례는 `docs/limitations.md` 4-0-1).

### flags 어휘 (고정 목록)

파싱 단계에서 룰 기반으로 부여합니다. LLM에 전달할 레코드를 추리는 필터로 쓰이므로 어휘를 고정합니다.

| flag | 조건 |
|---|---|
| `timestamp_mismatch` | $SI와 $FN 타임스탬프 불일치 |
| `deleted` | MFT 레코드 미할당 상태 |
| `zero_timestamp` | 타임스탬프가 0 또는 비정상 값 |
| `account_created` | EVTX 4720 |
| `privileged_group_add` | EVTX 4728/4732, 대상이 특권 그룹 |
| `outside_time_range` | 선별된 시간 범위 밖 |

LLM 입력 축소는 `flags`가 비어있지 않은 레코드 + 시간순 상위 N건 방식으로 처리합니다. 전달된 레코드 목록은 `05_findings.json`의 `input_refs`에 기록합니다.

---

## 05_findings.json

sLLM 해석 결과. 모든 문장에 `refs` 필수입니다.

```json
{
  "case_id": "C-001",
  "stage": "05_interpret",
  "schema_version": "1.0",
  "generated_at": "2026-08-06T04:21:47Z",
  "generator": "qwen2.5-7b-instruct-q4",
  "input_refs": ["MFT#12345", "MFT#12346", "EVTX-SEC#40912", "EVTX-SEC#40915"],
  "findings": [
    {
      "id": "F1",
      "statement": "웹루트 하위 upload 디렉터리에 shell.aspx가 2026-07-20 03:14:22에 생성되었으며, $SI와 $FN 타임스탬프가 일치하지 않아 타임스탬프 조작 정황이 확인됩니다.",
      "refs": ["MFT#12345"],
      "claims": [
        { "ref": "MFT#12345", "field": "path", "value": "C:\\inetpub\\wwwroot\\upload\\shell.aspx" },
        { "ref": "MFT#12345", "field": "si_ctime", "value": "2026-07-20T03:14:22Z" },
        { "ref": "MFT#12345", "field": "flags", "value": "timestamp_mismatch" }
      ],
      "technique": "T1505.003",
      "severity": "high"
    },
    {
      "id": "F2",
      "statement": "웹셸 생성 약 8분 후 IIS 애플리케이션 풀 계정에 의해 svc_backup 계정이 생성되고 Administrators 그룹에 추가되었습니다.",
      "refs": ["EVTX-SEC#40912", "EVTX-SEC#40915"],
      "claims": [
        { "ref": "EVTX-SEC#40912", "field": "fields.TargetUserName", "value": "svc_backup" },
        { "ref": "EVTX-SEC#40912", "field": "timestamp", "value": "2026-07-20T03:22:15Z" },
        { "ref": "EVTX-SEC#40915", "field": "fields.MemberName", "value": "svc_backup" }
      ],
      "technique": "T1136.001",
      "severity": "high"
    },
    {
      "id": "F3",
      "statement": "전반적으로 웹셸을 통한 초기 침투 이후 계정 생성으로 지속성을 확보한 전형적인 공격 흐름으로 판단됩니다.",
      "refs": [],
      "claims": [],
      "technique": null,
      "severity": "info"
    }
  ],
  "timeline": [
    { "ts": "2026-07-20T03:14:22Z", "event": "shell.aspx 생성", "refs": ["MFT#12345"] },
    { "ts": "2026-07-20T03:22:15Z", "event": "svc_backup 계정 생성", "refs": ["EVTX-SEC#40912"] },
    { "ts": "2026-07-20T03:22:19Z", "event": "svc_backup을 Administrators에 추가", "refs": ["EVTX-SEC#40915"] }
  ]
}
```

### claims 필드가 핵심입니다

`statement`는 자연어라 기계 검증이 불가능합니다. 그래서 문장이 주장하는 사실을 `(ref, field, value)` 삼중항으로 별도 분해하게 합니다. 검증기는 `claims`만 대조하면 됩니다.

`F3`처럼 종합 판단은 `claims`가 비어 있으며, 다음 단계에서 `unverifiable`로 분류됩니다.

---

## 06_verified.json

```json
{
  "case_id": "C-001",
  "stage": "06_verify",
  "schema_version": "1.0",
  "generated_at": "2026-08-06T04:22:03Z",
  "generator": "verify.py",
  "tolerance": { "timestamp_seconds": 1 },
  "passed": [
    { "id": "F1", "checks": 3, "checks_passed": 3 },
    { "id": "F2", "checks": 3, "checks_passed": 3 }
  ],
  "rejected": [],
  "unverifiable": [
    { "id": "F3", "reason": "claims 없음 (종합 판단 문장)" }
  ],
  "stats": {
    "total_findings": 3,
    "passed": 2,
    "rejected": 0,
    "unverifiable": 1,
    "hallucination_rate": 0.0
  }
}
```

### 기각 사례 예시

```json
{
  "rejected": [
    {
      "id": "F4",
      "reason": "ref_not_found",
      "detail": { "ref": "MFT#99999", "message": "파싱 결과에 존재하지 않는 레코드" }
    },
    {
      "id": "F5",
      "reason": "value_mismatch",
      "detail": {
        "ref": "MFT#12345", "field": "si_ctime",
        "claimed": "2026-07-19T22:00:00Z",
        "actual": "2026-07-20T03:14:22Z"
      }
    },
    {
      "id": "F6",
      "reason": "ref_not_in_input",
      "detail": { "ref": "MFT#12400", "message": "LLM에 전달되지 않은 레코드를 참조" }
    }
  ]
}
```

### 판정 규칙

| 조건 | 판정 |
|---|---|
| `claims`의 모든 항목이 파싱 결과와 일치 | `passed` |
| `claims` 중 하나라도 불일치 또는 참조 없음 | `rejected` (부분 통과 없음) |
| `claims`가 빈 배열 | `unverifiable` |
| `refs`가 `input_refs`에 없는 레코드를 포함 | `rejected` |

`ref_not_in_input` 검사는 LLM이 입력받지 않은 레코드를 지어낸 경우를 잡습니다. 실무에서 가장 흔한 환각 유형입니다.

타임스탬프 비교는 `tolerance.timestamp_seconds` 범위 내 오차를 허용합니다. 문자열 완전 일치를 요구하면 초 단위 절삭 표기(`03:14:22` vs `03:14:22.1234567Z`)에서 대량 오탐이 발생합니다.

---

## 07_report.md

`06_verified.json`의 `passed` 항목만 입력으로 받아 생성합니다. 원본 파싱 데이터는 다시 주지 않습니다.

```markdown
# 침해사고 분석 보고서 — C-001

## 개요
- 대상 호스트: WEB01 (Windows Server 2019)
- 분석 기간: 2026-07-18 ~ 2026-07-22
- 식별 기법: T1505.003 (Web Shell), T1136.001 (Create Account)

## 확인된 사항

### F1 — 웹셸 파일 생성 및 타임스탬프 조작 [높음]
웹루트 하위 upload 디렉터리에 shell.aspx가 2026-07-20 03:14:22에 생성되었으며,
$SI와 $FN 타임스탬프가 일치하지 않아 타임스탬프 조작 정황이 확인됩니다.

> 근거: $MFT 레코드 12345 (오프셋 0x1E000)

### F2 — 특권 계정 생성 [높음]
...

## 타임라인
| 시각 | 사건 | 근거 |
|---|---|---|
| 2026-07-20 03:14:22 | shell.aspx 생성 | MFT#12345 |
| 2026-07-20 03:22:15 | svc_backup 계정 생성 | EVTX-SEC#40912 |

## 미검증 항목
다음 서술은 특정 증거로 뒷받침되지 않는 종합 판단이며 분석가 검토가 필요합니다.
- 웹셸을 통한 초기 침투 이후 계정 생성으로 지속성을 확보한 흐름으로 판단됨

## 분석 범위

### 확인한 아티팩트
| 아티팩트 | 레코드 | 비고 |
|---|---|---|
| $MFT | 1,842건 |  |
| evtx:Security | 517건 | 부분 판독 — 구간 1곳 / 4,096바이트를 읽지 못함 |

### 확인하지 못한 아티팩트
| 아티팩트 | 사유 |
|---|---|
| prefetch | Windows Server 기본 비활성화로 수집 불가 |
| $LogFile | 본 버전 파싱 모듈 미지원 |
| $UsnJrnl | Tier 2 루프백 미구현으로 미평가 (조건: Tier1 $MFT에서 timestamp_mismatch 또는 deleted 플래그 발견 시) |
```

미검증 항목과 분석 범위를 보고서에 명시하는 것이 이 도구의 신뢰성 근거입니다. 자동 생성 시 누락되지 않도록 템플릿에 고정 섹션으로 둡니다.

### 범위 섹션의 규칙

**양쪽을 다 적습니다.** "안 본 것"만 적으면 읽는 사람이 무엇을 봤는지 알 수 없고, "본 것"만 적으면 못 본 것이 사라집니다.

| 상태 | 어디에 | 판단 근거 |
|---|---|---|
| 읽었다 (0건 포함) | 확인한 아티팩트 | `_manifest.json`의 `files[]` |
| 읽었으나 일부 구간 실패 | 확인한 아티팩트 + 비고 | `parse_errors` / `unreadable_bytes` |
| 03이 제외 / Tier 2 유예 | 확인하지 못한 아티팩트 | `03_selection.json` |
| 04가 읽지 못함 | 확인하지 못한 아티팩트 | `_manifest.json`의 `skipped[]` |
| 선별됐는데 양쪽 어디에도 없음 | 확인하지 못한 아티팩트 | 차집합 검산 |

**레코드 0건은 "확인함"입니다.** 파싱은 됐는데 범위에 아무것도 없었던 것이며, 그것이 곧 "봤는데 없었다"입니다. 한계로 옮기면 못 본 것과 구별되지 않습니다.

마지막 줄(차집합)이 있는 이유는, 04단계가 새 실패 유형을 만들고 기록을 빠뜨려도 **조용히 사라지지 않게** 하기 위함입니다.

---

## errors.jsonl

단계 구분 없이 append 방식으로 누적합니다.

```jsonl
{"ts":"2026-08-06T04:12:30Z","stage":"02_normalize","type":"schema_violation","detail":{"field":"techniques[0].id","value":"T9999","message":"유효하지 않은 ATT&CK ID"},"action":"retry","attempt":1}
{"ts":"2026-08-06T04:12:33Z","stage":"02_normalize","type":"schema_violation","detail":{"field":"confidence","value":1.5,"message":"범위 초과"},"action":"retry","attempt":2}
{"ts":"2026-08-06T04:18:01Z","stage":"04_parse","type":"parse_error","detail":{"artifact":"evtx:Security","offset":"0x2B4000","message":"레코드 시그니처 불일치, 건너뜀"},"action":"skip"}
{"ts":"2026-08-06T04:21:50Z","stage":"05_interpret","type":"malformed_output","detail":{"message":"JSON 파싱 실패, 코드펜스 제거 후 재시도"},"action":"retry","attempt":1}
```

### 집계용 필드

`type`과 `action`은 고정 어휘로 관리합니다. 발표 자료의 통계가 여기서 직접 산출되기 때문입니다.

- `type`: `schema_violation` / `parse_error` / `malformed_output` / `empty_result` / `timeout`
- `action`: `retry` / `skip` / `abort`

예를 들어 `stage=02_normalize`이면서 `type=schema_violation`인 항목을 케이스 수로 나누면 정규화 단계 실패율이 나오고, `detail.field` 분포를 보면 어떤 필드에서 sLLM이 자주 틀리는지 드러납니다. 이것이 이후 폴백 설계의 근거 데이터가 됩니다.

---

## 단계 실행 인터페이스

모든 스크립트는 동일한 CLI 형태를 따릅니다.

```bash
.venv/Scripts/python.exe -m src.stage02_normalize.normalize \
    --in cases/C-001/01_input.json --out cases/C-001/02_scenario.json
.venv/Scripts/python.exe -m src.stage03_select.select \
    --in cases/C-001/02_scenario.json --out cases/C-001/03_selection.json \
    --mappings mappings/
.venv/Scripts/python.exe -m src.stage04_parse.parse \
    --in cases/C-001/03_selection.json --out cases/C-001/04_parsed/ \
    --evidence /mnt/evidence/WEB01
.venv/Scripts/python.exe -m src.stage05_interpret.interpret \
    --in cases/C-001/04_parsed/ --scenario cases/C-001/02_scenario.json \
    --out cases/C-001/05_findings.json
.venv/Scripts/python.exe -m src.stage06_verify.verify \
    --findings cases/C-001/05_findings.json --parsed cases/C-001/04_parsed/ \
    --out cases/C-001/06_verified.json
.venv/Scripts/python.exe -m src.stage07_report.report \
    --in cases/C-001/06_verified.json --findings cases/C-001/05_findings.json \
    --selection cases/C-001/03_selection.json --out cases/C-001/07_report.md
```

각 스크립트는 시작 시 입력 파일을, 종료 시 출력 파일을 `schemas/` 아래 JSON Schema로 검증합니다. 검증 실패는 `errors.jsonl`에 기록 후 비정상 종료합니다.

전체 실행은 `run_pipeline.sh`가 엮으며, 중간 단계부터 재실행할 수 있습니다. 파싱이 가장 오래 걸리므로 04단계에 `04_parsed/`가 이미 있으면 건너뛰는 `--skip-existing`이 있고, `run_pipeline.sh`는 이 옵션을 항상 붙입니다.
