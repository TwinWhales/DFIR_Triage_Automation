# work-GPT.md — sLLM 기반 트리아지 파이프라인 인지(Cognitive)·검증(Verification) 체계 개편 로드맵

> **핵심 철학:**  
> 본 개선의 목표는 "탐지 규칙을 덕지덕지 늘리는 것(Rule-based EDR 회귀)"이 아닙니다.  
> **"sLLM이 반드시 봐야 할 증거 묶음을 구조화하여 보장(Packaging)하고, sLLM이 도출한 주장의 사실관계를 기계적으로 엄격히 검산(Typed Assertion)하는 인간-AI 협업 체계"**를 정립하는 것입니다.
>
> - **파이썬 (결정론적 코드):** 양질의 증거 패킷 구성 (트리/시계열/표준화) & 관계 검증 (모순 기각)
> - **sLLM (소형 언어 모델):** 비정상 맥락 추론, 행위 의도 판단, 다종 아티팩트를 엮은 단일 침해 내러티브(Incident Story) 구성

---

## 0. 배경 및 실측 진단 (SVCStealer 실측 결과)

* **실측 대상:** `evidence/SVCStealer-kape/C`, 모델 `qwen2.5:latest` (7B 로컬 Ollama), 케이스 `K-LIVE-SVCSTEALER`
* **현상:** 파이프라인 11단계는 100% 정상 완주(116.8s, 13,361건 파싱, 보고된 환각률 0.0%)하였으나, 포렌식 원본 대조 결과 치명적 결함 발견.

### 발견된 주요 결함 및 근본 원인

1. **F3 허위 소견 (False Positive):**
   * **보고서 내용:** `popats.exe가 프로그램 파일 폴더 외부에 위치함` (악성 의심 소견 F3로 채택).
   * **실제 원본 (Amcache):** `C:\Program Files (x86)\ESTsoft\ALZip\popats.exe` (정상 설치 경로).
   * **원인:** Amcache의 `path`는 레지스트리 키(`Amcache\Root\InventoryApplicationFile\...`)이고, 실제 실행 파일 경로는 `fields.LowerCaseLongPath`에 존재. sLLM이 이를 혼동했고, 타임밴드가 4시간으로 넓어져 정상 유틸리티가 엉뚱하게 얽힘.
2. **검증기(Stage 06) 무력화 (0.0% 환각률의 허위):**
   * `claim_for()`가 sLLM 출력 대신 원본 텍스트를 그대로 복사하여 `(ref, field, value)` 일치만 검사(`value_match`).
   * `popats.exe`라는 문자열이 레코드에 존재하므로 검증기는 "사실 일치(0.0% 환각)"로 잘못 통과시킴 (의미적 참/거짓 검증 부재).
3. **핵심 침해 행위 대량 누락 (Information Dropping):**
   * 루트 프로세스(`3a297d...exe`)는 실행 0.44초 만에 종료(15:30:06.216 KST)되고 7개 자식 프로세스를 생성함.
   * `SYSMON#722/#724`: `cmd.exe /c "netsh wlan export profile key=clear folder=C:\Users\test\AppData\Local\Temp"` (Wi-Fi 비밀번호 평문 탈취).
   * Edge 브라우저 자격증명 저장소 접근 정황: Prefetch의 `Login Data` 참조. (`Cookies.json`은 현재 증거에서 확인되지 않았으므로 정답에 포함하지 않음.)
   * 크롬/엣지 샌드박스 비활성화: `--no-sandbox`.
   * 정상 소프트웨어 위장 가능성이 있는 설치·실행 착지: `ProgramData\LightCoralAquamarine\FnHotkeyUtility.exe`. 지속성 확보 여부는 추가 레지스트리 증거가 있어야 확정 가능.
   * 타임스톰핑 흔적: 1970-01-01 생성 시각.
   * **원인:** 위 증거들이 sLLM 60건 프롬프트에 들어갔음에도 불구하고, 평면 레코드 청크 방식의 선택 공간 과다로 인해 sLLM이 선별하지 않고 탈락시킴.

---

## 1. 아키텍처 개편 목표 구조

```text
04 원본 레코드 파싱
  ↓
04.5 증거 패킷 구성            ← Python: 상관관계·시계열·가시성 보장 (Incident Packet)
  ↓
05-A 패킷별 분석               ← sLLM: 행위 의미와 의도 판단 (Map)
  ↓
05-B 사건 종합                 ← sLLM: 단일 Incident Story 구성 (Reduce)
  ↓
06 구조화된 주장 검증          ← Python: 사실·관계·모순 검증 (Typed Assertion)
  ↓
07 보고서 작성                 ← 사실 / 분석적 추론 / 미확인 사항 분리
```

---

## 2. 단계별 개선 과제 상세 (우선순위 1~8)

### 1순위: SVCStealer 회귀 테스트 벤치마크 고정
수정 작업 착수 전, 이번 실측에서 드러난 결함과 참값을 재현 가능한 벤치마크로 고정한다 (`tests/data/svcstealer_expected.json`). 탐지 규칙이 아니라 **"이번 결함이 다시 생기지 않았는가"**를 검사하는 평가 데이터이다.

* **최소 합격 기준:**
  - `popats.exe`를 Program Files 외부라고 판단하면 실패 (F3 오판 방지)
  - 루트 프로세스의 직접 자식 7개(`o1ar5ewb`, `yligwv7t`, `k8vvoogc`, `oygcbgl0`, `z7hriire`, `y5jo43xy`, `OpenBulletCE`)가 증거 패킷에 포함
  - `SYSMON#722/#724`의 `netsh wlan ... key=clear`가 sLLM 판단 대상에 포함
  - `o1ar5ewb.exe`의 Edge `Login Data` 접근 흔적이 포함 (`Cookies.json`은 관찰되지 않았으므로 요구하지 않음)
  - `FnHotkeyUtility.exe` 설치·실행 체인이 포함
  - 루트 실행 종료 시각이 `15:30:06.216 KST` (실행시간 약 0.44초)로 올바르게 계산
  - 모든 강제 검토 시그널에 대해 sLLM의 `selected / dismissed / uncertain` 응답 필수
  - 프롬프트 잘림(Truncation)이 없어야 함
  - F3와 같은 모순 주장은 06단계에서 `rejected` 또는 `unverifiable` 판정

---

### 2순위: 레코드의 의미 필드 정규화 (`canonical` 오버레이 추가)
F3 오판의 직접 원인은 아티팩트마다 경로 필드의 의미가 달랐기 때문이다.
- MFT/Prefetch: `path`가 실제 파일 경로
- Amcache: `path`는 레지스트리 키 이름이고, 실제 실행 파일 경로는 `fields.LowerCaseLongPath`에 존재

**조치:**
04단계 산출물에 원본 필드를 보존하면서 아래와 같은 `canonical` 오버레이 필드를 주입한다. 악성 판정이 아니라 서로 다른 아티팩트의 같은 의미를 통일하여 sLLM이 쉽게 연결하게 한다.

```json
{
  "canonical": {
    "subject_path": "C:\\Program Files (x86)\\ESTsoft\\ALZip\\popats.exe",
    "event_time": "2026-09-07T06:26:27Z",
    "process_image": "C:\\Windows\\System32\\cmd.exe",
    "parent_image": "C:\\Users\\test\\AppData\\Local\\Temp\\o1ar5ewb.exe",
    "command_line": "cmd.exe /c \"netsh wlan export profile key=clear ...\""
  }
}
```

* **수정 대상:**
  - Amcache: `subject_path = fields.LowerCaseLongPath`
  - MFT / Prefetch: `subject_path = path`
  - Sysmon: `process_image`, `parent_image`, `command_line`
  - 공통: `event_time`, `hashes`, `user`

---

### 3순위: 기존 프로세스 상관 기능을 "증거 패킷(Incident Packet)"으로 승격
현재 `_process_context()`(`src/stage05_interpret/allocation.py`)가 ProcessGuid 기반 자손 거리를 계산하지만 정렬 힌트로만 쓰이고 sLLM에게는 명시적 트리로 전달되지 않는다.

**조치:**
이를 별도 `incident_packet` 구조로 직렬화하여 sLLM에게 전달한다.
- 파이썬은 `spawned`, `same_path`, `same_hash`, `within_time` 같은 관찰 가능한 관계만 구성한다. ("스틸러", "탈취" 등의 주관적 판단 배제)
- **프로세스 수명 결합(Correlation Closure):** Sysmon EID 1(생성)을 선별할 때 동일 ProcessGuid의 EID 5(종료)를 자동으로 함께 묶음. (`mappings/windows/T1204.002.yaml` line 35에서 EID 1만 읽던 한계 수정).

```json
{
  "anchor": "SYSMON#654",
  "burst": {
    "start": "2026-09-07T06:30:05.776Z",
    "end": "2026-09-07T06:30:06.216Z",
    "direct_children": 7
  },
  "process_edges": [
    {
      "parent": "SYSMON#654",
      "child": "SYSMON#655",
      "relation": "spawned",
      "delta_ms": 167
    }
  ],
  "corroboration": [
    {
      "refs": ["SYSMON#655", "PF#240668804", "MFT#120483"],
      "join": "normalized_path"
    }
  ]
}
```

---

### 4순위: 시그널은 판정이 아니라 "강제 검토권(`must_review`)"으로 사용
파이썬이 "악성이다"라고 독단적으로 판정하지 않고, 위험 냄새가 나는 레코드에 **중립적 시그널**을 달아 쿼터 탈락을 방지하고 sLLM에게 의무 검토를 부여한다.

* **중립적 시그널 명명 (좋은 예 vs 나쁜 예):**
  - **좋은 예 (관찰된 사실):**
    - `credential_export_option_observed` (`netsh ... key=clear`)
    - `sensitive_store_referenced` (`Login Data`, `Cookies`)
    - `shell_spawned`
    - `browser_sandbox_disabled` (`--no-sandbox`)
    - `rapid_process_fanout`
    - `silent_installer_chain` (`/VERYSILENT`)
    - `user_writable_execution` (`Temp`, `AppData` 경로 실행)
    - `timestamp_anomaly` (1970년 등 비정상 타임스탬프)
  - **피해야 할 예 (단정적 판정):**
    - `credential_theft_confirmed`, `malware_detected`, `backdoor_installed`
* **할당 2개 레인 운용:**
  1. 보장 레인: `must_review=true` 패킷 전부 (쿼터 우선 보장)
  2. 탐색 레인: 나머지 후보를 우선순위·시간·아티팩트 다양성으로 배분
* **sLLM의 의무 응답 포맷 (누락 방지):**
  ```json
  {
    "signal_id": "S12",
    "disposition": "selected | dismissed | uncertain",
    "reason": "cmd executing netsh wlan export profile key=clear dumps cleartext Wi-Fi passwords to Temp",
    "evidence_fields": ["canonical.command_line"]
  }
  ```

---

### 5순위: 평면 레코드 Map-Reduce → 사건 패킷 Map-Reduce로 개편
60개의 흩어진 레코드를 던져주고 고르라고 하면 7B 소형 모델은 길을 잃는다.

* **Map (패킷 단위 질의):**
  - 입력: 프로세스/시계열 패킷 1개 단위
  - 출력:
    - 직접 관찰된 사실 (Observed Facts)
    - 행위 가설 (Behavior Hypothesis)
    - 대안 설명 (Alternative benign explanation)
    - 심각도 (Severity)
    - 구조화된 주장 (Structured Assertions)
    - 추가로 필요한 아티팩트 (Investigation Requests)
* **Reduce (사건 종합):**
  - Map 결과들을 받아 단일 침해 내러티브(Incident Story) 구성:
    1. 초기 실행 (Initial Execution)
    2. 자식 프로세스 전개 (Process Fanout)
    3. 자격 증명 접근 정황 (Credential Access - `netsh`, `Login Data`)
    4. 설치 및 착지 정황과 지속성 가설 (Drop/Install - `LightCoralAquamarine`; Persistence는 미확인으로 분리)
    5. 가장 심각한 분기 (Most critical threat branch)
    6. 확인되지 않은 공백 (Unverified / Unknowns)

---

### 6순위: 06단계 검증을 Typed Assertion 기반으로 확장
단순히 `(ref, field, value)`의 문자열 일치만 보는 `value_match`를 넘어, **관계형 술어(Predicate) 검증**으로 확장한다.

```json
{
  "predicate": "outside_path",
  "subject": {
    "ref": "AMCACHE#2274620",
    "field": "canonical.subject_path"
  },
  "object": "C:\\Program Files"
}
```

* **검증 가능한 관계 술어 (파이썬이 수학적으로 팩트체크):**
  - `equals`, `contains`, `list_contains`
  - `under_path` / `outside_path`
  - `before` / `after` / `within`
  - `spawned`, `same_path`, `same_hash`, `duration`, `count`
* **F3 오판 기각 메커니즘:**
  ```text
  주장: outside_path(popats.exe, "C:\Program Files")
  실제: C:\Program Files (x86)\ESTsoft\ALZip\popats.exe
  06단계 판정: contradicted (모순 발견) → REJECTED 기각!
  ```
* **핵심 변경점:**
  - `evidence_fields`를 필수로 만들고, 비어 있을 때 임의 필드로 fallback하지 않음.
  - 하나의 문장이 여러 사실을 말하면 assertion도 여러 개 요구 ("생성되고 실행됐다" → MFT 생성 assertion + Sysmon 실행 assertion 필수).
  - 최종 내러티브에 대해 배치형 sLLM critic을 1회 적용하여 문장별 `supported / contradicted / insufficient` 판정 지원.

---

### 7순위: sLLM 주도의 1회 증거 확장 루프 (`investigation_requests`)
초기 입력 기법(`T1204.002`)에만 갇히지 않고 sLLM이 자율적으로 단서를 확장할 수 있도록 지원.

```json
{
  "investigation_requests": [
    {
      "artifact": "registry:SYSTEM",
      "reason": "FnHotkeyUtility 서비스 등록 여부 확인"
    },
    {
      "artifact": "evtx:Defender",
      "reason": "드롭 파일 탐지 여부 확인"
    }
  ]
}
```

* **파이썬의 역할:**
  - 지원 아티팩트 및 증거 내 실제 존재 여부 확인
  - 최대 1회 · 최대 N개 한도로 제한
  - 요청된 증거를 파싱하여 2차 sLLM 종합에 공급

---

### 8순위: 지표 및 보고서 영역 분리

* **세부 지표 체계화 (8종):**
  - `value_match_rate` (문자열 일치율)
  - `semantic_contradiction_rate` (의미 모순율)
  - `unsupported_inference_rate` (근거 부족 추론율)
  - `must_review_delivery_rate` (필수 시그널 도달률)
  - `must_review_disposition_rate` (필수 시그널 판단율)
  - `incident_chain_coverage` (침해 체인 커버리지)
  - `prompt_truncation_count` (프롬프트 잘림 횟수)
  - `unavailable_artifact_count` (부재 아티팩트 요청 수)
* **보고서 3영역 분리:**
  1. **확인된 사실 (Facts):** 원본과 06단계 관계 검증까지 완전히 통과한 사실
  2. **분석적 판단 (Inferences):** sLLM의 맥락적 해석 및 신뢰도
  3. **미확인 사항 (Unknowns):** 필요한 증거가 없거나 상반된 공백 영역

---

## 3. 가장 빠른 실행 순서 (Action Items 1~10 Checklist)

GPT/Codex는 아래 10단계 순서를 지키며 하나씩 완수해 나간다:

- [x] **1. [1단계] SVCStealer 회귀 정답 및 실패 조건 추가**
  - `tests/data/svcstealer_expected.json` 작성 (F3 기각, `netsh`, `Login Data`, 자식 7개, 0.44s 수명)
  - 회귀 단위 테스트 `tests/test_svcstealer_benchmark.py` 작성
- [x] **2. [2단계] `canonical` 필드 오버레이 및 EID 1↔5 lifecycle 결합**
  - `src/stage04_parse/` 산출물에 `canonical.subject_path`, `event_time`, `command_line` 주입
  - `mappings/windows/T1204.002.yaml` 및 Sysmon 파서에 EID 1 ↔ EID 5 ProcessGuid 수명 주기 묶음 구현
- [x] **3. [3단계] `must_review` 중립 시그널 및 보장 쿼터 추가**
  - `mappings/_flags.yaml`에 `credential_export_option_observed`, `sensitive_store_referenced` 등 등록
  - `src/stage05_interpret/allocation.py`에 보장 레인(Guaranteed Lane) 구현
- [x] **4. [4단계] Map 출력 포맷에 필수 시그널 disposition 강제**
  - `src/stage05_interpret/prompts/` 및 파서에서 `must_review` 시그널에 대한 `selected|dismissed|uncertain` 응답 강제
- [ ] **5. [5단계] Typed Assertion 및 관계 검증기 구현** *(핵심 경로 술어 완료, 나머지 술어·critic 잔여)*
  - `src/stage06_verify/`에 `outside_path`, `under_path`, `spawned` 등 Predicate 검증기 추가
  - F3 소견(`outside_path` on ALZip)이 `contradicted`로 기각되는지 단위 테스트로 검증
- [ ] **6. [6단계] 프로세스 트리를 `incident_packet`으로 직렬화** *(lifecycle·직접 자식 완료, 다종 corroboration 잔여)*
  - `src/stage05_interpret/allocation.py`의 `_process_context()` 결과를 `incident_packet` 구조로 포맷팅
- [ ] **7. [7단계] 패킷 기반 Map → 사건 기반 Reduce 프롬프트 개편**
  - 단일 평면 60개 선택 방식에서 탈피하여, 패킷별 분석 후 사건 전체 내러티브 종합 체계로 프롬프트 개선
- [ ] **8. [8단계] 한 번짜리 증거 확장 루프 (`investigation_requests`) 구현**
  - sLLM이 추가 아티팩트를 요청하면 파이썬이 1회 한정 파싱하여 2차 종합에 주입하는 루프 연결
- [ ] **9. [9단계] 보고서 3영역 분리 및 세부 평가 지표 산출**
  - `07_report.md`에 [확인된 사실 / 분석적 판단 / 미확인 사항] 분리 출력
  - `semantic_contradiction_rate`, `must_review_disposition_rate` 등 지표 계산 로직 추가
- [ ] **10. [10단계] 동일 명령어로 SVCStealer 재실측 및 검증**
  - `tools/live_check.py --case-id K-LIVE-SVCSTEALER ...` 재실행
  - F3 기각, `netsh`/`Login Data` 소견 반영, 0.44s 수명 표시, 무환각 확인
  - **2026-09-07 부분 완료:** 11/11 PASS, `netsh`/`Login Data` 반영, popats 오판
    미재발, rejected 0/unverifiable 0. 단, 0.44초 수명의 최종 보고서 표시는 9단계
    보고서 영역 개편과 함께 남아 있어 체크박스는 열어 둔다.

---

## 4. 작업 시 절대 원칙 (Constraints)

1. **sLLM의 인공지능 정체성 보존:** 파이썬 코드에서 `is_malicious = True` 식의 하드코딩 룰 탐지를 절대 넣지 않는다. 파이썬은 증거를 보기 좋게 포장하고(Packaging), 사실관계 모순을 검산(Verification)할 뿐, 위협 판단과 내러티브 구성은 반드시 sLLM이 수행한다.
2. **기존 스키마 하위 호환:** `canonical` 필드는 원본 필드를 대체하는 것이 아니라 추가 오버레이로 주입한다.
3. **기록 보존:** 각 단계 완료 시 `docs/limitations-log.md`에 완료 내역을 기록하고, 잔여 한계는 `docs/limitations.md`에 갱신한다.
