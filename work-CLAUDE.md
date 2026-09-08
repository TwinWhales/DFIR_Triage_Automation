# work-CLAUDE.md — 코덱스(GPT) 구현 내역 요약 및 클로드 검증/후속 과제

---

## 1. 개요 및 최근 진행 상황

클로드(Claude)가 02~04단계 선행 작업(고위험 플래그 5종 추가, 시간대 KAPE 상한 보정, 일상 한국어 정규화, Sysmon 베이스라인 매핑)을 완수하고 머지(`12d9b12`)한 뒤,  
**코덱스(GPT)가 이어받아 `work-GPT.md`에 명시된 핵심 과제(신호등 검증 체계 및 07단계 3단 보고서 개편)의 구현과 실측 검증을 완료**했습니다.

이에 따라 클로드에게 코덱스의 변경 사항을 공유하고, **코드 무결성 검증, 과적합 배제 여부 확인, 실물 KIOSK 라이브 테스트 크로스체크**를 요청합니다.

---

## 2. 코덱스(GPT) 주요 구현 내역 (검증 대상)

1. **[05단계] 고위험 플래그 5종 보장 레인 연결 (`mappings/_attention_signals.yaml`, `attention.py`)**
   - 클로드가 04단계에 추가했던 5종 플래그(`lolbin_download`, `security_tool_config_changed`, `persistence_command`, `uac_bypass_candidate`, `discovery_command`)를 `must_review: true` 관심 시그널에 정식 등록.
   - 각 시그널군 대표 레코드가 05단계 sLLM의 60~68건 입력 윈도우에 무조건 배달되도록 보장 레인 수립.
   - `fields.CommandLine` 대소문자 매칭 버그 픽스.

2. **[06단계] 신호등 판정 분리 및 서사 연쇄 탈락 방지 (`verify.py`, `verified.schema.json`)**
   - 종전의 All-or-Nothing(소견 내 사소한 단어 표기 차이나 종합 판단이 섞이면 소견 및 서사 10문장 연쇄 삭제) 결함 해소.
   - `supported_with_warning` 상태를 신설하여, 인용 소견이 경고(Warning) 상태라도 서사 문장을 기각하지 않고 살려두어 서사의 연속성 보존.
   - 원본 증거와 대조: 🟢 `passed` (확정 사실) / 🟡 `unverifiable` (주의 필요 소견) / 🔴 `rejected` (환각/모순 차단).

3. **[07단계] 신호등 3단 보고서 체계 및 명령행 원문 인용 (`report.py`, `report.md.j2`)**
   - 보고서 목차 개편:
     - `## 확인된 사실 (🟢 Passed)`
     - `## 주의 필요 소견 (🟡 Warning - 분석가 교차 검증 요망)` (`> ⚠️ 분석가 확인 권장: [사유]`)
     - `## 미확인 사항 (⚪ Unknowns)`
   - 타임라인 표에 판정 배지(Passed / Warning) 열 추가 및 노란불 소견 누락 없이 수록.
   - 검증된 실제 악성 터미널 명령어 원문(`fields.CommandLine`)을 본문 인용구에 직접 렌더링.

4. **[도구 및 문서] `live_check.py` 모델 Fallback & `limitations.md` 대폭 슬림화**
   - `tools/live_check.py`: 기본 모델을 `qwen2.5:latest`로 변경 및 로컬 Ollama 모델 자동 감지 fallback 추가.
   - `docs/limitations.md`: 날짜별 일지 제거 및 4대 영역(입력/파서/LLM/신호등)으로 재편 (3,163줄 ➔ 107줄, 97% 슬림화 완료, 해결 이력은 `limitations-log.md`로 아카이빙).

---

## 3. 실물 라이브 테스트 결과 (`K-LIVE-KIOSK-MYTEST`)

* **실행 명령어**:
  ```powershell
  .\.venv\Scripts\python.exe tools\live_check.py `
    --force `
    --case-id K-LIVE-KIOSK-MYTEST `
    --evidence "C:\Users\user\Desktop\케이쉴드주니어\DFIR_Triage_Automation\DFIR_Triage_Automation\evidence\KIOSK_snapshotA_20260908T032657\C" `
    --raw "2026년 9월 7일 밤 10시 35분경 키오스크 단말에 비인가 USB가 삽입된 후 cmd 명령 셸이 실행되고 외부 접속이 발생했습니다. 단말 침해 여부와 실행된 행위를 조사해 주세요."
  ```
* **측정 지표**: 11단계 전원 PASS (240초대 완주), 통과 9 / 주의 1 / 기각 3, 환각률 0.0% (허위 사실 보고 0건).
* **확인된 침해 체인**:
  - `fodhelper.exe` (UAC 우회) ➔ 🟢 Passed
  - `schtasks.exe /create ... Autorun_s_ps1` (재부팅 지속성) ➔ 🟢 Passed
  - `Set-MpPreference -DisableRealtimeMonitoring True ...` (디펜더 무력화) ➔ 🟢 Passed
  - `whoami.exe` (계정 및 권한 정찰) ➔ 🟢 Passed
  - `OneDrive` 시간 범위 외 실행 ➔ 🟡 Warning (표기 차이로 버려지지 않고 보존)

---

## 4. 클로드(Claude) 검증 및 후속 점검 요청 사항

클로드는 위 변경 사항을 바탕으로 다음 3가지를 집중 검토 및 검증해 주세요:

1. **과적합(Overfitting) 배제 여부 검증**:
   - 특정 케이스명(예: `s.ps1`, `shell.ps1`, KIOSK 전용 하드코딩 등)에 특화된 억지 로직 없이, 범용적인 DFIR 규칙과 신호등 판정 정책으로 일반화되어 구현되었는지 코드 무결성 검증.
2. **`certutil` 기법 오분류 현상 완화 방안 검토**:
   - 이번 실측에서 `certutil` 다운로드(`SYSMON#22236`)가 분명히 AI 모델에 전달되었으나, 모델이 기법을 `T1105`(다운로드) 대신 `T1091`(USB 복제)로 오분류하여 06단계에서 `technique_unsupported`로 기각(Rejected)된 현상 발생.
   - 02단계 프롬프트나 05단계 조립 규칙에서 이 같은 기법 오분류를 방지하거나, 검증 단계에서 기법 불일치를 'Warning'으로 유연하게 완화할 수 있는 여지가 있는지 검토.
3. **전체 테스트 스위트 회귀 검증**:
   - `.\.venv\Scripts\pytest -q` 실행하여 기존 단위/통합 테스트와의 호환성 확인.
