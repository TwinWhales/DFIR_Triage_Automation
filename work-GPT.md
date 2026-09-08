# work-GPT.md — 신호등 검증 체계(Traffic Light System) 및 보고서 보존 로드맵

---

## 1. 최근 클로드(Claude) 작업 완료 내역 요약

1. **[04단계] 침해 체인 정밀 플래그 5종 추가 (`mappings/_flags.yaml`)**
   * `lolbin_download` (certutil 다운로드), `uac_bypass_candidate` (fodhelper), `security_tool_config_changed` (디펜더 무력화), `persistence_command` (schtasks 등록), `discovery_command` (whoami 등)
   * 전체 Sysmon 중 노이즈 없이 0.69%만 정밀 타격하여 05단계 sLLM에 공격 신호 전달 성공.
2. **[02단계] 시간대 산수 보정 및 KAPE 수집시각 상한 가드 (`src/stage02_normalize/timeband.py`)**
   * 자연어에 `UTC`가 포함되어도 모델이 범위를 틀리면 파이썬이 올바른 범위로 보정.
   * KAPE `*_CopyLog.csv` 파일명에서 실제 증거 수집 시각을 동적으로 읽어 상한선으로 강제 ➔ 시간 단서 부재 시 발생하던 32만 건의 `outside_time_range` 노이즈 중 98% 해소.
3. **[02단계] 일상 표현 기법 분류 개선 (`grounding.py`, `normalize_system.txt`, fewshot)**
   * "명령 창", "검은 창", "다운로드" 등 일상 한국어 표현을 공백 정규화(`_SPACES.sub`)로 처리하여 시스템 크래시 방지 및 `T1059.003` + `T1105` 기법 적중 완료.
4. **[06단계] `Node.js` 구두점 오탐 완화 (`statement_grounded.py`)**
   * 디렉터리명(`nodejs`)과 제품 표기(`Node.js`) 간의 구두점 차이 허용으로 `F1` 소견 정식 통과 복원.

---

## 2. 실물 라이브 테스트 방법 (live_check.py)

* **대상 증거 위치 (볼륨 루트 `C`):**
  `C:\Users\user\Desktop\케이쉴드주니어\DFIR_Triage_Automation\DFIR_Triage_Automation\evidence\KIOSK_snapshotA_20260908T032657\C`

* **실행 명령어 (PowerShell):**
  ```powershell
  python tools/live_check.py `
    --case-id K-LIVE-KIOSK-GPT `
    --evidence "C:\Users\user\Desktop\케이쉴드주니어\DFIR_Triage_Automation\DFIR_Triage_Automation\evidence\KIOSK_snapshotA_20260908T032657\C" `
    --raw "2026년 9월 7일 밤 10시 35분경 키오스크 단말에 비인가 USB가 삽입된 후 cmd 명령 셸이 실행되고 외부 접속이 발생했습니다. 단말 침해 여부와 실행된 행위를 조사해 주세요."
  ```

---

## 3. 핵심 단일 과제: '신호등 검증 체계(Green/Yellow/Red)' 구현 및 최종 보고서 반영

### 문제 배경 (극단적인 처벌 전파 결함)
현재 06단계 사실 검증기는 단어 하나(`Node.js` 등 경미한 표기 차이)나 자연어 추론이 조금만 섞여도 소견 전체(`F1`)를 `unverifiable`로 강등시킵니다. 더 나아가 그 소견을 인용한 서사 문장 10개까지 도미노처럼 `insufficient`로 처리하여 **실제 침해 체인이 최종 보고서에서 통째로 쫓겨나 백지가 되는 'All-or-Nothing' 결함**을 안고 있습니다.

### 목표: 신호등 3단계 체계 도입
단어 하나 때문에 공격 내용을 날려버리지 않고, **유연하게 보고서에 실어주되 주의가 필요한 부분은 투명하게 경고를 명시**합니다.

1. 🟢 **초록불 (`passed` / 100% 일치)**:
   * 원본 증거와 완벽하게 대조 통과한 사실.
   * `07_report.md`의 **[확인된 사실 (Facts)]** 섹션에 정식 등록.
2. 🟡 **노란불 (`unverifiable` / 부분 일치 및 주의 필요)**:
   * 핵심 침해 사실(스크립트 실행, 백신 무력화 등)은 맞으나 표기 차이나 자연어 추론이 섞인 소견.
   * **소견을 버리지 않고 `07_report.md` 본문의 [주의 필요 소견 (Warning)]에 보존.**
   * `"⚠️ 분석가 확인 권장: [사유]"` 형태의 명확한 경고 라벨 표기.
   * 노란불 소견을 인용한 서사 문장도 함께 살려두어 서사가 끊기지 않게 유지 (`supported_with_warning`).
3. 🔴 **빨간불 (`rejected` / 명백한 환각·날조)**:
   * 증거에 전혀 없는 파일명 날조나 모순된 주장.
   * 보고서 본문에서 차단하고 환각 통계에만 집계.

### 수정 대상 파일
1. **`src/stage06_verify/verify.py` & `checkers/`**:
   * 소견 내 미검증 표현이 일부 존재하더라도 유효한 팩트 주장은 살리는 부분 강등(Partial Downgrade) 지원.
   * `story_review`에서 노란불 소견을 인용한 서사 문장을 탈락시키지 않고 `supported_with_warning`으로 판정.
2. **`src/stage07_report/report.py`**:
   * 최종 보고서(`07_report.md`) 템플릿 개편:
     * `## 확인된 사실 (🟢 Passed)`
     * `## 주의 필요 소견 (🟡 Warning - 분석가 교차 검증 요망)`
     * `## 미확인 사항 (⚪ Unknowns)`
     * 타임라인에도 노란불 소견의 핵심 타임스탬프가 누락되지 않고 표기되도록 지원.

### 완료 기준
* 위 라이브 테스트 실행 시, `07_report.md` 보고서 본문에 `certutil` 다운로드, `s.ps1` 실행, Defender 무력화 등 실제 침해 체인이 **초록/노란불 라벨과 함께 당당하게 표시**되어 분석가가 즉시 위협을 인지할 수 있을 것.
