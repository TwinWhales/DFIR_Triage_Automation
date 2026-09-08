# work-GPT.md — 코덱스(GPT) 진행 중 과제

> 코덱스(GPT) 작업용 문서입니다. 08단계 코드 리뷰에서 도출된 결함 3건 핫픽스 과제를 기술합니다.

---

## 🎯 코덱스(GPT) 현재 할 일: 08단계(캠페인 레이어) 결함 핫픽스 3건 패치

코덱스(GPT)의 08단계 교차 검증에서 도출된 **보완 필요 3건**을 패치하고 단위/회귀 테스트를 수행합니다.

### 📋 세부 핫픽스 과제

1. **[높음] `campaign.py`: JSON 파싱 에러 방어 및 `incomplete` 기록**
   * 대상: `src/stage08_campaign/campaign.py`의 `read_verdicts()` 및 `read_node()`
   * 내용: `05_findings.json`, `06_verified.json`, `02_scenario.json` 파싱 실패 시 `ValueError`가 전파되어 전체 캠페인이 다운되지 않도록 `try...except`로 감싸고, 노드 상태를 `"incomplete"` 및 사유 기록 처리.

2. **[중간] `correlate.py`: 명령행 URL 도메인 호스트 추출 보강**
   * 대상: `src/stage08_campaign/correlate.py`의 `_network_keys()`
   * 내용: 명령행에서 `_IPV4`뿐만 아니라 `http://` / `https://` 형태의 도메인 호스트명(예: `c2.example.test`)도 정규식/`urllib.parse`로 추출하여 네트워크 키에 등록.

3. **[낮음] `campaign.py`: 시각 없는 관측의 억지 방향 간선 제외**
   * 대상: `src/stage08_campaign/campaign.py`의 `_mermaid()`
   * 내용: 시각 정보가 없는(`at is None` 또는 `"미상"`) 관측에 대해 `timed --> unknown` 식의 임의 방향 간선을 그리지 않도록 방어.

### ✅ 검증 완료 기준
* `pytest tests/test_campaign.py -v` (새 케이스 추가 및 23건 이상 전원 통과)
* `pytest -q` (전체 회귀 테스트 통과)
* `benchmark/validator_check.py` (46/46 통과)

---

## 📌 직전 검토 완료 이력
* **08단계(캠페인 레이어) 1차 교차 검증 완료**: 핵심 기능 합격 판정 (커밋 `82e3d8b`, `c2734d2`, `ebbb9d2`, PR #85 머지 완료).
