# Coverage-guided Loopback

## 목표

짧은 자연어 입력이 도구명·IP·계정·경로를 말하지 않아도, 조사하지 않은
행위 범주를 투명하게 드러내고 이미 파싱된 증거를 행위 패턴으로 다시 찾는다.
검색은 결론을 강제하지 않는다. 결과는 `observed`, 무결과는
`searched_no_evidence`로 남긴다.

## 호환성 경계

동결된 `02_scenario.json`, `05_findings.json`, `06_verified.json`,
`08_campaign.json`에는 필드를 추가하지 않는다. 새 상태는
`05_coverage.json` 사이드카에 둔다. 기존 `05_requests.json`에는 선택적인
`request_behavior` oneOf 갈래만 추가했으므로 기존 요청 문서는 그대로
유효하다.

## 데이터 흐름

```text
01_input.raw ───────────────┐
02_scenario + 05_findings ─┼─> 05_coverage.json (1차 원장)
                            │
05 조사 질의 ─ request_behavior
                            │
04_parsed 전체 ─ behavior_search ─> 검색 ref + 원장 상태
                                      │
                                      └─ must_review 보장 레인
                                             │
                                             └─ 2차 Stage05

06_verified ─> 원장의 observed를 verified로 승격
07/08 ──────> 커버리지 매트릭스 렌더링
```

## 열 개 범주

`initial_access`, `execution`, `persistence`, `defense_evasion`, `discovery`,
`lateral_movement`, `credential_access`, `collection`, `exfiltration`, `impact`.

범주와 ATT&CK 기법·원문 키워드·관측 패턴은
`mappings/_behavior_families.yaml`에 있다. ATT&CK 기법은 소견을 원장에
투영할 때 사용하고, 재검색 자체는 도구명 하나가 아니라 플래그·명령행·
프로세스 관계·네트워크 복합 패턴을 사용한다.

## 상태

- `not_searched`: 아직 이 범주를 확인하지 않았다.
- `searched_no_evidence`: 재검색을 수행했으나 일치 근거가 없었다.
- `observed`: 05 소견 또는 재검색에서 근거 ref를 찾았다.
- `verified`: 관련 05 소견이 06 검증을 통과했다.
- `unsupported`: 필요한 수집물이나 파서가 없어 조사할 수 없다.

`summary.gaps`는 `observed`와 `verified`가 아닌 범주이고,
`relevant_gaps`는 그중 사용자 원문 또는 02 기법과 관련된 범주다.

## request_behavior

```json
{
  "type": "request_behavior",
  "based_on": {"kind": "scenario_claim", "claim_id": "SC1"},
  "rationale": "POS로 이어지는 원격 접속을 다시 검색한다",
  "category": "lateral_movement",
  "pivots": ["POS"]
}
```

근거는 두 종류다.

- `evidence_ref`: 1차 Stage05에 실제 전달된 ref만 허용한다.
- `scenario_claim`: `01_input.raw`에서 그대로 보존한 문장과 그 문장에
  결정론적으로 연결된 범주만 허용한다. 원문을 새로 요약한 문장은 받을 수
  없다.

## 검색과 승격

현재 검색기는 다음을 지원한다.

- 범주별 명령행·경로·플래그 패턴
- 피벗 문자열과 원격 네트워크 주소의 동시 출현
- 동일 프로세스가 120초 안에 네 개 이상의 IP/포트에 닿는 스캔 패턴
- 도구명이 없어도 10 MiB 이상인 외부 송신량
- 동일 ProcessGuid와 직접 자식의 전후 180초 맥락

최대 30개의 직접 일치와 관계 폐쇄를 포함한 최대 60개 ref만 승격한다.
승격된 ref는 인메모리 레코드에 `must_review=true`가 붙고 Stage05의 기존
보장 레인에 합류한다. `request_behavior`만 수용되어 03 선별이 같을 때는
04를 다시 파싱하지 않고 2차 Stage05만 실행한다.

## 가드레일

- 조사 요청 전체 상한은 기존과 같이 3개다.
- 범주와 scenario claim은 constrained output enum으로 제한한다.
- scenario claim은 조사의 이유일 뿐 사건이 확인됐다는 근거가 아니다.
- 일치가 0건이어도 지우지 않고 `searched_no_evidence`로 기록한다.
- 기존 1차 인용 ref와 행위 검색 ref는 모두 2차에서 고정한다.
- 보고서는 원장이 없을 때 흔적 없음으로 쓰지 않고 `원장 없음`으로 표시한다.

