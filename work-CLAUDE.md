# work-CLAUDE.md — 클로드(Claude) 진행 중 과제

## 🎯 현재 진행 중 과제: 5단계(해석) ➔ 2단계(정규화) 자율 루프백 로직 구현 (Agentic ReAct Loop)

- **배경 및 핵심 목표**:
  - 일방통행(01 ➔ 07) 분석의 한계를 극복하고, LLM이 포렌식 분석관처럼 "의심스러운 단서를 발견하면 스스로 추가 증거를 재요청하는 자율 피드백 루프(ReAct Loop)" 확립.
  - 05단계 LLM 해석 과정에서 미진한 단서 발견 시 구조화된 `investigation_requests`를 출력하고, 이를 오케스트레이터가 수신하여 02단계(시간/기법 확장) ➔ 03단계(추가 선별) ➔ 04단계(2차 타겟 파싱)를 재트리거.
  - 무한 루프 방지(최대 1회 루프백 가드레일) 및 1차+2차 증거 통합을 통한 최종 서사 및 신호등 소견 완결.

---

## ✅ 직전 완료 과제: 멀티 노드 상관분석 및 캠페인 레이어 (Stage 08)

- **설계서**: [docs/proposals/multi-node-campaign.md](docs/proposals/multi-node-campaign.md) (PR #84)
- **반영 커밋**: `82e3d8b`, `c2734d2`, `ebbb9d2` (전체 완료, 코덱스/GPT 검증 대기 중)
- **세부 완료 내역**:
  1. `canonical.py` 네트워크 축 필드 보강 (`remote_ip`, `remote_port`)
  2. `schemas/campaign.schema.json` & `src/stage08_campaign/` 뼈대 구축
  3. 5대 피벗 상관분석 엔진 (`correlate.py`)
  4. 신호등 판정 연계 및 신뢰도 링크 부여
  5. 전사 캠페인 통합 보고서 렌더링 (`08_campaign.md`)
  6. 픽스처 E2E 관통 테스트 (23개 테스트 통과)
