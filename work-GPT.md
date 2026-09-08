# work-GPT.md — 코덱스(GPT) 진행 중 과제 및 공유

> 코덱스(GPT) 참고 및 작업용 문서입니다. 클로드의 08단계 작업 완료에 따른 교차 검증 요청 사항을 기술합니다.

---

## 🎯 코덱스(GPT) 현재 할 일: 클로드 08단계(캠페인 레이어) 구현 내역 교차 검증 및 코드 리뷰

클로드가 **[멀티 노드 상관분석 및 캠페인 레이어 (Stage 08)]** 구축 작업(설계서 7장 1~6번)을 완료했습니다.  
안정성과 엔지니어링 정합성을 보장하기 위해 아래 6개 항목에 대해 교차 검증을 수행합니다.

### 📋 주요 검사 항목

1. **커밋 내역 및 형상 관리 검토**:
   - `82e3d8b feat(08): 노드 여럿을 한 사건으로 잇는 캠페인 레이어`
   - `c2734d2 fix(08): 인용되지 않은 레코드가 인용된 것을 가리지 못하게 한다`
   - `ebbb9d2 docs: 캠페인 레이어의 남은 한계를 limitations.md 5장으로 옮긴다`
   - 기존 01~07단계 동결 스키마 불변 원칙 준수 여부 및 `src/common/schema.py` 등록 확인

2. **5대 피벗 축 및 상관분석 엔진 (`src/stage08_campaign/correlate.py`) 정합성 검토**:
   - 5대 축(해시, 네트워크 C2/명령행, 파일명, 경로, 계정) 추출 알고리즘 확인
   - `rejected` 소견 배제 확인 (기각된 레코드로 링크가 생성되지 않는지)
   - 최저 등급 상속(보수적 신뢰도) 및 미인용 레코드의 `context_links` 분리 확인
   - ⭐️ **`c2734d2` 결함 수정 검토**: 대표 관측 선정 시 "판정 좋은 순 > 같으면 이른 순" 정렬 로직이 의도대로 동작하는지 확인

3. **입력/출력 스키마 및 예외 처리 검토 (`schemas/campaign.schema.json`, `campaign.py`)**:
   - 다중 노드 누락/파싱 실패 시 파이프라인 중단 없이 `missing` 사유를 수록하는지 확인

4. **3노드 가상 픽스처 관통 및 보고서 검증**:
   - `benchmark/fixtures/campaign-3node/` 실행 및 결과 확인:
     ```bash
     python -m src.stage08_campaign.campaign --in benchmark/fixtures/campaign-3node/campaign.json --cases benchmark/fixtures/campaign-3node/cases --out scratch/test-campaign-out
     ```
   - 공격 체인 표 및 Mermaid 다이어그램(`kiosk --> pos --> server`) 정상 렌더링 확인

5. **단위 및 전체 테스트 회귀 검증**:
   - `pytest tests/test_campaign.py -v` (23건 전원 통과 확인)
   - `pytest -q` (전체 1,591건 회귀 여부 확인)
   - `python tools/validator_check.py`

6. **남은 한계점 문서화 검토**:
   - [docs/limitations.md](docs/limitations.md) 5장(인과관계 단정 불가, 베이스라인 부재, 미수집 노드 한계, 합성 픽스처 수치 인용 금지) 서술 타당성 검토

---

## 📌 직전 완료 이력 요약

1. **`docs/limitations.md` 참조 71곳 전수 복원 (PR #83)**
2. **멀티 노드 상관분석 아키텍처 설계 (PR #84)**
3. **08단계 캠페인 레이어 구현 완료 (클로드)**
