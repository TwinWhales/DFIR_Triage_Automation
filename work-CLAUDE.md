# work-CLAUDE.md

## 🎯 과제: 출력 예산 기반 동적 청크 분할 구조화 (`allocation.py`)

### 1. 현상 및 문제점

- `RESERVE_SELECTION_TOKENS = 3072` 상향은 임시방편(증상 치료)임.
- 현재 시스템은 **입력 프롬프트 글자수만 감시**하고, **요구되는 출력량은 계산하지 않음**.
- `must_review`(보장 레인) 레코드가 한 조각에 많이 몰릴 경우(예: 40개 이상), 레코드마다 `signal_dispositions` 작성을 강제하므로 모델의 출력 토큰 상한을 초과해 응답이 잘리는 현상 발생.

### 2. 해결 방안 (구조적 개선)

- `allocation.chunk_records`에서 입력 글자수뿐만 아니라, **해당 조각에 포함된 `must_review` 레코드 수 × 처분당 예상 토큰(약 40~60토큰)**을 계산.
- 예상 출력량이 `RESERVE_SELECTION_TOKENS` 예약을 초과할 위험이 있으면 사전에 조각을 더 작게 자동 분할하도록 로직 구현.

### 3. 검증

- 조각당 `must_review` 밀집 시 자동 분할 동작 검증.
- `pytest tests/test_allocation.py` 및 전체 단위 테스트 통과 확인.
