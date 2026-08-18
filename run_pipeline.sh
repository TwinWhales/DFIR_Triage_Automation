#!/usr/bin/env bash
#
# 전체 파이프라인을 한 번에 돌린다.
#
#   ./run_pipeline.sh <case_id> <evidence_root> [replay_dir]
#
# replay_dir 을 주면 02·05단계가 스텁으로 동작한다. 모델 없이 파이프라인
# 배선만 확인할 때 쓴다. 프롬프트 조립·응답 파싱·스키마 검증·재시도까지
# 실제 경로를 그대로 지나가고 네트워크 호출만 대체된다.
#
#   ./run_pipeline.sh C-001 /mnt/evidence/WEB01 \
#       benchmark/datasets/C-001-webshell/mock
#
# evidence_root 는 **볼륨 루트**다. KAPE 출력이면 <수집폴더>/C 이지
# <수집폴더>가 아니다. 볼륨이 여럿이면 케이스를 나눠 각각 돌린다
# (C-001-C, C-001-D). 도구가 어느 볼륨인지 추측하지 않게 하려는 것이고,
# 덤으로 ref 가 유일해진다.
#
# 04단계는 $MFT 와 $UsnJrnl 만 파싱한다. evtx 파서는 아직 없다.
# --skip-existing 이 붙어 있으므로 cases/<id>/04_parsed/ 에 산출물이
# 미리 있으면 건너뛴다. tools/make_case.py --seed-parsed 로 채울 수 있다.

set -euo pipefail

CASE_ID="${1:?usage: run_pipeline.sh <case_id> <evidence_root> [replay_dir]}"
EVIDENCE="${2:?usage: run_pipeline.sh <case_id> <evidence_root> [replay_dir]}"
REPLAY="${3:-}"

C="cases/$CASE_ID"
PY="${PYTHON:-python}"

if [[ -n "$REPLAY" ]]; then
  NORMALIZE_LLM=(--llm stub --replay "$REPLAY/02_scenario.json")
  INTERPRET_LLM=(--llm stub --replay "$REPLAY/05_findings.json")
  echo "== 스텁 모드: $REPLAY (실제 추론 없음) =="
else
  NORMALIZE_LLM=(--llm ollama)
  INTERPRET_LLM=(--llm ollama)
fi

echo "== 02 정규화 =="
$PY -m src.stage02_normalize.normalize \
    --in "$C/01_input.json" --out "$C/02_scenario.json" "${NORMALIZE_LLM[@]}"

echo "== 03 선별 =="
$PY -m src.stage03_select.select \
    --in "$C/02_scenario.json" --out "$C/03_selection.json" --mappings mappings/

echo "== 04 파싱 =="
$PY -m src.stage04_parse.parse \
    --in "$C/03_selection.json" --out "$C/04_parsed/" \
    --evidence "$EVIDENCE" --skip-existing

echo "== 05 해석 =="
$PY -m src.stage05_interpret.interpret \
    --in "$C/04_parsed/" --scenario "$C/02_scenario.json" \
    --out "$C/05_findings.json" "${INTERPRET_LLM[@]}"

echo "== 06 검증 =="
$PY -m src.stage06_verify.verify \
    --findings "$C/05_findings.json" --parsed "$C/04_parsed/" \
    --out "$C/06_verified.json"

echo "== 07 보고 =="
$PY -m src.stage07_report.report \
    --in "$C/06_verified.json" --findings "$C/05_findings.json" \
    --selection "$C/03_selection.json" --scenario "$C/02_scenario.json" \
    --parsed "$C/04_parsed/" --out "$C/07_report.md"

echo
echo "done: $C/07_report.md"
[[ -f "$C/errors.jsonl" ]] && echo "errors: $C/errors.jsonl ($(wc -l < "$C/errors.jsonl") 건)"
exit 0
