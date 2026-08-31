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
#       benchmark/fixtures/C-001-webshell
#
# evidence_root 는 **볼륨 루트**다. KAPE 출력이면 <수집폴더>/C 이지
# <수집폴더>가 아니다. 볼륨이 여럿이면 케이스를 나눠 각각 돌린다
# (C-001-C, C-001-D). 도구가 어느 볼륨인지 추측하지 않게 하려는 것이고,
# 덤으로 ref 가 유일해진다.
#
# evidence_root 가 **디스크 이미지 파일**이면 그 안에 NTFS 가 여럿일 수
# 있다. 일반적인 Win10/11 물리 디스크는 복구 파티션도 NTFS 라 거의 항상
# 해당한다. 그때는 VOLUME 으로 어느 것인지 고른다:
#
#   VOLUME=1 PYTHON=.venv/Scripts/python.exe ./run_pipeline.sh K-ALERT evidence/0824test.001
#
# 주지 않으면 04단계가 후보를 보여 주고 멈춘다. 그 동작이 정상이다 —
# 크기로 추측하면 복구 파티션과 시스템 볼륨을 바꿔 골라도 "아티팩트 없음"이
# 아니라 다른 볼륨의 결과가 조용히 나온다.
#
# 04단계는 카탈로그에 등재된 아티팩트를 파싱한다($MFT, $UsnJrnl, evtx,
# 레지스트리). --skip-existing 이 붙어 있으므로 cases/<id>/04_parsed/ 에 산출물이
# 미리 있으면 건너뛴다. tools/make_case.py --seed-parsed 로 채울 수 있다.
#
# ## 실제 모델로 돌릴 때
#
# replay_dir 을 빼면 02·05 가 Ollama 를 부른다. 모델과 호출 조건은 환경
# 변수로 넘긴다:
#
#   MODEL=qwen2.5:14b NUM_CTX=32768 TIMEOUT=900 TEMPERATURE=0.3 \
#   VOLUME=1 PYTHON=.venv/Scripts/python.exe ./run_pipeline.sh K-001 evidence/x.001
#
# **MODEL 은 필수다.** 단계에도 기본값이 있지만 여기서는 받지 않는다 —
# 산출물의 generator 필드가 "어느 모델로 돌린 결과인가"를 들고 있어야
# 모델별 비교가 성립하는데(io.make_generator), 기본값에 기대면 그 값이
# 실행한 사람의 기계 사정에 좌우된다.
#
#   MODEL       ollama 모델명 (필수). `ollama list` 의 이름 그대로
#   NUM_CTX     컨텍스트 창. 기본값은 단계가 정한다(32768)
#   TIMEOUT     한 번 호출의 상한(초). 60GB 급에서 120초는 부족하다는 실측이 있다
#   TEMPERATURE 0 이면 재시도가 같은 답을 반복한다. 실측에서 존재하지 않는
#               하위기법을 다섯 번 연속 냈다(docs/limitations.md 5장 ⑤)
#   LIMIT       05단계가 모델에 보낼 레코드 수의 **상한**. 토큰 예산이
#               더 낮으면 그쪽이 이긴다
#   OLLAMA_HOST 기본 http://localhost:11434

set -euo pipefail

CASE_ID="${1:?usage: run_pipeline.sh <case_id> <evidence_root> [replay_dir]}"
EVIDENCE="${2:?usage: run_pipeline.sh <case_id> <evidence_root> [replay_dir]}"
REPLAY="${3:-}"

C="cases/$CASE_ID"
PY="${PYTHON:-python}"

# 이미지에 NTFS 가 여럿일 때 열 볼륨. 빈 값을 그대로 넘기면 --volume 이
# 인자 없이 붙어 04단계가 죽으므로, 있을 때만 배열을 채운다.
if [[ -n "${VOLUME:-}" ]]; then
  PARSE_VOLUME=(--volume "$VOLUME")
else
  PARSE_VOLUME=()
fi

if [[ -n "$REPLAY" ]]; then
  NORMALIZE_LLM=(--llm stub --replay "$REPLAY/02_scenario.json")
  INTERPRET_LLM=(--llm stub --replay "$REPLAY/05_findings.json")
  echo "== 스텁 모드: $REPLAY (실제 추론 없음) =="
else
  if [[ -z "${MODEL:-}" ]]; then
    echo "MODEL 이 필요하다 — 실제 모델로 돌리려면 모델명을 준다." >&2
    echo "  MODEL=<이름> PYTHON=$PY ./run_pipeline.sh $CASE_ID $EVIDENCE" >&2
    echo "  설치된 이름은 'ollama list' 로 본다." >&2
    echo "  모델 없이 배선만 볼 거면 세 번째 인자로 replay 디렉터리를 준다." >&2
    exit 2
  fi

  # 있을 때만 붙인다. 빈 값을 그대로 넘기면 인자 없는 플래그가 되어
  # argparse 가 뒤 인자를 값으로 먹는다 — VOLUME 과 같은 이유다.
  COMMON_LLM=(--llm ollama --model "$MODEL")
  [[ -n "${NUM_CTX:-}" ]] && COMMON_LLM+=(--num-ctx "$NUM_CTX")
  [[ -n "${TIMEOUT:-}" ]] && COMMON_LLM+=(--timeout "$TIMEOUT")
  [[ -n "${TEMPERATURE:-}" ]] && COMMON_LLM+=(--temperature "$TEMPERATURE")
  [[ -n "${OLLAMA_HOST:-}" ]] && COMMON_LLM+=(--host "$OLLAMA_HOST")

  NORMALIZE_LLM=("${COMMON_LLM[@]}")
  INTERPRET_LLM=("${COMMON_LLM[@]}")
  # --limit 은 05단계에만 있다. 02단계에 붙이면 argparse 가 거부한다.
  [[ -n "${LIMIT:-}" ]] && INTERPRET_LLM+=(--limit "$LIMIT")

  echo "== 실제 모델: $MODEL${NUM_CTX:+ (num_ctx $NUM_CTX)} =="
  if [[ -z "${TEMPERATURE:-}" ]]; then
    # 조용히 0 으로 도는 것이 함정이라 여기서 말한다. 실측 근거는 위 주석에.
    echo "   temperature 를 안 줬다 — 0 이면 재시도가 같은 답을 반복한다"
  fi
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
    --evidence "$EVIDENCE" --skip-existing "${PARSE_VOLUME[@]+"${PARSE_VOLUME[@]}"}"

echo "== 05 해석 =="
$PY -m src.stage05_interpret.interpret \
    --in "$C/04_parsed/" --scenario "$C/02_scenario.json" \
    --selection "$C/03_selection.json" \
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

# 다음에 할 일을 여기서 알려 준다. 실행한 사람의 눈이 여기 있고, 이 둘은
# 실제 사건에서 거치는 자리다 (README "산출물 확인").
#
# **자동으로 돌리지 않는다.** 이 스크립트의 계약은 01→07 을 관통하는 것이고,
# 확인은 사람이 결과를 보고 판단하는 일이다. 여기서 대신 돌려 종료 코드를
# 바꾸면 "파이프라인이 실패했다" 와 "산출물이 스스로와 안 맞는다" 가 같아
# 보인다.
echo
echo "확인:"
echo "  $PY tools/inspect_jsonl.py --parsed $C/04_parsed"
echo "      04 산출물이 매니페스트·ref 유일성과 맞는지 (어긋나면 종료 코드 1)"
echo "  $PY tools/hexdump_record.py <ref> --parsed $C/04_parsed --evidence $EVIDENCE"
echo "      보고서의 ref 를 디스크의 원본 바이트로 되짚는다"
exit 0
