#!/usr/bin/env bash
#
# PostToolUse(Write|Edit) 훅 — src/ 나 tests/ 의 파이썬 파일이 바뀌면 테스트를 돌린다.
#
# 통과하면 아무것도 출력하지 않고 조용히 끝난다. 실패하면 종료코드 2로 끝내
# 실패 내용을 모델에게 되돌린다. 이 프로젝트의 원칙 그대로다 — 실패는 조용히
# 넘어가지 않는다.
#
# 훅 입력은 stdin의 JSON이다. jq가 이 기계에 없어서 프로젝트 파이썬으로 읽는다.
#
# 직접 시험해 보려면:
#   echo '{"tool_input":{"file_path":"<리포>/src/common/io.py"}}' \
#     | bash .claude/hooks/pytest-on-source-change.sh; echo "종료코드: $?"

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
py="$root/.venv/Scripts/python.exe"
[ -x "$py" ] || py="$root/.venv/bin/python"
[ -x "$py" ] || exit 0          # 가상환경이 없으면 조용히 넘어간다

# 경로를 뽑고 구분자를 /로 통일한다. Windows에서는 역슬래시로 들어온다.
file="$("$py" -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print(""); raise SystemExit
p = (d.get("tool_input") or {}).get("file_path") \
    or (d.get("tool_response") or {}).get("filePath") or ""
print(p.replace(chr(92), "/"))
')"

case "$file" in
  *src/*.py|*tests/*.py) ;;
  *) exit 0 ;;
esac

cd "$root" || exit 0

# -x: 첫 실패에서 멈춘다. 고칠 것이 하나여야 다음 행동이 분명해진다.
if out="$("$py" -m pytest -q -x 2>&1)"; then
  exit 0
fi

echo "pytest 실패 — $file 변경 후:"
# 진행 표시 점만 있는 줄은 버리고 실패 내역만 남긴다.
printf '%s\n' "$out" | grep -v '^[.sxFE]* *\[ *[0-9]*%\]$' | tail -40
exit 2
