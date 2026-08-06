#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-dfir-triage}"

echo "Creating project scaffold at: $ROOT"

mkdir -p "$ROOT"/src/common
mkdir -p "$ROOT"/src/stage02_normalize/prompts
mkdir -p "$ROOT"/src/stage03_select
mkdir -p "$ROOT"/src/stage04_parse/parsers
mkdir -p "$ROOT"/src/stage04_parse/structs
mkdir -p "$ROOT"/src/stage05_interpret/prompts
mkdir -p "$ROOT"/src/stage06_verify/checkers
mkdir -p "$ROOT"/src/stage07_report/prompts
mkdir -p "$ROOT"/src/stage07_report/templates
mkdir -p "$ROOT"/schemas
mkdir -p "$ROOT"/mappings/windows
mkdir -p "$ROOT"/mappings/linux
mkdir -p "$ROOT"/benchmark/datasets/C-001-webshell/evidence
mkdir -p "$ROOT"/benchmark/results
mkdir -p "$ROOT"/cases
mkdir -p "$ROOT"/tests/fixtures
mkdir -p "$ROOT"/docs/meeting-notes
mkdir -p "$ROOT"/tools

for d in common stage02_normalize stage03_select stage04_parse stage04_parse/parsers \
         stage04_parse/structs stage05_interpret stage06_verify stage06_verify/checkers \
         stage07_report; do
  touch "$ROOT/src/$d/__init__.py"
done

touch "$ROOT"/src/common/{io,schema,errors,refs,attack}.py
touch "$ROOT"/src/stage02_normalize/{normalize,llm_client,alert_adapter}.py
touch "$ROOT"/src/stage02_normalize/prompts/normalize_system.txt
touch "$ROOT"/src/stage02_normalize/prompts/normalize_fewshot.json
touch "$ROOT"/src/stage03_select/{select,mapping_loader,scope_resolver}.py
touch "$ROOT"/src/stage04_parse/{parse,flagging}.py
touch "$ROOT"/src/stage04_parse/parsers/{base,mft,usnjrnl,evtx}.py
touch "$ROOT"/src/stage04_parse/structs/{mft_record,usn_record}.py
touch "$ROOT"/src/stage05_interpret/{interpret,record_filter,llm_client}.py
touch "$ROOT"/src/stage05_interpret/prompts/{interpret_system,claims_extract}.txt
touch "$ROOT"/src/stage06_verify/{verify,comparators}.py
touch "$ROOT"/src/stage06_verify/checkers/{ref_exists,ref_in_input,value_match}.py
touch "$ROOT"/src/stage07_report/report.py
touch "$ROOT"/src/stage07_report/prompts/report_system.txt
touch "$ROOT"/src/stage07_report/templates/report.md.j2

touch "$ROOT"/schemas/{input,scenario,selection,parsed_record,findings,verified}.schema.json
touch "$ROOT"/mappings/{_flags,_artifacts}.yaml
touch "$ROOT"/mappings/windows/{T1505.003,T1136.001,T1543.003,T1053.005,T1070.006}.yaml
touch "$ROOT"/mappings/linux/.gitkeep

touch "$ROOT"/benchmark/{evaluate,validator_check}.py
touch "$ROOT"/benchmark/ground_truth_schema.json
touch "$ROOT"/benchmark/datasets/C-001-webshell/{input.json,ground_truth.json}
touch "$ROOT"/benchmark/results/.gitkeep
touch "$ROOT"/cases/.gitkeep

touch "$ROOT"/tests/test_{mft_parser,usn_parser,evtx_parser,mapping_loader,verify_checkers}.py
touch "$ROOT"/tests/fixtures/.gitkeep

touch "$ROOT"/docs/{pipeline-io-spec,mapping-guide,artifact-notes,limitations}.md
touch "$ROOT"/tools/{make_case,inspect_jsonl,hexdump_record}.py

cat > "$ROOT"/.gitignore <<'EOF'
__pycache__/
*.py[cod]
.venv/
venv/

cases/*
!cases/.gitkeep

benchmark/datasets/*/evidence/
benchmark/results/*
!benchmark/results/.gitkeep

tests/fixtures/*.bin
*.dd
*.E01
*.raw
*.vmdk

.DS_Store
.idea/
.vscode/
EOF

cat > "$ROOT"/requirements.txt <<'EOF'
jsonschema>=4.21
pyyaml>=6.0
jinja2>=3.1
python-evtx>=0.7.4
construct>=2.10
requests>=2.31
pytest>=8.0
EOF

cat > "$ROOT"/run_pipeline.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CASE_ID="${1:?usage: run_pipeline.sh <case_id> <evidence_root>}"
EVIDENCE="${2:?usage: run_pipeline.sh <case_id> <evidence_root>}"
C="cases/$CASE_ID"

python -m src.stage02_normalize.normalize --in "$C/01_input.json"    --out "$C/02_scenario.json"
python -m src.stage03_select.select       --in "$C/02_scenario.json" --out "$C/03_selection.json" --mappings mappings/
python -m src.stage04_parse.parse         --in "$C/03_selection.json" --out "$C/04_parsed/" --evidence "$EVIDENCE" --skip-existing
python -m src.stage05_interpret.interpret --in "$C/04_parsed/" --scenario "$C/02_scenario.json" --out "$C/05_findings.json"
python -m src.stage06_verify.verify       --findings "$C/05_findings.json" --parsed "$C/04_parsed/" --out "$C/06_verified.json"
python -m src.stage07_report.report       --in "$C/06_verified.json" --findings "$C/05_findings.json" --selection "$C/03_selection.json" --out "$C/07_report.md"

echo "done: $C/07_report.md"
EOF
chmod +x "$ROOT"/run_pipeline.sh

cat > "$ROOT"/README.md <<'EOF'
# dfir-triage

시나리오 기반 아티팩트 선별과 sLLM 해석을 결합한 침해사고 트리아지 도구.

## 파이프라인

입력(자연어 또는 EDR/SIEM 알럿) -> 시나리오 정규화 -> 아티팩트 우선순위 선별
-> 결정론적 파싱 -> sLLM 해석 -> 근거 검증 -> 결과 보고

각 단계는 독립 CLI이며 파일로 입출력을 주고받습니다. 상세 계약은
`docs/pipeline-io-spec.md`를 참조하세요.

## 실행

```bash
pip install -r requirements.txt
python tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01
./run_pipeline.sh C-001 /mnt/evidence/WEB01
```

## 평가

```bash
python benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell
python benchmark/validator_check.py
```
EOF

echo "Done."
find "$ROOT" -type d | sort | head -40
