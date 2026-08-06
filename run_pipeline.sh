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
