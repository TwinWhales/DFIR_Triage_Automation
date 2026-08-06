"""07단계 — 결과 보고.

``06_verified.json``의 ``passed`` 항목만 입력으로 받는다. 원본 파싱
데이터는 다시 주지 않는다.

**이 단계는 LLM을 쓰지 않는다.** 스펙은 sLLM으로 적었으나, 검증을 통과한
문장을 모델이 다시 쓰게 하면 마지막 단계에서 환각이 재유입된다. 앞의
모든 검증이 무의미해지는 지점이다. 템플릿 렌더링은 "검증 통과분만 실린다"를
구조적으로 보장한다.

문장을 다듬는 LLM 경로가 필요해지면 ``prompts/report_system.txt``를 쓰되,
**통과한 문장의 재작성이 아니라 요약문 추가**로 한정해야 한다.

미검증 항목과 분석 범위 한계는 템플릿의 고정 섹션이다. 자동 생성에서
누락되지 않는 것이 이 도구의 신뢰성 근거다.

사용법::

    python -m src.stage07_report.report \\
        --in cases/C-001/06_verified.json \\
        --findings cases/C-001/05_findings.json \\
        --selection cases/C-001/03_selection.json \\
        --scenario cases/C-001/02_scenario.json \\
        --parsed cases/C-001/04_parsed/ \\
        --out cases/C-001/07_report.md
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ..common import attack
from ..common import errors as errlog
from ..common import io, refs, schema

__all__ = ["STAGE", "SEVERITY_LABELS", "build_context", "render", "main"]

STAGE = "07_report"
TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITY_LABELS = {"high": "높음", "medium": "중간", "low": "낮음", "info": "참고"}


def build_context(
    verified: dict[str, Any],
    findings_doc: dict[str, Any],
    selection: dict[str, Any],
    scenario: dict[str, Any] | None = None,
    records: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """템플릿에 넘길 값을 만든다.

    ``passed``에 없는 finding은 여기서 걸러진다. 템플릿이 실수로 전체
    목록을 돌더라도 기각된 문장이 실릴 수 없게, 걸러진 결과만 넘긴다.
    """
    by_id = {finding["id"]: finding for finding in findings_doc.get("findings", [])}
    passed_ids = [entry["id"] for entry in verified.get("passed", [])]
    unverifiable_ids = [entry["id"] for entry in verified.get("unverifiable", [])]

    passed = []
    for finding_id in passed_ids:
        finding = by_id.get(finding_id)
        if finding is None:
            continue
        passed.append(
            {
                "id": finding_id,
                "title": _title(finding),
                "severity_label": SEVERITY_LABELS.get(finding.get("severity", ""), "참고"),
                "statement": finding["statement"],
                "evidence": [_evidence_line(ref, records) for ref in finding.get("refs", [])],
            }
        )

    unverifiable = [
        {"statement": by_id[fid]["statement"]} for fid in unverifiable_ids if fid in by_id
    ]

    # 통과한 문장이 근거로 삼은 사건만 타임라인에 남긴다. 기각된 문장이
    # 만든 타임라인 항목이 남으면 보고서가 검증을 우회하게 된다.
    allowed_refs = {ref for finding in passed for ref in by_id[finding["id"]].get("refs", [])}
    timeline = [
        entry
        for entry in findings_doc.get("timeline", [])
        if entry.get("refs") and set(entry["refs"]) <= allowed_refs
    ]

    scope = _period(selection, scenario)
    return {
        "case_id": verified["case_id"],
        "hosts": (scenario or {}).get("entities", {}).get("hosts", []),
        "target_os": (scenario or {}).get("target_os", "미상"),
        "period_start": scope[0],
        "period_end": scope[1],
        "techniques": _techniques(selection, scenario),
        "stats": verified.get("stats", {}),
        "passed": passed,
        "unverifiable": unverifiable,
        "timeline": timeline,
        "limits": _limits(selection),
        "generated_at": io.utc_now(),
        "generator": io.make_generator("report.py"),
    }


def _title(finding: dict[str, Any]) -> str:
    """제목은 기법명에서 가져온다.

    findings에는 제목 필드가 없다. 문장에서 요약을 만들어 내면 그것이
    검증되지 않은 새 문장이 되므로, 이미 검증된 값인 기법 ID만 쓴다.
    """
    technique = finding.get("technique")
    if not technique:
        return "근거 확인 사항"
    return f"{technique} {attack.name_of(technique) or ''}".strip()


def _evidence_line(ref: str, records: dict[str, dict[str, Any]] | None) -> str:
    """``$MFT 레코드 12345 (오프셋 0x1E000)`` 형태의 근거 표기."""
    try:
        parsed = refs.parse_ref(ref)
        label = f"{parsed.artifact} 레코드 {parsed.record_num}"
    except refs.RefError:
        return ref

    record = (records or {}).get(ref)
    if record and record.get("offset"):
        return f"{label} (오프셋 {record['offset']})"
    return label


def _period(selection: dict[str, Any], scenario: dict[str, Any] | None) -> tuple[str, str]:
    """분석 기간. 실제로 읽은 범위(selection)를 우선한다."""
    for entry in selection.get("selected", []):
        time_range = (entry.get("scope") or {}).get("time_range")
        if time_range:
            return time_range["start"][:10], time_range["end"][:10]
    if scenario and scenario.get("time_range"):
        return scenario["time_range"]["start"][:10], scenario["time_range"]["end"][:10]
    return "미상", "미상"


def _techniques(selection: dict[str, Any], scenario: dict[str, Any] | None) -> list[str]:
    """실제로 선별을 유발한 기법. 시나리오가 아니라 selection에서 뽑는다."""
    seen: dict[str, None] = {}
    for entry in selection.get("selected", []):
        technique = (entry.get("reason") or {}).get("technique")
        if technique:
            seen.setdefault(technique, None)
    if not seen and scenario:
        for technique in scenario.get("techniques", []):
            seen.setdefault(technique["id"], None)
    return [f"{tid} ({attack.name_of(tid) or '이름 미상'})" for tid in seen]


def _limits(selection: dict[str, Any]) -> list[dict[str, str]]:
    """확인하지 않은 아티팩트와 사유.

    ``excluded``와 발동하지 않은 ``deferred``를 합친다. 스펙의 보고서
    예시가 둘을 한 표에 담고 있으나 합치는 규칙은 적혀 있지 않아
    여기서 정한다. 본 버전은 Tier 2 루프백을 구현하지 않으므로
    ``deferred``는 전부 미발동이다.
    """
    limits = [
        {"artifact": entry["artifact"], "reason": entry["reason"]}
        for entry in selection.get("excluded", [])
    ]
    limits.extend(
        {
            "artifact": entry["artifact"],
            "reason": f"Tier 2 조건 미충족 ({entry['trigger']})",
        }
        for entry in selection.get("deferred", [])
    )
    return limits


def render(context: dict[str, Any]) -> str:
    """템플릿을 렌더링한다."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        # 정의되지 않은 값을 조용히 빈 문자열로 만들면, 보고서에서
        # 섹션이 통째로 사라져도 아무도 모른다.
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template("report.md.j2").render(**context)


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage07_report.report",
        description="검증을 통과한 항목만으로 보고서를 만든다.",
    )
    parser.add_argument("--in", dest="in_path", required=True, help="06_verified.json 경로")
    parser.add_argument("--findings", required=True, help="05_findings.json 경로")
    parser.add_argument("--selection", required=True, help="03_selection.json 경로")
    parser.add_argument(
        "--scenario", default=None, help="02_scenario.json 경로. 개요의 호스트·OS에 쓰인다"
    )
    parser.add_argument(
        "--parsed", default=None, help="04_parsed/ 디렉터리. 근거에 원본 오프셋을 적는다"
    )
    parser.add_argument("--out", required=True, help="07_report.md 출력 경로")
    parser.add_argument("--errors", default=None)
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    out_path = Path(args.out)
    log = errlog.ErrorLog(Path(args.errors) if args.errors else out_path.parent / "errors.jsonl")

    verified = io.read_json(args.in_path)
    findings_doc = io.read_json(args.findings)
    selection = io.read_json(args.selection)
    scenario = io.read_json(args.scenario) if args.scenario else None

    try:
        schema.validate(verified, "verified")
        schema.validate(findings_doc, "findings")
        schema.validate(selection, "selection")
        if scenario is not None:
            schema.validate(scenario, "scenario")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())

    records = None
    if args.parsed:
        try:
            records = io.read_parsed_records(args.parsed)
        except (ValueError, NotADirectoryError) as e:
            log.abort(STAGE, "parse_error", {"message": str(e)})

    context = build_context(verified, findings_doc, selection, scenario, records)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(context), encoding="utf-8", newline="\n")

    print(
        f"{out_path}: 확인된 사항 {len(context['passed'])}건 / "
        f"미검증 {len(context['unverifiable'])}건 / 범위 한계 {len(context['limits'])}건"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
