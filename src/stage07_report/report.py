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
    manifest: dict[str, Any] | None = None,
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
        "windows": _windows(manifest),
        "period_start": scope[0],
        "period_end": scope[1],
        "techniques": _techniques(selection, scenario),
        "technique_evidence": _technique_evidence(scenario),
        "stats": verified.get("stats", {}),
        "passed": passed,
        "unverifiable": unverifiable,
        "timeline": timeline,
        "examined": _examined(manifest),
        "limits": _limits(selection, manifest),
        # 02단계가 어느 서술도 기법으로 옮기지 못했다면 그 축은 조사에서
        # 통째로 빠진다. 인쇄하지 않으면 "증거 없음"과 구별되지 않는다.
        "unmapped_text": (scenario or {}).get("unmapped_text", []),
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


def _technique_evidence(scenario: dict[str, Any] | None) -> list[dict[str, str]]:
    """기법마다 02단계가 입력의 어느 구간을 근거로 삼았는가.

    **판정하지 않고 나란히 놓기만 한다.** 절을 엉뚱한 기법에 붙인 것은
    기계가 못 가른다 — 가르려면 "이 절은 어느 기법이어야 하는가"를 알아야
    하는데, 그것을 아는 표를 만드는 순간 02단계를 표로 대체한 것이 된다
    (`work.md` 7-2). 그래서 **사람이 한 줄 보고 알게** 만든다.

    실측(`K-LIVE-0902-wide` 3차, 2026-09-04)에서 이렇게 나왔다 —
    ``T1543.003 (Windows Service 생성) ← "계정 관련 변경이 있었는지도"``.
    기법 ID 만 인쇄하던 때는 보고서 어디에도 드러나지 않았다.
    """
    return [
        {
            "id": technique["id"],
            "name": attack.name_of(technique["id"]) or technique.get("name") or "이름 미상",
            "evidence_text": technique.get("evidence_text", ""),
        }
        for technique in (scenario or {}).get("techniques", [])
    ]


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


#: 04단계의 스킵 사유 코드 → 보고서 문장.
#:
#: 사유마다 **분석가가 할 일이 다르다.** 수집을 다시 해야 하는지, 추출이
#: 잘못됐는지, 이 도구가 아직 못 읽는 것인지가 구별되어야 한다.
SKIP_REASONS = {
    "artifact_not_found": "증거에 없음 (수집 누락)",
    "empty_artifact": "파일이 0바이트 (추출 확인 필요)",
    "parser_missing": "본 버전 미지원 (파서 없음)",
    # 위 셋과 조치가 다르다. 앞의 것들은 "다시 뽑아 오라"이지만 이것은
    # **다시 뽑아도 없다.** 가르지 않으면 분석가가 존재하지 않는 파일을
    # 찾으러 간다(src/stage04_parse/osinfo.py).
    "version_not_applicable": "이 Windows 버전에 없는 아티팩트 (재수집 불필요)",
}


def _windows(manifest: dict[str, Any] | None) -> str:
    """증거에서 판정한 Windows 버전. 한 줄로.

    시나리오의 ``target_os``와 나란히 실립니다. **둘은 출처가 다릅니다** —
    시나리오는 사람이 적어 넣은 값이고 이쪽은 SOFTWARE 하이브에서 읽은
    값입니다. 어긋나면 그 자체가 조사할 거리이므로 한쪽을 다른 쪽으로
    덮어쓰지 않고 둘 다 보여 줍니다.

    판정하지 못했으면 사유를 그대로 냅니다. 빈 문자열은 04단계가 이
    필드를 쓰기 전의 산출물이라는 뜻이므로 아무것도 적지 않습니다.
    """
    info = (manifest or {}).get("windows")
    if not info:
        return ""
    if not info.get("determined"):
        return f"판정 불가 — {info.get('reason', '사유 없음')}"

    parts = [str(info.get("product_name") or info.get("family", "이름 없음"))]
    build = f"빌드 {info['build']}"
    if info.get("revision") is not None:
        build += f".{info['revision']}"
    parts.append(build)
    for key in ("display_version", "release_id", "installation_type"):
        if info.get(key):
            parts.append(str(info[key]))
    return f"{parts[0]} ({', '.join(parts[1:])})"


#: 매니페스트의 신뢰도 집계 → 보고서 문구.
#:
#: 04단계가 "무엇을 셌나"를 정하고(``stage04_parse.parse.RELIABILITY_STATS``)
#: 여기가 "분석가에게 무엇으로 읽히나"를 정한다. 어느 쪽도 상대의 어휘를
#: 베껴 두지 않는다 — 매니페스트 키가 곧 보고서 문장이면, 키 이름을 바꾸는
#: 순간 보고서가 조용히 바뀐다.
#:
#: **수를 문장에 넣는 이유**는 판단이 절대량이 아니라 비율이기 때문이다.
#: ``fixup_errors`` 3건은 손상이고 30,000건은 섹터 크기 판정 오류다. 같은
#: 표에 ``record_count``가 있으므로 읽는 사람이 그 자리에서 나눠 볼 수 있다.
RELIABILITY_NOTES: tuple[tuple[str, str], ...] = (
    (
        "dirty_hive",
        "더티 하이브 — 트랜잭션 로그(.LOG1/.LOG2)를 재생하지 않았으므로 "
        "값이 최신이 아닐 수 있음",
    ),
    ("recovered_chunks", "헤더가 선언하지 않은 청크 {n:,}개를 복구해 읽음"),
    ("bad_chunks", "체크섬이 맞지 않는 청크 {n:,}개를 건너뜀"),
    (
        "fixup_errors",
        "업데이트 시퀀스 복원 실패 {n:,}건 — 레코드 수와 비슷하면 손상이 "
        "아니라 섹터 크기 판정을 의심",
    ),
    (
        "scope_undecidable",
        "{n:,}건은 드라이브 문자를 정하지 못해 경로 범위를 적용하지 못함",
    ),
    ("missing_tables", "프로파일이 기대한 테이블 {n:,}개가 없음"),
    ("unsupported_tables", "읽지 못하는 형태의 테이블 {n:,}개를 건너뜀"),
)


def _reliability_notes(entry: dict[str, Any]) -> list[str]:
    """읽기는 했는데 액면 그대로 보면 안 되는 사유들.

    ``parse_errors``와 달리 **못 읽은 것이 아닙니다.** 읽었는데 값이
    낡았거나, 정상 경로 밖에서 나왔거나, 선별이 안 걸린 것입니다. 그래서
    "부분 판독"과 같은 칸에 적되 문장을 따로 씁니다.

    ``dirty_hive``는 0/1 플래그라 수를 넣지 않습니다. 문구에 ``{n}``이
    없으면 그대로 나갑니다.
    """
    notes: list[str] = []
    for key, template in RELIABILITY_NOTES:
        count = entry.get(key)
        if not count:
            continue
        notes.append(template.format(n=count) if "{n" in template else template)
    return notes


def _examined(manifest: dict[str, Any] | None) -> list[dict[str, str]]:
    """실제로 읽은 아티팩트와 규모.

    **"안 본 것"만 적으면 범위가 반쪽입니다.** 무엇을 봤는지도 함께 적어야
    읽는 사람이 보고서만으로 분석 범위를 확인할 수 있습니다.

    레코드 0건도 여기 들어갑니다 — 파싱은 됐는데 범위에 아무것도 없었던
    경우이며, 그것이 곧 **"봤는데 없었다"**입니다. 한계로 옮기면 못 본 것과
    구별되지 않습니다.
    """
    if not manifest:
        return []

    rows: list[dict[str, str]] = []
    for entry in manifest.get("files", []):
        notes: list[str] = []
        unreadable = entry.get("unreadable_bytes")
        if unreadable:
            # 부분 판독. "안 봤다"가 아니지만 "다 봤다"도 아니므로 따로 적는다.
            notes.append(
                f"부분 판독 — 구간 {entry.get('parse_errors', 0)}곳 / "
                f"{unreadable:,}바이트를 읽지 못함"
            )
        elif entry.get("parse_errors"):
            notes.append(f"부분 판독 — 구간 {entry['parse_errors']}곳")
        if entry.get("source_empty_skipped"):
            notes.append("0바이트 후보를 건너뛰고 읽음 (추출 확인 권장)")
        # 읽기는 했는데 액면 그대로 보면 안 되는 사유. 위의 "못 읽은 것"
        # 뒤에 붙는다 — 분석가가 먼저 볼 것은 여전히 결손이다.
        notes.extend(_reliability_notes(entry))
        note = "; ".join(notes)
        rows.append(
            {
                "artifact": entry["artifact"],
                "records": f"{entry.get('record_count', 0):,}건",
                "note": note,
            }
        )
    return rows


def _limits(
    selection: dict[str, Any], manifest: dict[str, Any] | None = None
) -> list[dict[str, str]]:
    """확인하지 않은 아티팩트와 사유.

    세 갈래를 합칩니다.

    1. ``excluded`` — 03단계가 애초에 제외
    2. ``deferred`` — Tier 2로 유예
    3. **04단계가 읽지 못한 것** — 매니페스트의 ``skipped``

    3번이 없으면 보고서가 **읽지 못한 아티팩트를 언급조차 하지 않습니다.**
    "봤는데 없었다"와 "못 봤다"를 구분하는 것이 이 도구의 존재 이유이므로,
    그 구멍은 기능 결손이 아니라 논지의 구멍입니다(docs/limitations.md 4-1).

    마지막으로 **차집합으로 검산합니다.** ``selected``에 있는데 읽지도
    스킵되지도 않은 아티팩트가 남으면 04단계가 기록을 빠뜨린 것이므로,
    사유를 모른 채로라도 표에 올립니다. 조용히 사라지는 것보다 낫습니다.
    """
    limits = [
        {"artifact": entry["artifact"], "reason": entry["reason"]}
        for entry in selection.get("excluded", [])
    ]
    limits.extend(
        {
            "artifact": entry["artifact"],
            # 본 버전은 Tier 2 루프백이 없다. 조건을 **평가한 적이 없으므로**
            # "조건 미충족"이라고 쓰면 사실과 다르다 — 평가했는데 안 걸린
            # 것처럼 읽힌다. 실제로 $MFT가 deleted 69건을 냈는데도 "미충족"
            # 으로 적힌 사례가 있었다(docs/limitations.md 3).
            "reason": f"Tier 2 루프백 미구현으로 미평가 (조건: {entry['trigger']})",
        }
        for entry in selection.get("deferred", [])
    )

    if manifest is None:
        # 매니페스트 없이 부른 경우(``--parsed`` 미지정). 04단계가 무엇을
        # 했는지 알 수 없으므로 차집합 검산을 하지 않는다. 모르는 것을
        # "빠뜨렸다"고 적으면 그것도 거짓이다.
        return limits

    for entry in manifest.get("skipped", []):
        code = entry.get("reason", "")
        reason = SKIP_REASONS.get(code, "읽지 못함")
        message = entry.get("message", "")
        # ``parser_missing``의 메시지는 소스 파일 경로를 담은 개발자용
        # 안내다. 분석가가 읽는 문서에는 사유만 싣는다. 나머지 사유의
        # 메시지는 기대 경로나 파일 상태라 분석가에게도 쓸모가 있다.
        if message and code != "parser_missing":
            reason = f"{reason} — {message}"
        limits.append({"artifact": entry["artifact"], "reason": reason})

    # 실제로 읽은 것은 한계에서 뺀다. 03단계가 "Tier 1로 읽는 것은
    # deferred 에서 뺀다"를 지키지만(docs/mapping-guide.md), 어긋나면
    # 같은 아티팩트가 "확인함"과 "확인 못 함"에 동시에 실린다. 산출물이
    # 있다는 사실이 더 강한 증거이므로 그쪽을 믿는다.
    read = {entry["artifact"] for entry in manifest.get("files", [])}
    limits = [row for row in limits if row["artifact"] not in read]

    accounted = {row["artifact"] for row in limits} | read
    for entry in selection.get("selected", []):
        artifact = entry["artifact"]
        if artifact not in accounted:
            accounted.add(artifact)
            limits.append(
                {
                    "artifact": artifact,
                    "reason": (
                        "선별됐으나 산출물에 없음 — 04단계가 사유를 남기지 않았습니다"
                    ),
                }
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
    manifest = None
    if args.parsed:
        try:
            records = io.read_parsed_records(args.parsed)
        except (ValueError, NotADirectoryError) as e:
            log.abort(STAGE, "parse_error", {"message": str(e)})

        # 04단계가 무엇을 읽고 무엇을 건너뛰었는지. 이것이 없으면 보고서의
        # "분석 범위"가 요청 목록만 보고 쓰이며, 읽지 못한 아티팩트가
        # 통째로 사라진다(docs/limitations.md 4-1).
        manifest_path = Path(args.parsed) / "_manifest.json"
        if manifest_path.is_file():
            manifest = io.read_json(manifest_path)
        else:
            # 조용히 넘어가면 "범위 한계 0건"이 사실인지 알 수 없다.
            log.record(
                STAGE,
                "empty_result",
                {"message": f"{manifest_path} 없음 — 분석 범위를 04 산출물로 검산하지 못했습니다"},
                action="skip",
            )
            print(f"[{STAGE}] 경고 — {manifest_path} 없음. 분석 범위가 불완전합니다.")

    context = build_context(verified, findings_doc, selection, scenario, records, manifest)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(context), encoding="utf-8", newline="\n")

    print(
        f"{out_path}: 확인된 사항 {len(context['passed'])}건 / "
        f"미검증 {len(context['unverifiable'])}건 / 범위 한계 {len(context['limits'])}건"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
