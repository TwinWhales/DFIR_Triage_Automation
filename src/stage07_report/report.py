"""07단계 — 결과 보고.

``06_verified.json``의 ``passed``는 확인된 사실로, ``unverifiable``은
주의 필요 소견으로 받는다. ``rejected``는 본문과 타임라인에서 차단한다.
서사는 ``story_review``가 판정한 문장만 싣는다 — 06이 보지 않은 문장은
검증을 우회한 산문이므로 본문에 넣지 않고 개수만 밝힌다.

**이 단계는 LLM을 쓰지 않는다.** 스펙은 sLLM으로 적었으나, 검증을 통과한
문장을 모델이 다시 쓰게 하면 마지막 단계에서 환각이 재유입된다. 앞의
모든 검증이 무의미해지는 지점이다. 템플릿 렌더링은 "검증 통과분만 실린다"를
구조적으로 보장한다.

문장을 다듬는 LLM 경로가 필요해지면 ``prompts/report_system.txt``를 쓰되,
**통과한 문장의 재작성이 아니라 요약문 추가**로 한정해야 한다.

주의 필요 소견과 미확인 범위는 템플릿의 고정 섹션이다. 자동 생성에서
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
from ..stage05_interpret import coverage as coverage_mod

__all__ = ["STAGE", "SEVERITY_LABELS", "build_context", "render", "main"]

STAGE = "07_report"
TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITY_LABELS = {"high": "높음", "medium": "중간", "low": "낮음", "info": "참고"}
DETAIL_CLAIM_FIELDS = frozenset({"fields.CommandLine", "fields.ParentCommandLine"})

#: 서사에 실을 수 있는 판정. 여기 없는 판정(``contradicted``·``insufficient``)은
#: 본문에서 빠지고 개수만 남는다.
STORY_BADGES = {"supported": "\U0001F7E2", "supported_with_warning": "\U0001F7E1"}
#: 관측과 판단을 한 줄에서 구별한다. 서사는 둘을 같은 문장 꼴로 쓰므로
#: 표시하지 않으면 읽는 사람이 가릴 수 없다.
STORY_KIND_LABELS = {
    "observed_fact": "관측",
    "analytical_assessment": "판단",
    "unknown": "미상",
}


#: 05단계가 낸 조사 요청의 종류 → 보고서에 인쇄할 말.
REQUEST_LABELS = {
    "expand_time_range": "분석 기간 확장",
    "request_technique": "기법 추가",
    "request_artifact": "아티팩트 추가 수집",
    "request_behavior": "행위 기반 재검색",
}

#: 기각 사유 → 보고서에 인쇄할 말.
#:
#: **어휘의 출처는 ``schemas/investigation.schema.json``** 이고 여기 있는
#: 것은 그 값을 사람이 읽을 문장으로 옮긴 표다. 04단계의 ``skipped`` 사유를
#: 07이 옮겨 적는 것과 같은 규약 — 무엇을 셀 것인가는 스키마가 정하고,
#: 분석가에게 무엇으로 읽히나는 이 단계가 정한다.
REJECTION_LABELS = {
    "ungrounded_ref": "근거로 든 레코드가 05단계에 전달된 적이 없습니다",
    "unknown_technique": "실재하지 않는 ATT&CK ID입니다",
    "unmapped_technique": "매핑 테이블이 없어 선별할 아티팩트가 정해지지 않습니다",
    "already_selected": "이미 1차에서 보고 있습니다",
    "unsupported_artifact": "이 버전이 읽지 못하는 아티팩트입니다",
    "out_of_evidence": "증거 수집 시각 밖이라 볼 것이 없습니다",
    "no_widening": "이미 분석 기간이 덮고 있습니다",
    "ungrounded_claim": "사용자 원문에서 확인되지 않은 조사 근거입니다",
    "unknown_behavior": "지원하지 않는 행위 범주입니다",
    "behavior_not_processed": "행위 재검색 실행기를 거치지 않았습니다",
    "searched_no_evidence": "재검색을 수행했으나 일치하는 근거가 없습니다",
}


def _request_target(request: dict[str, Any]) -> str:
    """무엇을 요청했는지 한 칸에 들어갈 말로."""
    kind = request.get("type")
    if kind == "expand_time_range":
        return f"{request.get('pivot_time', '?')} ± {request.get('window_hours', '?')}시간"
    if kind == "request_technique":
        return str(request.get("technique_id", "?"))
    if kind == "request_artifact":
        return str(request.get("artifact", "?"))
    if kind == "request_behavior":
        pivots = ", ".join(request.get("pivots") or [])
        return f"{request.get('category', '?')}" + (f" ({pivots})" if pivots else "")
    return "?"


def _request_ground(request: dict[str, Any]) -> str:
    if request.get("based_on_ref"):
        return str(request["based_on_ref"])
    based_on = request.get("based_on") or {}
    if based_on.get("kind") == "evidence_ref":
        return str(based_on.get("ref") or "")
    if based_on.get("kind") == "scenario_claim":
        return f"사용자 원문 {based_on.get('claim_id', '?')}"
    return ""


def _investigation(requests_doc: dict[str, Any] | None) -> list[dict[str, str]]:
    """05단계가 낸 추가 조사 요청과 그 처리.

    **기각된 요청이 이 절의 요지다.** 모델이 "이것을 더 봐야 한다"고 했는데
    보지 않은 것이므로 미확인 사항이고, 사유를 함께 적지 않으면 분석가는
    그것이 있었는지조차 모른다. 수용된 것도 함께 싣는 것은, 2차에서 무엇이
    늘었는지가 보고서의 나머지를 읽는 전제이기 때문이다.
    """
    rows = []
    for request in (requests_doc or {}).get("requests", []):
        disposition = request.get("disposition") or {}
        reason = disposition.get("reason", "")
        accepted = disposition.get("verdict") == "accepted"
        rows.append(
            {
                "kind": REQUEST_LABELS.get(str(request.get("type")), str(request.get("type"))),
                "target": _request_target(request),
                "ref": _request_ground(request),
                "rationale": request.get("rationale", ""),
                "verdict": "2차에서 확인" if accepted else "확인하지 않음",
                "reason": (
                    disposition.get("detail", "")
                    if accepted
                    else REJECTION_LABELS.get(reason, reason or "판정 없음")
                ),
            }
        )
    return rows


def build_context(
    verified: dict[str, Any],
    findings_doc: dict[str, Any],
    selection: dict[str, Any],
    scenario: dict[str, Any] | None = None,
    records: dict[str, dict[str, Any]] | None = None,
    manifest: dict[str, Any] | None = None,
    requests_doc: dict[str, Any] | None = None,
    coverage_doc: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """템플릿에 넘길 값을 만든다.

    ``passed``와 ``unverifiable``에 없는 finding은 여기서 걸러진다.
    템플릿이 실수로 전체 목록을 돌더라도 기각된 문장이 실릴 수 없게,
    걸러진 결과만 넘긴다.
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
                "evidence_details": _evidence_details(finding.get("refs", []), records),
                "verified_details": _verified_details(finding),
            }
        )

    # **사유를 함께 싣는다.** 검증불가로 오는 길이 둘이라 그렇다 — claims 가
    # 빈 종합 판단 문장과, 문장이 증거 밖 표현을 써서 강등된 것
    # (`stage06_verify/checkers/statement_grounded.py`). 앞은 "근거를 달지
    # 않았다"이고 뒤는 "증거에 없는 것을 말했다"라, 읽는 사람이 할 일이
    # 다르다. 한 덩어리로 실으면 그 구별이 보고서에서 사라진다.
    reasons = {entry["id"]: entry.get("reason", "") for entry in verified.get("unverifiable", [])}
    warnings = []
    for finding_id in unverifiable_ids:
        finding = by_id.get(finding_id)
        if finding is None:
            continue
        warnings.append(
            {
                "id": finding_id,
                "title": _title(finding),
                "severity_label": SEVERITY_LABELS.get(finding.get("severity", ""), "참고"),
                "statement": finding["statement"],
                "reason": reasons.get(finding_id, ""),
                "evidence": [_evidence_line(ref, records) for ref in finding.get("refs", [])],
                "evidence_details": _evidence_details(finding.get("refs", []), records),
                "verified_details": _verified_details(finding),
            }
        )

    # 통과한 문장이 근거로 삼은 사건만 타임라인에 남긴다. 기각된 문장이
    # 만든 타임라인 항목이 남으면 보고서가 검증을 우회하게 된다.
    passed_refs = {ref for finding in passed for ref in by_id[finding["id"]].get("refs", [])}
    warning_refs = {ref for finding in warnings for ref in by_id[finding["id"]].get("refs", [])}
    allowed_refs = passed_refs | warning_refs
    timeline = []
    for entry in findings_doc.get("timeline", []):
        refs_in_entry = set(entry.get("refs") or [])
        if not refs_in_entry or not refs_in_entry <= allowed_refs:
            continue
        timeline.append(
            {
                **entry,
                "verification": "Warning" if refs_in_entry & warning_refs else "Passed",
            }
        )

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
        "warnings": warnings,
        # 외부 호출자의 기존 context 계약도 유지한다.
        "unverifiable": warnings,
        "timeline": timeline,
        "story": _story(findings_doc, verified, records),
        "examined": _examined(manifest),
        "limits": _limits(selection, manifest),
        # 02단계가 어느 서술도 기법으로 옮기지 못했다면 그 축은 조사에서
        # 통째로 빠진다. 인쇄하지 않으면 "증거 없음"과 구별되지 않는다.
        "unmapped_text": (scenario or {}).get("unmapped_text", []),
        # 05→02 루프백이 돈 케이스에만 값이 있다. 안 돌았으면 빈 목록이고
        # 템플릿이 절을 통째로 뺀다 — 매 보고서에 "루프백을 돌리지
        # 않았습니다"를 인쇄하면 그 문장이 곧 소음이 된다.
        "investigation": _investigation(requests_doc),
        "coverage": coverage_mod.report_rows(coverage_doc),
        "generated_at": io.utc_now(),
        "generator": io.make_generator("report.py"),
    }


def _story(
    findings_doc: dict[str, Any],
    verified: dict[str, Any],
    records: dict[str, dict[str, Any]] | None,
) -> dict[str, Any]:
    """05단계 서사 중 06단계가 뒷받침을 확인한 문장만 순서대로 돌려준다.

    **판정 기록이 없는 문장은 싣지 않는다.** ``story_review``는 05단계가
    ``story_critic``을 냈을 때만 06단계가 만든다. 그것이 없는데 서사를
    그대로 인쇄하면, 소견은 전부 대조하면서 산문만 검증을 우회하는
    보고서가 된다 — 이 단계가 LLM을 부르지 않는 이유와 같은 이유다.

    **대신 빠진 것을 숨기지 않는다.** 근거가 기각·부족해 빠진 것과
    06단계가 보지 않아 빠진 것은 읽는 사람이 할 일이 다르므로 따로 센다.
    앞은 모델이 틀린 자리이고, 뒤는 05단계 설정이 빠진 자리다.
    """
    sentences = ((findings_doc.get("incident_story") or {}).get("sentences") or [])
    review = {
        item.get("sentence_id"): item
        for item in (verified.get("story_review") or [])
        if isinstance(item, dict)
    }

    kept: list[dict[str, Any]] = []
    dropped = unreviewed = 0
    for sentence in sentences:
        entry = review.get(sentence.get("id"))
        if entry is None:
            unreviewed += 1
            continue
        verdict = entry.get("verdict")
        badge = STORY_BADGES.get(verdict)
        if badge is None:
            dropped += 1
            continue
        kept.append(
            {
                "id": sentence.get("id", ""),
                "badge": badge,
                "kind_label": STORY_KIND_LABELS.get(sentence.get("kind", ""), "미상"),
                "text": sentence.get("text", ""),
                "evidence": [
                    _evidence_line(ref, records) for ref in sentence.get("refs", [])
                ],
                # 통과한 문장의 사유는 "왜 통과했나"라 보고서에 실을 것이
                # 없다. 노란불만 읽는 사람이 할 일이 있다.
                "reason": entry.get("reason", "") if verdict == "supported_with_warning" else "",
            }
        )
    return {"sentences": kept, "dropped": dropped, "unreviewed": unreviewed}


def _title(finding: dict[str, Any]) -> str:
    """제목은 기법명에서 가져온다.

    findings에는 제목 필드가 없다. 문장에서 요약을 만들어 내면 그것이
    검증되지 않은 새 문장이 되므로, 이미 검증된 값인 기법 ID만 쓴다.
    """
    technique = finding.get("technique")
    if not technique:
        return "근거 확인 사항"
    return f"{technique} {attack.name_of(technique) or ''}".strip()


def _verified_details(finding: dict[str, Any]) -> list[str]:
    """보고서에서 숨기면 의미가 손실되는 검증 완료 명령행을 돌려준다.

    새 문장을 만들지 않고 05가 원본에서 조립해 06이 대조한 claim 값만
    그대로 싣는다. 줄바꿈은 Markdown 인용 블록을 깨지 않게 공백으로 편다.
    """
    details: list[str] = []
    for claim in finding.get("claims", []):
        field = claim.get("field")
        value = claim.get("value")
        if field not in DETAIL_CLAIM_FIELDS or not isinstance(value, str):
            continue
        line = f"{field}: {' '.join(value.splitlines())}"
        if line not in details:
            details.append(line)
    return details


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


def _record_detail(ref: str, record: dict[str, Any]) -> str:
    """분석가가 원본을 직접 확인할 수 있도록 핵심 원본 정보(명령행, 네트워크, 파일 등)를 요약."""
    fields = record.get("fields") if isinstance(record.get("fields"), dict) else {}
    canonical = record.get("canonical") if isinstance(record.get("canonical"), dict) else {}

    ts = record.get("timestamp") or canonical.get("event_time")
    ts_str = f"[{ts}] " if ts else ""

    parts: list[str] = []

    # 1. 프로세스 실행 / 명령행
    cmdline = str(fields.get("CommandLine") or canonical.get("command_line") or "").strip()
    img = str(fields.get("Image") or canonical.get("process_image") or "").strip()
    parent = str(fields.get("ParentImage") or canonical.get("parent_image") or "").strip()
    user = str(fields.get("User") or canonical.get("user") or "").strip()

    dip = str(fields.get("DestinationIp") or canonical.get("remote_ip") or "").strip()
    dport = str(fields.get("DestinationPort") or canonical.get("remote_port") or "").strip()
    dhost = str(fields.get("DestinationHostname") or "").strip()

    if cmdline:
        cmd_clean = " ".join(cmdline.split())
        parts.append(f"명령행: `{cmd_clean}`")
        if parent:
            p_name = Path(parent.replace("\\", "/")).name
            parts.append(f"부모: `{p_name}`")
        if user:
            parts.append(f"계정: {user}")
    elif img:
        img_disp = Path(img.replace("\\", "/")).name if (dip or dport) else img
        parts.append(f"실행: `{img_disp}`")
        if parent:
            p_name = Path(parent.replace("\\", "/")).name
            parts.append(f"부모: `{p_name}`")
        if user:
            parts.append(f"계정: {user}")

    # 2. 네트워크 연결
    if dip or dport:
        sip = str(fields.get("SourceIp") or "").strip()
        sport = str(fields.get("SourcePort") or "").strip()
        proto = str(fields.get("Protocol") or "").upper()
        net_info = f"{sip}:{sport} -> {dip}:{dport}" if sip and sport else f"-> {dip}:{dport}"
        if dhost and dhost != "-":
            net_info += f" ({dhost})"
        elif proto:
            net_info += f" ({proto})"
        parts.append(f"네트워크: {net_info}")

    # 3. 보안 이벤트 / 계정 활동
    target_user = str(fields.get("TargetUserName") or "").strip()
    subj_user = str(fields.get("SubjectUserName") or "").strip()
    if target_user:
        parts.append(f"대상계정: {target_user}")
    if subj_user and not user:
        parts.append(f"주체계정: {subj_user}")

    # 4. 파일 정보
    name = str(record.get("name") or fields.get("FileName") or "").strip()
    reasons = record.get("reason")
    if name:
        r_str = f" ({', '.join(reasons)})" if isinstance(reasons, list) and reasons else ""
        parts.append(f"파일: `{name}`{r_str}")

    # 5. 스크립트 블록
    script = str(fields.get("ScriptBlockText") or "").strip()
    if script and not cmdline:
        script_snippet = " ".join(script.split())[:150]
        parts.append(f"스크립트: `{script_snippet}`")

    # 6. 레지스트리 / 일반 경로
    path = str(record.get("path") or canonical.get("subject_path") or "").strip()
    if path and not img and not cmdline:
        parts.append(f"경로: `{path}`")

    # 7. 이벤트 ID 및 플래그 (기타 식별 정보가 부족할 때)
    event_id = record.get("event_id")
    if event_id and not (cmdline or img or dip or script):
        flags = record.get("flags")
        flag_str = f" ({', '.join(flags)})" if isinstance(flags, list) and flags else ""
        parts.append(f"이벤트ID: {event_id}{flag_str}")

    summary = " | ".join(parts)
    return f"{ts_str}{ref} — {summary}" if summary else f"{ts_str}{ref}"


def _evidence_details(refs_list: list[str], records: dict[str, dict[str, Any]] | None) -> list[str]:
    """근거 레코드들의 원본 상세 정보를 추려 돌려준다."""
    if not records:
        return []
    details: list[str] = []
    seen: set[str] = set()
    for ref in refs_list:
        if ref in seen or ref not in records:
            continue
        seen.add(ref)
        line = _record_detail(ref, records[ref])
        if line:
            details.append(line)
    return details


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
    그 구멍은 기능 결손이 아니라 논지의 구멍입니다(docs/limitations-log.md 4-1).

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
            # 으로 적힌 사례가 있었다(docs/limitations.md 3-1).
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
    parser.add_argument(
        "--requests",
        default=None,
        help=(
            "05_requests.json 경로. 05단계가 낸 추가 조사 요청과 그 처리를 "
            "'미확인 사항'에 싣는다. **기각된 요청이 그 절의 요지다** — "
            "모델이 더 보자고 했는데 보지 않은 것이므로"
        ),
    )
    parser.add_argument(
        "--coverage",
        default=None,
        help="05_coverage.json 경로. 생략하면 06_verified.json 옆의 파일을 자동으로 읽는다",
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
    requests_doc = io.read_json(args.requests) if args.requests else None
    coverage_path = (
        Path(args.coverage)
        if args.coverage
        else Path(args.in_path).parent / "05_coverage.json"
    )
    coverage_doc = io.read_json(coverage_path) if coverage_path.is_file() else None

    try:
        schema.validate(verified, "verified")
        schema.validate(findings_doc, "findings")
        schema.validate(selection, "selection")
        if scenario is not None:
            schema.validate(scenario, "scenario")
        if requests_doc is not None:
            schema.validate(requests_doc, "investigation")
        if coverage_doc is not None:
            schema.validate(coverage_doc, "coverage")
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
        # 통째로 사라진다(docs/limitations-log.md 4-1).
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

    context = build_context(
        verified,
        findings_doc,
        selection,
        scenario,
        records,
        manifest,
        requests_doc,
        coverage_doc,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(context), encoding="utf-8", newline="\n")

    print(
        f"{out_path}: 확인된 사실 {len(context['passed'])}건 / "
        f"주의 필요 소견 {len(context['warnings'])}건 / 미확인 범위 {len(context['limits'])}건"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
