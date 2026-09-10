"""행위 범주별 조사 완결성 원장(``05_coverage.json``).

기존 동결 산출물에 필드를 추가하지 않고 별도 사이드카로 상태를 보존한다.
``observed``는 05 소견 또는 행위 재검색이 근거를 찾았다는 뜻이고,
``verified``는 그중 06단계 통과 소견이 있다는 뜻이다. ``not_searched``와
``searched_no_evidence``를 구분하는 것이 이 모듈의 핵심이다.
"""

from __future__ import annotations

import copy
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import yaml

from ..common import io

__all__ = [
    "FAMILY_IDS",
    "STATUS_ORDER",
    "apply_search",
    "apply_verified",
    "build",
    "family_table",
    "promoted_refs",
    "report_rows",
    "requestable_families",
    "scenario_claims",
]

FAMILY_FILE = "_behavior_families.yaml"
FAMILY_IDS = (
    "initial_access",
    "execution",
    "persistence",
    "defense_evasion",
    "discovery",
    "lateral_movement",
    "credential_access",
    "collection",
    "exfiltration",
    "impact",
)

# 큰 값이 더 강한 상태다. searched_no_evidence는 관측보다 약하지만
# not_searched와는 반드시 달라야 보고서가 "보지 않음"과 "봤으나 없음"을
# 구분할 수 있다.
STATUS_ORDER = {
    "unsupported": -1,
    "not_searched": 0,
    "searched_no_evidence": 1,
    "observed": 2,
    "verified": 3,
}


def _family_path(mappings: "str | Path") -> Path:
    return Path(mappings) / FAMILY_FILE


def family_table(mappings: "str | Path" = "mappings") -> dict[str, dict[str, Any]]:
    """범주 설정을 읽고 고정된 열 개가 정확히 한 번씩 있는지 확인한다."""
    path = _family_path(mappings)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = data.get("families")
    if not isinstance(entries, list):
        raise ValueError(f"{path}: families 는 목록이어야 합니다")
    table: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("id"):
            raise ValueError(f"{path}: id 없는 행위 범주가 있습니다")
        family_id = str(entry["id"])
        if family_id in table:
            raise ValueError(f"{path}: 중복 행위 범주 {family_id}")
        table[family_id] = entry
    if tuple(table) != FAMILY_IDS:
        raise ValueError(
            f"{path}: 행위 범주 순서/구성이 다릅니다: {tuple(table)!r} != {FAMILY_IDS!r}"
        )
    return table


def _matches(patterns: Iterable[Any], text: str) -> bool:
    for pattern in patterns:
        try:
            if re.search(str(pattern), text, re.IGNORECASE):
                return True
        except re.error as exc:
            raise ValueError(f"잘못된 행위 검색 정규식 {pattern!r}: {exc}") from exc
    return False


def scenario_claims(
    raw: str,
    *,
    mappings: "str | Path" = "mappings",
) -> list[dict[str, Any]]:
    """사용자 원문에서 조사 근거로 재사용할 수 있는 정확한 구간을 만든다.

    모델이 새 문장을 쓰지 못하게 원문 문장만 보존한다. 한 문장이 여러
    범주를 암시할 수 있으며, 그 관계만 결정론적 키워드로 붙인다.
    """
    if not isinstance(raw, str) or not raw.strip():
        return []
    table = family_table(mappings)
    spans = [part.strip() for part in re.split(r"(?<=[.!?。！？])\s*|\r?\n+", raw) if part.strip()]
    claims: list[dict[str, Any]] = []
    for span in spans:
        categories = [
            family_id
            for family_id, spec in table.items()
            if _matches(spec.get("scenario_terms") or [], span)
        ]
        if categories:
            claims.append(
                {"id": f"SC{len(claims) + 1}", "text": span, "categories": categories}
            )
    return claims


def _technique_families(table: dict[str, dict[str, Any]]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for family_id, spec in table.items():
        for technique in spec.get("techniques") or []:
            result.setdefault(str(technique), set()).add(family_id)
    return result


def _finding_families(
    finding: dict[str, Any], table: dict[str, dict[str, Any]], by_technique: dict[str, set[str]]
) -> set[str]:
    found = set(by_technique.get(str(finding.get("technique") or ""), set()))
    statement = str(finding.get("statement") or "")
    for family_id, spec in table.items():
        if _matches(spec.get("keywords") or [], statement):
            found.add(family_id)
    return found


def _recompute(document: dict[str, Any]) -> None:
    counts = Counter(item["status"] for item in document["categories"])
    gaps = [
        item["id"]
        for item in document["categories"]
        if item["status"] not in {"observed", "verified"}
    ]
    document["summary"] = {
        "counts": {status: counts.get(status, 0) for status in STATUS_ORDER},
        "gaps": gaps,
        "relevant_gaps": [
            item["id"]
            for item in document["categories"]
            if item["relevant"] and item["id"] in gaps
        ],
    }


def _category(document: dict[str, Any], family_id: str) -> dict[str, Any]:
    for item in document.get("categories", []):
        if item.get("id") == family_id:
            return item
    raise KeyError(family_id)


def build(
    scenario: dict[str, Any],
    findings: dict[str, Any],
    *,
    raw: str = "",
    previous: "dict[str, Any] | None" = None,
    mappings: "str | Path" = "mappings",
    generator: str = "coverage.py",
) -> dict[str, Any]:
    """1차 소견 뒤 원장을 만들고 이전 행위 검색 이력을 합친다."""
    table = family_table(mappings)
    claims = scenario_claims(raw, mappings=mappings)
    relevant = {
        family_id for claim in claims for family_id in claim.get("categories", [])
    }
    by_technique = _technique_families(table)
    for technique in scenario.get("techniques", []):
        relevant.update(by_technique.get(str(technique.get("id") or ""), set()))

    categories = [
        {
            "id": family_id,
            "label": str(spec.get("label") or family_id),
            "status": "not_searched",
            "relevant": family_id in relevant,
            "evidence_refs": [],
            "techniques": [],
            "reason": "아직 이 행위 범주를 조사하지 않았습니다.",
        }
        for family_id, spec in table.items()
    ]
    document = io.new_document(
        scenario["case_id"],
        "05_coverage",
        generator,
        categories=categories,
        scenario_claims=claims,
        searches=copy.deepcopy((previous or {}).get("searches") or []),
        summary={},
    )

    # 먼저 재검색 이력을 복원한 뒤 새 findings를 얹는다. 2차 Stage05가
    # 원장을 다시 만들더라도 1차 루프백의 searched_no_evidence가 사라지지 않는다.
    for search in document["searches"]:
        apply_search(
            document,
            str(search["category"]),
            search.get("refs") or [],
            reason=str(search.get("reason") or "행위 기반 재검색"),
            patterns=search.get("patterns") or {},
            record_search=False,
        )

    for finding in findings.get("findings", []):
        families = _finding_families(finding, table, by_technique)
        for family_id in families:
            item = _category(document, family_id)
            refs = sorted(set(item["evidence_refs"]) | set(finding.get("refs") or []))
            techniques = set(item["techniques"])
            if finding.get("technique"):
                techniques.add(str(finding["technique"]))
            item.update(
                status="observed",
                evidence_refs=refs,
                techniques=sorted(techniques),
                reason="05단계 소견에서 관련 행위를 관측했습니다.",
            )
    _recompute(document)
    return document


def apply_search(
    document: dict[str, Any],
    family_id: str,
    refs: Iterable[str],
    *,
    reason: str,
    patterns: "dict[str, int] | None" = None,
    record_search: bool = True,
) -> dict[str, Any]:
    """행위 재검색 결과를 원장에 반영한다."""
    item = _category(document, family_id)
    unique = sorted({str(ref) for ref in refs if ref})
    if unique:
        item["status"] = "observed"
        item["evidence_refs"] = sorted(set(item["evidence_refs"]) | set(unique))
        item["reason"] = reason
        search_status = "observed"
    elif STATUS_ORDER[item["status"]] < STATUS_ORDER["observed"]:
        item["status"] = "searched_no_evidence"
        item["reason"] = reason
        search_status = "searched_no_evidence"
    else:
        search_status = "observed"
    if record_search:
        document.setdefault("searches", []).append(
            {
                "category": family_id,
                "status": search_status,
                "refs": unique,
                "patterns": {str(k): int(v) for k, v in (patterns or {}).items()},
                "reason": reason,
            }
        )
    _recompute(document)
    return document


def apply_verified(
    document: dict[str, Any],
    findings: dict[str, Any],
    verified: dict[str, Any],
    *,
    mappings: "str | Path" = "mappings",
) -> dict[str, Any]:
    """06 통과 finding이 있는 범주만 ``verified``로 승격한다."""
    result = copy.deepcopy(document)
    table = family_table(mappings)
    by_technique = _technique_families(table)
    findings_by_id = {item.get("id"): item for item in findings.get("findings", [])}
    for verdict in verified.get("passed", []):
        finding = findings_by_id.get(verdict.get("id"))
        if not finding:
            continue
        for family_id in _finding_families(finding, table, by_technique):
            item = _category(result, family_id)
            item["status"] = "verified"
            item["evidence_refs"] = sorted(
                set(item["evidence_refs"]) | set(finding.get("refs") or [])
            )
            item["reason"] = "06단계에서 관련 소견의 근거 검증을 통과했습니다."
    result["generated_at"] = io.utc_now()
    _recompute(result)
    return result


def promoted_refs(document: "dict[str, Any] | None") -> set[str]:
    """행위 재검색이 찾은 ref. Stage05 보장 레인 입력으로 사용한다."""
    return {
        str(ref)
        for search in (document or {}).get("searches", [])
        if search.get("status") == "observed"
        for ref in search.get("refs", [])
    }


def requestable_families(document: dict[str, Any]) -> list[tuple[str, str, bool]]:
    """아직 관측/검증되지 않은 범주. 관련 범주를 먼저 돌려준다."""
    rows = [
        (str(item["id"]), str(item["label"]), bool(item["relevant"]))
        for item in document.get("categories", [])
        if item.get("status") == "not_searched"
    ]
    return sorted(rows, key=lambda row: (not row[2], FAMILY_IDS.index(row[0])))


STATUS_LABELS = {
    "not_searched": "⚪ 미조사",
    "searched_no_evidence": "🔵 조사했으나 근거 없음",
    "observed": "🟡 관측",
    "verified": "🟢 검증",
    "unsupported": "⚫ 미지원",
}


def report_rows(document: "dict[str, Any] | None") -> list[dict[str, Any]]:
    """07/08 템플릿이 공통으로 쓰는 표시용 행."""
    return [
        {
            **item,
            "status_label": STATUS_LABELS.get(str(item.get("status")), str(item.get("status"))),
            "relevant_label": "예" if item.get("relevant") else "아니오",
            "refs_label": ", ".join(item.get("evidence_refs") or []) or "-",
        }
        for item in (document or {}).get("categories", [])
    ]

