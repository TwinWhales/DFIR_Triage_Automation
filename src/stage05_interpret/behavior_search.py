"""이미 파싱된 레코드에서 행위 패턴을 다시 찾아 보장 레인으로 올린다."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from ..common import io
from . import coverage

__all__ = ["SearchResult", "apply_requests", "search"]

MAX_DIRECT_REFS = 30
MAX_PROMOTED_REFS = 60
MAX_DIRECT_PER_ARTIFACT = 12
MAX_DIRECT_PER_SIGNATURE = 3
SCAN_WINDOW_SECONDS = 120.0
SCAN_UNIQUE_ENDPOINTS = 4
CONTEXT_SECONDS = 180.0
LARGE_TRANSFER_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class SearchResult:
    refs: tuple[str, ...]
    patterns: dict[str, int]


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, nested in value.items():
            yield str(key)
            yield from _walk_strings(nested)
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            yield from _walk_strings(nested)
    elif value is not None:
        yield str(value)


def _blob(record: dict[str, Any]) -> str:
    return " ".join(_walk_strings(record)).casefold()


def _field(record: dict[str, Any], *names: str) -> Any:
    canonical = record.get("canonical") or {}
    fields = record.get("fields") or {}
    for name in names:
        if name in canonical and canonical[name] not in (None, ""):
            return canonical[name]
        if name in fields and fields[name] not in (None, ""):
            return fields[name]
    return None


def _moment(record: dict[str, Any]) -> "datetime | None":
    return io.parse_timestamp(record.get("timestamp"))


def _identity(record: dict[str, Any]) -> str:
    guid = _field(record, "process_guid", "ProcessGuid")
    if guid and str(guid) != "-":
        return f"guid:{str(guid).casefold()}"
    image = _field(record, "process_image", "Image", "NewProcessName")
    pid = _field(record, "process_id", "ProcessId", "NewProcessId")
    return f"pid:{str(image).casefold()}:{pid}" if image and pid is not None else ""


def _network_endpoint(record: dict[str, Any]) -> "tuple[str, str] | None":
    remote = _field(record, "remote_ip", "DestinationIp", "DestAddress")
    port = _field(record, "remote_port", "DestinationPort", "DestPort")
    if remote in (None, ""):
        return None
    return str(remote).casefold(), str(port or "?")


def _outbound_bytes(value: Any) -> int:
    """SRUM/네트워크 레코드의 송신량 후보 중 가장 큰 값."""
    largest = 0
    if not isinstance(value, dict):
        return largest
    for key, nested in value.items():
        lowered = str(key).casefold().replace("_", "")
        if isinstance(nested, (int, float)) and not isinstance(nested, bool):
            if ("sent" in lowered or "outbound" in lowered or "upload" in lowered) and (
                "byte" in lowered or "size" in lowered
            ):
                largest = max(largest, int(nested))
        elif isinstance(nested, dict):
            largest = max(largest, _outbound_bytes(nested))
    return largest


def _regex_hits(patterns: Iterable[Any], blob: str) -> list[str]:
    hits: list[str] = []
    for pattern in patterns:
        if re.search(str(pattern), blob, re.IGNORECASE):
            hits.append(str(pattern))
    return hits


def _scan_refs(records: list[dict[str, Any]]) -> tuple[set[str], int]:
    """동일 프로세스가 2분 안에 네 개 이상의 IP/포트에 닿은 구간."""
    groups: dict[str, list[tuple[datetime, tuple[str, str], str]]] = defaultdict(list)
    for record in records:
        ref = record.get("ref")
        identity = _identity(record)
        endpoint = _network_endpoint(record)
        moment = _moment(record)
        if not ref or not identity or endpoint is None or moment is None:
            continue
        groups[identity].append((moment, endpoint, str(ref)))

    refs: set[str] = set()
    bursts = 0
    for observations in groups.values():
        observations.sort(key=lambda item: item[0])
        left = 0
        for right in range(len(observations)):
            while (
                observations[right][0] - observations[left][0]
            ).total_seconds() > SCAN_WINDOW_SECONDS:
                left += 1
            window = observations[left : right + 1]
            if len({item[1] for item in window}) < SCAN_UNIQUE_ENDPOINTS:
                continue
            bursts += 1
            refs.update(item[2] for item in window)
            break  # 한 프로세스의 겹치는 창을 중복으로 세지 않는다.
    return refs, bursts


def _closure(records: list[dict[str, Any]], seeds: set[str]) -> set[str]:
    """seed와 같은 ProcessGuid 및 직접 자식의 짧은 시간 맥락을 더한다."""
    by_ref = {str(record.get("ref")): record for record in records if record.get("ref")}
    seed_records = [by_ref[ref] for ref in seeds if ref in by_ref]
    identities = {_identity(record) for record in seed_records} - {""}
    guids = {
        str(_field(record, "process_guid", "ProcessGuid")).casefold()
        for record in seed_records
        if _field(record, "process_guid", "ProcessGuid")
    }
    moments = [moment for record in seed_records if (moment := _moment(record)) is not None]

    selected = set(seeds)
    for record in records:
        if len(selected) >= MAX_PROMOTED_REFS:
            break
        ref = record.get("ref")
        if not ref:
            continue
        identity = _identity(record)
        parent_guid = _field(record, "parent_process_guid", "ParentProcessGuid")
        related = identity in identities or (
            parent_guid is not None and str(parent_guid).casefold() in guids
        )
        if not related:
            continue
        moment = _moment(record)
        if moments and moment is not None:
            if min(abs((moment - seed).total_seconds()) for seed in moments) > CONTEXT_SECONDS:
                continue
        selected.add(str(ref))
    return selected


def _diverse_direct_refs(
    scored: list[tuple[int, datetime | None, str, tuple[str, ...]]],
    rows: list[dict[str, Any]],
) -> set[str]:
    """동일 채널·일반 신호 반복이 직접 일치 좌석을 독점하지 않게 한다.

    각 키워드·플래그 신호의 최상위 후보를 먼저 한 번씩 고른 뒤 기존
    점수순으로 나머지를 채운다.  따라서 흔한 ``powershell``·``startup``
    레코드가 아티팩트 상한을 먼저 소진해도 드문 ``certutil``이나 파서의
    명시적 위험 플래그가 최소 한 좌석을 얻는다.
    """
    by_ref = {str(row.get("ref")): row for row in rows if row.get("ref")}
    artifact_counts: Counter[str] = Counter()
    signature_counts: Counter[tuple[str, str, str, str]] = Counter()
    selected: set[str] = set()

    def select(item: tuple[int, datetime | None, str, tuple[str, ...]]) -> None:
        _score, _moment_value, ref, _signals = item
        if ref in selected or len(selected) >= MAX_DIRECT_REFS:
            return
        row = by_ref.get(ref, {})
        artifact = str(row.get("artifact") or "")
        signature = (
            artifact,
            str(row.get("event_id") or ""),
            str(_field(row, "process_image", "Image", "NewProcessName") or "").casefold(),
            str(_field(row, "command_line", "CommandLine", "ProcessCommandLine") or "").casefold(),
        )
        if artifact_counts[artifact] >= MAX_DIRECT_PER_ARTIFACT:
            return
        if signature_counts[signature] >= MAX_DIRECT_PER_SIGNATURE:
            return
        selected.add(ref)
        artifact_counts[artifact] += 1
        signature_counts[signature] += 1

    # ``scored``는 이미 높은 점수, 이른 시각 순이다. 각 신호가 처음 만난
    # 레코드가 곧 그 신호의 최상위 대표 후보다.
    representative: dict[str, tuple[int, datetime | None, str, tuple[str, ...]]] = {}
    for item in scored:
        for signal in item[3]:
            representative.setdefault(signal, item)
    for item in representative.values():
        select(item)

    for item in scored:
        select(item)
        if len(selected) >= MAX_DIRECT_REFS:
            break
    return selected


def search(
    records: Iterable[dict[str, Any]],
    category: str,
    *,
    pivots: Iterable[str] = (),
    mappings: "str | Path" = "mappings",
) -> SearchResult:
    """범주 키워드·플래그·피벗과 복합 패턴으로 레코드를 재검색한다."""
    return _search_many(
        list(records), [(category, tuple(pivots))], mappings=mappings
    )[0]


def _search_many(
    rows: list[dict[str, Any]],
    requests: list[tuple[str, tuple[str, ...]]],
    *,
    mappings: "str | Path" = "mappings",
) -> list[SearchResult]:
    """여러 요청을 한 번의 레코드 문자열화로 평가한다.

    실제 케이스는 수십만 건이고 요청은 최대 세 건이다. 요청마다 ``_blob``을
    다시 만들면 같은 JSON 트리를 세 번 걷게 되므로 루프백 시간이 선형으로
    늘어난다. 범주 정규식 평가는 나뉘어도 비싼 레코드 평탄화는 한 번만 한다.
    """
    # request_behavior는 현재 조사 창 안의 재검색이다. 기간 밖을 보려면
    # 별도의 expand_time_range가 먼저 그 레코드를 창 안으로 가져와야 한다.
    rows = [
        row
        for row in rows
        if "outside_time_range" not in {str(flag) for flag in (row.get("flags") or [])}
    ]
    table = coverage.family_table(mappings)
    states: list[dict[str, Any]] = []
    for category, pivots in requests:
        if category not in table:
            raise KeyError(category)
        spec = table[category]
        states.append(
            {
                "category": category,
                "spec": spec,
                "wanted_flags": {str(flag).casefold() for flag in spec.get("flags") or []},
                "pivots": [
                    str(pivot).strip().casefold() for pivot in pivots if str(pivot).strip()
                ],
                "counts": Counter(),
                "scored": [],
            }
        )

    for record in rows:
        ref = record.get("ref")
        if not ref:
            continue
        blob = _blob(record)
        record_flags = {str(flag).casefold() for flag in (record.get("flags") or [])}
        has_network = _network_endpoint(record) is not None
        outbound = _outbound_bytes(record) if has_network else 0
        moment = _moment(record)
        for state in states:
            category = state["category"]
            keyword_hits = _regex_hits(state["spec"].get("keywords") or [], blob)
            flag_hits = state["wanted_flags"] & record_flags
            pivot_hits = [pivot for pivot in state["pivots"] if pivot in blob]
            large_transfer = (
                category == "exfiltration" and outbound >= LARGE_TRANSFER_BYTES
            )
            # 피벗 이름만 등장한 정상 레코드는 올리지 않는다. 다만 횡적 이동은
            # 피벗과 실제 원격 주소가 함께 있으면 그 자체가 재검색할 가치가 있다.
            pivot_network = category == "lateral_movement" and pivot_hits and has_network
            if not (keyword_hits or flag_hits or pivot_network or large_transfer):
                continue
            score = len(keyword_hits) * 3 + len(flag_hits) * 2 + len(pivot_hits)
            for hit in keyword_hits:
                state["counts"][f"keyword:{hit}"] += 1
            for hit in flag_hits:
                state["counts"][f"flag:{hit}"] += 1
            if pivot_network:
                state["counts"]["pivot_network"] += 1
            if large_transfer:
                state["counts"]["large_outbound_transfer"] += 1
                score += 4
            signals = tuple(
                [f"keyword:{hit}" for hit in keyword_hits]
                + [f"flag:{hit}" for hit in sorted(flag_hits)]
                + (["pivot_network"] if pivot_network else [])
                + (["large_outbound_transfer"] if large_transfer else [])
            )
            state["scored"].append((score, moment, str(ref), signals))

    scan_refs: set[str] = set()
    scan_categories = {
        state["category"] for state in states
    } & {"discovery", "lateral_movement"}
    if scan_categories:
        scan_refs, bursts = _scan_refs(rows)
        if bursts:
            for state in states:
                if state["category"] in scan_categories:
                    state["counts"]["multi_port_scan"] = bursts

    results: list[SearchResult] = []
    for state in states:
        # 점수가 높은 것을 먼저, 같으면 이른 것을 먼저 고른다. 최종 전달은
        # allocation이 다시 시간순으로 정렬한다.
        state["scored"].sort(
            key=lambda item: (-item[0], item[1] is None, item[1] or datetime.max, item[2])
        )
        direct = _diverse_direct_refs(state["scored"], rows)
        if state["category"] in scan_categories:
            room = max(0, MAX_PROMOTED_REFS - len(direct))
            direct.update(sorted(scan_refs - direct)[:room])
        refs = _closure(rows, direct) if direct else set()
        results.append(
            SearchResult(tuple(sorted(refs)), dict(sorted(state["counts"].items())))
        )
    return results


def _reject(request: dict[str, Any], reason: str, detail: str) -> None:
    request["disposition"] = {"verdict": "rejected", "reason": reason, "detail": detail}


def apply_requests(
    requests_doc: dict[str, Any],
    ledger: dict[str, Any],
    records: Iterable[dict[str, Any]],
    *,
    input_refs: set[str],
    mappings: "str | Path" = "mappings",
) -> set[str]:
    """``request_behavior``를 검증·실행하고 원장과 disposition을 갱신한다."""
    table = coverage.family_table(mappings)
    claims = {item.get("id"): item for item in ledger.get("scenario_claims", [])}
    promoted: set[str] = set()
    rows = list(records)
    accepted_requests: list[dict[str, Any]] = []

    for request in requests_doc.get("requests", []):
        if request.get("type") != "request_behavior":
            continue
        category = str(request.get("category") or "")
        if category not in table:
            _reject(request, "unknown_behavior", f"알 수 없는 행위 범주: {category}")
            continue

        based_on = request.get("based_on") or {}
        kind = based_on.get("kind")
        if kind == "evidence_ref":
            ref = based_on.get("ref")
            if ref not in input_refs:
                _reject(request, "ungrounded_ref", f"{ref} 는 05단계에 전달한 레코드가 아닙니다.")
                continue
        elif kind == "scenario_claim":
            claim = claims.get(based_on.get("claim_id"))
            if claim is None or category not in claim.get("categories", []):
                _reject(
                    request,
                    "ungrounded_claim",
                    "사용자 원문에서 확인되지 않거나 이 범주를 암시하지 않는 scenario_claim 입니다.",
                )
                continue
        else:
            _reject(request, "ungrounded_claim", "based_on.kind가 올바르지 않습니다.")
            continue

        accepted_requests.append(request)

    results = _search_many(
        rows,
        [
            (str(request["category"]), tuple(str(v) for v in request.get("pivots") or []))
            for request in accepted_requests
        ],
        mappings=mappings,
    ) if accepted_requests else []

    for request, result in zip(accepted_requests, results):
        category = str(request["category"])
        if result.refs:
            reason = f"행위 기반 재검색에서 {len(result.refs)}개 레코드를 발견했습니다."
            request["disposition"] = {
                "verdict": "accepted",
                "reason": "applied",
                "detail": reason,
            }
            promoted.update(result.refs)
        else:
            reason = "행위 기반 재검색을 수행했지만 일치하는 근거를 찾지 못했습니다."
            request["disposition"] = {
                "verdict": "accepted",
                "reason": "searched_no_evidence",
                "detail": reason,
            }
        coverage.apply_search(
            ledger,
            category,
            result.refs,
            reason=reason,
            patterns=result.patterns,
        )
    return promoted
