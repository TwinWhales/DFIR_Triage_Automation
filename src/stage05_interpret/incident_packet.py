"""Serialize deterministic process and cross-artifact facts for sLLM reasoning.

Packets contain graph/lifecycle facts and exact identity joins only. They never
assign intent, severity, or maliciousness.
"""

from __future__ import annotations

import re
from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from typing import Any

from ..common.io import normalize_path

MAX_REFS_PER_ARTIFACT = 2
CORROBORATION_ARTIFACTS = frozenset({"evtx:Sysmon", "$MFT", "prefetch", "registry:Amcache"})
_HASH_PREFIX = re.compile(r"^(?:md5|sha1|sha256)\s*[:=]\s*", re.IGNORECASE)
_DIGEST = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")


def _canonical(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("canonical")
    return value if isinstance(value, dict) else {}


def _path_key(record: dict[str, Any]) -> str | None:
    value = _canonical(record).get("subject_path")
    return normalize_path(value) if isinstance(value, str) and value.strip() else None


def _hash_keys(record: dict[str, Any]) -> frozenset[str]:
    value = _canonical(record).get("hashes")
    if value is None:
        return frozenset()
    values = value.values() if isinstance(value, dict) else value if isinstance(value, list) else [value]
    result: set[str] = set()
    for item in values:
        for token in re.split(r"[,;]", str(item)):
            digest = _HASH_PREFIX.sub("", token.strip()).casefold()
            if _DIGEST.fullmatch(digest):
                result.add(digest)
    return frozenset(result)


def _moment(record: dict[str, Any] | None) -> datetime | None:
    value = record.get("timestamp") if record else None
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _representatives(anchor: dict[str, Any], candidates: list[dict[str, Any]]) -> list[str]:
    """Keep deterministic, artifact-diverse refs without flooding the packet."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in candidates:
        if record.get("ref") != anchor.get("ref") and record.get("artifact") != anchor.get("artifact"):
            grouped[str(record.get("artifact") or "")].append(record)
    refs: list[str] = []
    for artifact in sorted(grouped):
        ordered = sorted(grouped[artifact], key=lambda item: (str(item.get("timestamp") or ""), str(item["ref"])))
        refs.extend(str(item["ref"]) for item in ordered[:MAX_REFS_PER_ARTIFACT])
    return refs


def enrich(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach an ``incident_packet`` to observable Sysmon EID 1 anchors."""
    result = [dict(record) for record in records]
    by_ref = {str(record["ref"]): record for record in result if record.get("ref")}
    by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for record in result:
        if record.get("artifact") not in CORROBORATION_ARTIFACTS:
            continue
        path = _path_key(record)
        if path:
            by_path[path].append(record)
        for digest in _hash_keys(record):
            by_hash[digest].append(record)

    for anchor in result:
        if anchor.get("artifact") != "evtx:Sysmon" or int(anchor.get("event_id") or 0) != 1:
            continue
        context = anchor.get("incident_context")
        context = context if isinstance(context, dict) else {}

        process: dict[str, Any] = {"start_ref": anchor["ref"]}
        for source, target in (
            ("stop_ref", "stop_ref"),
            ("lifetime_seconds", "lifetime_seconds"),
            ("child_refs", "child_refs"),
            ("child_count", "direct_children"),
            ("children_within_2s", "children_within_2s"),
        ):
            if source in context:
                process[target] = context[source]

        child_records = [by_ref[ref] for ref in context.get("child_refs", []) if ref in by_ref]
        child_times = [value for value in (_moment(record) for record in child_records) if value is not None]
        burst: dict[str, Any] = {"start": anchor.get("timestamp")}
        if child_times:
            burst["end"] = max(child_times).isoformat().replace("+00:00", "Z")
        if "child_count" in context:
            burst["direct_children"] = context["child_count"]
        if "children_within_2s" in context:
            burst["children_within_2s"] = context["children_within_2s"]

        path = _path_key(anchor)
        same_path_refs = _representatives(anchor, by_path[path]) if path else []
        hash_candidates: dict[str, dict[str, Any]] = {}
        for digest in _hash_keys(anchor):
            for record in by_hash[digest]:
                if record.get("ref") != anchor.get("ref"):
                    hash_candidates[str(record["ref"])] = record
        same_hash_refs = _representatives(anchor, list(hash_candidates.values()))

        if not context and not same_path_refs and not same_hash_refs:
            continue

        corroboration: list[dict[str, Any]] = []
        if same_path_refs:
            corroboration.append({"relation": "same_path", "refs": [anchor["ref"], *same_path_refs]})
        if same_hash_refs:
            corroboration.append({"relation": "same_hash", "refs": [anchor["ref"], *same_hash_refs]})

        packet: dict[str, Any] = {
            "version": 1,
            "anchor": anchor["ref"],
            "process": process,
            "burst": burst,
        }
        if corroboration:
            packet["corroboration"] = corroboration
        if same_path_refs:
            packet["same_path_refs"] = same_path_refs
        if same_hash_refs:
            packet["same_hash_refs"] = same_hash_refs
        anchor["incident_packet"] = packet

    return result


def corroboration_refs(record: dict[str, Any]) -> tuple[str, ...]:
    packet = record.get("incident_packet")
    if not isinstance(packet, dict):
        return ()
    return tuple(dict.fromkeys([
        *packet.get("same_path_refs", []),
        *packet.get("same_hash_refs", []),
    ]))


def relation_catalog(
    records: list[dict[str, Any]], selected_refs: set[str]
) -> list[dict[str, Any]]:
    """Return only deterministic packet relations the Reduce model may cite.

    The model chooses whether a relation matters to the incident narrative; it
    does not manufacture endpoint pairs or predicates.  Every candidate is
    derived from an already-built packet and is rechecked by Stage 06.
    """
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for record in sorted(records, key=lambda item: str(item.get("ref") or "")):
        anchor = str(record.get("ref") or "")
        packet = record.get("incident_packet")
        if anchor not in selected_refs or not isinstance(packet, dict):
            continue

        relations = (
            ("same_path", "incident_packet.same_path_refs", packet.get("same_path_refs", [])),
            ("same_hash", "incident_packet.same_hash_refs", packet.get("same_hash_refs", [])),
        )
        process = packet.get("process") if isinstance(packet.get("process"), dict) else {}
        relations += (("spawned", "incident_packet.process.child_refs", process.get("child_refs", [])),)
        for predicate, field, targets in relations:
            for target in targets if isinstance(targets, list) else []:
                target = str(target)
                key = (predicate, anchor, target)
                if target not in selected_refs or key in seen:
                    continue
                seen.add(key)
                candidates.append({
                    "predicate": predicate,
                    "subject": {"ref": anchor, "field": field},
                    "object": target,
                    "refs": [anchor, target],
                })

    for index, candidate in enumerate(candidates, 1):
        candidate["id"] = f"R{index}"
    return candidates


def restrict(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove packet links to records that were not actually sent to the sLLM."""
    shipped = {str(record.get("ref")) for record in records if record.get("ref")}
    result: list[dict[str, Any]] = []
    for record in records:
        packet = record.get("incident_packet")
        if not isinstance(packet, dict):
            result.append(record)
            continue
        copy = dict(record)
        limited = deepcopy(packet)
        for key in ("same_path_refs", "same_hash_refs"):
            if key in limited:
                limited[key] = [ref for ref in limited[key] if ref in shipped]
                if not limited[key]:
                    limited.pop(key)
        corroboration = []
        for item in limited.get("corroboration", []):
            refs = [ref for ref in item.get("refs", []) if ref in shipped]
            if len(refs) >= 2:
                corroboration.append({**item, "refs": refs})
        if corroboration:
            limited["corroboration"] = corroboration
        else:
            limited.pop("corroboration", None)
        copy["incident_packet"] = limited
        result.append(copy)
    owners: dict[str, str] = {}
    for record in result:
        packet = record.get("incident_packet")
        if not isinstance(packet, dict):
            continue
        owner = str(packet.get("anchor") or record.get("ref"))
        refs = [owner]
        process = packet.get("process") if isinstance(packet.get("process"), dict) else {}
        refs.extend(process.get("child_refs", []))
        if process.get("stop_ref"):
            refs.append(process["stop_ref"])
        refs.extend(packet.get("same_path_refs", []))
        refs.extend(packet.get("same_hash_refs", []))
        for ref in refs:
            if ref in shipped:
                owners.setdefault(str(ref), owner)
    return [{**record, "packet_id": owners[str(record["ref"])]} if str(record.get("ref")) in owners else record for record in result]
