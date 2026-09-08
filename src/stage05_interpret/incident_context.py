"""Build deterministic process/lifecycle context without deciding intent."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _fields(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("fields")
    return value if isinstance(value, dict) else {}


def _moment(record: dict[str, Any]) -> datetime | None:
    value = record.get("timestamp")
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def enrich(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach lifecycle and graph facts to Sysmon EID 1 records.

    Event 5 records stay in the stream as independently citable evidence.
    Added values are derived pointers and durations only; no risk label is made.
    """
    result = [dict(record) for record in records]
    starts: dict[str, dict[str, Any]] = {}
    stops: dict[str, dict[str, Any]] = {}
    children: dict[str, list[dict[str, Any]]] = {}

    for record in result:
        if record.get("artifact") != "evtx:Sysmon":
            continue
        fields = _fields(record)
        guid = str(fields.get("ProcessGuid") or "").casefold()
        event_id = int(record.get("event_id") or 0)
        if guid and event_id == 1:
            starts[guid] = record
        elif guid and event_id == 5:
            stops[guid] = record
        parent_guid = str(fields.get("ParentProcessGuid") or "").casefold()
        if parent_guid and event_id == 1:
            children.setdefault(parent_guid, []).append(record)

    for guid, start in starts.items():
        context: dict[str, Any] = {}
        stop = stops.get(guid)
        started, ended = _moment(start), _moment(stop) if stop else None
        if stop:
            context["stop_ref"] = stop.get("ref")
            if started and ended:
                context["lifetime_seconds"] = round((ended - started).total_seconds(), 6)
        direct = sorted(children.get(guid, []), key=lambda item: _moment(item) or datetime.max.replace(tzinfo=started.tzinfo if started else None))
        if direct:
            context["child_refs"] = [item["ref"] for item in direct if item.get("ref")]
            context["child_count"] = len(context["child_refs"])
            if started:
                first_two_seconds = sum(
                    1 for item in direct
                    if _moment(item) is not None and 0 <= (_moment(item) - started).total_seconds() <= 2
                )
                context["children_within_2s"] = first_two_seconds
        if context:
            start["incident_context"] = context
    return result
