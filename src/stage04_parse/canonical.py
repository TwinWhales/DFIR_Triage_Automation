"""Additive, artifact-neutral fields used by later reasoning stages.

The overlay never replaces parser output.  It only gives downstream code a
stable place to find common concepts such as the subject path and event time.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any


def overlay(record: dict[str, Any]) -> dict[str, Any]:
    result = dict(record)
    fields = record.get("fields") if isinstance(record.get("fields"), dict) else {}
    artifact = str(record.get("artifact") or "")

    subject_path: Any = None
    if artifact == "registry:Amcache":
        subject_path = fields.get("LowerCaseLongPath") or fields.get("FullPath")
    elif artifact == "evtx:Sysmon":
        subject_path = fields.get("Image")
    else:
        subject_path = record.get("path") or fields.get("Path")

    values = {
        "subject_path": subject_path,
        "event_time": record.get("timestamp"),
        "process_image": fields.get("Image") if artifact == "evtx:Sysmon" else None,
        "parent_image": fields.get("ParentImage") if artifact == "evtx:Sysmon" else None,
        "command_line": fields.get("CommandLine") if artifact == "evtx:Sysmon" else None,
        "hashes": fields.get("Hashes") or record.get("hashes"),
        "user": fields.get("User") or record.get("user"),
    }
    result["canonical"] = {key: value for key, value in values.items() if value not in (None, "")}
    return result


def apply(records: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for record in records:
        yield overlay(record)
