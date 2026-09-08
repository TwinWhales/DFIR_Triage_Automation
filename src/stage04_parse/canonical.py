"""Additive, artifact-neutral fields used by later reasoning stages.

The overlay never replaces parser output.  It only gives downstream code a
stable place to find common concepts such as the subject path and event time.

The network axis (``remote_ip`` / ``remote_port``) exists for the same reason:
the campaign layer correlates nodes on values that cannot be invented, and it
must not have to know which channel names a destination address what.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any


#: 원격 상대의 주소가 실리는 필드 이름. 채널마다 다르게 부른다 —
#: Sysmon EID 3 은 ``DestinationIp``, Security 5156(필터링 플랫폼)은
#: ``DestAddress`` 다. **아티팩트로 좁히지 않는다** — 이름 자체가 충분히
#: 특징적이고, 좁히면 새 채널을 열 때마다 여기를 고쳐야 한다.
_REMOTE_IP_FIELDS = ("DestinationIp", "DestAddress", "DestinationHostname")
_REMOTE_PORT_FIELDS = ("DestinationPort", "DestPort")


def _first(fields: dict[str, Any], names: tuple[str, ...]) -> Any:
    """``names`` 중 값이 있는 첫 필드. 없으면 ``None``."""
    for name in names:
        value = fields.get(name)
        if value not in (None, ""):
            return value
    return None


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
        "remote_ip": _first(fields, _REMOTE_IP_FIELDS),
        "remote_port": _first(fields, _REMOTE_PORT_FIELDS),
    }
    result["canonical"] = {key: value for key, value in values.items() if value not in (None, "")}
    return result


def apply(records: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for record in records:
        yield overlay(record)
