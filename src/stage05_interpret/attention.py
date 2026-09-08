"""Observable attention signals that guarantee sLLM review.

These signals do not classify a record as malicious.  They identify evidence
whose meaning must be dispositioned by the model so allocation cannot silently
discard it.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..common import attention_policy


def _text(record: dict[str, Any]) -> str:
    fields = record.get("fields") if isinstance(record.get("fields"), dict) else {}
    values: list[str] = []
    for value in fields.values():
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(str(item) for item in value if isinstance(item, (str, int, float)))
    values.extend(str(record.get(key) or "") for key in ("path", "name", "timestamp"))
    return "\n".join(values).lower()


def signal_ids(record: dict[str, Any], *, mappings: str | None = None) -> list[str]:
    blob = _text(record)
    signals: list[str] = []
    policy = attention_policy.load(mappings)
    signals.extend(rule.name for rule in policy.signals if rule.must_review and rule.matches(blob))
    for group in policy.path_groups:
        if group.signal and group.must_review and any(token in blob for token in group.contains):
            signals.append(group.signal)
    # Fan-out is retained in incident_context for contextual reasoning, but is
    # not globally promoted to must_review: browsers and service hosts routinely
    # exceed the threshold and would flood the mandatory disposition output.
    return signals


def apply(records: Iterable[dict[str, Any]], *, mappings: str | None = None) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = [dict(record) for record in records]
    policy = attention_policy.load(mappings)
    candidates: dict[str, list[dict[str, Any]]] = {}
    for record in enriched:
        for signal in signal_ids(record, mappings=mappings):
            candidates.setdefault(signal, []).append(record)
            if signal == "sensitive_credential_store_referenced":
                blob = _text(record)
                matches = [
                    token
                    for group in policy.path_groups
                    if group.signal == signal
                    for token in group.contains
                    if token in blob
                ]
                if matches:
                    record.setdefault("attention_evidence", {})[signal] = matches

    def score(signal: str, record: dict[str, Any]) -> tuple[int, str]:
        fields = record.get("fields") if isinstance(record.get("fields"), dict) else {}
        image = str(fields.get("Image") or record.get("name") or "").casefold()
        points = 0
        if signal == "credential_export_option_observed":
            points = 3 if image.endswith("netsh.exe") else 2 if image.endswith("cmd.exe") else 1
        elif signal == "silent_install_option_observed":
            points = 3 if image.endswith("z7hriire.exe") else 1
        elif signal == "sensitive_credential_store_referenced":
            ordered = next(
                (group.contains for group in policy.path_groups if group.signal == signal), ()
            )
            matches = (record.get("attention_evidence") or {}).get(signal, [])
            priority = max((len(ordered) - ordered.index(token) for token in matches), default=0)
            points = priority * 10 + (3 if image == "msedge.exe" else 1)
        return points, str(record.get("ref") or "")

    representatives = {
        signal: max(group, key=lambda record: score(signal, record))
        for signal, group in candidates.items()
    }
    for signal, record in representatives.items():
        record.setdefault("attention_signals", []).append(signal)
        record["must_review"] = True

    # Related duplicates remain ordinary context.  A single disposition covers
    # the observable signal family and keeps a 1,024-token local-model response
    # from being consumed by repeated cmd/conhost/netsh descendants.
    return enriched
