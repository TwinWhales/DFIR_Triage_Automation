from src.stage05_interpret.incident_context import enrich


def _event(ref, event_id, ts, guid, **fields):
    return {"ref": ref, "artifact": "evtx:Sysmon", "event_id": event_id,
            "timestamp": ts, "fields": {"ProcessGuid": guid, **fields}}


def test_event_one_and_five_are_paired_and_children_are_explicit():
    records = [
        _event("SYSMON#1", 1, "2026-09-07T06:30:05Z", "{root}"),
        _event("SYSMON#2", 1, "2026-09-07T06:30:05.200Z", "{child}", ParentProcessGuid="{root}"),
        _event("SYSMON#3", 5, "2026-09-07T06:30:05.444739Z", "{root}"),
    ]
    got = enrich(records)
    assert got[0]["incident_context"] == {
        "stop_ref": "SYSMON#3", "lifetime_seconds": 0.444739,
        "child_refs": ["SYSMON#2"], "child_count": 1, "children_within_2s": 1,
    }
    assert got[2]["event_id"] == 5
