from src.stage05_interpret.incident_packet import enrich, relation_catalog, restrict


SHA256 = "ab" * 32


def _record(ref, artifact, path, *, hashes=None, **extra):
    canonical = {"subject_path": path}
    if hashes is not None:
        canonical["hashes"] = hashes
    return {"ref": ref, "artifact": artifact, "canonical": canonical, **extra}


def test_packet_serializes_lifecycle_burst_and_cross_artifact_joins():
    records = [
        _record(
            "SYSMON#1", "evtx:Sysmon", r"C:\Temp\drop.exe", hashes=f"SHA256={SHA256.upper()}",
            event_id=1, timestamp="2026-09-07T06:30:05.776Z",
            incident_context={
                "stop_ref": "SYSMON#3", "lifetime_seconds": 0.44,
                "child_refs": ["SYSMON#2"], "child_count": 1, "children_within_2s": 1,
            },
        ),
        _record("SYSMON#2", "evtx:Sysmon", r"C:\Windows\cmd.exe", event_id=1, timestamp="2026-09-07T06:30:05.900Z"),
        _record("SYSMON#3", "evtx:Sysmon", r"C:\Temp\drop.exe", event_id=5, timestamp="2026-09-07T06:30:06.216Z"),
        _record("MFT#10", "$MFT", r"c:/temp/DROP.exe", hashes=SHA256),
        _record("PF#20", "prefetch", r"C:\TEMP\drop.exe"),
        _record("AMCACHE#30", "registry:Amcache", r"C:\Temp\drop.exe", hashes={"sha256": SHA256}),
    ]

    packet = enrich(records)[0]["incident_packet"]

    assert packet["anchor"] == "SYSMON#1"
    assert packet["process"] == {
        "start_ref": "SYSMON#1", "stop_ref": "SYSMON#3", "lifetime_seconds": 0.44,
        "child_refs": ["SYSMON#2"], "direct_children": 1, "children_within_2s": 1,
    }
    assert packet["burst"]["end"] == "2026-09-07T06:30:05.900000Z"
    assert packet["same_path_refs"] == ["MFT#10", "PF#20", "AMCACHE#30"]
    assert packet["same_hash_refs"] == ["MFT#10", "AMCACHE#30"]
    assert [item["relation"] for item in packet["corroboration"]] == ["same_path", "same_hash"]


def test_same_artifact_repetition_is_not_cross_artifact_corroboration():
    records = [
        _record("SYSMON#1", "evtx:Sysmon", r"C:\Windows\cmd.exe", event_id=1, incident_context={"child_count": 1}),
        _record("SYSMON#2", "evtx:Sysmon", r"C:\Windows\cmd.exe", event_id=1),
    ]
    packet = enrich(records)[0]["incident_packet"]
    assert "corroboration" not in packet


def test_process_without_lifecycle_or_graph_context_gets_no_packet():
    record = _record("SYSMON#1", "evtx:Sysmon", r"C:\Windows\cmd.exe", event_id=1)
    assert "incident_packet" not in enrich([record])[0]


def test_restrict_removes_dangling_corroboration_refs():
    anchor = _record(
        "SYSMON#1", "evtx:Sysmon", r"C:\Temp\x.exe", event_id=1,
        incident_context={"child_count": 1},
    )
    mft = _record("MFT#1", "$MFT", r"C:\Temp\x.exe")
    prefetch = _record("PF#1", "prefetch", r"C:\Temp\x.exe")
    packetized = enrich([anchor, mft, prefetch])

    limited = restrict([packetized[0], packetized[1]])[0]["incident_packet"]

    assert limited["same_path_refs"] == ["MFT#1"]
    assert limited["corroboration"] == [
        {"relation": "same_path", "refs": ["SYSMON#1", "MFT#1"]}
    ]


def test_relation_catalog_exposes_only_precomputed_selected_packet_edges():
    records = restrict(enrich([
        _record(
            "SYSMON#1", "evtx:Sysmon", r"C:\Temp\x.exe", event_id=1,
            incident_context={"child_refs": ["SYSMON#2"], "child_count": 1},
        ),
        _record("SYSMON#2", "evtx:Sysmon", r"C:\Temp\child.exe", event_id=1),
        _record("MFT#1", "$MFT", r"C:\Temp\x.exe"),
    ]))

    catalog = relation_catalog(records, {"SYSMON#1", "SYSMON#2", "MFT#1"})

    assert [(item["id"], item["predicate"], item["object"]) for item in catalog] == [
        ("R1", "same_path", "MFT#1"),
        ("R2", "spawned", "SYSMON#2"),
    ]
    assert catalog[0]["subject"]["field"] == "incident_packet.same_path_refs"
    assert catalog[1]["subject"]["field"] == "incident_packet.process.child_refs"
