from src.stage05_interpret import allocation, attention
from src.stage04_parse import flagging


def _record(ref, command, *, flags=None):
    return {
        "ref": ref,
        "artifact": "evtx:Sysmon",
        "record_num": int(ref.split("#")[1]),
        "offset": "0x0",
        "flags": flags or [],
        "event_id": 1,
        "timestamp": "2026-09-07T06:30:10Z",
        "fields": {"CommandLine": command},
    }


def test_high_value_observations_are_neutral_attention_signals():
    records = attention.apply([
        _record("SYSMON#1", r"netsh wlan export profile key=clear folder=C:\\Temp"),
        _record("SYSMON#2", r"msedge.exe --no-sandbox"),
    ])
    assert records[0]["must_review"] is True
    assert "credential_export_option_observed" in records[0]["attention_signals"]
    assert "key=clear" in records[0]["attention_context"]["credential_export_option_observed"][0]
    assert records[0]["attention_requirements"]["credential_export_option_observed"] == {
        "all": ["netsh", "wlan", "key=clear"]
    }
    assert "browser_sandbox_disabled" in records[1]["attention_signals"]
    assert all("malicious" not in signal for record in records for signal in record["attention_signals"])


def test_generic_fanout_is_context_not_a_global_mandatory_signal():
    record = _record("SYSMON#9", "browser.exe")
    record["incident_context"] = {"children_within_2s": 12}
    assert "rapid_process_fanout_observed" not in attention.signal_ids(record)


def test_must_review_record_survives_a_one_seat_quota():
    ordinary = _record("SYSMON#1", "ordinary.exe", flags=["execution_from_unusual_path"])
    required = attention.apply([_record("SYSMON#2", "netsh wlan export profile key=clear")])[0]
    selected, _, _ = allocation.allocate_records([ordinary, required], limit=1)
    assert any(record["ref"] == "SYSMON#2" for record in selected)


def test_duplicate_signal_family_gets_one_disposition_representative():
    cmd = _record("SYSMON#1", "cmd /c netsh wlan export profile key=clear")
    netsh = _record("SYSMON#2", "netsh wlan export profile key=clear")
    netsh["fields"]["Image"] = r"C:\\Windows\\System32\\netsh.exe"
    got = attention.apply([cmd, netsh])
    assert sum(bool(record.get("must_review")) for record in got) == 1
    assert got[1]["must_review"] is True


def test_t1555_vocabulary_drives_attention_and_prompt_preservation():
    paths = [rf"C:\\Windows\\System32\\{index}.dll" for index in range(30)]
    paths[29] = r"C:\\Users\\test\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\x\\logins.json"
    record = {"ref": "PF#1", "artifact": "prefetch", "fields": {"loaded_files": paths}}

    enriched = attention.apply([record])[0]
    trimmed = allocation.for_prompt(record, 5, flagging.prompt_keep_paths())

    assert enriched["attention_signals"] == ["sensitive_credential_store_referenced"]
    assert paths[29] in enriched["attention_context"]["sensitive_credential_store_referenced"]
    assert "\\logins.json" in enriched["attention_requirements"]["sensitive_credential_store_referenced"]["any"]
    assert paths[29] in trimmed["fields"]["loaded_files"]
