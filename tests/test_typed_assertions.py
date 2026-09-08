from src.stage06_verify import verify


def _doc(assertion, refs=None):
    refs = refs or ["AMCACHE#1"]
    return {
        "case_id": "C-ASSERT", "input_refs": refs,
        "findings": [{"id": "F1", "statement": "typed claim", "refs": refs,
                      "claims": [], "assertions": [assertion], "technique": None, "severity": "info"}],
    }


def test_outside_program_files_contradiction_is_rejected():
    records = {"AMCACHE#1": {"ref": "AMCACHE#1", "artifact": "registry:Amcache",
                              "canonical": {"subject_path": r"c:\\program files (x86)\\estsoft\\alzip\\popats.exe"}}}
    assertion = {"predicate": "outside_path", "subject": {"ref": "AMCACHE#1", "field": "canonical.subject_path"},
                 "object": r"C:\\Program Files"}
    result = verify.verify(_doc(assertion), records)
    assert result["rejected"][0]["reason"] == "assertion_contradicted"


def test_under_program_files_assertion_passes():
    records = {"AMCACHE#1": {"ref": "AMCACHE#1", "artifact": "registry:Amcache",
                              "canonical": {"subject_path": r"c:\\program files (x86)\\estsoft\\alzip\\popats.exe"}}}
    assertion = {"predicate": "under_path", "subject": {"ref": "AMCACHE#1", "field": "canonical.subject_path"},
                 "object": r"C:\\Program Files"}
    result = verify.verify(_doc(assertion), records)
    assert result["passed"][0]["checks"] == 1


def test_list_contains_verifies_a_sensitive_store_path():
    records = {"AMCACHE#1": {"ref": "AMCACHE#1", "artifact": "prefetch",
                              "fields": {"loaded_files": [r"C:\\Profile\\Login Data"]}}}
    assertion = {"predicate": "list_contains", "subject": {"ref": "AMCACHE#1", "field": "fields.loaded_files"},
                 "object": r"\login data"}
    result = verify.verify(_doc(assertion), records)
    assert result["passed"][0]["checks"] == 1


def test_spawned_verifies_process_guid_edge():
    records = {
        "SYSMON#1": {"ref": "SYSMON#1", "canonical": {"process_guid": "{PARENT}"}},
        "SYSMON#2": {"ref": "SYSMON#2", "canonical": {"parent_process_guid": "{parent}"}},
    }
    assertion = {
        "predicate": "spawned",
        "subject": {"ref": "SYSMON#2", "field": "canonical.parent_process_guid"},
        "object": {"ref": "SYSMON#1", "field": "canonical.process_guid"},
    }
    result = verify.verify(_doc(assertion, list(records)), records)
    assert result["passed"][0]["checks"] == 1


def test_spawned_rejects_a_different_parent_guid():
    records = {
        "SYSMON#1": {"ref": "SYSMON#1", "canonical": {"process_guid": "{PARENT}"}},
        "SYSMON#2": {"ref": "SYSMON#2", "canonical": {"parent_process_guid": "{OTHER}"}},
    }
    assertion = {
        "predicate": "spawned",
        "subject": {"ref": "SYSMON#2", "field": "canonical.parent_process_guid"},
        "object": {"ref": "SYSMON#1", "field": "canonical.process_guid"},
    }
    result = verify.verify(_doc(assertion, list(records)), records)
    assert result["rejected"][0]["reason"] == "assertion_contradicted"


def test_spawned_verifies_incident_packet_child_ref_without_exposing_guid():
    records = {
        "SYSMON#1": {"ref": "SYSMON#1", "incident_context": {"child_refs": ["SYSMON#2"]}},
        "SYSMON#2": {"ref": "SYSMON#2"},
    }
    assertion = {
        "predicate": "spawned",
        "subject": {"ref": "SYSMON#1", "field": "incident_context.child_refs"},
        "object": "SYSMON#2",
    }
    result = verify.verify(_doc(assertion, list(records)), records)
    assert result["passed"][0]["checks"] == 1


def test_same_hash_accepts_algorithm_prefix_and_case_difference():
    digest = "ab" * 32
    records = {
        "MFT#1": {"ref": "MFT#1", "fields": {"hash": f"MD5={'0' * 32},SHA256={digest.upper()}"}},
        "AMCACHE#1": {"ref": "AMCACHE#1", "fields": {"hashes": {"sha256": digest}}},
    }
    assertion = {
        "predicate": "same_hash",
        "subject": {"ref": "MFT#1", "field": "fields.hash"},
        "object": {"ref": "AMCACHE#1", "field": "fields.hashes"},
    }
    result = verify.verify(_doc(assertion, list(records)), records)
    assert result["passed"][0]["checks"] == 1


def test_packet_same_path_ref_is_rechecked_against_original_records():
    records = {
        "SYSMON#1": {
            "ref": "SYSMON#1", "canonical": {"subject_path": r"C:\Temp\x.exe"},
            "incident_packet": {"same_path_refs": ["MFT#1"]},
        },
        "MFT#1": {"ref": "MFT#1", "canonical": {"subject_path": r"c:/temp/X.exe"}},
    }
    assertion = {
        "predicate": "same_path",
        "subject": {"ref": "SYSMON#1", "field": "incident_packet.same_path_refs"},
        "object": "MFT#1",
    }
    result = verify.verify(_doc(assertion, list(records)), records)
    assert result["passed"][0]["checks"] == 1


def test_packet_same_hash_ref_is_rejected_if_raw_hashes_disagree():
    records = {
        "SYSMON#1": {
            "ref": "SYSMON#1", "canonical": {"hashes": "SHA256=" + "a" * 64},
            "incident_packet": {"same_hash_refs": ["AMCACHE#1"]},
        },
        "AMCACHE#1": {"ref": "AMCACHE#1", "canonical": {"hashes": "SHA256=" + "b" * 64}},
    }
    assertion = {
        "predicate": "same_hash",
        "subject": {"ref": "SYSMON#1", "field": "incident_packet.same_hash_refs"},
        "object": "AMCACHE#1",
    }
    result = verify.verify(_doc(assertion, list(records)), records)
    assert result["rejected"][0]["reason"] == "assertion_contradicted"


def test_within_uses_assertion_tolerance():
    records = {
        "SYSMON#1": {"ref": "SYSMON#1", "timestamp": "2026-09-07T06:30:05.776Z"},
        "SYSMON#2": {"ref": "SYSMON#2", "timestamp": "2026-09-07T06:30:06.216Z"},
    }
    assertion = {
        "predicate": "within",
        "subject": {"ref": "SYSMON#1", "field": "timestamp"},
        "object": {"ref": "SYSMON#2", "field": "timestamp"},
        "tolerance_seconds": 0.44,
    }
    result = verify.verify(_doc(assertion, list(records)), records)
    assert result["passed"][0]["checks"] == 1


def test_duration_and_count_compare_numeric_values():
    records = {"SYSMON#1": {"ref": "SYSMON#1", "canonical": {"duration_seconds": 0.44, "direct_children": 7}}}
    doc = _doc({
        "predicate": "duration",
        "subject": {"ref": "SYSMON#1", "field": "canonical.duration_seconds"},
        "object": 0.4,
        "tolerance_seconds": 0.05,
    }, ["SYSMON#1"])
    doc["findings"][0]["assertions"].append({
        "predicate": "count",
        "subject": {"ref": "SYSMON#1", "field": "canonical.direct_children"},
        "object": 7,
    })
    result = verify.verify(doc, records)
    assert result["passed"][0]["checks"] == 2


def test_stage06_invalidates_supported_story_sentence_when_its_finding_is_rejected():
    records = {"AMCACHE#1": {"ref": "AMCACHE#1", "canonical": {"subject_path": r"C:\Program Files\x.exe"}}}
    assertion = {
        "predicate": "outside_path",
        "subject": {"ref": "AMCACHE#1", "field": "canonical.subject_path"},
        "object": r"C:\Program Files",
    }
    doc = _doc(assertion)
    doc["incident_story"] = {
        "summary": "요약", "critical_threat": "미확인",
        "sentences": [{"id": "N1", "text": "외부 경로다", "kind": "observed_fact", "refs": ["AMCACHE#1"]}],
    }
    doc["story_critic"] = [{"sentence_id": "N1", "verdict": "supported", "reason": "경로 근거"}]

    result = verify.verify(doc, records)

    assert result["story_review"][0]["verdict"] == "contradicted"
