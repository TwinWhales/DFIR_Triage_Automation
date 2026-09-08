from src.stage06_verify import verify


def _doc(assertion):
    return {
        "case_id": "C-ASSERT", "input_refs": ["AMCACHE#1"],
        "findings": [{"id": "F1", "statement": "path claim", "refs": ["AMCACHE#1"],
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
