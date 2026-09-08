from src.stage04_parse.canonical import overlay


def test_amcache_subject_path_uses_the_semantic_path_not_registry_key_path():
    record = {
        "artifact": "registry:Amcache",
        "path": r"Root\\InventoryApplicationFile\\abc",
        "fields": {"LowerCaseLongPath": r"c:\\program files (x86)\\estsoft\\alzip\\popats.exe"},
    }
    got = overlay(record)
    assert got["path"] == record["path"]
    assert got["canonical"]["subject_path"].endswith(r"alzip\\popats.exe")


def test_sysmon_overlay_preserves_source_and_exposes_common_fields():
    record = {
        "artifact": "evtx:Sysmon",
        "timestamp": "2026-09-07T06:30:05Z",
        "fields": {"Image": r"C:\\Temp\\x.exe", "ParentImage": "explorer.exe", "User": "test"},
    }
    got = overlay(record)
    assert got["fields"] == record["fields"]
    assert got["canonical"] == {
        "subject_path": r"C:\\Temp\\x.exe",
        "event_time": "2026-09-07T06:30:05Z",
        "process_image": r"C:\\Temp\\x.exe",
        "parent_image": "explorer.exe",
        "user": "test",
    }
