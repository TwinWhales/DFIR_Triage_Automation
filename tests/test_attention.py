from pathlib import Path

from src.common import attention_policy
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


def test_signal_vocabulary_only_looks_at_the_fields_it_declares():
    r"""``match_fields`` 를 안 적으면 레코드의 모든 문자열이 대상이 된다.

    그러면 시각 어휘 `1970-` 가 `C:\photos\1970-summer.jpg` 같은 정상 경로에
    걸려 보장 레인 한 자리를 먹는다(2026-09-08 확인).
    """
    innocent = {
        "ref": "MFT#1", "artifact": "$MFT", "timestamp": "2026-09-08T10:00:00Z",
        "fields": {"TargetFilename": r"C:\photos970-summer.jpg"},
    }
    genuine = {"ref": "MFT#2", "artifact": "$MFT", "timestamp": "1970-01-01T00:00:00Z", "fields": {}}

    assert attention.signal_ids(innocent) == []
    assert attention.signal_ids(genuine) == ["epoch_timestamp_observed"]


def test_representative_priority_is_declared_not_hardcoded():
    """대표 선택 우선순위에 실행 파일 이름을 파이썬에 적지 않는다.

    적으면 그 표본에서만 맞는 값이 코드에 남는다 — `z7hriire.exe` 는 SVCStealer
    가 그 실행에서 만든 무작위 이름이라 다른 어떤 증거에도 존재하지 않는다.
    YAML 에 없는 이름은 어느 것도 가점을 받지 않아야 한다.
    """
    source = (Path(__file__).resolve().parents[1] / "src" / "stage05_interpret" / "attention.py").read_text(encoding="utf-8")
    assert ".exe" not in source

    policy = attention_policy.load()
    declared = {
        name
        for rule in policy.signals for name in rule.representative_images
    } | {
        name for group in policy.path_groups for name in group.representative_images
    }
    assert "netsh.exe" in declared and "z7hriire.exe" not in declared


def test_representative_tie_breaks_on_first_observation_not_ref_text():
    """동점이면 먼저 관측된 것이 대표다.

    ref 문자열로 가르면 사전순이라 `SYSMON#99` 가 `SYSMON#1000` 보다 커져
    선택이 사실과 무관해진다.
    """
    early = _record("SYSMON#1000", "installer.exe /verysilent")
    early["timestamp"] = "2026-09-07T06:30:10Z"
    late = _record("SYSMON#99", "installer.exe /verysilent")
    late["timestamp"] = "2026-09-07T06:31:00Z"

    got = attention.apply([late, early])
    representative = [record["ref"] for record in got if record.get("must_review")]
    assert representative == ["SYSMON#1000"]
