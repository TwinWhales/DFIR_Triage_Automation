"""05단계 추가 조사 요청 질의 (`llm_client.propose_investigation`, `investigation.py`).

여기서 지키는 것은 **모델이 지어낼 자리를 만들지 않았는가**다. 요청 가능한
``ref``·기법·아티팩트가 전부 열거형이고, ``pivot_time`` 은 아예 묻지 않는다 —
근거 레코드만 받으면 그 시각은 우리가 안다.

02단계 확장 쪽 시험은 ``tests/test_loopback.py`` 에 있다.
설계는 ``docs/proposals/stage05-investigation-loopback.md``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.common import attack
from src.common import errors as errlog
from src.common import io, llm, schema
from src.stage03_select import mapping_loader
from src.stage05_interpret import investigation
from src.stage05_interpret.llm_client import InterpretClient, investigation_schema
from casepaths import FIXTURES, GOLDEN

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = REPO_ROOT / "mappings"


class _FakeBackend:
    """``tests/test_interpret.py`` 의 것과 같은 규약."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []
        self.formats: list[dict | None] = []
        self.name = "fake"
        self.last_prompt_tokens: int | None = None

    def complete(self, system, user, *, fmt=None):
        self.calls.append((system, user))
        self.formats.append(fmt)
        response = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture(scope="module")
def catalog():
    return mapping_loader.load_catalog(MAPPINGS)


@pytest.fixture
def scenario():
    return io.read_json(FIXTURES / "02_scenario.json")


def _client(*responses):
    return InterpretClient(_FakeBackend(*responses))


def _findings():
    return io.read_json(FIXTURES / "05_findings.json")


def _records():
    return list(io.read_parsed_records(FIXTURES / "04_parsed").values())


def _answer(*requests):
    return json.dumps({"investigation_requests": list(requests)}, ensure_ascii=False)


# ==================================================== 출력 스키마


def test_the_model_is_never_asked_for_a_timestamp():
    """``pivot_time`` 은 출력 스키마에 없다. 근거 레코드에서 우리가 뽑는다.

    ``input_refs`` 를 묻지 않는 것과 같은 이유다 — 모델이 타임스탬프를
    지어낼 토큰 경로를 아예 없앤다.
    """
    built = investigation_schema(["MFT#12345"], ["MFT#12345"], ["T1041"], ["prefetch"])
    branches = built["properties"]["investigation_requests"]["items"]["oneOf"]
    widen = next(b for b in branches if b["properties"]["type"]["const"] == "expand_time_range")
    assert "pivot_time" not in widen["properties"]
    assert widen["properties"]["window_hours"]["maximum"] == 24


def test_only_requestable_things_are_in_the_grammar():
    """열거형이 곧 가드다. 걸러 낼 것이 아니라 나오지 않게 한다."""
    built = investigation_schema(["MFT#1"], ["MFT#1", "MFT#2"], ["T1041"], ["prefetch"])
    branches = built["properties"]["investigation_requests"]["items"]["oneOf"]
    by_kind = {b["properties"]["type"]["const"]: b["properties"] for b in branches}

    assert by_kind["request_technique"]["technique_id"]["enum"] == ["T1041"]
    assert by_kind["request_artifact"]["artifact"]["enum"] == ["prefetch"]
    # 시각을 뽑을 수 있는 레코드만 시간 확장의 근거가 된다.
    assert by_kind["expand_time_range"]["based_on_ref"]["enum"] == ["MFT#1"]
    assert by_kind["request_technique"]["based_on_ref"]["enum"] == ["MFT#1", "MFT#2"]


def test_the_time_branch_disappears_when_no_record_has_a_time():
    """축이 될 레코드가 없으면 그 요청 자체를 낼 수 없어야 한다.

    갈래가 하나만 남으면 ``oneOf`` 로 감싸지 않는다. 항목이 하나인 ``oneOf``
    는 문법에 군더더기이고, 좁은 창에서는 그 군더더기가 곧 레코드다.
    """
    built = investigation_schema([], ["MFT#1"], ["T1041"], [])
    items = built["properties"]["investigation_requests"]["items"]
    assert "oneOf" not in items
    assert items["properties"]["type"]["const"] == "request_technique"


def test_the_cap_matches_the_document_schema():
    """질의의 상한과 문서의 상한이 어긋나면 받은 요청이 통째로 버려진다."""
    built = investigation_schema(["MFT#1"], ["MFT#1"], [], [])
    document = schema.load_schema("investigation")
    assert (
        built["properties"]["investigation_requests"]["maxItems"]
        == document["properties"]["requests"]["maxItems"]
    )


# ==================================================== 축(pivot)


def test_the_pivot_is_the_earliest_activity_of_the_cited_record():
    """``$MFT`` 는 시각을 넷 들고 있다. 범위를 넓히는 축이라 앞선 것을 쓴다."""
    table = investigation.pivots(_records())
    assert table["MFT#12345"] == "2026-07-20T03:14:22Z"
    assert table["EVTX-SEC#40912"] == "2026-07-20T03:22:15Z"


def test_the_client_fills_in_the_pivot_time(scenario):
    client = _client(
        _answer(
            {
                "type": "expand_time_range",
                "based_on_ref": "MFT#12345",
                "rationale": "유입 경로가 기간 밖이다",
                "window_hours": 6,
            }
        )
    )
    requests = client.propose_investigation(
        scenario,
        _findings(),
        pivots={"MFT#12345": "2026-07-20T03:14:22Z"},
        techniques=[("T1041", "Exfiltration Over C2 Channel")],
        artifacts=[],
    )
    assert requests[0]["pivot_time"] == "2026-07-20T03:14:22Z"
    assert requests[0]["window_hours"] == 6


def test_a_time_request_on_a_record_without_a_time_is_malformed(scenario):
    """제약을 켠 실행에서는 문법이 막지만, ``--no-constrain`` 에서는 온다."""
    client = _client(
        _answer(
            {
                "type": "expand_time_range",
                "based_on_ref": "MFT#12346",
                "rationale": "…",
                "window_hours": 2,
            }
        )
    )
    with pytest.raises(llm.MalformedOutput):
        client.propose_investigation(
            scenario, _findings(), pivots={}, techniques=[], artifacts=[]
        )


# ==================================================== 응답 검사


def test_more_requests_than_the_cap_is_malformed_not_truncated(scenario):
    """자르지 않는다.

    상한을 넘겼다는 것은 제약이 안 걸렸다는 뜻이고, 그런 응답의 앞 세 건만
    믿을 근거가 없다.
    """
    one = {
        "type": "request_technique",
        "based_on_ref": "MFT#12345",
        "rationale": "…",
        "technique_id": "T1041",
    }
    client = _client(_answer(one, one, one, one))
    with pytest.raises(llm.MalformedOutput):
        client.propose_investigation(
            scenario, _findings(), pivots={}, techniques=[("T1041", "x")], artifacts=[]
        )


def test_a_request_missing_its_reason_is_malformed(scenario):
    client = _client(
        _answer({"type": "request_artifact", "based_on_ref": "MFT#12345", "artifact": "prefetch"})
    )
    with pytest.raises(llm.MalformedOutput):
        client.propose_investigation(
            scenario, _findings(), pivots={}, techniques=[], artifacts=[("prefetch", "")]
        )


def test_an_unknown_request_kind_is_malformed(scenario):
    client = _client(
        _answer({"type": "run_yara", "based_on_ref": "MFT#12345", "rationale": "…"})
    )
    with pytest.raises(llm.MalformedOutput):
        client.propose_investigation(
            scenario, _findings(), pivots={}, techniques=[], artifacts=[]
        )


# ==================================================== 요청 가능 목록


def test_the_requestable_lists_leave_out_what_we_already_have(scenario, catalog):
    selection = io.read_json(GOLDEN / "03_selection.json")
    techniques = dict(investigation.requestable_techniques(scenario, str(MAPPINGS)))
    artifacts = dict(investigation.requestable_artifacts(scenario, selection, catalog))

    # 이미 식별된 기법과 이미 수집한 아티팩트는 요청 대상이 아니다.
    assert "T1505.003" not in techniques and "T1136.001" not in techniques
    assert "$MFT" not in artifacts and "evtx:Security" not in artifacts
    # 매핑이 없는 기법과 파서가 없는 아티팩트는 애초에 못 고른다.
    # T1499 는 우리 카탈로그 밖의 실재 ATT&CK ID 다 — 2026-09-10 에
    # KNOWN_TECHNIQUES 전부가 매핑을 갖게 되어 예전 예시(T1486)가 사라졌다.
    assert "T1499" not in techniques
    assert "psreadline_history" not in artifacts
    # 열 수 있는 것은 남아 있어야 한다. 비면 질의 자체가 뜻이 없다.
    assert "T1041" in techniques and "prefetch" in artifacts


def test_the_artifact_list_carries_a_description(scenario, catalog):
    """이름만 보내면 모델이 ``srum:NetworkConnectivity`` 가 무엇인지 모른다."""
    artifacts = dict(investigation.requestable_artifacts(scenario, {"selected": []}, catalog))
    assert artifacts["prefetch"]


# ==================================================== 실패해도 1차를 잃지 않는다


def test_a_failed_investigation_query_does_not_lose_the_findings(tmp_path, scenario, catalog):
    """findings 는 이미 나왔다. 여기서 멈추면 멀쩡한 1차 결과를 버린다.

    내러티브 critic 이 실패했을 때와 같은 처리다 — 사유를 남기고 2차 없이 끝낸다.
    """
    log = errlog.ErrorLog(tmp_path / "errors.jsonl")
    document = investigation.collect(
        _client(llm.LLMTimeout("모델이 응답하지 않음")),
        scenario,
        _findings(),
        _records(),
        log,
        selection={"selected": []},
        catalog=catalog,
        mappings_dir=str(MAPPINGS),
    )

    assert document is None
    entries = [
        json.loads(line)
        for line in (tmp_path / "errors.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert entries[-1]["action"] == "skip"
    assert "2차 없이 진행" in entries[-1]["detail"]["message"]


def test_an_empty_request_list_still_produces_a_document(tmp_path, scenario, catalog):
    """물었고 더 볼 것이 없다고 한 것과, 묻지 않은 것은 다르다."""
    log = errlog.ErrorLog(tmp_path / "errors.jsonl")
    document = investigation.collect(
        _client(_answer()),
        scenario,
        _findings(),
        _records(),
        log,
        selection={"selected": []},
        catalog=catalog,
        mappings_dir=str(MAPPINGS),
    )

    assert document is not None
    assert document["requests"] == []
    assert document["round"] == 1
    schema.validate(document, "investigation")


def test_nothing_to_ask_means_no_query_at_all(tmp_path, scenario, catalog):
    """열거형이 전부 비면 무엇을 내든 실패하는 질의를 보내는 셈이다."""
    log = errlog.ErrorLog(tmp_path / "errors.jsonl")
    backend = _FakeBackend(_answer())
    client = InterpretClient(backend)
    everything = {
        "selected": [{"artifact": name} for name in catalog.artifacts],
    }
    full_scenario = {
        **scenario,
        "techniques": [
            {"id": tid, "name": tid, "confidence": 0.5, "evidence_text": ""}
            for tid in attack.mapped_techniques(str(MAPPINGS))
        ],
    }

    document = investigation.collect(
        client,
        full_scenario,
        _findings(),
        [],
        log,
        selection=everything,
        catalog=catalog,
        mappings_dir=str(MAPPINGS),
    )

    assert document is None
    assert backend.calls == []


# ==================================================== CLI 계약


def test_investigate_without_a_selection_stops_before_asking(tmp_path, capsys):
    """요청 목록을 만들려면 이미 수집한 것을 알아야 한다."""
    from src.stage05_interpret import interpret as interpret_mod

    code = interpret_mod.main(
        [
            "--in", str(FIXTURES / "04_parsed"),
            "--scenario", str(FIXTURES / "02_scenario.json"),
            "--out", str(tmp_path / "05_findings.json"),
            "--llm", "stub", "--replay", str(FIXTURES / "05_selection.json"),
            "--investigate",
        ]
    )
    assert code == 2
    assert "--selection 이 필요하다" in capsys.readouterr().err


# ==================================================== 증거에 없는 것은 안 묻는다
#
# 카탈로그와 OS 로는 읽을 수 있지만 **이번 증거에 없는** 아티팩트가 있습니다.
# 요청받아도 04단계가 같은 사유로 다시 건너뛰므로, 모델의 요청 한 자리와
# 2차 재파싱 시간을 함께 버립니다. 실측(K-LOOP-0909-on)에서 이 수집에 없는
# evtx:AssignedAccess 3종과 evtx:DriverFrameworks 가 목록에 올라 있었습니다.


def _manifest(*skipped):
    return {
        "files": [{"artifact": "$MFT", "path": "mft.jsonl", "record_count": 3}],
        "skipped": list(skipped),
    }


def test_what_the_first_round_could_not_find_is_read_from_the_manifest():
    manifest = _manifest(
        {"artifact": "evtx:DriverFrameworks", "reason": "artifact_not_found", "message": "없음"},
        {"artifact": "evtx:BITS", "reason": "empty_artifact", "message": "0바이트"},
    )
    assert investigation.unavailable_artifacts(manifest) == {"evtx:DriverFrameworks"}


def test_no_manifest_filters_nothing():
    """못 찾았다는 사실과 모른다는 것은 다르다. 04를 안 돌렸으면 거르지 않는다."""
    assert investigation.unavailable_artifacts(None) == set()
    assert investigation.unavailable_artifacts({}) == set()


def test_an_artifact_the_evidence_does_not_have_is_not_offered(scenario, catalog):
    manifest = _manifest(
        {"artifact": "evtx:AssignedAccess", "reason": "artifact_not_found", "message": "없음"}
    )
    offered = dict(
        investigation.requestable_artifacts(
            scenario,
            {"selected": []},
            catalog,
            investigation.unavailable_artifacts(manifest),
        )
    )

    assert "evtx:AssignedAccess" not in offered
    # 나머지는 그대로다 — 하나가 없다고 목록이 좁아지면 안 된다.
    assert "prefetch" in offered and "evtx:AssignedAccessAdmin" in offered


def test_collect_passes_the_manifest_through(tmp_path, scenario, catalog):
    """배선이 끊기면 조용히 예전대로 돈다 — 목록에 그대로 오른다."""
    backend = _FakeBackend(_answer())
    client = InterpretClient(backend)
    manifest = _manifest(
        {"artifact": "prefetch", "reason": "artifact_not_found", "message": "없음"}
    )

    investigation.collect(
        client,
        scenario,
        _findings(),
        _records(),
        errlog.ErrorLog(tmp_path / "errors.jsonl"),
        selection={"selected": []},
        catalog=catalog,
        mappings_dir=str(MAPPINGS),
        manifest=manifest,
    )

    _system, user = backend.calls[0]
    assert "prefetch" not in user
    assert "registry:SOFTWARE" in user


def test_pivots_filter_unflagged_noise_while_preserving_signals_and_cited_records():
    """소견에 인용된 레코드나 플래그가 있는 의심 신호만 pivot에 남고, 무플래그 배경 노이즈는 제외된다."""
    records = [
        {"ref": "EVTX-PS#101", "timestamp": "2026-09-10T10:00:00Z", "flags": []},
        {"ref": "EVTX-SEC#202", "timestamp": "2026-09-10T10:05:00Z", "flags": ["account_created"]},
        {"ref": "EVTX-PS#1327", "timestamp": "2026-09-02T04:32:19Z", "flags": []},
    ]
    cited = {"EVTX-PS#101"}
    table = investigation.pivots(records, cited_refs=cited)
    assert "EVTX-PS#101" in table
    assert "EVTX-SEC#202" in table
    assert "EVTX-PS#1327" not in table

