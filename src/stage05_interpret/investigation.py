"""05단계 — 추가 조사 요청(``05_requests.json``).

1차 해석을 마친 **뒤에** 모델에게 한 번 더 묻는다. "무엇을 더 봐야 하는가."
그 답을 02단계 확장(``stage02_normalize.expand``)이 받아 2차 시나리오를
만들고, 오케스트레이터가 03→04→05 를 다시 돌린다.

**소견 질의에 얹지 않고 따로 묻는 이유**가 있다. 조립 경로의 두 출력 스키마
(``selection_schema``·``connection_schema``)는 토큰 예산이 촘촘히 잡혀 있어,
거기에 필드를 얹으면 그만큼 레코드가 덜 실린다. 이 질의는 원본 레코드를
다시 싣지 않아 작고, ``--mode`` 두 경로가 findings 를 쓴 **뒤** 같은 자리에서
불리므로 경로가 갈라지지 않는다.

**요청할 수 있는 것을 열거형으로 묶는다.** 매핑 없는 기법이나 파서 없는
아티팩트를 요청받아 봐야 02단계 확장이 기각할 뿐이고, 그 왕복은 모델의
자리와 우리의 시간을 함께 쓴다. 걸러 낼 것이 아니라 나오지 않게 한다
(``llm_client.constrained_schema`` 가 ``ref`` 에 대해 내린 것과 같은 판단).

**질의가 실패해도 05단계를 실패시키지 않는다.** findings 는 이미 나왔고
파일로 쓰였다. 요청은 그 위에 얹는 것이라, 못 받으면 사유를 ``errors.jsonl``
에 적고 파일을 만들지 않는다 — 내러티브 critic 이 실패했을 때와 같은 처리다
(``interpret.interpret_assembled``). 그러면 2차가 돌지 않고 1차로 끝난다.

설계는 ``docs/proposals/stage05-investigation-loopback.md``.
"""

from __future__ import annotations

from typing import Any

from ..common import attack, io, llm
from ..common import errors as errlog
from ..stage03_select import mapping_loader
from . import record_filter
from . import coverage as coverage_mod
from .llm_client import InterpretClient

__all__ = [
    "STAGE",
    "DOCUMENT_STAGE",
    "collect",
    "pivots",
    "requestable_artifacts",
    "requestable_techniques",
    "unavailable_artifacts",
    "UNAVAILABLE_SKIP_REASONS",
]

#: ``errors.jsonl`` 에 적을 단계. 이 질의는 05단계의 것이다.
STAGE = "05_interpret"

#: 문서의 ``stage``. ``schemas/investigation.schema.json`` 의 const 다.
DOCUMENT_STAGE = "05_investigate"


def pivots(records: list[dict[str, Any]]) -> dict[str, str]:
    """``ref`` → 그 레코드의 활동 시각. 시각이 없는 레코드는 빠진다.

    **모델에게 ``pivot_time`` 을 묻지 않기 위한 표다.** 어느 레코드를 근거로
    들었는지만 받으면 그 레코드가 언제인지는 우리가 안다 — ``input_refs`` 를
    묻지 않는 것과 같은 이유이고, 타임스탬프를 지어낼 자리가 사라진다.

    ``$MFT`` 처럼 시각을 넷 들고 있는 레코드는 **가장 이른 것**을 쓴다.
    범위를 넓히는 축이므로, 여러 후보 중 앞선 것을 잡아야 그 사이가 덮인다
    (``record_filter.activity_times`` 가 어느 필드를 보는지 정한다).
    """
    table: dict[str, str] = {}
    for record in records:
        ref = record.get("ref")
        if not ref:
            continue
        times = record_filter.activity_times(record)
        if times:
            table[str(ref)] = min(times).strftime("%Y-%m-%dT%H:%M:%SZ")
    return table


def requestable_techniques(
    scenario: dict[str, Any], mappings_dir: str
) -> list[tuple[str, str]]:
    """추가로 요청할 수 있는 기법. ``(ID, 이름)``.

    **매핑 YAML 이 있는 것만**이다. 없으면 03단계가 아무 아티팩트도 고르지
    못해 2차가 헛돈다. 이미 시나리오에 있는 기법도 뺀다 — 다시 요청해 봐야
    ``already_selected`` 로 기각된다.
    """
    identified = {t.get("id") for t in scenario.get("techniques", [])}
    return [
        (technique_id, attack.name_of(technique_id) or technique_id)
        for technique_id in sorted(attack.mapped_techniques(mappings_dir))
        if technique_id not in identified
    ]


#: 1차 04단계가 남긴 스킵 사유 중 **이 증거에는 없다**는 뜻인 것.
#:
#: 그런 아티팩트를 2차에 요청해 봐야 04단계가 같은 자리에서 같은 사유로
#: 다시 건너뛴다. 모델의 요청 한 자리와 2차 재파싱 시간을 함께 버리는 것이라
#: 목록에서 미리 뺀다 — ``psreadline_history`` 를 파서가 없다고 빼는 것과
#: 같은 판단이고, 다른 점은 **이번 증거에 한정된 사실**이라는 것뿐이다.
#:
#: 나머지 사유는 넣지 않았다. ``parser_missing`` 은 카탈로그의 ``supported``
#: 가 이미 거르고, ``empty_artifact``(0바이트)와 ``version_not_applicable``
#: (이 Windows 버전엔 없다)은 같은 부류로 보이지만 아직 실측으로 확인한
#: 자리가 아니다. 넓히려면 그때 여기 한 줄을 더한다.
UNAVAILABLE_SKIP_REASONS = frozenset({"artifact_not_found"})


def unavailable_artifacts(manifest: "dict[str, Any] | None") -> set[str]:
    """1차가 **증거에서 찾지 못한** 아티팩트 이름.

    04단계 매니페스트의 ``skipped`` 를 읽는다. 그 목록은 이 단계가 "안 한
    일"을 적는 곳이므로(``stage04_parse.parse.note_skip``), 무엇이 없었는지를
    아는 유일한 산출물이다.
    """
    return {
        str(entry["artifact"])
        for entry in (manifest or {}).get("skipped") or []
        if entry.get("artifact") and entry.get("reason") in UNAVAILABLE_SKIP_REASONS
    }


def requestable_artifacts(
    scenario: dict[str, Any],
    selection: dict[str, Any],
    catalog: mapping_loader.Catalog,
    unavailable: "set[str] | None" = None,
) -> list[tuple[str, str]]:
    """추가로 수집할 수 있는 아티팩트. ``(이름, 설명)``.

    **파서가 있고 이 OS 에서 읽을 수 있는 것만**이다(``unusable_reason``).
    ``psreadline_history`` 처럼 ``parser: null`` 인 것을 목록에 넣으면 모델이
    요청은 하는데 03단계 ``_force_select`` 가 올리지 않아, 2차가 아무것도 못
    가져오면서 재파싱 시간만 쓴다.

    설명을 함께 보내는 이유는 이름만으로는 ``srum:NetworkConnectivity`` 가
    무엇인지 모델이 알 수 없기 때문이다. 열거형은 무엇을 낼 수 있는지만
    정하고, 무엇을 골라야 하는지는 이 설명이 말한다.

    ``unavailable`` 은 1차가 **증거에서 찾지 못한** 이름이다
    (``unavailable_artifacts``). 카탈로그와 OS 로는 읽을 수 있는 아티팩트지만
    이번 증거에 없으므로, 요청받아도 04단계가 같은 사유로 다시 건너뛴다.
    실측에서 이 수집에 없는 ``evtx:AssignedAccess`` 3종과
    ``evtx:DriverFrameworks`` 가 목록에 올라 있었다(`K-LOOP-0909-on`).
    """
    target_os = scenario.get("target_os", "windows")
    already = {entry["artifact"] for entry in selection.get("selected", [])}
    missing = unavailable or set()
    return [
        (name, spec.description or "")
        for name, spec in sorted(catalog.artifacts.items())
        if name not in already
        and name not in missing
        and spec.unusable_reason(target_os) is None
    ]


def collect(
    client: InterpretClient,
    scenario: dict[str, Any],
    findings: dict[str, Any],
    records: list[dict[str, Any]],
    log: errlog.ErrorLog,
    *,
    selection: dict[str, Any],
    catalog: mapping_loader.Catalog,
    mappings_dir: str,
    manifest: "dict[str, Any] | None" = None,
    coverage_doc: "dict[str, Any] | None" = None,
    queries: Any = None,
) -> "dict[str, Any] | None":
    """모델에게 묻고 ``05_requests.json`` 문서를 만든다.

    물어볼 것이 하나도 없거나(요청 가능한 기법·아티팩트가 없고 시각을 가진
    레코드도 없다) 질의가 실패하면 ``None``. 요청이 **0건이어도 문서는
    만든다** — "물었고 더 볼 것이 없다고 했다"는 것과 "묻지 않았다"는 다르고,
    그 차이가 2차를 안 돌린 이유가 된다.
    """
    table = pivots(records)
    techniques = requestable_techniques(scenario, mappings_dir)
    artifacts = requestable_artifacts(
        scenario, selection, catalog, unavailable_artifacts(manifest)
    )
    behaviors = (
        coverage_mod.requestable_families(coverage_doc) if coverage_doc is not None else []
    )
    claims = list((coverage_doc or {}).get("scenario_claims") or [])

    if not (table or techniques or artifacts or behaviors):
        # 열거형이 전부 비면 모델이 낼 수 있는 요청이 없다. 빈 enum 을 주고
        # 묻는 것은 무엇을 내든 실패하는 질의를 보내는 것이다.
        log.record(
            STAGE,
            "empty_result",
            {
                "field": "investigation_requests",
                "message": (
                    "요청할 수 있는 것이 없어 조사 요청 질의를 보내지 않았습니다 "
                    "(추가 기법·아티팩트·행위 범주 없음, 시각을 가진 레코드 없음)."
                ),
            },
            action="skip",
        )
        return None

    try:
        requests = client.propose_investigation(
            scenario,
            findings,
            pivots=table,
            techniques=techniques,
            artifacts=artifacts,
            behaviors=behaviors,
            claims=claims,
        )
    except (llm.LLMError, llm.MalformedOutput) as e:
        # **실패한 질의도 남긴다.** 무엇을 물었길래 이렇게 답했는지가
        # 없으면 프롬프트를 고칠 근거가 없다(``QueryLog`` 의 요지).
        if queries is not None:
            queries.record(client, "investigation", note=f"실패: {e}")
        # findings 는 이미 나왔다. 여기서 멈추면 멀쩡한 1차 결과를 버리는
        # 것이므로, 사유를 남기고 2차 없이 끝낸다(critic 실패와 같은 처리).
        log.record(
            STAGE,
            "malformed_output" if isinstance(e, llm.MalformedOutput) else "llm_error",
            {"message": f"추가 조사 요청 질의 실패, 2차 없이 진행: {e}"},
            action="skip",
        )
        return None

    if queries is not None:
        queries.record(client, "investigation", note=f"요청 {len(requests)}건")

    return io.new_document(
        findings["case_id"],
        DOCUMENT_STAGE,
        findings["generator"],
        # **1 뿐이다.** 2차 05 실행에는 --investigate 를 주지 않으므로 3차
        # 요청이 생길 자리가 없다(가드레일 G1). 스키마도 const 로 못 박는다.
        round=1,
        requests=requests,
    )
