"""03단계 — 아티팩트 우선순위 선별.

이 프로젝트의 핵심 뒤집기가 일어나는 자리다. 전수 파싱 후 해석하는 대신,
**무엇을 볼지 먼저 정한다.** 그래서 리스크도 여기 있다. 선별이 실패하면
증거를 아예 놓친다. 재현율을 측정하는 이유다.

LLM은 관여하지 않는다. 매핑 테이블을 참조하는 결정론적 스크립트다.
같은 시나리오에 같은 선별이 나와야 재현율이 모델 성능의 지표가 된다.

산출물의 ``excluded``는 최종 보고서까지 그대로 전달된다. 보지 않기로 한
것과 그 이유를 남기는 것이 선별 방식의 리스크를 "방법론적 결함"에서
"문서화된 판단"으로 바꾼다.

사용법::

    python -m src.stage03_select.select \\
        --in  cases/C-001/02_scenario.json \\
        --out cases/C-001/03_selection.json \\
        --mappings mappings/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from ..common import errors as errlog
from ..common import io, schema
from . import mapping_loader, scope_resolver

__all__ = ["FORCE_PRIORITY", "resolve_force_names", "resolve_force_scopes", "select", "main"]

STAGE = "03_select"

#: 카탈로그에는 있으나 이번 시나리오의 어떤 기법도 요청하지 않은 아티팩트.
NOT_REQUESTED_REASON = "식별된 기법에 매핑된 아티팩트가 아님"

#: 강제 선별된 아티팩트가 받는 조사 비중. **가장 강한 값이다.**
#:
#: 사람이 "이것은 반드시 본다"고 말한 것이라, 매핑이 (기법, 아티팩트) 쌍에
#: 매겨 둔 값보다 앞선다. 05단계가 이 값으로 레코드 자리를 배분한다 —
#: 강제로 선별해 놓고 자리를 안 주면 04단계까지만 일하고 모델에는 한 건도
#: 가지 않는다(`docs/limitations.md` 6-7 과 같은 실패 방식이다).
FORCE_PRIORITY = 1

#: 바탕 선별 항목의 ``rationale`` 머리말. 읽는 사람이 "이건 기법 매핑이
#: 고른 게 아니라 늘 여는 바탕"임을 알 수 있어야 한다.
BASELINE_RATIONALE = "상관분석 바탕"

#: 강제 선별 항목의 ``rationale`` 머리말. 보고서까지 그대로 전달되므로,
#: 읽는 사람이 "이건 기법 매핑이 고른 게 아니라 사람이 지정한 것"임을
#: 알 수 있어야 한다.
FORCE_RATIONALE = "사용자 지정 필수 수집 대상(--force-artifacts)"

#: 묶음 접두어는 편의를 위한 요청이라 하이브 전체를 파는 뜻으로 보지
#: 않는다. 정확한 registry:SOFTWARE 요청은 기존처럼 전체 하이브를 뜻한다.
FORCE_GROUP_SCOPES: dict[str, dict[str, dict[str, list[str]]]] = {
    "registry": {
        "registry:SOFTWARE": {
            "path_prefix": [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            ]
        },
        "registry:SYSTEM": {
            "path_prefix": [
                r"SYSTEM\CurrentControlSet\Services",
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
            ]
        },
        "registry:Amcache": {
            "path_prefix": [
                r"Amcache\Root\InventoryApplicationFile",
                r"Amcache\Root\File",
                r"Amcache\Root\Programs",
            ]
        },
    }
}


def resolve_force_names(
    names: "list[str] | tuple[str, ...]", catalog: mapping_loader.Catalog
) -> list[str]:
    """사용자가 적은 이름을 카탈로그의 아티팩트 이름으로 편다.

    두 가지를 받는다.

    - **정확한 이름** — ``$MFT``, ``prefetch``, ``evtx:Security``.
    - **묶음 접두어** — ``evtx`` 는 ``evtx:*`` 전부, ``registry`` 는
      ``registry:*`` 전부로 편다. 사람이 손으로 채널 열다섯 개를 적게
      만들지 않기 위한 것이다.

    **모르는 이름은 멈춘다.** 조용히 버리면 오타 하나로 강제 선별이 통째로
    사라지는데, 산출물만 봐서는 그것이 오타 때문인지 아티팩트가 원래
    선별될 이유가 없었기 때문인지 구별되지 않는다. 매핑 로더가 카탈로그
    밖 이름을 거부하는 것과 같은 이유다.
    """
    resolved: list[str] = []
    for name in names:
        if name in catalog:
            matched = [name]
        else:
            matched = sorted(n for n in catalog.artifacts if n.startswith(f"{name}:"))
        if not matched:
            known = ", ".join(catalog.artifacts)
            raise mapping_loader.MappingError(
                f"강제 선별할 아티팩트를 카탈로그에서 찾지 못했습니다: {name!r} "
                f"(등록된 값: {known}). 묶음으로 지정하려면 접두어를 쓰십시오 — "
                f"'evtx' 는 evtx:* 전부입니다"
            )
        for artifact in matched:
            if artifact not in resolved:
                resolved.append(artifact)
    return resolved


def resolve_force_scopes(
    names: "list[str] | tuple[str, ...]", catalog: mapping_loader.Catalog
) -> dict[str, dict[str, Any]]:
    """묶음으로 강제한 아티팩트에만 적용할 기본 조사 범위를 돌려준다."""
    scopes: dict[str, dict[str, Any]] = {}
    exact = {name for name in names if name in catalog}
    for name in names:
        if name in exact:
            continue
        for artifact, scope in FORCE_GROUP_SCOPES.get(name, {}).items():
            if artifact in catalog and artifact not in exact:
                scopes[artifact] = scope
    return scopes


def select(
    scenario: dict[str, Any],
    catalog: mapping_loader.Catalog,
    mappings: dict[str, mapping_loader.Mapping],
    *,
    generator: str = "select.py",
    force: "list[str] | tuple[str, ...]" = (),
    force_scopes: "dict[str, dict[str, Any]] | None" = None,
    baseline: "tuple[mapping_loader.BaselineRequest, ...]" = (),
) -> tuple[dict[str, Any], list[str]]:
    """선별을 수행한다. 문서와 "매핑이 없던 기법 목록"을 함께 돌려준다.

    파일을 읽지도 쓰지도 않는다. 매핑 결손 목록을 별도로 내보내는 이유는
    그것이 재현율 저하의 원인을 모델과 매핑 중 어느 쪽으로 돌릴지
    가르는 데이터이기 때문이다.

    ``force`` 는 **기법 매핑과 무관하게 반드시 Tier 1 로 읽을** 아티팩트
    이름이다(`resolve_force_names` 가 편 것). 자세한 것은
    `_force_select` 에 있다.

    ``baseline`` 은 **어느 실행에나 여는 상관분석 바탕**이다
    (`mapping_loader.load_baseline`). ``force`` 와 달리 사람이 그때그때
    지정하는 것이 아니라 늘 걸린다. 파일을 읽지 않는다는 이 함수의 성질을
    지키려고 호출부가 읽어서 넘긴다.
    """
    target_os = scenario["target_os"]
    time_range = scenario["time_range"]

    selected: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    requested: set[str] = set()
    unmapped: list[str] = []
    seen: set[tuple[str, str, int]] = set()
    #: 강제 선별이 Tier 2 를 승격시킬 때 쓴다. 유예 항목은 ``scope`` 를
    #: 갖고 있지 않으므로(스키마), 매핑이 적어 둔 범위를 되살리려면 요청
    #: 객체와 그때의 치환 컨텍스트가 함께 남아 있어야 한다. 같은
    #: 아티팩트를 여러 기법이 유예했으면 **먼저 나온 것**을 쓴다.
    deferred_requests: dict[str, tuple[mapping_loader.ArtifactRequest, dict[str, str]]] = {}

    for technique in scenario["techniques"]:
        mapping = mappings.get(technique["id"])
        if mapping is None:
            unmapped.append(technique["id"])
            continue

        context = scope_resolver.build_context(scenario, mapping.defaults)
        for request in mapping.requests:
            if catalog[request.artifact].unusable_reason(target_os) is not None:
                continue  # excluded에서 사유와 함께 다룬다

            key = (request.technique, request.artifact, request.tier)
            if key in seen:
                continue
            seen.add(key)
            requested.add(request.artifact)

            reason = {"technique": request.technique, "rationale": request.rationale}
            if request.tier == 1:
                selected.append(
                    {
                        "artifact": request.artifact,
                        "tier": 1,
                        # 05단계가 레코드 자리를 배분할 때 쓴다. 매핑에서
                        # 읽은 값을 케이스 산출물에 그대로 실어 두는 이유는
                        # "왜 이 60건입니까"에 답할 근거가 나중에도 남아야
                        # 하기 때문이다. 05단계가 mappings/ 를 다시 읽으면
                        # 그 사이 매핑이 바뀌었을 때 대조가 불가능해진다.
                        "priority": request.priority,
                        "scope": scope_resolver.resolve(
                            request.scope_template, context, time_range
                        ),
                        "reason": reason,
                    }
                )
            else:
                deferred.append(
                    {
                        "artifact": request.artifact,
                        "tier": 2,
                        "trigger": request.trigger,
                        "reason": reason,
                    }
                )
                deferred_requests.setdefault(request.artifact, (request, context))

    _apply_baseline(
        baseline,
        catalog=catalog,
        scenario=scenario,
        target_os=target_os,
        time_range=time_range,
        selected=selected,
        requested=requested,
    )

    _force_select(
        force,
        scenario=scenario,
        catalog=catalog,
        target_os=target_os,
        time_range=time_range,
        selected=selected,
        deferred_requests=deferred_requests,
        requested=requested,
        force_scopes=force_scopes or {},
    )

    # 이미 Tier 1로 읽는 아티팩트를 다시 유예할 이유가 없다. 보고서에
    # "안 봤다"고 적히면 사실과 다르다. **강제 선별 뒤에 거른다** —
    # 승격된 것이 유예 목록에 남으면 07단계가 같은 아티팩트를 "봤다"와
    # "안 봤다" 양쪽에 인쇄한다.
    selected_artifacts = {entry["artifact"] for entry in selected}
    deferred = [entry for entry in deferred if entry["artifact"] not in selected_artifacts]

    excluded = _build_excluded(catalog, target_os, requested)

    return (
        io.new_document(
            scenario["case_id"],
            STAGE,
            generator,
            mapping_table_version=catalog.mapping_table_version,
            selected=selected,
            deferred=deferred,
            excluded=excluded,
            stats={
                "selected_count": len(selected),
                "deferred_count": len(deferred),
                "excluded_count": len(excluded),
            },
        ),
        unmapped,
    )


def _leading_technique(scenario: dict[str, Any]) -> str:
    """강제 선별 항목이 달고 갈 기법 ID.

    **스키마가 요구해서 있는 값이다.** ``selected[].reason.technique`` 는
    ``^T\\d{4}(\\.\\d{3})?$`` 이고 생략할 수 없는데(``selection.schema.json``),
    강제 선별은 정의상 기법이 고른 것이 아니다. 그래서 이번 시나리오에서
    **가장 확신이 높은 기법**을 달고, 사람이 지정했다는 사실은
    ``rationale`` 이 말한다. 07단계가 "선별을 유발한 기법" 목록을 이
    필드에서 뽑으므로(``report._techniques``), 시나리오에 없는 ID를 넣으면
    보고서가 조사하지 않은 기법을 인쇄한다.
    """
    techniques = scenario["techniques"]
    return max(techniques, key=lambda t: float(t.get("confidence", 0.0)))["id"]


def _apply_baseline(
    baseline: "tuple[mapping_loader.BaselineRequest, ...]",
    *,
    catalog: mapping_loader.Catalog,
    scenario: dict[str, Any],
    target_os: str,
    time_range: dict[str, str],
    selected: list[dict[str, Any]],
    requested: set[str],
) -> None:
    """기법과 무관하게 여는 바탕을 선별에 합친다. ``selected`` 를 제자리에서 고친다.

    **덮어쓰지 않고 더한다.** 기법이 이미 그 아티팩트를 요청했으면 그쪽
    ``scope`` 에 ``event_ids`` 를 합집합으로 넣는다 — ``T1041`` 의
    ``[3, 22]`` 는 그 기법에 맞는 판단이고, 우리는 거기에 ``1`` 을 더할
    뿐이다. 기법이 ``event_ids`` 를 안 적었으면 이미 채널 전체가 열린
    것이므로 **손대지 않는다.**

    아무도 요청하지 않았으면 Tier 1 항목을 새로 만든다. 그 자리가 바로
    이 장치가 있는 이유다 — 41개 매핑 중 13개가 ``evtx:Sysmon`` 을 아예
    요청하지 않고, 그중에 ``T1091``(USB)·``T1200``(하드웨어)처럼 키오스크
    조사에서 자주 걸리는 것들이 있다.

    OS 에서 못 읽는 아티팩트는 올리지 않는다 — ``_force_select`` 와 같은
    이유다. 그 자리는 ``excluded`` 가 사유와 함께 받는다.
    """
    if not baseline:
        return

    by_artifact = {entry["artifact"]: entry for entry in selected}
    for request in baseline:
        if request.artifact not in catalog:
            raise mapping_loader.MappingError(
                f"{mapping_loader.BASELINE_FILE}: 카탈로그에 없는 아티팩트 {request.artifact!r}"
            )
        if catalog[request.artifact].unusable_reason(target_os) is not None:
            continue

        requested.add(request.artifact)
        existing = by_artifact.get(request.artifact)
        if existing is not None:
            scope = existing.get("scope") or {}
            current = scope.get("event_ids")
            if current is None:
                continue  # 채널 전체가 이미 열려 있다
            merged = sorted(set(current) | set(request.event_ids))
            if merged != list(current):
                scope["event_ids"] = merged
                existing["reason"]["rationale"] = (
                    f"{existing['reason']['rationale']} (바탕으로 "
                    f"{', '.join(str(v) for v in request.event_ids)} 추가)"
                )
            continue

        entry = {
            "artifact": request.artifact,
            "tier": 1,
            "priority": request.priority,
            "scope": scope_resolver.resolve(
                {"event_ids": list(request.event_ids)} if request.event_ids else {},
                {},
                time_range,
            ),
            "reason": {
                "technique": _leading_technique(scenario),
                "rationale": (
                    f"{BASELINE_RATIONALE} — {request.rationale}. "
                    f"이번 시나리오의 어떤 기법도 요청하지 않았다"
                ),
            },
        }
        selected.append(entry)
        by_artifact[request.artifact] = entry


def _force_select(
    force: "list[str] | tuple[str, ...]",
    *,
    scenario: dict[str, Any],
    catalog: mapping_loader.Catalog,
    target_os: str,
    time_range: dict[str, str],
    selected: list[dict[str, Any]],
    deferred_requests: dict[str, tuple[mapping_loader.ArtifactRequest, dict[str, str]]],
    requested: set[str],
    force_scopes: dict[str, dict[str, Any]],
) -> None:
    """사람이 지정한 아티팩트를 기법 매핑과 무관하게 Tier 1 로 올린다.

    ``selected`` 와 ``requested`` 를 제자리에서 고친다.

    **왜 필요한가.** ``--artifacts`` 는 여태 02단계 프롬프트에 실리는
    힌트일 뿐이었다. 03단계는 그것을 보지 않으므로, 02가 기법 하나를
    잘못 고르면 사람이 "이건 꼭 봐라"고 적어 준 아티팩트가 통째로
    빠졌다. 2026-09-07 `518_Test_0907` 이 그 경우다 — ``prefetch`` 를
    지정했는데 ``T1059.003`` 매핑이 그것을 Tier 2 로 두는 바람에 유예됐고,
    Tier 2 루프백이 없어 영구 미수집이 됐다.

    세 갈래로 갈린다.

    - **이미 Tier 1** — 손대지 않는다. 매핑이 적어 둔 범위와 사유가
      사람이 지정한 것보다 구체적이다.
    - **Tier 2 로 유예됨** — 승격한다. **매핑이 적어 둔 ``scope_template``
      을 그대로 쓴다** — 유예했다고 해서 어디를 볼지에 대한 판단까지
      틀린 것은 아니다.
    - **아무도 요청하지 않음** — 범위 없이 추가한다. 좁힐 근거가 없으므로
      ``time_range`` 만 걸린다. **비싸다** — ``$MFT`` 를 이렇게 넣으면
      볼륨의 모든 파일 레코드가 나온다. 사람이 그러라고 지정한 것이므로
      막지 않되, ``rationale`` 에 그렇게 적어 남긴다.

    OS 에서 못 읽는 아티팩트는 올리지 않는다. 그 자리는 ``excluded`` 가
    사유와 함께 받는다 — 강제로 올려 봐야 04단계가 파서 없이 멈춘다.
    """
    if not force:
        return

    already = {entry["artifact"] for entry in selected}
    for artifact in force:
        if catalog[artifact].unusable_reason(target_os) is not None:
            continue
        requested.add(artifact)
        if artifact in already:
            continue

        promoted = deferred_requests.get(artifact)
        if promoted is not None:
            request, context = promoted
            scope = scope_resolver.resolve(request.scope_template, context, time_range)
            reason = {
                "technique": request.technique,
                "rationale": f"{FORCE_RATIONALE} — Tier 2 승격: {request.rationale}",
            }
        else:
            scope = scope_resolver.resolve(force_scopes.get(artifact, {}), {}, time_range)
            reason = {
                "technique": _leading_technique(scenario),
                "rationale": (
                    f"{FORCE_RATIONALE} — 이번 시나리오의 어떤 기법도 요청하지 않아 "
                    f"범위를 좁힐 근거가 없다. 시간 범위로만 한정한다"
                ),
            }

        selected.append(
            {
                "artifact": artifact,
                "tier": 1,
                "priority": FORCE_PRIORITY,
                "scope": scope,
                "reason": reason,
            }
        )
        already.add(artifact)


def _build_excluded(
    catalog: mapping_loader.Catalog, target_os: str, requested: set[str]
) -> list[dict[str, str]]:
    """읽지 않을 아티팩트와 그 사유. 카탈로그 순서를 따른다.

    아무도 요청하지 않은 것까지 넣는 이유는, 보고서를 읽는 사람이
    "이 도구가 prefetch를 볼 줄 아는데 이번엔 안 봤다"와 "애초에 볼 줄
    모른다"를 구별할 수 있어야 하기 때문이다.
    """
    excluded: list[dict[str, str]] = []
    for name, spec in catalog.artifacts.items():
        reason = spec.unusable_reason(target_os)
        if reason is not None:
            excluded.append({"artifact": name, "reason": reason})
        elif name not in requested:
            excluded.append({"artifact": name, "reason": NOT_REQUESTED_REASON})
    return excluded


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage03_select.select",
        description="시나리오에서 읽을 아티팩트와 범위를 결정한다.",
    )
    parser.add_argument("--in", dest="in_path", required=True, help="02_scenario.json 경로")
    parser.add_argument("--out", required=True, help="03_selection.json 출력 경로")
    parser.add_argument("--mappings", default="mappings", help="매핑 디렉터리. 기본 %(default)s")
    parser.add_argument(
        "--force-artifacts",
        nargs="+",
        default=[],
        metavar="ARTIFACT",
        help=(
            "기법 매핑과 무관하게 Tier 1 로 읽을 아티팩트. Tier 2 로 유예된 것은 "
            "승격하고, 아무도 요청하지 않은 것은 시간 범위만 걸어 추가한다. "
            "묶음 접두어를 받는다 — 'evtx' 는 evtx:* 전부. "
            "예: --force-artifacts '$MFT' '$UsnJrnl' prefetch evtx"
        ),
    )
    parser.add_argument("--errors", default=None, help="errors.jsonl 경로. 생략하면 --out과 같은 디렉터리")
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    out_path = Path(args.out)
    log = errlog.ErrorLog(Path(args.errors) if args.errors else out_path.parent / "errors.jsonl")

    scenario = io.read_json(args.in_path)
    try:
        io.check_header(scenario, expected_stage="02_normalize")
        schema.validate(scenario, "scenario")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())
    except io.HeaderError as e:
        log.abort(STAGE, "schema_violation", {"field": "<header>", "message": str(e)})

    try:
        catalog = mapping_loader.load_catalog(args.mappings)
        mappings = mapping_loader.load_all(args.mappings, scenario["target_os"], catalog)
        forced = resolve_force_names(args.force_artifacts, catalog)
        forced_scopes = resolve_force_scopes(args.force_artifacts, catalog)
        baseline = mapping_loader.load_baseline(args.mappings)
    except mapping_loader.MappingError as e:
        log.abort(STAGE, "schema_violation", {"field": "<mappings>", "message": str(e)})

    try:
        selection, unmapped = select(
            scenario, catalog, mappings,
            force=forced, force_scopes=forced_scopes, baseline=baseline,
        )
    except scope_resolver.UnresolvedVariable as e:
        log.abort(STAGE, "empty_result", {"field": "<scope_template>", "message": str(e)})

    if forced:
        # 무엇이 사람의 지정으로 올라왔는지 화면에 남긴다. 산출물의
        # rationale 에도 있지만, 실행하는 사람이 선별 결과를 열어 보지
        # 않고도 "지정한 넷이 다 올라왔는가"를 확인할 수 있어야 한다.
        landed = {
            entry["artifact"]
            for entry in selection["selected"]
            if entry["reason"]["rationale"].startswith(FORCE_RATIONALE)
        }
        kept = [a for a in forced if a not in landed]
        print(
            f"[{STAGE}] 강제 선별 {len(forced)}건 지정 "
            f"→ 새로 올림 {len(landed)}건"
            + (f" / 이미 Tier 1 이거나 이 OS 에서 못 읽음 {len(kept)}건" if kept else ""),
            file=sys.stderr,
        )

    for technique_id in unmapped:
        # 실패가 아니라 매핑 테이블의 결손이다. 누적된 목록이 어디를
        # 채워야 하는지 알려 준다.
        log.record(
            STAGE,
            "empty_result",
            {
                "field": "techniques[].id",
                "value": technique_id,
                "message": "매핑 테이블 없음, 해당 기법 건너뜀",
            },
            action="skip",
        )
        print(f"[{STAGE}] 매핑 없음: {technique_id}", file=sys.stderr)

    if not selection["selected"]:
        log.abort(
            STAGE,
            "empty_result",
            {
                "message": (
                    "선별된 아티팩트가 없다. 식별된 기법에 매핑이 없거나 "
                    "대상 OS에서 읽을 수 있는 아티팩트가 없다."
                )
            },
        )

    try:
        schema.validate(selection, "selection")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())

    io.write_json(out_path, selection)

    stats = selection["stats"]
    print(
        f"{out_path}: selected {stats['selected_count']} / "
        f"deferred {stats['deferred_count']} / excluded {stats['excluded_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
