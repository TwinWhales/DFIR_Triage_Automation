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

__all__ = ["select", "main"]

STAGE = "03_select"

#: 카탈로그에는 있으나 이번 시나리오의 어떤 기법도 요청하지 않은 아티팩트.
NOT_REQUESTED_REASON = "식별된 기법에 매핑된 아티팩트가 아님"


def select(
    scenario: dict[str, Any],
    catalog: mapping_loader.Catalog,
    mappings: dict[str, mapping_loader.Mapping],
    *,
    generator: str = "select.py",
) -> tuple[dict[str, Any], list[str]]:
    """선별을 수행한다. 문서와 "매핑이 없던 기법 목록"을 함께 돌려준다.

    파일을 읽지도 쓰지도 않는다. 매핑 결손 목록을 별도로 내보내는 이유는
    그것이 재현율 저하의 원인을 모델과 매핑 중 어느 쪽으로 돌릴지
    가르는 데이터이기 때문이다.
    """
    target_os = scenario["target_os"]
    time_range = scenario["time_range"]

    selected: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    requested: set[str] = set()
    unmapped: list[str] = []
    seen: set[tuple[str, str, int]] = set()

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

    # 이미 Tier 1로 읽는 아티팩트를 다시 유예할 이유가 없다. 보고서에
    # "안 봤다"고 적히면 사실과 다르다.
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
    except mapping_loader.MappingError as e:
        log.abort(STAGE, "schema_violation", {"field": "<mappings>", "message": str(e)})

    try:
        selection, unmapped = select(scenario, catalog, mappings)
    except scope_resolver.UnresolvedVariable as e:
        log.abort(STAGE, "empty_result", {"field": "<scope_template>", "message": str(e)})

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
