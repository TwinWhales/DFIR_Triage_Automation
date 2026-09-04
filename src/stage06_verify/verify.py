"""06단계 — 근거 검증.

05단계의 해석 문장이 실제 증거에 근거하는지 기계적으로 대조한다.
LLM은 여기에 관여하지 않는다. 판정 주체가 또 LLM이면 순환 논리가 된다.

판정 규칙:

===============================================  ================
조건                                              판정
===============================================  ================
``claims``의 모든 항목이 파싱 결과와 일치          ``passed``
``claims`` 중 하나라도 불일치 또는 참조 없음       ``rejected``
``claims``가 빈 배열                              ``unverifiable``
``refs``가 ``input_refs`` 밖 레코드를 포함         ``rejected``
===============================================  ================

부분 통과를 두지 않는 이유는 하나라도 틀린 문장은 신뢰할 수 없기 때문이다.

``claims``가 비었으면서 동시에 없는 레코드를 참조하는 문장은 **기각이
우선한다.** 종합 판단이라도 지어낸 근거를 달았다면 그것은 환각이다.
스펙의 규칙 표에 두 조건이 함께 걸리는 경우가 명시되어 있지 않아
여기서 정한다.

사용법::

    python -m src.stage06_verify.verify \\
        --findings cases/C-001/05_findings.json \\
        --parsed   cases/C-001/04_parsed/ \\
        --out      cases/C-001/06_verified.json

검증 강도별 실험::

    ... --checkers ref_exists,value_match
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from ..common import errors as errlog
from ..common import io, schema
from ..stage03_select import mapping_loader
from . import checkers, runlog

__all__ = ["verify", "load_records", "judged_rate", "format_rate", "main"]

STAGE = "06_verify"
DEFAULT_TOLERANCE_SECONDS = 1.0

#: ``unverifiable``에 남기는 사유. 보고서가 이 문구로 미검증 항목을 구분한다.
UNVERIFIABLE_REASON = "claims 없음 (종합 판단 문장)"


#: 04단계 산출물 읽기는 05단계와 공유하므로 공용에 있다. 두 단계가
#: 다르게 읽으면 ``input_refs``와 검증 대상이 어긋난다.
DuplicateRefError = io.DuplicateRefError
load_records = io.read_parsed_records


def technique_artifacts(mappings_dir: "str | Path") -> dict[str, frozenset[str]]:
    """기법 → 그 기법의 근거로 매핑에 등재된 아티팩트 이름.

    ``mappings/*/T*.yaml`` 의 ``artifacts:`` 와 ``corroborates:`` 를 합쳐
    뒤집은 표입니다. **둘의 축이 다릅니다** — ``artifacts:`` 는 03단계가
    "어디를 수집할까"로 읽어 좁아야 하고, ``corroborates:`` 는 이 표에만
    더해져 "이 증거로 그 기법을 말할 수 있나"를 넓힙니다. 한 목록을 양쪽에
    쓰면 넓힐 때 04 가 다 읽어야 하고 좁힐 때 06 이 정탐을 기각합니다
    (`work.md` 10번).
    **새 판단 기준을 만드는 것이 아닙니다** — 03단계가 이 표로 선별하고,
    06단계가 같은 표로 "그 증거로 그 기법을 말했는가"를 봅니다.

    **키는 요청 자신의 기법입니다.** ``Mapping.requests`` 에는 그 파일의
    ``artifacts:`` 와 ``followups:`` 가 함께 들어 있는데, ``followups`` 는
    **자기 ``technique`` 을 따로 갖습니다** — "웹셸 다음에 관행적으로 함께
    보는 것"이라 파일은 T1505.003 인데 항목은 T1543.003 입니다. 파일 키로
    묶으면 T1505.003 이 ``evtx:System`` 을 자기 근거로 인정하게 되고,
    그것은 다른 기법의 근거입니다(2026-09-03 에 고쳤습니다).

    **OS 를 가리지 않고 합집합으로 읽습니다.** 05단계 산출물에는 대상 OS 가
    없고(시나리오에 있습니다), 같은 기법 번호라도 OS 마다 근거 아티팩트가
    다릅니다. 합치면 판정이 느슨해지는 쪽인데, 이 자리에서는 그쪽이 안전한
    방향입니다 — 판정할 수 없는 것을 기각하면 환각률이 실제 환각이 아니라
    우리 설정을 셉니다(``benchmark/validator_check.py``).

    **이 표는 "어디를 수집할까"의 목록입니다.** 03단계가 그 뜻으로 쓰고,
    06단계가 뒤집어 "이 기법을 이 증거로 말할 수 있나"로 씁니다. 방향이
    다르므로 **목록에 없다고 근거가 아닌 것은 아닙니다** — 파서가 있는 것만,
    작성자가 생각한 것만 들어 있는 부분집합입니다. 그래서 기각 사유에
    ``also_supports`` 를 함께 실어, 매핑 미비인지 기법 오지정인지 사람이
    가를 수 있게 합니다(``docs/limitations.md``).

    **못 읽으면 빈 표를 냅니다.** 그러면 ``technique_supported`` 가 아무것도
    기각하지 않습니다. 이 단계는 매핑이 없어도 돌아야 하는 결정론적 구간이라,
    표가 없다고 멈추면 04단계 산출물만으로 검증하던 경로가 막힙니다.
    """
    directory = Path(mappings_dir)
    if not directory.is_dir():
        return {}

    try:
        catalog = mapping_loader.load_catalog(directory)
    except (mapping_loader.MappingError, OSError):
        return {}

    table: dict[str, set[str]] = {}
    for os_dir in sorted(p.name for p in directory.iterdir() if p.is_dir()):
        try:
            loaded = mapping_loader.load_all(directory, os_dir, catalog)
        except (mapping_loader.MappingError, OSError):
            continue
        for mapping in loaded.values():
            for request in mapping.requests:
                # 파일의 기법이 아니라 **요청 자신의 기법**으로 묶는다.
                # followups 는 다른 기법의 것이다 — 위 설명 참조.
                table.setdefault(request.technique, set()).add(request.artifact)
            # `corroborates:` 는 03단계가 수집하지 않지만 **근거로는 인정하는**
            # 것이다. 파일 단위 선언이므로 그 파일의 기법으로 묶는다
            # (`followups` 와 달리 자기 technique 을 갖지 않는다).
            if mapping.corroborates:
                table.setdefault(mapping.technique, set()).update(mapping.corroborates)
    return {technique: frozenset(names) for technique, names in table.items()}


def verify(
    findings_doc: dict[str, Any],
    records: dict[str, dict[str, Any]],
    *,
    checker_names: "list[str] | None" = None,
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    supported_artifacts: "dict[str, frozenset[str]] | None" = None,
    generator: str = "verify.py",
) -> dict[str, Any]:
    """판정을 수행하고 ``06_verified.json`` 문서를 만든다.

    파일을 읽지도 쓰지도 않는다. 순수 함수라 목업만으로 완주할 수 있고,
    그것이 이 단계를 04·05보다 먼저 구현할 수 있는 이유다.
    """
    active = checkers.resolve(checker_names)
    ctx = checkers.CheckContext(
        records=records,
        input_refs=frozenset(findings_doc.get("input_refs", [])),
        tolerance_seconds=tolerance_seconds,
        technique_artifacts=supported_artifacts or {},
    )

    passed: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    unverifiable: list[dict[str, Any]] = []

    for finding in findings_doc.get("findings", []):
        rejection = None
        checks = checks_passed = 0

        for _name, run in active:
            result = run(finding, ctx)
            checks += result.checks
            checks_passed += result.checks_passed
            if result.rejection is not None:
                rejection = result.rejection
                break  # 부분 통과가 없으므로 더 볼 이유가 없다

        if rejection is not None:
            rejected.append(
                {"id": finding["id"], "reason": rejection.reason, "detail": rejection.detail}
            )
        elif not finding.get("claims"):
            unverifiable.append({"id": finding["id"], "reason": UNVERIFIABLE_REASON})
        else:
            passed.append(
                {"id": finding["id"], "checks": checks, "checks_passed": checks_passed}
            )

    total = len(passed) + len(rejected) + len(unverifiable)
    judged = len(passed) + len(rejected)
    return io.new_document(
        findings_doc["case_id"],
        STAGE,
        generator,
        tolerance={"timestamp_seconds": _tidy_number(tolerance_seconds)},
        passed=passed,
        rejected=rejected,
        unverifiable=unverifiable,
        stats={
            "total_findings": total,
            "passed": len(passed),
            "rejected": len(rejected),
            "unverifiable": len(unverifiable),
            # unverifiable은 분모에서 뺀다. 검증 대상이 아니었던 문장을
            # 환각으로 셀 수 없다.
            "hallucination_rate": round(len(rejected) / judged, 4) if judged else 0.0,
        },
    )


def judged_rate(stats: dict[str, Any]) -> "float | None":
    """환각률을 **판정 건수가 0이면 ``None``** 으로 돌려준다.

    ``stats["hallucination_rate"]`` 는 판정 대상이 없을 때 ``0.0`` 입니다.
    동결 스키마가 ``number`` 를 요구해 ``null`` 을 실을 수 없기 때문이고,
    그래서 **"아무것도 말하지 않음"과 "전부 맞음"이 같은 숫자로 나옵니다.**

    실측으로 겪은 자리입니다(`docs/limitations.md` 실물 규모 A/B) — 제약을
    끈 쪽이 소견 1건을 `claims` 빈 배열로 내 06 이 `unverifiable` 로 넘겼고,
    분모가 0이라 환각률이 0.0% 로 찍혔습니다. 제약을 켠 쪽의 진짜 0.0%
    (판정 3건 전부 통과)와 표에서 구별되지 않았습니다.

    **수치를 읽는 쪽은 전부 이 함수를 거칩니다.** 파일에 실리는 값은
    스키마 때문에 그대로 두고, 사람이 보는 자리에서만 갈라 냅니다 —
    ``benchmark/evaluate.py`` 의 ``_ratio`` 가 "분모가 0이면 ``None``,
    0.0으로 두면 완벽히 실패로 잘못 읽힌다"고 적어 둔 것과 같은 규약입니다.
    """
    judged = int(stats.get("passed", 0)) + int(stats.get("rejected", 0))
    if not judged:
        return None
    return round(int(stats.get("rejected", 0)) / judged, 4)


def format_rate(stats: dict[str, Any]) -> str:
    """사람이 읽는 한 토막. 판정 0건이면 수치 대신 그 사실을 적는다."""
    rate = judged_rate(stats)
    if rate is None:
        return "환각률 — (판정 0건)"
    return f"환각률 {rate:.1%} (판정 {stats['passed'] + stats['rejected']}건)"


def _tidy_number(value: float) -> float | int:
    """``1.0``을 ``1``로. 결과 파일을 사람이 읽기 좋게 한다."""
    return int(value) if float(value).is_integer() else value


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage06_verify.verify",
        description="05단계 해석 문장을 파싱 결과와 대조해 검증한다.",
    )
    parser.add_argument("--findings", required=True, help="05_findings.json 경로")
    parser.add_argument("--parsed", required=True, help="04_parsed/ 디렉터리")
    parser.add_argument("--out", required=True, help="06_verified.json 출력 경로")
    parser.add_argument(
        "--run-log",
        default=None,
        help=(
            "기각을 덧붙일 대장 경로. 기본은 benchmark/results/rejections.jsonl 이다. "
            "빈 문자열을 주면 기록하지 않는다"
        ),
    )
    parser.add_argument(
        "--checkers",
        default=None,
        help=(
            "쉼표로 구분한 체커 목록. 생략하면 전부 사용. "
            f"사용 가능: {','.join(checkers.DEFAULT_ORDER)}"
        ),
    )
    parser.add_argument(
        "--mappings",
        default="mappings",
        help=(
            "매핑 디렉터리. 기법마다 어느 아티팩트가 근거인지 읽어 "
            "technique_supported 가 쓴다. 기본 %(default)s. "
            "없거나 못 읽으면 그 체커는 아무것도 기각하지 않는다"
        ),
    )
    parser.add_argument(
        "--tolerance-seconds",
        type=float,
        default=DEFAULT_TOLERANCE_SECONDS,
        help="타임스탬프 비교 허용 오차(초). 기본 %(default)s",
    )
    parser.add_argument(
        "--errors",
        default=None,
        help="errors.jsonl 경로. 생략하면 --out과 같은 디렉터리",
    )
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    out_path = Path(args.out)
    log = errlog.ErrorLog(Path(args.errors) if args.errors else out_path.parent / "errors.jsonl")

    checker_names = (
        [name.strip() for name in args.checkers.split(",") if name.strip()]
        if args.checkers
        else None
    )
    try:
        checkers.resolve(checker_names)
    except ValueError as e:
        print(f"[{STAGE}] {e}", file=sys.stderr)
        return 2  # 사용자 입력 오류다. errors.jsonl은 파이프라인 실패만 담는다.

    # 입력 검증
    findings_doc = io.read_json(args.findings)
    try:
        io.check_header(findings_doc, expected_stage="05_interpret")
        schema.validate(findings_doc, "findings")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())
    except io.HeaderError as e:
        log.abort(STAGE, "schema_violation", {"field": "<header>", "message": str(e)})

    try:
        records = load_records(args.parsed)
    except (DuplicateRefError, ValueError, NotADirectoryError) as e:
        log.abort(STAGE, "parse_error", {"message": str(e)})

    if not records:
        log.abort(
            STAGE,
            "empty_result",
            {"message": f"파싱 결과가 비어 있음: {args.parsed}. 04단계를 먼저 실행한다."},
        )

    supported = technique_artifacts(args.mappings)
    if not supported:
        # 조용히 넘어가면 technique_supported 가 아무것도 안 잡는데 통과율만
        # 올라가고, 그것을 성능으로 읽게 된다. 실패는 아니므로 멈추지는
        # 않지만 말은 한다.
        print(
            f"[{STAGE}] 경고: {args.mappings} 에서 기법-아티팩트 표를 읽지 못했습니다. "
            "technique_supported 가 아무것도 기각하지 않습니다.",
            file=sys.stderr,
        )

    verified = verify(
        findings_doc,
        records,
        checker_names=checker_names,
        tolerance_seconds=args.tolerance_seconds,
        supported_artifacts=supported,
    )

    # 출력 검증
    try:
        schema.validate(verified, "verified")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())

    io.write_json(out_path, verified)

    # **입구와 무관하게 남긴다.** 기각 상세는 이 파일에도 있지만 같은
    # case-id 를 다시 돌리면 덮인다. 매핑을 넓힐 근거는 여러 실행에 걸쳐
    # 쌓여야 하므로 덮이지 않는 대장에 덧붙인다(`runlog` 의 설명).
    # 빈 문자열은 "쓰지 않는다"이고 None 은 "기본 자리에 쓴다"이다.
    # `or None` 으로 합치면 끄려던 것이 기본값으로 되살아난다.
    written = 0 if args.run_log == "" else runlog.append_rejections(verified, args.run_log)
    if written:
        print(f"  기각 {written}건을 대장에 덧붙였다 — benchmark/collect.py --rejections")

    stats = verified["stats"]
    print(
        f"{out_path}: passed {stats['passed']} / rejected {stats['rejected']} "
        f"/ unverifiable {stats['unverifiable']} "
        f"({format_rate(stats)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
