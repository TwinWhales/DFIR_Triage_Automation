"""04단계 — 결정론적 파싱.

선별 결과를 받아 해당 아티팩트의 지정된 범위만 읽는다. LLM은 관여하지
않는다. 소형 모델에 파싱까지 맡기면 환각이 데이터 계층에서 발생해
검증 자체가 불가능해진다.

**현재 상태: 파서 미구현.** 입력 처리(선별 결과 병합, 매니페스트 계약,
``--skip-existing``)는 완성되어 있고 ``parsers/``의 바이트 레벨 구현만
비어 있다. 목업 ``04_parsed/``를 미리 넣어 두고 ``--skip-existing``으로
건너뛰면 나머지 단계를 관통시킬 수 있다.

사용법::

    python -m src.stage04_parse.parse \\
        --in cases/C-001/03_selection.json --out cases/C-001/04_parsed/ \\
        --evidence /mnt/evidence/WEB01 --skip-existing
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from ..common import errors as errlog
from ..common import io, schema

__all__ = ["STAGE", "group_by_artifact", "merge_scopes", "write_manifest", "main"]

STAGE = "04_parse"

#: 아티팩트 이름 → ``04_parsed/`` 안의 파일명.
OUTPUT_FILENAMES: dict[str, str] = {
    "$MFT": "mft.jsonl",
    "$UsnJrnl": "usnjrnl.jsonl",
    "evtx:Security": "evtx_security.jsonl",
    "evtx:System": "evtx_system.jsonl",
}

#: 합집합으로 넓히는 범위 키. 여기 없는 키는 첫 값을 쓴다.
UNION_KEYS = ("path_prefix", "extensions", "event_ids")


def merge_scopes(scopes: list[dict[str, Any]]) -> dict[str, Any]:
    """같은 아티팩트에 대한 여러 scope를 하나로 합친다.

    **좁히지 않고 넓힌다.** 두 기법이 각각 다른 경로를 요구하면 둘 다
    읽어야 한다. 교집합을 취하면 한 기법의 증거를 놓치는데, 그것이
    선별 방식의 가장 큰 리스크다.

    ``time_range``는 가장 이른 시작과 가장 늦은 끝으로 넓힌다.
    """
    merged: dict[str, Any] = {}

    for key in UNION_KEYS:
        values: list[Any] = []
        for scope in scopes:
            values.extend(scope.get(key, []))
        if values:
            merged[key] = list(dict.fromkeys(values))

    starts = [s["time_range"]["start"] for s in scopes if s.get("time_range")]
    ends = [s["time_range"]["end"] for s in scopes if s.get("time_range")]
    if starts and ends:
        # ISO 8601 UTC Z 표기는 문자열 정렬이 곧 시간 정렬이다.
        merged["time_range"] = {"start": min(starts), "end": max(ends)}

    return merged


def group_by_artifact(selection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """``selected``를 아티팩트별로 묶는다.

    같은 아티팩트가 여러 번 나올 수 있다. 03단계가 기법마다 "왜 필요한지"를
    보존하려고 합치지 않기 때문이다. 같은 파일을 두 번 파싱하지 않도록
    여기서 묶는다. ``docs/mapping-guide.md``에 적힌 04단계 계약이다.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in selection.get("selected", []):
        grouped.setdefault(entry["artifact"], []).append(entry.get("scope") or {})
    return {artifact: merge_scopes(scopes) for artifact, scopes in grouped.items()}


def write_manifest(out_dir: Path, case_id: str, files: list[dict[str, Any]]) -> Path:
    """``_manifest.json``을 쓴다.

    ``record_count``는 실제 줄 수와 반드시 같아야 한다. 이 값으로
    "몇 건을 읽었는가"를 보고하고, 테스트가 파일과 대조한다.
    """
    manifest = io.new_document(
        case_id,
        STAGE,
        io.make_generator("parse.py"),
        files=files,
        total_records=sum(entry["record_count"] for entry in files),
        flagged_records=sum(entry["flagged_count"] for entry in files),
    )
    return io.write_json(out_dir / "_manifest.json", manifest)


def _already_parsed(out_dir: Path) -> bool:
    """건너뛸 수 있을 만큼 산출물이 갖춰져 있는가."""
    return (out_dir / "_manifest.json").is_file() and any(out_dir.glob("*.jsonl"))


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage04_parse.parse",
        description="선별된 아티팩트의 지정 범위만 파싱한다.",
    )
    parser.add_argument("--in", dest="in_path", required=True, help="03_selection.json 경로")
    parser.add_argument("--out", required=True, help="04_parsed/ 출력 디렉터리")
    parser.add_argument("--evidence", required=True, help="증거 루트 경로")
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="산출물이 이미 있으면 건너뛴다. 파싱이 가장 오래 걸리므로 실험 반복에 필수",
    )
    parser.add_argument("--errors", default=None)
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    out_dir = Path(args.out)
    log = errlog.ErrorLog(Path(args.errors) if args.errors else out_dir.parent / "errors.jsonl")

    selection = io.read_json(args.in_path)
    try:
        io.check_header(selection, expected_stage="03_select")
        schema.validate(selection, "selection")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())
    except io.HeaderError as e:
        log.abort(STAGE, "schema_violation", {"field": "<header>", "message": str(e)})

    targets = group_by_artifact(selection)

    if args.skip_existing and _already_parsed(out_dir):
        print(
            f"{out_dir}: 이미 산출물이 있어 건너뜀 "
            f"({', '.join(sorted(targets))} 요청됨, --skip-existing)"
        )
        return 0

    unsupported = sorted(set(targets) - set(OUTPUT_FILENAMES))
    if unsupported:
        log.abort(
            STAGE,
            "parse_error",
            {
                "message": (
                    f"출력 파일명이 정의되지 않은 아티팩트: {', '.join(unsupported)}. "
                    "OUTPUT_FILENAMES에 추가한다."
                )
            },
        )

    # 여기부터가 parsers/ 담당 구간이다. 아티팩트별로 targets[artifact]의
    # scope를 넘겨 레코드를 만들고, flagging.py로 flags를 붙인 뒤
    # OUTPUT_FILENAMES[artifact] 에 JSONL로 쓰고 write_manifest를 부른다.
    print(
        f"[{STAGE}] 파서가 아직 구현되지 않았습니다.\n"
        f"  요청된 아티팩트: {', '.join(f'{a} {s}' for a, s in sorted(targets.items()))}\n"
        f"  증거 루트: {args.evidence}\n"
        f"  목업으로 관통 실행하려면 {out_dir} 에 04_parsed 산출물을 넣고\n"
        f"  --skip-existing 을 붙이십시오.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
