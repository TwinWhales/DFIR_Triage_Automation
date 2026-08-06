"""신규 케이스 디렉터리를 만든다.

``cases/<case_id>/01_input.json``을 쓰고, 필요하면 파싱 산출물을 미리
넣어 둔다. 04단계 파서가 구현되기 전까지 나머지 단계를 관통시키려면
``--seed-parsed``가 필요하다.

사용법::

    # 자연어 입력으로 새 케이스
    python tools/make_case.py --case-id C-003 --evidence /mnt/evidence/WEB03 \\
        --raw "웹서버에서 이상한 파일이 발견됐습니다"

    # 벤치마크 데이터셋에서 (파싱 산출물까지 채움)
    python tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01 \\
        --input     benchmark/datasets/C-001-webshell/input.json \\
        --seed-parsed benchmark/datasets/C-001-webshell/mock/04_parsed
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import io, schema  # noqa: E402


def build_input(case_id: str, raw: str, evidence: str, os_hint: str) -> dict:
    """자연어 입력으로 ``01_input.json`` 본문을 만든다."""
    return {
        "case_id": case_id,
        "stage": "01_input",
        "schema_version": io.SCHEMA_VERSION,
        "generated_at": io.utc_now(),
        "source_type": "natural_language",
        "raw": raw,
        "evidence": {
            "root": evidence,
            "os_hint": os_hint,
            "artifacts_available": ["$MFT", "$UsnJrnl", "evtx"],
        },
    }


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/make_case.py", description="신규 케이스 디렉터리를 만든다."
    )
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--evidence", required=True, help="증거 루트 경로")
    parser.add_argument("--cases-dir", default="cases", help="기본 %(default)s")
    parser.add_argument("--raw", default=None, help="자연어 서술")
    parser.add_argument("--input", default=None, help="기존 01_input.json을 복사")
    parser.add_argument("--os-hint", default="windows_server_2019")
    parser.add_argument(
        "--seed-parsed",
        default=None,
        help="04_parsed/ 를 미리 채운다. 파서 구현 전 관통 실행용",
    )
    parser.add_argument("--force", action="store_true", help="기존 01_input.json을 덮어쓴다")
    args = parser.parse_args(argv)
    io.configure_console()

    if bool(args.raw) == bool(args.input):
        parser.error("--raw 또는 --input 중 하나만 지정하십시오")

    case_dir = Path(args.cases_dir) / args.case_id
    input_path = case_dir / "01_input.json"

    if input_path.exists() and not args.force:
        # 01_input은 재실행 시 진입점이므로 절대 덮어쓰지 않는 것이 방침이다.
        print(f"이미 존재합니다: {input_path} (덮어쓰려면 --force)", file=sys.stderr)
        return 1

    if args.input:
        document = io.read_json(args.input)
        document["case_id"] = args.case_id
        document.setdefault("evidence", {})["root"] = args.evidence
    else:
        document = build_input(args.case_id, args.raw, args.evidence, args.os_hint)

    try:
        schema.validate(document, "input")
    except schema.SchemaViolation as violation:
        print(f"입력이 스키마를 만족하지 않습니다 — {violation}", file=sys.stderr)
        return 1

    io.write_json(input_path, document)
    print(f"생성: {input_path}")

    if args.seed_parsed:
        source = Path(args.seed_parsed)
        if not source.is_dir():
            print(f"파싱 산출물 원본이 없습니다: {source}", file=sys.stderr)
            return 1
        target = case_dir / "04_parsed"
        shutil.copytree(source, target, dirs_exist_ok=True)
        count = len(list(target.glob("*.jsonl")))
        print(f"파싱 산출물 복사: {target} ({count}개 파일) — 파서 구현 전 임시")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
