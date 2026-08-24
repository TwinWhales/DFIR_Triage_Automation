"""프리패치 폴더를 **파서와 다른 길로** 읽어 파서 출력과 대조한다.

프리패치에는 ``wevtutil``이나 ``reg load`` 같은 자리가 없습니다. Windows에
기본 탑재된 프리패치 판독기가 없고, 외부 도구(PECmd 등)는 받아야 합니다.
그래서 ``tools/scan_hive_cells.py``와 같은 방법을 씁니다 — **같은 파일을
다른 경로로 읽어 정답지를 만듭니다.**

## 무엇이 다른 길인가

파서는 **파일 메트릭 배열을 걸어** 각 원소가 가리키는 문자열을 꺼냅니다
(원소마다 오프셋과 문자 수가 있습니다). 이 스캐너는 배열을 아예 보지 않고
**문자열 블록을 널로 쪼갭니다.**

두 경로가 어긋나는 경우가 실제 위험입니다.

* 메트릭 원소 크기(20 vs 32바이트)를 버전별로 잘못 잡으면 배열을 걷는
  쪽만 어긋납니다. 개수가 맞지 않거나 문자열이 중간부터 잘립니다.
* 문자열 블록 크기를 잘못 읽으면 쪼개는 쪽만 어긋납니다.

즉 **개수와 내용이 둘 다 일치하면 두 해석이 서로를 지지합니다.**
값이 맞는지(실행 횟수·실행 시각)는 이 스캐너가 모릅니다. 그쪽은 헤더
해시와 파일명, 헤더의 파일 크기와 실제 크기를 맞춰 보는 것으로 대신합니다 —
**둘 다 Windows가 쓴 값**이라 우리 해석과 독립입니다.

사용법::

    # 범위 없이 전체를 뽑은 뒤 대조한다. scope 를 주면 파서가 일부러
    # 적게 내므로 개수 대조가 성립하지 않는다.
    .venv/Scripts/python.exe tools/scan_prefetch.py \\
        --dir "evidence/[root]/Windows/Prefetch" \\
        --ours cases/C-001/04_parsed/prefetch.jsonl

    # 폴더만 훑어보기
    .venv/Scripts/python.exe tools/scan_prefetch.py --dir ".../Prefetch"
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common import io as _io  # noqa: E402
from src.stage04_parse.structs import prefetch_record as pf  # noqa: E402

__all__ = ["scan_file", "scan_directory", "main"]


def scan_file(path: Path) -> dict:
    """파일 하나를 독립적으로 읽는다. 메트릭 배열은 보지 않는다."""
    raw = path.read_bytes()
    compressed = pf.is_compressed(raw)
    if compressed:
        raw = pf.decompress_mam(raw)

    header = pf.read_header(raw)
    # 앞머리 9개 dword 는 모든 버전에서 같은 자리다. 여기까지는 파서와
    # 같은 값을 볼 수밖에 없다 — 다른 길로 갈 곳이 없다.
    strings_offset, strings_size = struct.unpack_from("<II", raw, pf.HEADER_SIZE + 0x10)

    blob = raw[strings_offset : strings_offset + strings_size]
    names = [s for s in blob.decode("utf-16-le", "replace").split("\x00") if s]

    from_name = None
    stem = path.name.rsplit("-", 1)
    if len(stem) == 2:
        try:
            from_name = int(stem[1].split(".", 1)[0], 16)
        except ValueError:
            from_name = None

    return {
        "file": path.name,
        "version": header.version,
        "executable": header.executable,
        "path_hash": header.path_hash,
        "hash_from_filename": from_name,
        "declared_size": header.file_size,
        "actual_size": path.stat().st_size,
        "compressed": compressed,
        "names": names,
    }


def scan_directory(directory: Path) -> tuple[list[dict], list[str]]:
    """폴더 안의 .pf 를 전부 읽는다. 못 읽은 것은 사유와 함께 돌려준다."""
    scanned: list[dict] = []
    failed: list[str] = []
    for path in sorted(directory.glob("*.pf"), key=lambda p: p.name.lower()):
        if path.stat().st_size == 0:
            failed.append(f"{path.name}: 0바이트")
            continue
        try:
            scanned.append(scan_file(path))
        except Exception as e:  # noqa: BLE001 - 무엇이 나올지 모른다
            failed.append(f"{path.name}: {type(e).__name__} {e}")
    return scanned, failed


def _compare(scanned: list[dict], ours_path: Path) -> int:
    """파서 출력과 맞춰 본다. 불일치 수를 돌려준다."""
    ours = {}
    with ours_path.open(encoding="utf-8") as fh:
        for line in fh:
            record = json.loads(line)
            ours[record["fields"]["prefetch_file"]] = record

    mismatches = 0
    for entry in scanned:
        record = ours.get(entry["file"])
        if record is None:
            print(f"  [파서에 없음] {entry['file']}")
            mismatches += 1
            continue

        theirs = record["fields"]["loaded_files"]
        if theirs != entry["names"]:
            print(
                f"  [적재 목록 불일치] {entry['file']}: "
                f"파서 {len(theirs)}건 / 스캐너 {len(entry['names'])}건"
            )
            for index, (a, b) in enumerate(zip(theirs, entry["names"])):
                if a != b:
                    print(f"      첫 불일치 #{index}: {a!r} != {b!r}")
                    break
            mismatches += 1

        if record["record_num"] != entry["path_hash"]:
            print(f"  [해시 불일치] {entry['file']}")
            mismatches += 1

    extra = set(ours) - {e["file"] for e in scanned}
    for name in sorted(extra):
        print(f"  [스캐너에 없음] {name}")
        mismatches += 1
    return mismatches


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/scan_prefetch.py",
        description="프리패치 폴더를 파서와 다른 길로 읽어 대조한다.",
    )
    parser.add_argument("--dir", required=True, help="Prefetch 폴더 경로")
    parser.add_argument("--ours", default=None, help="04단계가 낸 prefetch.jsonl")
    args = parser.parse_args(argv)
    _io.configure_console()

    directory = Path(args.dir)
    if not directory.is_dir():
        print(f"폴더 없음: {directory}", file=sys.stderr)
        return 2

    scanned, failed = scan_directory(directory)
    versions: dict[int, int] = {}
    for entry in scanned:
        versions[entry["version"]] = versions.get(entry["version"], 0) + 1

    print(f"{directory}")
    print(f"  읽은 파일 {len(scanned)}건 / 건너뛴 {len(failed)}건")
    print(f"  버전 분포: {', '.join(f'{v}={n}' for v, n in sorted(versions.items()))}")
    print(f"  적재 파일 경로 총 {sum(len(e['names']) for e in scanned)}건")

    hash_bad = [
        e for e in scanned if e["hash_from_filename"] not in (None, e["path_hash"])
    ]
    size_bad = [e for e in scanned if e["declared_size"] != e["actual_size"]]
    # 둘 다 Windows 가 쓴 값이라 우리 해석과 독립이다.
    print(f"  파일명 해시 불일치 {len(hash_bad)}건 / 헤더 크기 불일치 {len(size_bad)}건")
    for entry in hash_bad + size_bad:
        print(f"    {entry['file']}")
    for reason in failed:
        print(f"    건너뜀 — {reason}")

    if args.ours is None:
        return 0

    print(f"\n파서 출력 대조: {args.ours}")
    mismatches = _compare(scanned, Path(args.ours))
    print(f"  불일치 {mismatches}건")
    return 1 if mismatches or hash_bad or size_bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
