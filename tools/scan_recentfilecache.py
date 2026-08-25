"""``RecentFileCache.bcf``를 **파서와 다른 길로** 읽어 파서 출력과 대조한다.

Windows에 기본 탑재된 판독기가 없고 외부 도구(`RecentFileCacheParser`)는
받아야 합니다. `tools/scan_prefetch.py`·`tools/scan_hive_cells.py`와 같은
방법을 씁니다 — **같은 파일을 다른 경로로 읽어 정답지를 만듭니다.**

## 무엇이 다른 길인가

파서는 **길이 필드를 걸어** 항목을 하나씩 짚어 나갑니다. 항목마다 앞
4바이트가 문자 수이고, 그만큼 읽은 뒤 종결자 2바이트를 건너뜁니다.

이 스캐너는 **길이 필드를 아예 보지 않습니다.** 헤더 20바이트를 뗀
나머지를 통째로 UTF-16LE로 디코딩한 뒤 널 문자로 쪼갭니다. 길이 필드는
그 자리에서 제어문자로 나타나므로 함께 버립니다.

두 경로가 어긋나는 경우가 실제 위험입니다.

* 길이 필드의 **단위**를 잘못 잡으면(문자 수 ↔ 바이트) 걷는 쪽만
  어긋납니다. 경로가 절반에서 잘리는데 UTF-16LE의 앞 절반은 여전히
  읽히는 문자열이라 **그럴듯한 경로가 나옵니다.**
* 헤더 크기를 잘못 잡으면 쪼개는 쪽만 어긋납니다.

즉 **개수와 내용이 둘 다 일치하면 두 해석이 서로를 지지합니다.**

## Windows가 쓴 값과도 맞춰 본다

우리 해석과 독립인 값이 하나 있습니다 — **파일 크기**입니다. 길이 필드를
따라 걸었을 때 마지막 항목의 끝이 파일 끝과 정확히 같아야 합니다. 단위를
잘못 잡았다면 67번 연쇄하는 동안 어긋나 남는 바이트가 생깁니다.

사용법::

    # 볼륨 이미지에서 바로
    .venv/Scripts/python.exe tools/scan_recentfilecache.py \\
        --evidence evidence/windows7_testimage.001 --volume 1 \\
        --ours cases/C-007/04_parsed/recentfilecache.jsonl

    # 추출해 둔 파일로
    .venv/Scripts/python.exe tools/scan_recentfilecache.py \\
        --file "<수집폴더>/C/Windows/AppCompat/Programs/RecentFileCache.bcf"
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

from src.stage04_parse.structs import recentfilecache_record as rfc  # noqa: E402

__all__ = ["split_strings", "walk_lengths", "main"]

#: 경로로 볼 최소 길이. 길이 필드가 디코딩된 찌꺼기를 걸러 낸다.
#:
#: 길이 필드 4바이트는 UTF-16LE 로는 문자 둘이고, 실제 값이 작아
#: 제어문자 영역에 들어간다. 아래 필터가 그것을 버린다.
_MIN_PATH = 3


def split_strings(data: bytes) -> list[str]:
    """**길이 필드를 보지 않고** 문자열 블록을 널로 쪼갠다.

    파서와 완전히 다른 경로입니다. 항목 경계를 우리가 정하지 않고 널
    종결자에 맡깁니다.
    """
    blob = data[rfc.HEADER_SIZE :].decode("utf-16-le", "replace")
    out: list[str] = []
    for piece in blob.split("\x00"):
        # 길이 필드가 디코딩된 조각을 버린다. 제어문자가 하나라도 있으면
        # 경로가 아니다 — 실제 경로에는 들어갈 수 없는 문자다.
        if len(piece) < _MIN_PATH or any(ch < " " for ch in piece):
            continue
        out.append(piece)
    return out


def walk_lengths(data: bytes) -> tuple[list[str], int]:
    """길이 필드를 걷는다. 경로 목록과 **끝나고 남은 바이트**를 돌려준다.

    파서와 같은 경로처럼 보이지만 여기서는 검증을 하지 않습니다 — 파서가
    거부하는 조건에서도 끝까지 걸어 **어디서 얼마가 남는지**를 봅니다.
    남는 바이트가 0이라는 사실이 곧 "단위를 맞게 잡았다"의 증거입니다.
    """
    out: list[str] = []
    cursor = rfc.HEADER_SIZE
    while cursor + 4 <= len(data):
        count = struct.unpack_from("<I", data, cursor)[0]
        end = cursor + 4 + count * 2
        if count == 0 or end + 2 > len(data):
            break
        out.append(data[cursor + 4 : end].decode("utf-16-le", "replace"))
        cursor = end + 2
    return out, len(data) - cursor


def _read_evidence(path: str, volume: "int | None") -> bytes:
    from src.stage04_parse import evidence

    source = evidence.open_source(path, volume=volume)
    with source.open("recentfilecache") as stream:
        return stream.read()


def _compare(scanned: list[str], ours_path: Path) -> int:
    """파서 출력과 맞춰 본다. 불일치 수를 돌려준다."""
    ours: list[str] = []
    with ours_path.open(encoding="utf-8") as fh:
        for line in fh:
            ours.append(json.loads(line)["path"])

    if len(ours) != len(scanned):
        print(f"  [건수 불일치] 파서 {len(ours)}건 / 스캐너 {len(scanned)}건")

    mismatches = 0
    for index, (a, b) in enumerate(zip(ours, scanned)):
        if a != b:
            print(f"  [불일치 #{index}] 파서 {a!r} != 스캐너 {b!r}")
            mismatches += 1
    return mismatches + abs(len(ours) - len(scanned))


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(prog="python tools/scan_recentfilecache.py")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="추출된 RecentFileCache.bcf 경로")
    source.add_argument("--evidence", help="디스크 이미지 또는 볼륨 루트")
    parser.add_argument("--volume", type=int, help="--evidence 가 디스크 이미지일 때 볼륨 번호")
    parser.add_argument("--ours", help="파서 출력(recentfilecache.jsonl). 주면 대조한다")
    args = parser.parse_args(argv)

    data = (
        Path(args.file).read_bytes()
        if args.file
        else _read_evidence(args.evidence, args.volume)
    )

    print(f"파일 크기: {len(data):,}바이트")
    print(f"시그니처: {data[:4].hex()} (기대 {rfc.SIGNATURE.hex()})")
    if data[:4] != rfc.SIGNATURE:
        print("  ** 시그니처가 다릅니다. 구조 가정이 틀렸을 수 있습니다. **")

    split = split_strings(data)
    walked, remainder = walk_lengths(data)

    print(f"길이 필드를 걸어서: {len(walked)}건, 끝나고 남은 바이트 {remainder}")
    print(f"널로 쪼개서:       {len(split)}건")

    if walked == split:
        print("→ 두 해석이 일치합니다.")
    else:
        print("→ **두 해석이 어긋납니다.**")
        for index, (a, b) in enumerate(zip(walked, split)):
            if a != b:
                print(f"    첫 불일치 #{index}: 걷기 {a!r} != 쪼개기 {b!r}")
                break

    failures = 0 if walked == split else 1
    if remainder:
        print(f"→ **{remainder}바이트가 남습니다.** 길이 필드의 단위를 확인하십시오.")
        failures += 1

    if args.ours:
        print(f"\n파서 출력 대조: {args.ours}")
        found = _compare(split, Path(args.ours))
        print("  일치" if found == 0 else f"  불일치 {found}건")
        failures += found

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
