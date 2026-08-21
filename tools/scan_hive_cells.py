"""하이브의 nk 셀을 직접 세어 파서의 순회 누락을 잡는다.

레지스트리 파서의 위험은 ``$MFT``와 성격이 다릅니다. 값을 틀리게 읽는
것이 아니라 **서브트리를 통째로 못 보고 지나가는 것**입니다.

python-registry는 서브키 목록(``lf``/``lh``/``li``/``ri`` 셀)을 따라
트리를 내려갑니다. 그 목록 하나가 손상됐거나 처리하지 못하는 타입이면
**그 아래 전부가 조용히 사라집니다.** 예외도 경고도 없이 키 개수만
줄어듭니다. evtx에서 ``ChunkHeader.records()``가 청크 나머지를 삼키던
것과 같은 유형입니다(``parsers/evtx.py``).

이 스캐너는 **서브키 목록을 전혀 따라가지 않습니다.** hbin 블록을 처음부터
끝까지 걸으면서 셀 헤더의 크기 값으로 다음 셀로 넘어가고, 시그니처가
``nk``인 셀을 셉니다. 트리 구조와 무관하므로 목록이 깨져 고아가 된 키도
세어집니다.

즉 **커버리지 정답지**입니다. 값이 맞는지는 모르고, 몇 개를 봤어야
하는지만 압니다. 값 대조는 ``reg load``로 따로 합니다(아래).

사용법::

    # 범위 없이 전체를 뽑은 뒤 대조한다. scope 를 주면 파서가 일부러
    # 적게 내므로 개수 대조가 성립하지 않는다.
    python -m src.stage04_parse.parse --in <selection-without-scope> \\
        --out /tmp/reg --evidence <volume-root>
    python tools/scan_hive_cells.py --hive <volume>/Windows/System32/config/SYSTEM \\
        --ours /tmp/reg/registry_system.jsonl

    # 하이브만 훑어보기
    python tools/scan_hive_cells.py --hive .../SYSTEM

## 값까지 대조하려면

``reg load``를 씁니다. **모든 Windows에 들어 있고 마이크로소프트 자신의
구현이라** ``wevtutil``과 같은 조건입니다 — 받을 것이 없고 공통 오해가
생기지 않습니다. ``python-registry``나 ``regipy``로 대조하면 우리가 쓰는
바로 그 라이브러리이거나 같은 계열이라 의미가 줄어듭니다.

관리자 권한이 필요하고, **원본이 아니라 복사본에 걸어야 합니다** —
마운트가 하이브를 더티로 만들 수 있습니다::

    copy <evidence>\\SYSTEM %TEMP%\\SYSTEM.copy
    reg load HKLM\\DfirTemp %TEMP%\\SYSTEM.copy
    reg query HKLM\\DfirTemp\\ControlSet001\\Services\\Dnscache
    reg unload HKLM\\DfirTemp
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import io  # noqa: E402

__all__ = ["HiveScan", "scan", "count_ours", "main"]

#: 기본 블록 크기. 첫 hbin 이 시작하는 자리이기도 하다.
BASE_BLOCK_SIZE = 4096

#: hbin 헤더 크기. 셀은 그 뒤부터 시작한다.
HBIN_HEADER_SIZE = 32


@dataclass
class HiveScan:
    """스캔 결과."""

    hbins: int
    allocated: int
    #: 미할당 셀에 남아 있는 nk. **삭제된 키의 흔적**이다.
    #:
    #: 우리 파서는 이것을 내지 않는다(python-registry 가 할당된 트리만
    #: 걷는다). 개수만 보고해 두는 이유는, 여기 값이 크면 삭제된 키
    #: 복구가 이 증거에서 의미 있다는 신호이기 때문이다.
    unallocated: int
    #: 셀 체인이 hbin 경계 전에 끊긴 횟수. 손상 신호다.
    broken_chains: int

    def summary(self) -> str:
        return (
            f"hbin {self.hbins}개 / 할당된 nk {self.allocated}개 / "
            f"미할당 nk {self.unallocated}개 / 끊긴 체인 {self.broken_chains}개"
        )


def scan(path: Path) -> HiveScan:
    """하이브를 걸으며 nk 셀을 센다.

    hbin 헤더가 선언한 크기로 다음 hbin 을 찾고, hbin 안에서는 셀 크기로
    다음 셀을 찾습니다. **크기가 0이면 거기서 멈춥니다** — 0으로 전진하면
    무한 루프가 되고, 0은 정상 하이브에 없는 값입니다.

    셀 크기는 부호 있는 32비트입니다. 음수가 할당된 셀, 양수가 free 입니다.
    """
    buf = path.read_bytes()
    if buf[:4] != b"regf":
        raise ValueError(f"{path}: 레지스트리 하이브가 아닙니다 (매직 불일치)")

    hbins = allocated = unallocated = broken = 0
    offset = BASE_BLOCK_SIZE

    while offset + HBIN_HEADER_SIZE <= len(buf):
        if buf[offset : offset + 4] != b"hbin":
            break
        hbin_size = struct.unpack_from("<I", buf, offset + 8)[0]
        if hbin_size == 0:
            break
        hbins += 1

        end = min(offset + hbin_size, len(buf))
        cell = offset + HBIN_HEADER_SIZE
        while cell + 4 <= end:
            size = struct.unpack_from("<i", buf, cell)[0]
            if size == 0:
                # 정상 하이브에는 없는 값이다. 남은 구간을 못 걷는다.
                broken += 1
                break
            if cell + 6 <= end and buf[cell + 4 : cell + 6] == b"nk":
                if size < 0:
                    allocated += 1
                else:
                    unallocated += 1
            cell += abs(size)

        offset += hbin_size

    return HiveScan(hbins=hbins, allocated=allocated, unallocated=unallocated, broken_chains=broken)


def count_ours(path: Path) -> int:
    """우리 파서가 낸 레코드 수. ``ref`` 중복이 있으면 알린다."""
    seen: set[str] = set()
    total = 0
    for record in io.read_jsonl(path):
        total += 1
        ref = record.get("ref")
        if ref is not None:
            seen.add(ref)
    if len(seen) != total:
        print(
            f"경고: {path.name} 에 ref 중복이 있습니다 "
            f"({total}줄 / 고유 ref {len(seen)}개). "
            "05·06단계가 DuplicateRefError 로 멈춥니다.",
            file=sys.stderr,
        )
    return total


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/scan_hive_cells.py",
        description="하이브의 nk 셀을 직접 세어 파서의 순회 누락을 잡는다.",
    )
    parser.add_argument("--hive", required=True, help="하이브 파일 경로 (SYSTEM/SOFTWARE)")
    parser.add_argument(
        "--ours",
        default=None,
        help="우리 파서가 낸 JSONL. 주면 개수를 대조한다 (범위 없이 뽑은 것이어야 함)",
    )
    args = parser.parse_args(argv)

    io.configure_console()
    hive = Path(args.hive)
    try:
        result = scan(hive)
    except (OSError, ValueError) as e:
        print(f"오류: {e}", file=sys.stderr)
        return 2

    print(f"{hive.name}: {result.summary()}")

    if result.unallocated:
        print(
            f"  미할당 nk {result.unallocated}개 — 삭제된 키의 흔적입니다. "
            "본 버전은 복구하지 않습니다."
        )
    if result.broken_chains:
        print(f"  끊긴 셀 체인 {result.broken_chains}곳 — 이 하이브는 손상됐을 수 있습니다.")

    if args.ours is None:
        return 0

    ours = count_ours(Path(args.ours))
    print(f"우리 파서: {ours}건 / 할당된 nk: {result.allocated}건")

    if ours == result.allocated:
        print("일치. 파서가 놓친 서브트리가 없습니다.")
        return 0

    missing = result.allocated - ours
    if missing > 0:
        print(
            f"불일치: {missing}건을 놓쳤습니다. 서브키 목록(lf/lh/li/ri)이 "
            "깨졌거나 처리하지 못한 타입이 있습니다.",
            file=sys.stderr,
        )
    else:
        print(
            f"불일치: {-missing}건이 더 많습니다. 같은 키를 두 번 냈을 수 "
            "있습니다 — ref 중복이면 05·06단계가 멈춥니다.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
