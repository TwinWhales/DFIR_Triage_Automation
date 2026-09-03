"""regf 명세대로 nk/vk 를 직접 디코딩해 파서 출력과 값 단위로 대조한다.

``scan_hive_cells.py`` 가 **몇 개를 봤어야 하는가**(커버리지)를 본다면
이쪽은 **그 값이 맞는가**를 본다. 파서가 낸 nk 오프셋을 받아 그 자리의
바이트를 직접 읽고, 이름·LastWrite·값을 명세대로 해석해 맞춘다.
python-registry 를 전혀 쓰지 않는다.

## 이 대조로 잡은 것

셋 다 조용히 틀리는 종류였고, 이 대조가 아니면 그대로 갔다.
기록은 ``docs/limitations-log.md`` 「레지스트리 — 라이브러리를 우회한 곳」.

1. **한글 문자열 잘림** — 라이브러리가 UTF-16LE 종결자를 정렬 없이
   찾는다. SYSTEM 하이브 문자열 42,578건 중 56건.
2. **MULTI_SZ 종결자가 값으로 남음** — ``['rpcss', '', '']``.
   06단계 ``compare`` 가 리스트를 "원소 중 하나라도 일치"로 보므로
   지어낸 ``value: ""`` 가 검증을 통과했다.
3. **타임스탬프 반올림** — 나머지 파서는 절삭한다.

## 한계

같은 사람이 명세를 읽고 짠 두 구현이라 **공통 오해는 잡지 못한다**
(``limitations.md`` 5장의 "독립 순회 정답지" 함정과 같다).
big data(``db``) 레코드도 구현하지 않았다 — 값이 16,344바이트를 넘어
여러 셀로 쪼개진 경우이며, 그쪽은 라이브러리가 맞다. 실측에서 46,147키
중 5건이 여기 해당했다.

최종 값 대조는 ``reg load`` 로 한다. 절차는 ``scan_hive_cells.py``.

사용법::

    python tools/decode_hive_values.py --evidence "evidence/[root]"
    python tools/decode_hive_values.py --evidence <volume-root> --show 20
"""

from __future__ import annotations

import argparse
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import io  # noqa: E402
from src.stage04_parse import parsers  # noqa: E402
from src.stage04_parse.parsers.base import Scope  # noqa: E402

__all__ = ["decode_key", "decode_value", "interpret", "compare_hive", "main"]

#: 셀 오프셋은 hbin 시작(= 기본 블록 끝) 기준이다.
HBIN_BASE = 4096

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD = 1, 2, 3, 4
REG_DWORD_BE, REG_LINK, REG_MULTI_SZ = 5, 6, 7
REG_QWORD = 11


def filetime(raw: int):
    if raw <= 0:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=raw // 10)
    except OverflowError:
        return None


def cell_data(buf: bytes, offset: int) -> bytes:
    """셀 하나의 내용. offset 은 hbin 기준."""
    pos = HBIN_BASE + offset
    size = struct.unpack_from("<i", buf, pos)[0]
    return buf[pos + 4 : pos + abs(size)]


def decode_value(buf: bytes, vk: bytes):
    """vk 레코드 하나 → (이름, 값). 명세대로 직접 읽는다."""
    if vk[:2] != b"vk":
        raise ValueError("vk 시그니처 아님")

    name_len, data_size, data_offset, data_type = struct.unpack_from("<HIII", vk, 2)
    flags = struct.unpack_from("<H", vk, 0x10)[0]

    raw_name = vk[0x14 : 0x14 + name_len]
    name = raw_name.decode("latin-1") if flags & 1 else raw_name.decode("utf-16-le", "replace")

    # 최상위 비트가 서면 데이터가 data_offset 필드 안에 직접 들어 있다.
    if data_size & 0x80000000:
        length = data_size & 0x7FFFFFFF
        data = struct.pack("<I", data_offset)[:length]
    else:
        data = cell_data(buf, data_offset)[:data_size]

    return name, interpret(data_type, data)


def interpret(data_type: int, data: bytes):
    """레지스트리 타입 → 파이썬 값. 파서의 value_to_field 와 같은 형태로 낸다."""
    if data_type in (REG_SZ, REG_EXPAND_SZ, REG_LINK):
        text = data.decode("utf-16-le", "replace")
        return text.split("\x00", 1)[0]
    if data_type == REG_MULTI_SZ:
        text = data.decode("utf-16-le", "replace")
        parts = text.split("\x00")
        # 실물에서 끝에 빈 항목이 남는다. python-registry 도 그대로 둔다.
        while parts and parts[-1] == "":
            parts.pop()
        return parts
    if data_type == REG_DWORD:
        return struct.unpack("<I", data[:4].ljust(4, b"\x00"))[0]
    if data_type == REG_DWORD_BE:
        return struct.unpack(">I", data[:4].ljust(4, b"\x00"))[0]
    if data_type == REG_QWORD:
        return struct.unpack("<Q", data[:8].ljust(8, b"\x00"))[0]
    return data.hex()


def decode_key(buf: bytes, nk_offset: int):
    """nk 오프셋 → (이름, LastWrite, {값이름: 값}).

    파서가 내는 offset 은 **nk 레코드 데이터의 절대 위치**다. 셀 헤더가
    아니라 시그니처가 그 자리에 있다(실측으로 확인). 반면 레코드 안에
    들어 있는 참조(value_list_offset, data_offset)는 hbin 기준 상대값이고
    셀 헤더를 가리킨다 — 그쪽은 cell_data 가 다룬다.
    """
    # 슬라이스를 제한한다. 49MB 버퍼를 키마다 통째로 복사하면 O(n²)이 된다.
    nk = buf[nk_offset : nk_offset + 0x400]
    if nk[:2] != b"nk":
        raise ValueError(f"@0x{nk_offset:X}: nk 시그니처 아님")

    stamp = filetime(struct.unpack_from("<Q", nk, 4)[0])
    value_count, value_list_offset = struct.unpack_from("<II", nk, 0x24)
    # 이름 길이는 0x48, 이름은 0x4C 부터다. 0x4C/0x50 으로 읽으면
    # "services" 가 "ices" 로 나오고 길이는 largest-value-data-length 를
    # 집는다 — 실제로 처음에 그렇게 틀렸다.
    name_len = struct.unpack_from("<H", nk, 0x48)[0]
    flags = struct.unpack_from("<H", nk, 2)[0]

    raw_name = nk[0x4C : 0x4C + name_len]
    name = raw_name.decode("latin-1") if flags & 0x20 else raw_name.decode("utf-16-le", "replace")

    values: dict[str, object] = {}
    if value_count and value_list_offset != 0xFFFFFFFF:
        listing = cell_data(buf, value_list_offset)
        for i in range(value_count):
            (vk_offset,) = struct.unpack_from("<I", listing, i * 4)
            vname, value = decode_value(buf, cell_data(buf, vk_offset))
            values[vname or "(default)"] = value

    return name, stamp, values


# ------------------------------------------------------------------ 대조

#: 하이브별 기본 대조 범위. 전체를 돌면 오래 걸리므로 대표 구간을 쓴다.
HIVES = {
    "registry:SYSTEM": ("SYSTEM", "SYSTEM\CurrentControlSet\Services"),
    "registry:SOFTWARE": ("SOFTWARE", "SOFTWARE\Microsoft\Windows\CurrentVersion"),
}


def _find_hive(config_dir: Path, name: str) -> Path | None:
    """대소문자 어느 쪽으로 추출됐는지 모른다."""
    for candidate in (config_dir / name, config_dir / name.lower()):
        if candidate.is_file():
            return candidate
    return None


def compare_hive(path: Path, artifact: str, prefix: str, show: int) -> bool:
    """한 하이브를 대조한다. 전부 일치하면 True."""
    buf = path.read_bytes()
    parser = parsers.get(artifact)
    scope = Scope.from_selection({"path_prefix": [prefix]})

    keys = names = stamps = fields = 0
    mismatches: list[str] = []

    with path.open("rb") as stream:
        for record in parser.parse(stream, scope):
            keys += 1
            try:
                name, stamp, values = decode_key(buf, record["record_num"])
            except Exception as e:  # noqa: BLE001
                mismatches.append(f"{record['ref']} 디코딩 실패: {e}")
                continue

            if name == record["name"]:
                names += 1
            else:
                mismatches.append(f"{record['ref']} 이름: {name!r} != {record['name']!r}")

            theirs = stamp.strftime("%Y-%m-%dT%H:%M:%S.%f0Z") if stamp else None
            if theirs == record.get("timestamp"):
                stamps += 1
            else:
                mismatches.append(f"{record['ref']} 시각: {theirs} != {record.get('timestamp')}")

            if values == record["fields"]:
                fields += 1
            else:
                mine = {k: v for k, v in values.items() if record["fields"].get(k) != v}
                theirs_only = {k: v for k, v in record["fields"].items() if values.get(k) != v}
                mismatches.append(
                    f"{record['ref']} {record['path']}\n"
                    f"      독립 디코더: {str(mine)[:160]}\n"
                    f"      파서       : {str(theirs_only)[:160]}"
                )

    print(f"=== {artifact}  ({prefix}) ===")
    print(f"  키           {keys}건")
    print(f"  이름 일치    {names}건")
    print(f"  LastWrite    {stamps}건")
    print(f"  값 전체 일치 {fields}건")
    if mismatches:
        print(f"  불일치 {len(mismatches)}건 (앞 {show}건):")
        for line in mismatches[:show]:
            print(f"    {line}")
        print()
        print("  값 불일치가 큰 값(16KB 초과)에만 나온다면 big data 레코드다 —")
        print("  이 도구가 구현하지 않은 것이며 파서가 맞다.")
    else:
        print("  불일치 없음")
    print()
    return not mismatches


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/decode_hive_values.py",
        description="하이브 값을 명세대로 직접 디코딩해 파서 출력과 대조한다.",
    )
    parser.add_argument("--evidence", required=True, help="볼륨 루트 경로")
    parser.add_argument("--show", type=int, default=10, help="불일치 예시 출력 수")
    args = parser.parse_args(argv)

    io.configure_console()
    config = Path(args.evidence) / "Windows" / "System32" / "config"
    if not config.is_dir():
        print(f"오류: {config} 가 없습니다. --evidence 는 볼륨 루트여야 합니다.", file=sys.stderr)
        return 2

    ok = True
    for artifact, (filename, prefix) in HIVES.items():
        hive = _find_hive(config, filename)
        if hive is None:
            print(f"{filename} 하이브 없음, 건너뜀", file=sys.stderr)
            continue
        ok = compare_hive(hive, artifact, prefix, args.show) and ok

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
