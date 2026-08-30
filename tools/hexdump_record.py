"""04단계가 남긴 ``offset``으로 원본 바이트를 되짚는다.

``parsed_record`` 스키마가 ``offset``을 이렇게 설명합니다 — *"원본 바이트
위치. 기존 파서를 쓰지 않고 직접 구현하는 이유가 이 필드다.
``tools/hexdump_record.py``가 이 값으로 원본을 되짚는다."* 그 문장이 가리키던
자리를 채우는 파일입니다. 그전까지 이 프로젝트는 오프셋을 넣고 다니면서
**그것으로 원본에 실제로 내려가 본 적이 없었습니다**
(``docs/limitations.md`` 2026-08-28).

## 무엇을 하나

    ref  →  04_parsed 에서 레코드를 찾고  →  증거에서 그 오프셋을 읽고
         →  거기 있는 바이트가 정말 그 레코드인지 대조하고  →  덤프한다

**다시 파싱하지 않습니다.** 파서가 맞다는 것을 같은 파서로 증명할 수
없습니다(``tools/scan_prefetch.py``와 같은 태도). 대조는 우리가 해석해
넣은 값이 아니라 **레코드가 자기 안에 들고 있는 식별자**로 합니다 —
``$MFT`` 헤더의 레코드 번호, USN 레코드의 USN, evtx 의 EventRecordID.
그 값이 ``ref``와 같으면 오프셋이 가리키는 자리가 맞습니다.

## 대조가 어디까지 성립하나

====================  ==========================================================
아티팩트               ref 를 무엇으로 확인하나
====================  ==========================================================
``$MFT``              헤더 ``0x2C``의 레코드 번호. 덤으로 업데이트 시퀀스가
                      섹터 끝마다 맞는지 본다 — 레코드 경계에 정확히
                      내려앉았다는 가장 강한 증거다
``$UsnJrnl``          ``0x18``의 USN. 이 값이 곧 ``record_num``이다
``evtx:*``            ``0x8``의 EventRecordID. 매직 ``**\\x00\\x00``도 함께 본다
``registry:*``        ``nk`` 매직과 오프셋 자신. 레지스트리는 일련번호가 없어
                      **오프셋이 곧 식별자**라, 키 이름까지 맞춰 본다
``recentfilecache``   항목 자신의 오프셋과 경로 문자열
``prefetch``          ``offset``이 항상 ``0x0``이라 오프셋으로 가릴 것이 없다.
                      대신 ``.pf`` 파일명 뒤 8자리 해시 = ``record_num``을 본다
``srum:*``            **페이지까지만 성립한다.** ESE 레코드는 페이지 안에서
                      태그로 가리켜져 레코드 시작 바이트를 파일 좌표로 말할
                      수 없다(``parsers/srum.py``). 그 안에서는 조인다 —
                      페이지 크기를 **DB 헤더에서 읽어** 배수인지 보고,
                      예약 페이지와 파일 범위까지 본다. 한계는 출력에 적는다
====================  ==========================================================

## 못 하는 것

- **``$MFT``는 업데이트 시퀀스를 되돌리기 전 바이트입니다.** 섹터 끝
  2바이트가 원래 값이 아니라 USN입니다. 파서 출력의 타임스탬프와 눈으로
  맞출 때 이 자리에 걸리면 그것이 정상입니다.
- **압축된 프리패치(Win10 MAM)는 헤더가 압축돼 있습니다.** 덤프는 압축된
  바이트 그대로이고, 경로 해시 대조는 파일명으로만 합니다.
- 대조가 통과했다고 **파싱한 값이 맞다**는 뜻은 아닙니다. "이 레코드를
  여기서 읽었다"까지가 이 도구가 말할 수 있는 전부입니다.

## 사용법

::

    # 레코드 하나를 되짚는다
    .venv/Scripts/python.exe tools/hexdump_record.py MFT#12345 \\
        --parsed cases/K-ALERT/04_parsed --evidence evidence/0824test.001 --volume 1

    # 여러 건을 한 번에. 덤프 없이 대조만
    .venv/Scripts/python.exe tools/hexdump_record.py MFT#12345 USN#5063392 \\
        --parsed cases/K-ALERT/04_parsed --evidence ... --volume 1 --no-dump

    # 아티팩트마다 20건씩 골라 오프셋이 전부 되짚어지는지 본다
    .venv/Scripts/python.exe tools/hexdump_record.py --sample 20 \\
        --parsed cases/K-ALERT/04_parsed --evidence ... --volume 1

**하나라도 어긋나면 종료 코드가 1입니다.** 조용히 덤프만 뱉지 않습니다 —
오프셋이 틀렸다는 것은 근거 추적 구조 전체가 흔들린다는 뜻입니다.
"""

from __future__ import annotations

import argparse
import struct
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Iterator

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common import io as _io  # noqa: E402
from src.common import refs  # noqa: E402
from src.stage04_parse import evidence  # noqa: E402
from src.stage04_parse.parse import OUTPUT_FILENAMES  # noqa: E402

__all__ = [
    "HexdumpError",
    "Check",
    "Window",
    "find_record",
    "read_window",
    "verify",
    "hexdump",
    "main",
]

#: 길이를 스스로 정할 때의 상한. 레지스트리 셀이나 evtx 레코드는 수십 KB가
#: 될 수 있는데, 되짚어 보는 것이 목적이라 앞부분이면 충분하다. 더 필요하면
#: ``--length``로 명시한다.
MAX_AUTO_LENGTH = 4096

#: 길이를 정할 근거를 찾지 못했을 때. 레코드 머리는 대개 여기 다 들어온다.
FALLBACK_LENGTH = 256

#: 길이 필드를 읽어 보려고 먼저 떠 오는 양.
PROBE_LENGTH = 96

#: ``$MFT`` 레코드 크기로 인정하는 값. ``parsers/mft.py``와 같은 목록이다.
VALID_RECORD_SIZES = (512, 1024, 2048, 4096)

#: 한 줄에 찍을 바이트 수.
DUMP_WIDTH = 16

#: ESE 데이터베이스 헤더의 매직(``0x4``)과 페이지 크기(``0xEC``).
#: 실측으로 확인했다 — ``docs/artifact-notes.md`` 2026-08-30 절.
ESE_MAGIC = 0x89ABCDEF
ESE_PAGE_SIZE_AT = 0xEC
ESE_HEADER_PROBE = ESE_PAGE_SIZE_AT + 4

#: ESE 는 앞의 두 페이지를 DB 헤더와 그 그림자로 쓴다. 레코드가 실린
#: 페이지는 그 뒤다 — ``parsers/srum.py``의 ``PAGE_NUMBER_BIAS``와 같은 사실이다.
ESE_RESERVED_PAGES = 2


class HexdumpError(RuntimeError):
    """되짚을 수 없다. 사유를 그대로 사람에게 보인다."""


@dataclass(frozen=True)
class Check:
    """대조 한 줄.

    ``hard``가 거짓인 것은 **어긋나도 오프셋이 틀렸다고 말할 수 없는**
    검사다. 예를 들어 ``$MFT``의 이름 문자열은 업데이트 시퀀스가 덮은
    자리에 걸치면 원본 바이트에서 찾지 못할 수 있다. 그런 것을 실패로
    세면 "대조 실패"의 뜻이 흐려진다.
    """

    ok: bool
    label: str
    detail: str
    hard: bool = True


@dataclass(frozen=True)
class Window:
    """되짚어 읽은 구간."""

    ref: str
    artifact: str
    offset: int
    data: bytes
    #: 어느 파일에서 읽었나. 증거가 이미지면 볼륨 안의 경로다.
    source: str
    #: ``evidence.Located.method`` — ``search``면 제자리에 없던 파일이다.
    method: str
    #: 파일 끝에 걸려 요청보다 적게 읽었나.
    truncated: bool = False
    #: **창 밖에서 온 사실.** 레코드 바이트만으로는 판정할 수 없는 것을
    #: 대조에 넘긴다 — SRUM 의 페이지 크기가 그렇다. 파일 헤더가 말하는
    #: 값이라 우리가 추측한 것이 아니다.
    context: "dict[str, Any]" = field(default_factory=dict)


# =============================================================== 레코드 찾기


def find_record(parsed_dir: Path, ref: str) -> dict[str, Any]:
    """``04_parsed/``에서 ``ref``의 레코드를 찾는다.

    ``ref``의 접두어가 어느 파일을 봐야 하는지 이미 말해 주므로
    (``refs.py``) 디렉터리를 통째로 훑지 않습니다.
    """
    artifact = refs.artifact_of(ref)
    filename = OUTPUT_FILENAMES.get(artifact)
    if filename is None:
        raise HexdumpError(f"{ref}: {artifact} 는 04단계 출력 파일이 없는 아티팩트다")

    path = parsed_dir / filename
    if not path.is_file():
        raise HexdumpError(
            f"{ref}: {path} 가 없다 — 그 아티팩트를 파싱한 적이 없거나 "
            f"--parsed 가 04_parsed 디렉터리를 가리키지 않는다"
        )

    for record in _io.read_jsonl(path):
        if record.get("ref") == ref:
            return record
    raise HexdumpError(f"{ref}: {path} 안에 없다 (그 실행이 이 레코드를 내지 않았다)")


def sample_refs(parsed_dir: Path, count: int, artifact: "str | None" = None) -> list[str]:
    """아티팩트마다 ``count``건씩 고르게 고른다.

    **무작위가 아니라 균등 간격입니다.** 같은 산출물에서 언제 돌려도 같은
    레코드가 나와야 "지난번과 같은 것을 봤다"고 말할 수 있습니다.
    """
    picked: list[str] = []
    for name, filename in OUTPUT_FILENAMES.items():
        if artifact is not None and name != artifact:
            continue
        path = parsed_dir / filename
        if not path.is_file():
            continue
        total = _io.count_jsonl(path)
        if total == 0:
            continue
        step = max(1, total // count)
        wanted = {min(i * step, total - 1) for i in range(count)}
        for index, record in enumerate(_io.read_jsonl(path)):
            if index in wanted and record.get("ref"):
                picked.append(record["ref"])
    return picked


# =============================================================== 원본 읽기


@contextmanager
def _stream_for(
    source: evidence.EvidenceSource, record: dict[str, Any]
) -> "Iterator[tuple[Any, BinaryIO]]":
    """레코드가 나온 파일을 연다.

    프리패치만 갈립니다 — 폴더 단위 아티팩트라 ``open()``이 거부하므로
    ``fields.prefetch_file``이 말하는 파일을 골라 엽니다. 04단계가 그
    이름을 남긴 이유가 여기 있습니다(``parsers/prefetch.py``).
    """
    artifact = record["artifact"]
    location = evidence.FILE_LAYOUT.get(artifact)

    if location is not None and location.is_directory:
        wanted = str((record.get("fields") or {}).get("prefetch_file") or "")
        if not wanted:
            raise HexdumpError(
                f"{record['ref']}: 폴더 단위 아티팩트인데 fields.prefetch_file 이 없다 — "
                "어느 파일에서 나온 레코드인지 알 수 없다"
            )
        for opened in source.open_all(artifact):
            if opened.path.name.lower() == wanted.lower():
                yield opened.path, opened.stream
                return
        raise HexdumpError(f"{record['ref']}: 증거의 {artifact} 폴더에 {wanted} 가 없다")

    stream = source.open(artifact)
    try:
        located = source.locate(artifact)
        yield (located.path if located is not None else Path(artifact)), stream
    finally:
        stream.close()


def _read_at(stream: BinaryIO, offset: int, length: int) -> bytes:
    """``offset``에서 ``length``만큼. 파일 끝에 걸리면 있는 만큼 돌려준다."""
    if offset < 0:
        return b""
    stream.seek(offset)
    return stream.read(length)


def _u16(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<H", data, at)[0])


def _u32(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<I", data, at)[0])


def _i32(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<i", data, at)[0])


def _u64(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<Q", data, at)[0])


def natural_length(artifact: str, probe: bytes) -> int:
    """레코드가 스스로 말하는 길이. 말하지 않으면 기본값.

    **레코드의 길이 필드를 그대로 믿지 않습니다** — 오프셋이 엉뚱한 곳을
    가리키면 그 자리의 아무 숫자나 길이로 읽히기 때문입니다. 말이 되는
    범위 밖이면 기본값으로 떨어뜨리고, 판단은 대조 쪽에 맡깁니다.
    """
    try:
        if artifact == "$MFT" and len(probe) >= 0x20:
            allocated = _u32(probe, 0x1C)
            return allocated if allocated in VALID_RECORD_SIZES else 1024

        if artifact == "$UsnJrnl" and len(probe) >= 4:
            length = _u32(probe, 0x0)
            # V2 헤더가 0x3C, 이름까지 붙어도 한 레코드가 이보다 크지 않다.
            if 0x3C <= length <= 1024 and length % 8 == 0:
                return length

        if artifact.startswith("evtx:") and len(probe) >= 8:
            size = _u32(probe, 0x4)
            # python-evtx 의 InvalidRecordException 과 같은 상한이다.
            if 0x18 <= size <= 0x10000:
                return min(size, MAX_AUTO_LENGTH)

        if artifact == "recentfilecache" and len(probe) >= 4:
            chars = _u32(probe, 0x0)
            if 0 < chars <= 512:
                return 4 + chars * 2 + 2
    except struct.error:
        pass
    return FALLBACK_LENGTH


def _context_for(artifact: str, stream: BinaryIO, file_size: int) -> "dict[str, Any]":
    """레코드 바이트 밖에서 와야 하는 사실을 모은다.

    지금은 SRUM 하나뿐입니다. ``offset``이 레코드가 아니라 **페이지**를
    가리키므로(``parsers/srum.py``), 그 페이지 크기를 알아야 대조가
    성립합니다. 그런데 **추측하면 안 됩니다** — 4096의 배수인지만 보면
    8192짜리 DB에서 엉뚱한 오프셋도 통과합니다. ESE 데이터베이스 헤더가
    ``0xEC``에 그 값을 들고 있으니 거기서 읽습니다.

    실측으로 확인했습니다 — ``SRUDB.dat``(win10_sysmon_testimage.001)의
    ``0x4``가 ``0x89ABCDEF``, ``0xEC``가 4096이고, ``dissect.esedb``의
    ``db.page_size``도 같은 값입니다.
    """
    if not artifact.startswith("srum:"):
        return {}

    header = _read_at(stream, 0, ESE_HEADER_PROBE)
    context: dict[str, Any] = {"file_size": file_size}
    if len(header) >= 0x8:
        context["ese_magic"] = _u32(header, 0x4)
    if len(header) >= ESE_HEADER_PROBE:
        context["page_size"] = _u32(header, ESE_PAGE_SIZE_AT)
    return context


def read_window(
    source: evidence.EvidenceSource,
    record: dict[str, Any],
    *,
    length: "int | None" = None,
) -> Window:
    """레코드가 가리키는 자리를 읽어 온다."""
    artifact = record["artifact"]
    offset = int(str(record["offset"]), 16)

    with _stream_for(source, record) as (path, stream):
        try:
            size = int(path.stat().st_size)
        except OSError:
            size = -1
        if size >= 0 and offset >= size:
            raise HexdumpError(
                f"{record['ref']}: 오프셋 0x{offset:X} 가 파일 크기 {size:,}바이트를 넘는다 "
                f"({path})"
            )

        want = length
        if want is None:
            probe = _read_at(stream, offset, PROBE_LENGTH)
            want = min(natural_length(artifact, probe), MAX_AUTO_LENGTH)

        # 창은 항상 offset 에서 시작한다. 레지스트리처럼 앞에 헤더가 더
        # 있는 구조(nk 앞 4바이트가 셀 크기다)라도 앞으로 물러서지 않는다 —
        # 덤프의 첫 바이트가 offset 이 가리키는 자리여야 되짚기가 성립한다.
        data = _read_at(stream, offset, want)
        context = _context_for(artifact, stream, size)

    located = source.locate(artifact)
    return Window(
        ref=str(record["ref"]),
        artifact=artifact,
        offset=offset,
        data=data,
        source=str(path),
        method=located.method if located is not None else "unknown",
        truncated=len(data) < want,
        context=context,
    )


# =============================================================== 대조


def _name_in(data: bytes, name: str) -> "Check | None":
    """레코드의 이름 문자열이 원본 바이트 안에 있는가.

    식별자 대조를 **보강**하는 검사입니다. 이름은 레코드 안에서 식별자와
    다른 자리에 있으므로, 둘이 같이 맞으면 우연일 가능성이 사라집니다.
    다만 어긋나도 실패로 세지 않습니다 — ``$MFT``는 업데이트 시퀀스가
    덮은 2바이트가 이름에 걸릴 수 있고, 잘린 창을 읽었을 수도 있습니다.
    """
    if not name:
        return None
    needle = name.encode("utf-16-le", "ignore")
    if needle and needle in data:
        return Check(True, "이름 문자열", f"{name!r} 가 원본 안에 있다", hard=False)
    if needle and needle.lower() in data.lower():
        return Check(True, "이름 문자열", f"{name!r} (대소문자 무시)", hard=False)
    return Check(False, "이름 문자열", f"{name!r} 를 이 구간에서 찾지 못했다", hard=False)


def _verify_mft(record: dict[str, Any], window: Window) -> list[Check]:
    data = window.data
    number = int(record["record_num"])
    checks: list[Check] = []

    signature = data[:4]
    checks.append(
        Check(
            signature in (b"FILE", b"BAAD"),
            "시그니처",
            f"{signature!r} (기대: FILE 또는 BAAD)",
        )
    )
    if len(data) < 0x30:
        checks.append(Check(False, "헤더", f"{len(data)}바이트뿐이라 헤더를 읽을 수 없다"))
        return checks

    header_number = _u32(data, 0x2C)
    if header_number:
        checks.append(
            Check(
                header_number == number,
                "헤더의 레코드 번호",
                f"0x2C = {header_number} / ref = {number}",
            )
        )
    else:
        # XP 이전이거나 값이 0이면 파서도 순회 순번을 썼다(parsers/mft.py).
        # 그때는 오프셋 자신이 유일한 근거다.
        size = _u32(data, 0x1C)
        size = size if size in VALID_RECORD_SIZES else 1024
        checks.append(
            Check(
                window.offset % size == 0 and window.offset // size == number,
                "순번(오프셋 ÷ 레코드 크기)",
                f"0x{window.offset:X} ÷ {size} = {window.offset // size} / ref = {number} "
                "(헤더의 번호가 0이라 순번으로 대조한다)",
            )
        )

    checks.extend(_update_sequence_checks(data))
    name = str(record.get("name") or "")
    name_check = _name_in(data, name)
    if name_check is not None:
        checks.append(name_check)
    return checks


def _update_sequence_checks(data: bytes) -> list[Check]:
    """업데이트 시퀀스가 섹터 끝마다 맞는가.

    **레코드 경계에 정확히 내려앉았다는 가장 강한 증거입니다.** NTFS는 각
    섹터의 마지막 2바이트를 같은 USN으로 덮어 씁니다. 오프셋이 한 섹터라도
    어긋나 있으면 이 값들이 서로 달라집니다.

    ``parsers/mft.py``와 달리 여기서는 **되돌리지 않고 확인만** 합니다.
    되돌리면 원본 바이트가 아니게 되고, 이 도구가 보여야 하는 것은 디스크에
    있는 그대로입니다.
    """
    try:
        usa_offset = _u16(data, 0x4)
        usa_count = _u16(data, 0x6)
    except struct.error:
        return []
    sectors = usa_count - 1
    if sectors <= 0 or usa_offset + usa_count * 2 > len(data):
        return [Check(False, "업데이트 시퀀스", f"배열 위치가 이상하다 (0x{usa_offset:X}, {usa_count}개)")]
    if len(data) % sectors:
        # 창이 잘렸다. 확인할 수 없는 것을 실패로 세지 않는다.
        return []

    sector_size = len(data) // sectors
    usn = data[usa_offset : usa_offset + 2]
    mismatched = [
        i for i in range(sectors) if data[(i + 1) * sector_size - 2 : (i + 1) * sector_size] != usn
    ]
    return [
        Check(
            not mismatched,
            "업데이트 시퀀스",
            f"섹터 {sectors}개의 끝 2바이트가 모두 {usn.hex().upper()} "
            f"(섹터 크기 {sector_size})"
            if not mismatched
            else f"섹터 {mismatched} 의 끝이 USN {usn.hex().upper()} 과 다르다",
        )
    ]


def _verify_usn(record: dict[str, Any], window: Window) -> list[Check]:
    data = window.data
    number = int(record["record_num"])
    if len(data) < 0x3C:
        return [Check(False, "헤더", f"{len(data)}바이트뿐이라 USN 헤더를 읽을 수 없다")]

    length = _u32(data, 0x0)
    major = _u16(data, 0x4)
    usn = _u64(data, 0x18)
    checks = [
        Check(0x3C <= length <= 1024 and length % 8 == 0, "레코드 크기", f"0x00 = {length}바이트"),
        Check(major == 2, "주 버전", f"0x04 = {major} (이 파서는 V2를 읽는다)"),
        Check(usn == number, "USN", f"0x18 = {usn} / ref = {number}"),
    ]
    name_check = _name_in(data, str(record.get("name") or ""))
    if name_check is not None:
        checks.append(name_check)
    return checks


def _verify_evtx(record: dict[str, Any], window: Window) -> list[Check]:
    data = window.data
    number = int(record["record_num"])
    if len(data) < 0x18:
        return [Check(False, "헤더", f"{len(data)}바이트뿐이라 레코드 헤더를 읽을 수 없다")]

    magic = data[:4]
    size = _u32(data, 0x4)
    record_id = _u64(data, 0x8)
    checks = [
        Check(magic == b"\x2a\x2a\x00\x00", "시그니처", f"{magic!r} (기대: b'**\\x00\\x00')"),
        Check(record_id == number, "EventRecordID", f"0x08 = {record_id} / ref = {number}"),
    ]
    if 0x18 <= size <= len(data):
        # 레코드 끝에 크기가 한 번 더 있다. 둘이 같으면 경계가 맞다.
        checks.append(
            Check(_u32(data, size - 4) == size, "레코드 끝의 크기 반복", f"0x04 = {size}")
        )
    return checks


def _verify_registry(record: dict[str, Any], window: Window) -> list[Check]:
    data = window.data
    number = int(record["record_num"])
    checks = [
        Check(data[:2] == b"nk", "시그니처", f"{data[:2]!r} (기대: b'nk')"),
        # 레지스트리에는 일련번호가 없어 오프셋이 곧 식별자다(refs.py).
        Check(window.offset == number, "오프셋 = record_num", f"0x{window.offset:X} = {number}"),
    ]
    if len(data) < 0x4C:
        checks.append(Check(False, "헤더", f"{len(data)}바이트뿐이라 이름을 읽을 수 없다"))
        return checks

    flags = _u16(data, 0x2)
    name_length = _u16(data, 0x48)
    raw = data[0x4C : 0x4C + name_length]
    if len(raw) == name_length:
        name = raw.decode("windows-1252" if flags & 0x0020 else "utf-16-le", "replace")
        checks.append(
            Check(
                name == str(record.get("name") or ""),
                "키 이름",
                f"0x4C = {name!r} / 레코드 = {record.get('name')!r}",
            )
        )
    return checks


def _verify_recentfilecache(record: dict[str, Any], window: Window) -> list[Check]:
    data = window.data
    number = int(record["record_num"])
    checks = [
        Check(window.offset == number, "오프셋 = record_num", f"0x{window.offset:X} = {number}"),
    ]
    if len(data) < 6:
        checks.append(Check(False, "항목", f"{len(data)}바이트뿐이라 항목을 읽을 수 없다"))
        return checks

    chars = _u32(data, 0x0)
    raw = data[4 : 4 + chars * 2]
    if len(raw) == chars * 2:
        # 길이 필드가 **문자 수**다. 바이트로 잘못 읽으면 여기서 어긋난다.
        path = raw.decode("utf-16-le", "replace")
        checks.append(
            Check(
                path == str(record.get("path") or ""),
                "경로",
                f"{path!r} / 레코드 = {record.get('path')!r}",
            )
        )
        end = 4 + chars * 2
        if len(data) >= end + 2:
            checks.append(
                Check(data[end : end + 2] == b"\x00\x00", "종결자", f"{data[end:end + 2]!r}")
            )
    return checks


def _verify_prefetch(record: dict[str, Any], window: Window) -> list[Check]:
    data = window.data
    number = int(record["record_num"])
    name = str((record.get("fields") or {}).get("prefetch_file") or "")

    checks = [
        # 레코드가 곧 파일이라 되짚을 자리가 파일 시작뿐이다(parsers/prefetch.py).
        Check(window.offset == 0, "오프셋", f"0x{window.offset:X} (프리패치는 항상 0x0)"),
    ]

    stem = name.rsplit(".", 1)[0]
    tail = stem.rsplit("-", 1)[-1] if "-" in stem else ""
    if len(tail) == 8:
        try:
            checks.append(
                Check(
                    int(tail, 16) == number,
                    "파일명의 경로 해시",
                    f"{name} → 0x{tail} = {int(tail, 16)} / ref = {number}",
                )
            )
        except ValueError:
            checks.append(Check(False, "파일명의 경로 해시", f"{name} 의 뒤 8자리가 16진수가 아니다"))

    compressed = data[:4] == b"MAM\x04"
    if compressed:
        checks.append(
            Check(True, "형식", "MAM 압축본이다 — 헤더가 압축돼 있어 해시 대조는 파일명으로만 한다")
        )
        return checks

    if len(data) >= 8:
        checks.append(Check(data[4:8] == b"SCCA", "시그니처", f"{data[4:8]!r} (기대: b'SCCA')"))
    if len(data) >= 0x50:
        # 비압축본은 헤더 0x4C 에 경로 해시가 그대로 있다.
        checks.append(
            Check(_u32(data, 0x4C) == number, "헤더 0x4C 의 경로 해시", f"{_u32(data, 0x4C)} / ref = {number}")
        )
    return checks


def _verify_srum(record: dict[str, Any], window: Window) -> list[Check]:
    """SRUM 은 페이지까지만 대조된다.

    ESE 레코드는 페이지 안에서 태그로 가리켜지고 압축된 키 접두어를
    공유해서, 레코드 하나의 시작 바이트를 파일 좌표로 말할 수 없습니다
    (``parsers/srum.py``의 ``_file_offset``). 그 사실을 감추지 않고
    출력에 싣습니다.

    **그 안에서는 최대한 조입니다.** "4096의 배수인가"만 보면 8192짜리
    DB에서 절반이 엉뚱한 오프셋도 통과합니다. 페이지 크기는 DB 헤더가
    말하는 값을 쓰고, 앞의 두 페이지(헤더와 그림자)에는 레코드가 있을 수
    없다는 것과 페이지가 파일 안에 있다는 것까지 봅니다.
    """
    magic = window.context.get("ese_magic")
    page_size = int(window.context.get("page_size") or 0)
    file_size = int(window.context.get("file_size") or 0)

    checks = [
        Check(
            magic == ESE_MAGIC,
            "ESE 데이터베이스",
            f"0x04 = 0x{magic:08X} (기대: 0x{ESE_MAGIC:08X})"
            if isinstance(magic, int)
            else "파일 헤더를 읽지 못했다",
        )
    ]
    if page_size <= 0 or page_size % 512:
        checks.append(
            Check(False, "페이지 크기", f"헤더 0x{ESE_PAGE_SIZE_AT:X} 의 값이 이상하다 ({page_size})")
        )
        return checks

    page = window.offset // page_size
    checks.append(
        Check(
            window.offset % page_size == 0,
            "페이지 경계",
            f"0x{window.offset:X} ÷ {page_size} = {page}"
            + ("" if window.offset % page_size == 0 else " — 나머지가 있다"),
        )
    )
    checks.append(
        Check(
            page >= ESE_RESERVED_PAGES,
            "예약 페이지",
            f"{page}번 페이지 (앞 {ESE_RESERVED_PAGES}개는 DB 헤더와 그림자라 레코드가 없다)",
        )
    )
    if file_size > 0:
        checks.append(
            Check(
                window.offset + page_size <= file_size,
                "파일 범위",
                f"페이지 끝 0x{window.offset + page_size:X} ≤ 파일 크기 0x{file_size:X}",
            )
        )
    checks.append(
        Check(
            True,
            "대조 한계",
            "ESE 레코드는 페이지 안에서 태그로 가리켜진다 — 이 오프셋은 "
            f"레코드가 실린 **페이지**이고, 그 안에서는 AutoIncId {record['record_num']} 로 찾는다",
            hard=False,
        )
    )
    return checks


def verify(record: dict[str, Any], window: Window) -> list[Check]:
    """되짚은 바이트가 정말 그 레코드인가."""
    artifact = window.artifact
    if artifact == "$MFT":
        return _verify_mft(record, window)
    if artifact == "$UsnJrnl":
        return _verify_usn(record, window)
    if artifact.startswith("evtx:"):
        return _verify_evtx(record, window)
    if artifact.startswith("registry:"):
        return _verify_registry(record, window)
    if artifact == "recentfilecache":
        return _verify_recentfilecache(record, window)
    if artifact == "prefetch":
        return _verify_prefetch(record, window)
    if artifact.startswith("srum:"):
        return _verify_srum(record, window)
    # 아티팩트가 늘었는데 여기 안 넣은 경우다. 조용히 통과시키지 않는다 —
    # "대조했다"와 "대조할 줄 모른다"는 다르다.
    return [Check(False, "대조", f"{artifact} 를 어떻게 대조하는지 이 도구가 모른다")]


# =============================================================== 출력


def hexdump(data: bytes, base: int, width: int = DUMP_WIDTH) -> Iterator[str]:
    """``xxd`` 모양. 왼쪽 열은 **파일 안의 절대 위치**다."""
    for start in range(0, len(data), width):
        chunk = data[start : start + width]
        left = " ".join(f"{b:02X}" for b in chunk[: width // 2])
        right = " ".join(f"{b:02X}" for b in chunk[width // 2 :])
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        hexed = f"{left:<{(width // 2) * 3 - 1}}  {right}".rstrip()
        yield f"  0x{base + start:08X}  {hexed:<{width * 3 + 1}}  |{text}|"


def _report(record: dict[str, Any], window: Window, checks: list[Check], *, dump: bool) -> bool:
    """한 건을 사람이 읽을 모양으로 찍는다. 대조를 통과했으면 참."""
    print(f"{window.ref}  {window.artifact}")
    print(f"  출처    {window.source}" + ("  (재귀 검색으로 찾은 파일)" if window.method == "search" else ""))
    print(f"  오프셋  0x{window.offset:X} ({window.offset:,}) · {len(window.data)}바이트" + ("  ※ 파일 끝에 걸려 잘렸다" if window.truncated else ""))
    for check in checks:
        mark = "✓" if check.ok else ("✗" if check.hard else "·")
        print(f"  {mark} {check.label}: {check.detail}")
    if window.artifact == "$MFT":
        print("  ※ 업데이트 시퀀스를 되돌리기 전의 바이트다 (섹터 끝 2바이트가 USN)")
    if dump:
        print()
        for line in hexdump(window.data, window.offset):
            print(line)
    print()
    return all(check.ok for check in checks if check.hard)


# =============================================================== CLI


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python tools/hexdump_record.py",
        description="04단계가 남긴 offset 으로 원본 바이트를 되짚는다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "예:\n"
            "  hexdump_record.py MFT#12345 --parsed cases/K-ALERT/04_parsed \\\n"
            "      --evidence evidence/0824test.001 --volume 1\n"
            "  hexdump_record.py --sample 20 --parsed cases/K-ALERT/04_parsed \\\n"
            "      --evidence evidence/0824test.001 --volume 1\n"
        ),
    )
    parser.add_argument("refs", nargs="*", metavar="REF", help="되짚을 ref (예: MFT#12345)")
    parser.add_argument(
        "--parsed", required=True, help="04_parsed 디렉터리 (레코드를 여기서 찾는다)"
    )
    parser.add_argument("--evidence", required=True, help="볼륨 루트 또는 디스크 이미지")
    parser.add_argument(
        "--volume", type=int, default=None, help="이미지에 NTFS가 여럿일 때 볼 볼륨 번호"
    )
    parser.add_argument(
        "--length", type=int, default=None, help="읽을 바이트 수 (기본: 레코드가 말하는 길이)"
    )
    parser.add_argument("--no-dump", action="store_true", help="덤프 없이 대조 결과만")
    parser.add_argument(
        "--sample",
        type=int,
        default=None,
        metavar="N",
        help="아티팩트마다 N건씩 균등 간격으로 골라 대조한다 (덤프 없음)",
    )
    parser.add_argument(
        "--artifact", default=None, help="--sample 을 이 아티팩트에만 건다 (예: '$MFT')"
    )
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    _io.configure_console()
    args = _parse_args(argv)

    parsed_dir = Path(args.parsed)
    if not parsed_dir.is_dir():
        print(f"04_parsed 디렉터리가 아니다: {parsed_dir}", file=sys.stderr)
        return 1

    if args.sample is not None:
        if args.sample <= 0:
            print("--sample 은 1 이상이어야 한다", file=sys.stderr)
            return 1
        if args.refs:
            # 조용히 무시하면 "골라 준 것을 봤다"고 오해한다.
            print(
                f"--sample 과 ref 를 같이 줄 수 없다 (준 ref: {', '.join(args.refs)}). "
                "표본을 보려면 ref 를 빼고, 그 레코드를 보려면 --sample 을 뺀다",
                file=sys.stderr,
            )
            return 1
        if args.artifact is not None and args.artifact not in OUTPUT_FILENAMES:
            # "레코드가 없다"로 뭉뚱그리면 이름 오타와 빈 산출물이 같아 보인다.
            print(
                f"--artifact {args.artifact!r} 는 04단계가 아는 이름이 아니다 "
                f"(예: {', '.join(sorted(OUTPUT_FILENAMES)[:3])} …)",
                file=sys.stderr,
            )
            return 1
        targets = sample_refs(parsed_dir, args.sample, args.artifact)
        if not targets:
            where = f"{parsed_dir} 의 {args.artifact}" if args.artifact else str(parsed_dir)
            print(f"{where} 에 고를 레코드가 없다 (그 아티팩트를 파싱한 적이 없다)", file=sys.stderr)
            return 1
    else:
        targets = list(args.refs)
        if not targets:
            print("되짚을 ref 를 주거나 --sample 을 쓴다", file=sys.stderr)
            return 1

    dump = not args.no_dump and args.sample is None

    try:
        source = evidence.open_source(args.evidence, volume=args.volume)
    except evidence.EvidenceError as e:
        print(f"증거를 열 수 없다: {e}", file=sys.stderr)
        return 1

    passed = 0
    failed: list[str] = []
    for ref in targets:
        try:
            record = find_record(parsed_dir, ref)
            window = read_window(source, record, length=args.length)
            checks = verify(record, window)
        except (HexdumpError, refs.RefError, evidence.EvidenceError) as e:
            print(f"{ref}: {e}", file=sys.stderr)
            failed.append(ref)
            continue

        if _report(record, window, checks, dump=dump):
            passed += 1
        else:
            failed.append(ref)

    total = len(targets)
    print(f"되짚음 {passed}/{total}건" + (f", 어긋남 {len(failed)}건: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
