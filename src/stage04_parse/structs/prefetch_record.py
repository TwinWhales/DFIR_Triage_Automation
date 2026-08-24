"""프리패치(.pf) 온디스크 구조 정의.

**여기에는 구조만 있습니다.** 오프셋, 크기, 필드 타입, 그리고 그것을 읽는
것 이상의 판단이 필요 없는 변환(FILETIME, UTF-16 디코딩)뿐입니다.

디렉터리를 훑고, 범위로 추리고, 레코드를 조립하는 로직은
``parsers/prefetch.py``에 있습니다.

## 출처

* ``[LIBSCCA]`` Windows Prefetch File (PF) format, Joachim Metz —
  헤더·파일 정보·파일 메트릭·볼륨 정보 레이아웃.
* ``[MS-XCA]`` — ``MAM`` 압축(``structs/xpress_huffman.py``).

## 버전마다 다른 것은 두 가지뿐이다

구조 전체가 버전마다 바뀌는 것처럼 보이지만 실제로 움직이는 것은 둘입니다.

* **실행 시각과 실행 횟수의 자리.** 버전 17·23은 실행 시각이 하나,
  26 이상은 여덟 개입니다.
* **배열 원소 크기.** 파일 메트릭 20 → 32바이트, 볼륨 정보 40 → 104 → 96바이트.

반대로 **파일 정보 블록 앞머리 9개 dword(0x00~0x23)는 모든 버전에서
같은 자리**입니다. 메트릭 배열·파일명 문자열·볼륨 정보의 위치와 개수가
전부 여기 있으므로, 적재 파일 목록과 볼륨은 버전과 무관하게 한 경로로
읽힙니다. 버전 분기는 ``FILE_INFORMATION`` 표 하나에 갇혀 있습니다.

## 표에 없는 조합은 읽지 않는다

``FILE_INFORMATION``은 **(버전, 파일 정보 블록 크기)** 로 찾습니다. 블록
크기는 표에서 가져오지 않고 **파일 자신이 말하는 값**(메트릭 배열 오프셋
- 헤더 크기)을 씁니다. 버전 30은 Windows 10 빌드에 따라 블록 크기가 달라
버전 번호만으로는 자리를 정할 수 없기 때문입니다.

표에 없는 조합을 만나면 **추측하지 않고 실패합니다**(``UnknownLayout``).
실행 횟수 자리를 잘못 잡으면 예외도 경고도 없이 그럴듯한 숫자가 나오고,
그것이 보고서에 "3회 실행됨"으로 실립니다. 조용히 틀리는 쪽이 못 읽는
쪽보다 나쁩니다.

## 실측으로 확인된 것은 버전 23뿐이다

``evidence/[root]`` 의 73건이 전부 버전 23입니다. 나머지 버전의 자리는
명세를 옮긴 것이며, 잘못 옮겼을 때를 대비해 ``plausible_run_count`` /
``plausible_run_times`` 로 값의 앞뒤를 봅니다. 자리가 어긋나면 FILETIME
여덟 개가 전부 그럴듯하게 나올 확률이 낮다는 것에 기댄 검사입니다.
``docs/limitations.md``에 적혀 있습니다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone

from .mft_record import StructError, filetime_to_datetime

__all__ = [
    "PrefetchError",
    "UnknownLayout",
    "SIGNATURE",
    "MAM_SIGNATURE",
    "HEADER_SIZE",
    "MAX_FILE_SIZE",
    "MAX_RUN_COUNT",
    "FILE_INFORMATION",
    "FileInfoLayout",
    "Header",
    "FileInformation",
    "Volume",
    "is_compressed",
    "decompress_mam",
    "read_header",
    "layout_for",
    "read_file_information",
    "read_filenames",
    "read_volumes",
    "plausible_run_count",
    "plausible_run_times",
]


class PrefetchError(StructError):
    """프리패치 파일 하나를 읽지 못했다."""


class UnknownLayout(PrefetchError):
    """(버전, 파일 정보 크기) 조합이 표에 없다.

    **손상이 아니라 우리가 모르는 것입니다.** 새 Windows 빌드가 블록
    크기를 바꾸면 여기로 옵니다. 메시지에 두 값을 다 담아, 표에 한 줄
    추가하면 되는 일임이 드러나게 합니다.
    """


#: 압축이 풀린 뒤의 시그니처. 헤더 0x04에 있다.
SIGNATURE = b"SCCA"

#: Windows 10 이후의 압축 컨테이너 시그니처. 네 번째 바이트가 압축 방식이고
#: 0x04 가 LZXPRESS Huffman 이다.
MAM_SIGNATURE = b"MAM\x04"

#: ``MAM`` 헤더 크기. 시그니처 4 + 해제 후 크기 4.
MAM_HEADER_SIZE = 8

#: 헤더 크기. 파일 정보 블록이 바로 뒤에 붙는다.
HEADER_SIZE = 84

#: 실행 파일 이름 자리(UTF-16LE). 0x10~0x4B.
_EXECUTABLE_OFFSET = 0x10
_EXECUTABLE_SIZE = 60

#: 해제 후 크기 상한. 정상 프리패치는 아무리 커도 몇 MB다. 깨진 ``MAM``
#: 헤더 하나가 수 GB를 할당하게 두지 않는다.
MAX_FILE_SIZE = 64 * 1024 * 1024

#: 실행 횟수 상한. 자리를 잘못 잡았는지 보는 기준이다. 실제 값은 보통
#: 한 자리~수백이고, 엉뚱한 자리를 읽으면 대개 수억이 나온다.
MAX_RUN_COUNT = 1_000_000

#: 실행 시각이 그럴듯한지 보는 하한. Windows 프리패치가 존재한 뒤다.
_EARLIEST_RUN = datetime(1995, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class FileInfoLayout:
    """버전 하나의 파일 정보 블록에서 움직이는 자리들."""

    #: 블록 크기. ``(버전, 이 값)`` 이 표의 키다.
    size: int
    #: 실행 시각 배열의 블록 내 오프셋.
    run_time_offset: int
    #: 실행 시각 개수. 17·23은 1, 26 이상은 8.
    run_time_count: int
    #: 실행 횟수(dword)의 블록 내 오프셋.
    run_count_offset: int
    #: 파일 메트릭 배열 원소 크기.
    metrics_entry_size: int
    #: 볼륨 정보 배열 원소 크기.
    volume_entry_size: int
    #: 이 자리를 무엇으로 확인했는지. 실측인지 명세인지 구분한다.
    source: str


#: (버전, 파일 정보 블록 크기) → 자리.
#:
#: 버전 23만 실측입니다(``evidence/[root]`` 73건). 나머지는 [LIBSCCA] 를
#: 옮긴 것이고 ``plausible_*`` 검사가 뒤를 받칩니다.
FILE_INFORMATION: dict[tuple[int, int], FileInfoLayout] = {
    (17, 68): FileInfoLayout(
        size=68,
        run_time_offset=0x24,
        run_time_count=1,
        run_count_offset=0x3C,
        metrics_entry_size=20,
        volume_entry_size=40,
        source="[LIBSCCA] Windows XP/2003",
    ),
    (23, 156): FileInfoLayout(
        size=156,
        run_time_offset=0x2C,
        run_time_count=1,
        run_count_offset=0x44,
        metrics_entry_size=32,
        volume_entry_size=104,
        source="실측 evidence/[root] 73건 (Windows 7)",
    ),
    (26, 224): FileInfoLayout(
        size=224,
        run_time_offset=0x2C,
        run_time_count=8,
        run_count_offset=0x7C,
        metrics_entry_size=32,
        volume_entry_size=104,
        source="[LIBSCCA] Windows 8.1",
    ),
    (30, 224): FileInfoLayout(
        size=224,
        run_time_offset=0x2C,
        run_time_count=8,
        run_count_offset=0x7C,
        metrics_entry_size=32,
        volume_entry_size=96,
        source="[LIBSCCA] Windows 10 (1809 이하)",
    ),
    (30, 220): FileInfoLayout(
        size=220,
        run_time_offset=0x2C,
        run_time_count=8,
        run_count_offset=0x7C,
        metrics_entry_size=32,
        volume_entry_size=96,
        source="실측 evidence/0824test.001 137건 (Windows 10)",
    ),
    (30, 216): FileInfoLayout(
        size=216,
        run_time_offset=0x2C,
        run_time_count=8,
        run_count_offset=0x74,
        metrics_entry_size=32,
        volume_entry_size=96,
        source="[LIBSCCA] Windows 10 (1903 이상)",
    ),
    (31, 224): FileInfoLayout(
        size=224,
        run_time_offset=0x2C,
        run_time_count=8,
        run_count_offset=0x7C,
        metrics_entry_size=32,
        volume_entry_size=96,
        source="[LIBSCCA] Windows 11",
    ),
}


@dataclass(frozen=True)
class Header:
    """.pf 헤더 84바이트."""

    version: int
    #: 헤더가 말하는 파일 크기. 실제 크기와 다르면 잘렸거나 덧붙었다.
    file_size: int
    #: 실행 파일 이름. 경로가 아니라 이름뿐이며 29자에서 잘린다.
    executable: str
    #: 실행 파일 **전체 경로**의 해시. 파일명 뒤 8자리 16진수와 같은 값이다.
    path_hash: int
    flags: int


@dataclass(frozen=True)
class FileInformation:
    """파일 정보 블록에서 뽑은 값."""

    metrics_offset: int
    metrics_count: int
    trace_offset: int
    trace_count: int
    strings_offset: int
    strings_size: int
    volumes_offset: int
    volumes_count: int
    volumes_size: int
    #: 최근 실행 시각들. 최신이 앞이다. 값이 없는 자리는 ``None``.
    run_times: tuple[datetime | None, ...]
    run_count: int


@dataclass(frozen=True)
class Volume:
    """볼륨 정보 하나."""

    #: ``\\DEVICE\\HARDDISKVOLUME2`` 형태. 드라이브 문자가 아니다.
    device_path: str
    serial_number: int
    created: datetime | None
    directory_count: int


def is_compressed(data: bytes) -> bool:
    """``MAM`` 컨테이너인가."""
    return data[:4] == MAM_SIGNATURE


def decompress_mam(data: bytes) -> bytes:
    """``MAM\\x04`` 컨테이너를 풀어 원래 .pf 바이트로.

    헤더는 시그니처 4바이트 + 해제 후 크기 4바이트입니다. 크기를 헤더가
    들고 있는 덕분에 압축 스트림만 보고 어디서 멈출지 고민할 필요가
    없습니다(``xpress_huffman.decompress``가 그 값을 요구합니다).
    """
    from .xpress_huffman import XpressError, decompress

    if len(data) < MAM_HEADER_SIZE:
        raise PrefetchError(f"MAM 헤더가 잘렸습니다 ({len(data)}바이트)")
    if data[:4] != MAM_SIGNATURE:
        raise PrefetchError(
            f"지원하지 않는 압축 컨테이너입니다: {data[:4]!r} "
            f"(아는 것은 {MAM_SIGNATURE!r} = LZXPRESS Huffman)"
        )
    size = struct.unpack_from("<I", data, 4)[0]
    if size == 0 or size > MAX_FILE_SIZE:
        raise PrefetchError(f"MAM 헤더의 해제 후 크기가 비정상입니다: {size}")
    try:
        return decompress(data[MAM_HEADER_SIZE:], size)
    except XpressError as e:
        raise PrefetchError(f"MAM 압축 해제 실패: {e}") from e


def read_header(data: bytes) -> Header:
    """헤더를 읽는다. ``SCCA``가 아니면 프리패치가 아니다."""
    if len(data) < HEADER_SIZE:
        raise PrefetchError(f"헤더가 잘렸습니다 ({len(data)}바이트, 최소 {HEADER_SIZE})")
    version, signature, _unknown, file_size = struct.unpack_from("<I4sII", data, 0)
    if signature != SIGNATURE:
        raise PrefetchError(f"프리패치 파일이 아닙니다 (시그니처 {signature!r})")

    raw_name = data[_EXECUTABLE_OFFSET : _EXECUTABLE_OFFSET + _EXECUTABLE_SIZE]
    executable = raw_name.decode("utf-16-le", "replace").split("\x00", 1)[0]

    path_hash, flags = struct.unpack_from("<II", data, 0x4C)
    return Header(
        version=version,
        file_size=file_size,
        executable=executable,
        path_hash=path_hash,
        flags=flags,
    )


def layout_for(version: int, file_info_size: int) -> FileInfoLayout:
    """``(버전, 블록 크기)``에 맞는 자리. 없으면 ``UnknownLayout``."""
    try:
        return FILE_INFORMATION[(version, file_info_size)]
    except KeyError:
        known = ", ".join(f"{v}/{s}" for v, s in sorted(FILE_INFORMATION))
        raise UnknownLayout(
            f"모르는 프리패치 레이아웃입니다 (버전 {version}, 파일 정보 {file_info_size}바이트). "
            f"아는 조합(버전/크기): {known}. "
            "structs/prefetch_record.py 의 FILE_INFORMATION 에 추가하십시오."
        ) from None


def read_file_information(data: bytes) -> tuple[FileInformation, FileInfoLayout]:
    """파일 정보 블록을 읽는다.

    **블록 크기를 표에서 가져오지 않고 파일이 말하는 값을 씁니다.**
    메트릭 배열이 블록 바로 뒤에 붙으므로 ``메트릭 오프셋 - 헤더 크기``가
    곧 블록 크기입니다. 버전 30은 빌드에 따라 이 값이 달라 버전만으로는
    자리를 정할 수 없습니다.
    """
    header = read_header(data)
    if len(data) < HEADER_SIZE + 36:
        raise PrefetchError(f"파일 정보 블록이 잘렸습니다 ({len(data)}바이트)")

    (
        metrics_offset,
        metrics_count,
        trace_offset,
        trace_count,
        strings_offset,
        strings_size,
        volumes_offset,
        volumes_count,
        volumes_size,
    ) = struct.unpack_from("<9I", data, HEADER_SIZE)

    file_info_size = metrics_offset - HEADER_SIZE
    if file_info_size <= 0:
        raise PrefetchError(
            f"메트릭 배열 오프셋이 헤더 안을 가리킵니다 (0x{metrics_offset:X}). 파일이 깨졌습니다."
        )
    layout = layout_for(header.version, file_info_size)

    base = HEADER_SIZE
    if len(data) < base + layout.size:
        raise PrefetchError(
            f"파일 정보 블록이 잘렸습니다 ({len(data)}바이트, 최소 {base + layout.size})"
        )

    run_times = tuple(
        filetime_to_datetime(
            struct.unpack_from("<Q", data, base + layout.run_time_offset + i * 8)[0]
        )
        for i in range(layout.run_time_count)
    )
    run_count = struct.unpack_from("<I", data, base + layout.run_count_offset)[0]

    return (
        FileInformation(
            metrics_offset=metrics_offset,
            metrics_count=metrics_count,
            trace_offset=trace_offset,
            trace_count=trace_count,
            strings_offset=strings_offset,
            strings_size=strings_size,
            volumes_offset=volumes_offset,
            volumes_count=volumes_count,
            volumes_size=volumes_size,
            run_times=run_times,
            run_count=run_count,
        ),
        layout,
    )


def read_filenames(
    data: bytes, info: FileInformation, layout: FileInfoLayout
) -> tuple[list[str], int]:
    """적재된 파일 경로 목록과 **읽지 못한 항목 수**.

    메트릭 배열의 각 원소가 문자열 블록 안의 자기 위치를 가리킵니다.
    문자열 블록을 널 기준으로 그냥 쪼개는 편이 짧지만, 그러면 원소와
    문자열의 대응이 우리 가정이 되고 어긋나도 드러나지 않습니다.

    경로는 ``\\DEVICE\\HARDDISKVOLUMEn\\...`` 형태 그대로입니다. 드라이브
    문자로 바꾸는 것은 판단이 필요한 일이라 파서가 합니다.

    원소 하나가 범위를 벗어나면 **그 원소만** 건너뜁니다. 나머지 목록은
    여전히 증거입니다.
    """
    names: list[str] = []
    skipped = 0

    for index in range(info.metrics_count):
        entry = info.metrics_offset + index * layout.metrics_entry_size
        if entry + layout.metrics_entry_size > len(data):
            skipped += info.metrics_count - index
            break
        # 문자열 오프셋과 문자 수는 17과 23 이상에서 자리가 다르다.
        # 앞의 두 dword(시작 시각·지속)는 같고, 17에는 평균 지속이 없다.
        name_offset_field = 0x08 if layout.metrics_entry_size == 20 else 0x0C
        name_offset, char_count = struct.unpack_from("<II", data, entry + name_offset_field)

        start = info.strings_offset + name_offset
        end = start + char_count * 2
        if name_offset + char_count * 2 > info.strings_size or end > len(data):
            skipped += 1
            continue
        names.append(data[start:end].decode("utf-16-le", "replace").rstrip("\x00"))

    return names, skipped


def read_volumes(
    data: bytes, info: FileInformation, layout: FileInfoLayout
) -> tuple[list[Volume], int]:
    """볼륨 정보 목록과 읽지 못한 항목 수.

    앞 0x28바이트는 모든 버전에서 같습니다. 버전마다 다른 것은 뒤에 붙는
    미상 필드의 길이(= 원소 크기)뿐입니다.
    """
    volumes: list[Volume] = []
    skipped = 0

    for index in range(info.volumes_count):
        entry = info.volumes_offset + index * layout.volume_entry_size
        if entry + 0x28 > len(data):
            skipped += info.volumes_count - index
            break
        (
            path_offset,
            path_chars,
            created,
            serial,
            _refs_offset,
            _refs_size,
            _dirs_offset,
            dirs_count,
        ) = struct.unpack_from("<IIQIIIII", data, entry)

        start = info.volumes_offset + path_offset
        end = start + path_chars * 2
        if end > len(data):
            skipped += 1
            continue
        volumes.append(
            Volume(
                device_path=data[start:end].decode("utf-16-le", "replace").rstrip("\x00"),
                serial_number=serial,
                created=filetime_to_datetime(created),
                directory_count=dirs_count,
            )
        )

    return volumes, skipped


def plausible_run_count(value: int) -> bool:
    """실행 횟수가 그럴듯한가. 자리를 잘못 잡았는지 보는 검사다."""
    return 0 <= value <= MAX_RUN_COUNT


def plausible_run_times(run_times: "tuple[datetime | None, ...]") -> bool:
    """실행 시각이 그럴듯한가.

    **하나라도 읽혔고, 읽힌 것이 전부 1995년 이후면** 통과입니다. 전부
    ``None``인 것도 정상입니다 — 여덟 칸 중 뒤쪽은 실행 이력이 쌓이기
    전까지 비어 있습니다. 자리가 어긋났다면 쓰레기 QWORD가 1601년이나
    수만 년 뒤로 나오므로 ``filetime_to_datetime``이 ``None``을 주거나
    이 하한에 걸립니다.
    """
    return all(moment >= _EARLIEST_RUN for moment in run_times if moment is not None)
