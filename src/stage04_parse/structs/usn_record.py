"""$UsnJrnl:$J 온디스크 구조 정의.

**여기에는 구조만 있습니다.** 오프셋, 크기, 필드 타입, 그리고 그것을
읽는 것 이상의 판단이 필요 없는 변환(FILETIME, 비트마스크 해석)뿐입니다.

스트림을 순회하고, 스파스 구간을 건너뛰고, 손상 후 재동기화하는 로직은
``parsers/usnjrnl.py``에 있습니다.

## 출처

레코드 레이아웃은 두 곳을 대조해 적었습니다.

* ``[LIBFSNTFS]`` New Technologies File System (NTFS), Joachim Metz,
  rev 0.0.28 — "USN change journal entry (USN_RECORD_V2)"
* MSDN ``USN_RECORD_V2`` (``winioctl.h``)

``$MFT`` 구조와 달리 **USN 레코드는 Microsoft가 공개한 API 구조체**라
리버싱 문서가 유일한 근거가 아닙니다. 두 출처가 일치합니다.

## 두 가지 함정

**이름 길이는 문자 수가 아니라 바이트 수입니다.** ``$FILE_NAME``
속성(``mft_record.FileName``)은 문자 수인데 여기는 바이트 수입니다.
``$MFT`` 파서 코드를 옮겨 오면 반드시 밟습니다.

**USN 값은 스트림 안의 자기 오프셋입니다.** 고유 식별자인 동시에 위치라
``ref``와 ``offset``을 같은 값에서 뽑을 수 있습니다. 다만 **추출된 $J
파일에서는 둘이 어긋날 수 있습니다** — 도구가 스파스 구간을 잘라내고
저장하면 파일 오프셋이 USN보다 작아집니다. 그래서 파서는 둘을 따로
기록합니다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime
from enum import IntFlag

from .mft_record import StructError, filetime_to_datetime

__all__ = [
    "RECORD_ALIGNMENT",
    "V2_HEADER_SIZE",
    "MAX_RECORD_SIZE",
    "SUPPORTED_MAJOR_VERSION",
    "UnsupportedVersion",
    "UsnReason",
    "UsnSource",
    "FILE_ATTRIBUTE_DIRECTORY",
    "FILE_ATTRIBUTE_DIRECTORY_NTFS",
    "FileReference",
    "UsnRecord",
    "decode_flags",
    "reason_names",
    "source_names",
]

#: 레코드는 8바이트 경계에 놓인다. 재동기화 스캔의 보폭이 이 값이다.
RECORD_ALIGNMENT = 8

#: 이름을 뺀 V2 레코드 헤더 크기.
V2_HEADER_SIZE = 60

#: 레코드 크기 상한. 이름은 최대 255자(UTF-16으로 510바이트)이므로
#: 60 + 510 = 570 을 넘을 수 없다. 넉넉히 잡아 이보다 크면 손상으로 본다.
#: 상한이 없으면 깨진 길이 값 하나가 스트림 전체를 건너뛰게 만든다.
MAX_RECORD_SIZE = 4096

#: 온디스크 $J 에 담기는 레코드 버전. V3(128비트 파일 ID)와 V4(범위 추적)는
#: API로는 존재하지만 NTFS 저널 스트림에서는 보지 못했다. 만나면 조용히
#: V2로 오해하지 말고 건너뛴다 — 필드가 통째로 밀린다.
SUPPORTED_MAJOR_VERSION = 2

#: USN 레코드로 실재하는 버전. 여기 없는 값은 "지원하지 않는 버전"이
#: 아니라 **애초에 레코드가 아니다.** 둘을 뭉뚱그리면 손상 구간을
#: 재스캔하다 나온 쓰레기가 "V0 레코드"로 집계된다.
KNOWN_MAJOR_VERSIONS = (2, 3, 4)


class UnsupportedVersion(StructError):
    """실재하지만 우리가 읽지 않는 버전(V3/V4).

    ``record_length``를 들고 있습니다. 파서가 **레코드 하나를 통째로**
    건너뛸 수 있어야 하기 때문입니다. 8바이트씩 걸어 들어가면 레코드
    본문을 레코드로 오해해 가짜 손상이 줄줄이 잡힙니다.
    """

    def __init__(self, message: str, record_length: int) -> None:
        super().__init__(message)
        self.record_length = record_length


class UsnReason(IntFlag):
    """변경 사유 비트마스크 (``USN_REASON_*``)."""

    DATA_OVERWRITE = 0x00000001
    DATA_EXTEND = 0x00000002
    DATA_TRUNCATION = 0x00000004
    NAMED_DATA_OVERWRITE = 0x00000010
    NAMED_DATA_EXTEND = 0x00000020
    NAMED_DATA_TRUNCATION = 0x00000040
    FILE_CREATE = 0x00000100
    FILE_DELETE = 0x00000200
    EA_CHANGE = 0x00000400
    SECURITY_CHANGE = 0x00000800
    RENAME_OLD_NAME = 0x00001000
    RENAME_NEW_NAME = 0x00002000
    INDEXABLE_CHANGE = 0x00004000
    BASIC_INFO_CHANGE = 0x00008000
    HARD_LINK_CHANGE = 0x00010000
    COMPRESSION_CHANGE = 0x00020000
    ENCRYPTION_CHANGE = 0x00040000
    OBJECT_ID_CHANGE = 0x00080000
    REPARSE_POINT_CHANGE = 0x00100000
    STREAM_CHANGE = 0x00200000
    TRANSACTED_CHANGE = 0x00400000
    CLOSE = 0x80000000


class UsnSource(IntFlag):
    """변경 주체 비트마스크 (``USN_SOURCE_*``).

    셋 다 "사람이 한 일이 아니다"는 뜻입니다. 복제·백업 소프트웨어가
    만든 변경을 사용자 행위로 읽지 않으려면 이 값을 봐야 합니다.
    """

    DATA_MANAGEMENT = 0x00000001
    AUXILIARY_DATA = 0x00000002
    REPLICATION_MANAGEMENT = 0x00000004


#: Win32 관점의 디렉터리 비트. USN 레코드의 파일 속성은 Win32 값이라
#: 0x10 이 실제로 설정된다.
FILE_ATTRIBUTE_DIRECTORY = 0x00000010

#: NTFS가 $SI/$FN 안에서 쓰는 디렉터리 비트. USN에서는 보지 못했지만
#: 둘 다 확인해 두면 손해가 없다. ``[LIBFSNTFS]`` 파일 속성 플래그 표는
#: 0x10 을 "Not used by NTFS"로, 0x10000000 을 디렉터리로 적고 있다.
FILE_ATTRIBUTE_DIRECTORY_NTFS = 0x10000000


def decode_flags(value: int, flags: type[IntFlag]) -> list[str]:
    """비트마스크를 소문자 이름 목록으로 편다.

    **모르는 비트를 버리지 않습니다.** ``unknown_0x00800000`` 형태로
    남깁니다. 조용히 떨어뜨리면 새 플래그가 생겼을 때 아무도 모릅니다.
    """
    names = [member.name.lower() for member in flags if value & member.value]
    known = 0
    for member in flags:
        known |= member.value
    leftover = value & ~known
    if leftover:
        names.append("unknown_0x{:08x}".format(leftover))
    return names


def reason_names(value: int) -> list[str]:
    """``0x102`` -> ``["data_extend", "file_create"]`` (정의 순서)."""
    return decode_flags(value, UsnReason)


def source_names(value: int) -> list[str]:
    return decode_flags(value, UsnSource)


@dataclass(frozen=True)
class FileReference:
    """파일 참조 (``FILE_REFERENCE``). 8바이트.

    ==============  ====  ====================================================
    오프셋           크기   내용
    ==============  ====  ====================================================
    ``0x00``          6   MFT 엔트리 번호
    ``0x06``          2   시퀀스 번호
    ==============  ====  ====================================================

    엔트리 번호가 ``$MFT`` 레코드 번호와 같은 값이라 ``MFT#<entry>`` 로
    상호 참조할 수 있습니다. 시퀀스 번호는 그 엔트리가 재사용된 횟수라,
    다르면 **지금의 $MFT 레코드는 그때 그 파일이 아닙니다.**
    """

    entry: int
    sequence: int

    @classmethod
    def unpack(cls, value: int) -> "FileReference":
        return cls(entry=value & 0x0000FFFFFFFFFFFF, sequence=(value >> 48) & 0xFFFF)


@dataclass(frozen=True)
class UsnRecord:
    """USN 변경 저널 레코드 (``USN_RECORD_V2``).

    ==============  ====  ====================================================
    오프셋           크기   내용
    ==============  ====  ====================================================
    ``0x00``          4   레코드 크기 (이 필드 포함, 8바이트 정렬)
    ``0x04``          2   주 버전 (2)
    ``0x06``          2   부 버전 (0)
    ``0x08``          8   파일 참조
    ``0x10``          8   부모 파일 참조
    ``0x18``          8   USN — 스트림 안의 자기 오프셋
    ``0x20``          8   변경 시각 (FILETIME)
    ``0x28``          4   변경 사유 (``UsnReason``)
    ``0x2C``          4   변경 주체 (``UsnSource``)
    ``0x30``          4   보안 기술자 식별자 ($Secure:$SII 항목 번호)
    ``0x34``          4   파일 속성 플래그
    ``0x38``          2   이름 크기 — **바이트 수**
    ``0x3A``          2   이름 오프셋 (레코드 시작 기준)
    ``0x3C``        ...   이름 (UTF-16LE, 종료 문자 없음)
    ``...``         ...   0바이트 정렬 패딩
    ==============  ====  ====================================================

    **이름뿐이고 경로가 없습니다.** 전체 경로를 얻으려면 부모 파일
    참조로 ``$MFT``를 되짚어야 합니다. 이 파서는 그것을 하지 않습니다 —
    한 아티팩트를 읽는 동안 다른 아티팩트에 의존하면 "무엇을 읽어서
    무엇이 나왔는가"가 흐려집니다.
    """

    #: 이름을 뺀 헤더 크기.
    SIZE = V2_HEADER_SIZE

    record_length: int
    major_version: int
    minor_version: int
    file_reference: FileReference
    parent_reference: FileReference
    usn: int
    timestamp: datetime | None
    reason: int
    source: int
    security_id: int
    file_attributes: int
    name: str

    @property
    def is_directory(self) -> bool:
        return bool(
            self.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DIRECTORY_NTFS)
        )

    @property
    def reason_names(self) -> list[str]:
        return reason_names(self.reason)

    @property
    def source_names(self) -> list[str]:
        return source_names(self.source)

    @classmethod
    def unpack(cls, data: bytes, offset: int = 0) -> "UsnRecord":
        """레코드 하나를 읽는다. 읽을 수 없으면 ``StructError``.

        길이·버전·이름 범위를 모두 검사합니다. 하나라도 어긋나면 그
        위치는 레코드가 아니라고 보고 예외를 냅니다. 파서는 그것을
        재동기화 신호로 씁니다 — **틀린 위치에서 억지로 읽어 그럴듯한
        레코드를 만들어 내는 것이 최악입니다.**
        """
        if len(data) - offset < cls.SIZE:
            raise StructError(
                "레코드가 짧음: {}바이트 (필요 {})".format(len(data) - offset, cls.SIZE)
            )

        (
            record_length,
            major_version,
            minor_version,
            file_reference,
            parent_reference,
            usn,
            timestamp,
            reason,
            source,
            security_id,
            file_attributes,
            name_size,
            name_offset,
        ) = struct.unpack_from("<IHHQQQQIIIIHH", data, offset)

        if record_length < cls.SIZE:
            raise StructError("레코드 크기가 헤더보다 작음: {}".format(record_length))
        if record_length > MAX_RECORD_SIZE:
            raise StructError(
                "레코드 크기가 상한을 넘음: {} > {}".format(record_length, MAX_RECORD_SIZE)
            )
        if record_length % RECORD_ALIGNMENT:
            raise StructError(
                "레코드 크기가 {}바이트 정렬이 아님: {}".format(RECORD_ALIGNMENT, record_length)
            )
        if major_version != SUPPORTED_MAJOR_VERSION:
            if major_version in KNOWN_MAJOR_VERSIONS:
                raise UnsupportedVersion(
                    "지원하지 않는 USN 레코드 버전: v{}.{}".format(major_version, minor_version),
                    record_length=record_length,
                )
            # 실재하지 않는 버전 = 레코드가 아니다. 손상으로 센다.
            raise StructError(
                "USN 레코드 버전이 아님: v{}.{}".format(major_version, minor_version)
            )

        # 이름 크기는 **바이트 수**다. $FILE_NAME 과 다르다.
        if name_size % 2:
            raise StructError("이름 크기가 홀수 바이트: {} (UTF-16이면 짝수)".format(name_size))
        if name_offset < cls.SIZE:
            raise StructError("이름 오프셋이 헤더 안을 가리킴: {}".format(name_offset))
        if name_offset + name_size > record_length:
            raise StructError(
                "이름이 레코드 밖으로 벗어남: {} + {} > {}".format(
                    name_offset, name_size, record_length
                )
            )
        if offset + record_length > len(data):
            raise StructError(
                "레코드가 버퍼 밖으로 벗어남: {} + {} > {}".format(
                    offset, record_length, len(data)
                )
            )

        start = offset + name_offset
        raw_name = data[start : start + name_size]
        # surrogatepass — NTFS 이름은 짝 없는 서로게이트를 허용한다.
        # strict 로 읽으면 그런 이름을 가진 레코드만 조용히 사라진다.
        name = raw_name.decode("utf-16-le", errors="surrogatepass")

        return cls(
            record_length=record_length,
            major_version=major_version,
            minor_version=minor_version,
            file_reference=FileReference.unpack(file_reference),
            parent_reference=FileReference.unpack(parent_reference),
            usn=usn,
            timestamp=filetime_to_datetime(timestamp),
            reason=reason,
            source=source,
            security_id=security_id,
            file_attributes=file_attributes,
            name=name,
        )
