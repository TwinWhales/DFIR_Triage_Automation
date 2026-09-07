"""$UsnJrnl:$J 온디스크 구조 정의.

**여기에는 구조만 있습니다.** 오프셋, 크기, 필드 타입, 그리고 그것을
읽는 것 이상의 판단이 필요 없는 변환(FILETIME, 비트마스크 해석)뿐입니다.

스트림을 순회하고, 스파스 구간을 건너뛰고, 손상 후 재동기화하는 로직은
``parsers/usnjrnl.py``에 있습니다.

## 출처

레코드 레이아웃은 두 곳을 대조해 적었습니다.

* ``[LIBFSNTFS]`` New Technologies File System (NTFS), Joachim Metz,
  rev 0.0.28 — "USN change journal entry (USN_RECORD_V2)"
* MSDN ``USN_RECORD_V2`` · ``USN_RECORD_V3`` (``winioctl.h``)

``$MFT`` 구조와 달리 **USN 레코드는 Microsoft가 공개한 API 구조체**라
리버싱 문서가 유일한 근거가 아닙니다. 두 출처가 일치합니다.

**V3는 실물로 대조한 적이 없습니다.** 두 출처를 옮겨 적은 것뿐입니다 —
NTFS 볼륨의 온디스크 ``$J`` 는 V2로 기록되고, V3가 나오려면 ReFS 이거나
범위 추적을 켠 볼륨이어야 하는데 우리 손에 그런 이미지가 없습니다.
`docs/limitations.md` 에 "확인 안 한 것"으로 남겨 두었습니다. 버전 축에서
배운 것이 정확히 이것입니다 — **명세를 옮긴 줄은 실물에 반증될 수 있고,
프리패치 표에서 실제로 반증됐습니다**(`work.md` 1번).

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
    "PRELUDE_SIZE",
    "V2_HEADER_SIZE",
    "V3_HEADER_SIZE",
    "HEADER_SIZES",
    "MAX_RECORD_SIZE",
    "SUPPORTED_MAJOR_VERSIONS",
    "IncompleteRecord",
    "UnsupportedRecord",
    "UnsupportedVersion",
    "UnmappableFileId",
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

#: 버전을 읽기 전에 확실한 것. 어느 버전이든 앞 8바이트는 같다 —
#: 크기(4) · 주 버전(2) · 부 버전(2). **레코드 길이와 버전을 먼저 읽어야
#: 헤더가 몇 바이트인지 알 수 있으므로** 이만큼은 버전과 무관하게 필요하다.
PRELUDE_SIZE = 8

#: 이름을 뺀 V2 레코드 헤더 크기.
V2_HEADER_SIZE = 60

#: 이름을 뺀 V3 레코드 헤더 크기. V2보다 16바이트 큰 것은 파일 참조 둘이
#: 8바이트에서 16바이트(``FILE_ID_128``)로 늘었기 때문이다.
V3_HEADER_SIZE = 76

#: 주 버전 -> 이름을 뺀 헤더 크기. **여기 있는 버전만 읽는다.**
HEADER_SIZES = {2: V2_HEADER_SIZE, 3: V3_HEADER_SIZE}

#: 레코드 크기 상한. 이름은 최대 255자(UTF-16으로 510바이트)이므로
#: V2는 60 + 510 = 570, V3는 76 + 510 = 586 을 넘을 수 없다. 넉넉히 잡아
#: 이보다 크면 손상으로 본다.
#: 상한이 없으면 깨진 길이 값 하나가 스트림 전체를 건너뛰게 만든다.
MAX_RECORD_SIZE = 4096

#: 읽는 레코드 버전. V2와 V3의 차이는 파일 참조 둘의 폭뿐이고, 나머지
#: 필드는 이름까지 그대로다.
#:
#: **V4는 읽지 않는다 — 못 하는 것이 아니라 낼 수 없는 것이다.** V4는 범위
#: 추적(``FSCTL_ENABLE_RANGE_TRACKING``)을 켰을 때만 나오는 레코드로,
#: 이름도 타임스탬프도 파일 속성도 없이 변경된 바이트 구간 목록만 들고 있다.
#: 04단계 출력은 ``name``·``is_directory`` 를 요구하므로(``schemas/``)
#: V4를 레코드로 낼 수 없다. 지어내지 않고 건너뛰며, 건수는 결산에 올린다.
SUPPORTED_MAJOR_VERSIONS = (2, 3)

#: USN 레코드로 실재하는 버전. 여기 없는 값은 "지원하지 않는 버전"이
#: 아니라 **애초에 레코드가 아니다.** 둘을 뭉뚱그리면 손상 구간을
#: 재스캔하다 나온 쓰레기가 "V0 레코드"로 집계된다.
KNOWN_MAJOR_VERSIONS = (2, 3, 4)


class IncompleteRecord(StructError):
    """**손상이 아니라 아직 다 안 들어온 것이다.**

    버퍼가 레코드 끝까지 담고 있지 않을 때 납니다. 파서는 이것을 받으면
    더 읽어 와서 다시 시도하고, 스트림이 끝났으면 잘린 꼬리로 보고
    버립니다 — 어느 쪽도 손상으로 세지 않습니다.

    **이것을 손상과 뭉뚱그리면 레코드를 잃습니다.** 청크 경계에 걸친
    레코드마다 8바이트씩 걸어 들어가 재동기화하므로, 그 레코드 하나가
    통째로 사라지고 있지도 않은 손상 구간이 결산에 오릅니다. 실측으로
    확인했습니다(``tests/test_usn_parser.py`` 의 경계 회귀 테스트).
    """


class UnsupportedRecord(StructError):
    """실재하는 레코드인데 우리가 04단계 출력으로 낼 수 없는 것.

    ``record_length``를 들고 있습니다. 파서가 **레코드 하나를 통째로**
    건너뛸 수 있어야 하기 때문입니다. 8바이트씩 걸어 들어가면 레코드
    본문을 레코드로 오해해 가짜 손상이 줄줄이 잡힙니다.

    손상(``StructError``)과 따로 셉니다. 조치가 갈립니다 — 앞은 저널이
    더러운 것이고 이것은 파서나 스키마를 넓혀야 하는 것입니다.
    """

    def __init__(self, message: str, record_length: int) -> None:
        super().__init__(message)
        self.record_length = record_length


class UnsupportedVersion(UnsupportedRecord):
    """읽지 않는 버전(V4). 왜 안 읽는지는 ``SUPPORTED_MAJOR_VERSIONS``."""


class UnmappableFileId(UnsupportedRecord):
    """V3의 128비트 파일 ID가 NTFS의 (엔트리, 시퀀스)가 아니다.

    NTFS에서 ``FILE_ID_128`` 은 64비트 파일 참조를 하위 8바이트에 담고
    상위 8바이트를 0으로 둡니다. 상위가 0이 아니면 그것은 NTFS 참조가
    아니라 다른 파일 시스템(ReFS)의 객체 ID입니다.

    **그때는 레코드를 내지 않습니다.** ``file_entry``·``parent_entry`` 는
    USN 레코드를 ``$MFT`` 와 잇는 유일한 통로라, 하위 8바이트만 잘라
    담으면 **존재하지 않는 MFT 엔트리를 가리키는 레코드**가 됩니다.
    06단계가 대조할 수 없는 값을 04단계가 지어내는 셈입니다.
    """


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

    @classmethod
    def unpack_128(cls, low: int, high: int, *, record_length: int, label: str) -> "FileReference":
        """V3의 ``FILE_ID_128`` 을 읽는다. 16바이트.

        **NTFS에서는 하위 8바이트가 곧 64비트 파일 참조이고 상위 8바이트는
        0입니다.** 그래서 상위가 0이기만 하면 V2와 똑같이 쪼갤 수 있습니다 —
        v3를 못 읽던 이유로 적혀 있던 "128비트라 (엔트리, 시퀀스)로
        쪼개지지 않는다"는 **NTFS 한정으로는 참이 아닙니다**
        (`docs/limitations-log.md`).

        상위가 0이 아니면 NTFS 참조가 아니므로 ``UnmappableFileId`` 를 냅니다.
        하위만 잘라 담지 않습니다 — 그러면 없는 MFT 엔트리를 가리킵니다.
        """
        if high:
            raise UnmappableFileId(
                "{}의 128비트 파일 ID가 NTFS 참조가 아님: 상위 64비트 0x{:016X} "
                "(NTFS라면 0이어야 합니다)".format(label, high),
                record_length=record_length,
            )
        return cls.unpack(low)


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

    ## V3 (``USN_RECORD_V3``)

    **파일 참조 둘이 8바이트에서 16바이트로 늘어난 것이 전부입니다.**
    그 뒤 필드는 이름까지 순서도 뜻도 같고, 오프셋만 16 밀립니다.

    ==============  ====  ====================================================
    오프셋           크기   내용
    ==============  ====  ====================================================
    ``0x00``          4   레코드 크기 (이 필드 포함, 8바이트 정렬)
    ``0x04``          2   주 버전 (3)
    ``0x06``          2   부 버전 (0)
    ``0x08``         16   파일 참조 (``FILE_ID_128``)
    ``0x18``         16   부모 파일 참조 (``FILE_ID_128``)
    ``0x28``          8   USN
    ``0x30``          8   변경 시각 (FILETIME)
    ``0x38``          4   변경 사유 (``UsnReason``)
    ``0x3C``          4   변경 주체 (``UsnSource``)
    ``0x40``          4   보안 기술자 식별자
    ``0x44``          4   파일 속성 플래그
    ``0x48``          2   이름 크기 — **바이트 수**
    ``0x4A``          2   이름 오프셋 (레코드 시작 기준)
    ``0x4C``        ...   이름 (UTF-16LE, 종료 문자 없음)
    ==============  ====  ====================================================

    ``major_version`` 으로 어느 레이아웃에서 나왔는지 알 수 있습니다.
    """

    #: 이름을 뺀 V2 헤더 크기. **버전별 크기는 ``HEADER_SIZES`` 를 봅니다.**
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
        available = len(data) - offset

        # 앞 8바이트로 크기와 버전을 먼저 읽는다. **헤더가 몇 바이트인지가
        # 버전에 달렸으므로** 이 순서를 뒤집을 수 없다.
        if available < PRELUDE_SIZE:
            raise IncompleteRecord(
                "레코드가 짧음: {}바이트 (버전을 읽으려면 {} 필요)".format(
                    available, PRELUDE_SIZE
                )
            )
        record_length, major_version, minor_version = struct.unpack_from("<IHH", data, offset)

        # 크기부터 본다. 이 셋은 버전과 무관하게 참이고, **버퍼가 모자란
        # 것과 값이 깨진 것을 가르기 전에** 확정돼야 한다 — 순서를 뒤집으면
        # 깨진 길이 값 하나가 "아직 안 들어왔다"로 오해된다.
        if record_length < PRELUDE_SIZE:
            raise StructError("레코드 크기가 헤더보다 작음: {}".format(record_length))
        if record_length > MAX_RECORD_SIZE:
            raise StructError(
                "레코드 크기가 상한을 넘음: {} > {}".format(record_length, MAX_RECORD_SIZE)
            )
        if record_length % RECORD_ALIGNMENT:
            raise StructError(
                "레코드 크기가 {}바이트 정렬이 아님: {}".format(RECORD_ALIGNMENT, record_length)
            )

        header_size = HEADER_SIZES.get(major_version)
        if header_size is None:
            if major_version in KNOWN_MAJOR_VERSIONS:
                raise UnsupportedVersion(
                    "지원하지 않는 USN 레코드 버전: v{}.{}".format(major_version, minor_version),
                    record_length=record_length,
                )
            # 실재하지 않는 버전 = 레코드가 아니다. 손상으로 센다.
            raise StructError(
                "USN 레코드 버전이 아님: v{}.{}".format(major_version, minor_version)
            )
        if record_length < header_size:
            raise StructError(
                "레코드 크기가 헤더보다 작음: {} (v{} 헤더는 {}바이트)".format(
                    record_length, major_version, header_size
                )
            )

        # **여기서부터는 손상이 아니라 덜 들어온 것이다.** 청크 경계에 걸린
        # 레코드가 이리로 오는데, 손상으로 세면 파서가 8바이트씩 걸어 들어가
        # 그 레코드를 통째로 잃는다 (``IncompleteRecord`` 설명 참조).
        if available < record_length:
            raise IncompleteRecord(
                "레코드가 버퍼 밖으로 벗어남: {} + {} > {}".format(
                    offset, record_length, len(data)
                )
            )

        if major_version == 2:
            (
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
            ) = struct.unpack_from("<QQQQIIIIHH", data, offset + PRELUDE_SIZE)
            file_ref = FileReference.unpack(file_reference)
            parent_ref = FileReference.unpack(parent_reference)
        else:
            (
                file_low,
                file_high,
                parent_low,
                parent_high,
                usn,
                timestamp,
                reason,
                source,
                security_id,
                file_attributes,
                name_size,
                name_offset,
            ) = struct.unpack_from("<QQQQQQIIIIHH", data, offset + PRELUDE_SIZE)
            file_ref = FileReference.unpack_128(
                file_low, file_high, record_length=record_length, label="파일 참조"
            )
            parent_ref = FileReference.unpack_128(
                parent_low, parent_high, record_length=record_length, label="부모 파일 참조"
            )

        # 이름 크기는 **바이트 수**다. $FILE_NAME 과 다르다.
        if name_size % 2:
            raise StructError("이름 크기가 홀수 바이트: {} (UTF-16이면 짝수)".format(name_size))
        if name_offset < header_size:
            raise StructError("이름 오프셋이 헤더 안을 가리킴: {}".format(name_offset))
        if name_offset + name_size > record_length:
            raise StructError(
                "이름이 레코드 밖으로 벗어남: {} + {} > {}".format(
                    name_offset, name_size, record_length
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
            file_reference=file_ref,
            parent_reference=parent_ref,
            usn=usn,
            timestamp=filetime_to_datetime(timestamp),
            reason=reason,
            source=source,
            security_id=security_id,
            file_attributes=file_attributes,
            name=name,
        )
