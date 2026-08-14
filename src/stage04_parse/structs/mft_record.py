"""$MFT 온디스크 구조 정의.

**여기에는 구조만 있습니다.** 오프셋, 크기, 필드 타입, 그리고 그것을
읽는 것 이상의 판단이 필요 없는 변환(FILETIME, fixup)뿐입니다.

레코드를 순회하고, 속성을 걸어 다니고, 부모를 따라 전체 경로를 만드는
로직은 ``parsers/mft.py``에 있습니다. 구조 정의를 분리해 두면 NTFS 스펙
문서와 1:1로 대조할 수 있습니다.

.. warning::

   **아래 오프셋 표는 스펙 대조 전입니다.**

   포렌식 도구에서 오프셋 하나가 틀리면 조용히 잘못된 값이 나옵니다.
   형식은 멀쩡해서 스키마도 통과하고, 06단계 검증도 통과합니다
   (레코드에 적힌 값과 문장이 일치하니까). **아무도 못 잡습니다.**

   그래서 두 가지를 반드시 하십시오.

   1. 각 표를 NTFS 스펙 문서와 눈으로 대조한다
   2. ``tools/compare_mft.py`` 로 MFTECmd 출력과 대조한다
      (레코드 수, 경로, 타임스탬프 4종 전부 일치해야 통과)

   대조에서 나온 불일치와 원인은 ``docs/artifact-notes.md``에 기록합니다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import IntEnum, IntFlag

__all__ = [
    "SECTOR_SIZE",
    "FILE_SIGNATURE",
    "BAAD_SIGNATURE",
    "END_OF_ATTRIBUTES",
    "AttributeType",
    "RecordFlags",
    "FileNameNamespace",
    "FixupError",
    "StructError",
    "filetime_to_datetime",
    "apply_fixups",
    "RecordHeader",
    "AttributeHeader",
    "StandardInformation",
    "FileName",
]


class StructError(ValueError):
    """구조를 읽을 수 없다. 데이터가 짧거나 시그니처가 다르다."""


class FixupError(StructError):
    """업데이트 시퀀스가 맞지 않는다. 레코드가 손상됐을 가능성이 높다."""


#: 섹터 크기. 4Kn 디스크는 4096이므로 부트섹터에서 읽어 넘겨야 한다.
SECTOR_SIZE = 512

FILE_SIGNATURE = b"FILE"
#: 손상되어 chkdsk가 표시한 레코드.
BAAD_SIGNATURE = b"BAAD"

#: 속성 목록의 끝 표시.
END_OF_ATTRIBUTES = 0xFFFFFFFF


class AttributeType(IntEnum):
    """속성 타입 코드."""

    STANDARD_INFORMATION = 0x10
    ATTRIBUTE_LIST = 0x20
    FILE_NAME = 0x30
    OBJECT_ID = 0x40
    SECURITY_DESCRIPTOR = 0x50
    VOLUME_NAME = 0x60
    VOLUME_INFORMATION = 0x70
    DATA = 0x80
    INDEX_ROOT = 0x90
    INDEX_ALLOCATION = 0xA0
    BITMAP = 0xB0
    REPARSE_POINT = 0xC0
    EA_INFORMATION = 0xD0
    EA = 0xE0
    LOGGED_UTILITY_STREAM = 0x100


class RecordFlags(IntFlag):
    """레코드 헤더의 flags 필드."""

    IN_USE = 0x0001
    DIRECTORY = 0x0002
    EXTENSION = 0x0004
    VIEW_INDEX = 0x0008


class FileNameNamespace(IntEnum):
    """``$FILE_NAME``의 이름 공간.

    한 파일이 ``$FN``을 여러 개 가질 수 있습니다. 8.3 단축 이름(DOS)과
    긴 이름(WIN32)이 따로 있는 경우입니다. **경로를 만들 때 DOS 이름을
    고르면 ``PROGRA~1`` 같은 값이 나옵니다.** WIN32 또는 WIN32_AND_DOS를
    우선하십시오.
    """

    POSIX = 0
    WIN32 = 1
    DOS = 2
    WIN32_AND_DOS = 3


# --------------------------------------------------------------- 변환

#: FILETIME 기준점. 1601-01-01 UTC부터 100ns 단위로 센다.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

#: datetime이 담을 수 있는 상한을 넘는 FILETIME 값을 거른다.
_FILETIME_MAX = 0x7FFF_FFFF_FFFF_FFFF


def filetime_to_datetime(value: int) -> datetime | None:
    """FILETIME(100ns 단위)을 UTC ``datetime``으로.

    ``0``은 "값 없음"이므로 ``None``을 돌려줍니다. 범위를 벗어난 값도
    ``None``입니다 — 조작 도구가 넣은 쓰레기 값이 예외를 던져 파싱 전체를
    멈추면 안 됩니다. 그런 레코드는 ``zero_timestamp`` 플래그로 표시됩니다.

    ``datetime``은 마이크로초(6자리)까지만 담습니다. FILETIME은 100ns
    (7자리)라 마지막 자리가 버려집니다. 허용 오차가 초 단위이므로
    판정에는 영향이 없습니다.
    """
    if value <= 0 or value > _FILETIME_MAX:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def apply_fixups(data: bytes, *, sector_size: int = SECTOR_SIZE) -> bytearray:
    """업데이트 시퀀스를 원래 값으로 되돌린다.

    NTFS는 각 섹터의 **마지막 2바이트를 업데이트 시퀀스 번호(USN)로
    덮어쓰고**, 원래 값은 레코드 앞쪽 배열에 보관합니다. 쓰기 도중
    전원이 끊긴 레코드를 감지하기 위해서입니다.

    **이걸 안 되돌리면 섹터 경계에서 값이 깨집니다.** 512바이트마다
    2바이트가 엉뚱한 값입니다. 경로 문자열이 중간에 깨지거나 타임스탬프가
    이상해지는데, 레코드 대부분은 멀쩡해서 원인을 찾기 어렵습니다.
    직접 구현에서 가장 흔히 놓치는 지점이라 여기에 넣어 둡니다.

    USN이 섹터 끝의 값과 다르면 ``FixupError``입니다. 그 레코드만
    건너뛰고 나머지는 계속 읽으십시오.
    """
    if len(data) < RecordHeader.SIZE:
        raise StructError(f"레코드가 너무 짧음: {len(data)}바이트")

    usa_offset, usa_count = struct.unpack_from("<HH", data, 0x04)
    if usa_count == 0:
        raise FixupError("업데이트 시퀀스 배열이 비어 있음")

    end_of_array = usa_offset + usa_count * 2
    if end_of_array > len(data):
        raise FixupError(f"업데이트 시퀀스 배열이 레코드를 벗어남 (끝 {end_of_array})")

    patched = bytearray(data)
    usn = bytes(patched[usa_offset : usa_offset + 2])

    # 배열의 첫 항목이 USN 자신이므로 1부터 센다.
    for index in range(1, usa_count):
        original = bytes(patched[usa_offset + index * 2 : usa_offset + index * 2 + 2])
        sector_end = index * sector_size - 2
        if sector_end + 2 > len(patched):
            raise FixupError(f"섹터 {index}가 레코드를 벗어남 (오프셋 {sector_end})")
        if bytes(patched[sector_end : sector_end + 2]) != usn:
            raise FixupError(
                f"섹터 {index} 끝의 USN 불일치 "
                f"(기대 {usn.hex()}, 실제 {bytes(patched[sector_end:sector_end + 2]).hex()})"
            )
        patched[sector_end : sector_end + 2] = original

    return patched


# ------------------------------------------------------- 레코드 헤더

@dataclass(frozen=True)
class RecordHeader:
    """FILE 레코드 헤더.

    ==============  ====  ====================================================
    오프셋           크기   내용
    ==============  ====  ====================================================
    ``0x00``          4   시그니처 ``FILE`` (손상 시 ``BAAD``)
    ``0x04``          2   업데이트 시퀀스 배열 오프셋
    ``0x06``          2   업데이트 시퀀스 배열 크기 (워드 수, USN 자신 포함)
    ``0x08``          8   ``$LogFile`` 시퀀스 번호
    ``0x10``          2   시퀀스 번호
    ``0x12``          2   하드 링크 수
    ``0x14``          2   첫 속성 오프셋
    ``0x16``          2   플래그 (``RecordFlags``)
    ``0x18``          4   레코드 사용 크기
    ``0x1C``          4   레코드 할당 크기
    ``0x20``          8   기준 레코드 참조 (확장 레코드면 0이 아님)
    ``0x28``          2   다음 속성 ID
    ``0x2A``          2   정렬 (XP 이상)
    ``0x2C``          4   MFT 레코드 번호 (XP 이상)
    ==============  ====  ====================================================

    ``0x2C``의 레코드 번호는 XP 이상에서만 유효합니다. 그 이전 버전이나
    값이 0이면 **순회 순서로 계산한 번호를 쓰십시오** — ``ref``의 근거가
    되는 값이라 틀리면 06단계 검증이 통째로 어긋납니다.
    """

    SIZE = 0x30

    signature: bytes
    usa_offset: int
    usa_count: int
    lsn: int
    sequence_number: int
    hard_link_count: int
    first_attribute_offset: int
    flags: RecordFlags
    used_size: int
    allocated_size: int
    base_record_reference: int
    next_attribute_id: int
    record_number: int

    @property
    def in_use(self) -> bool:
        return bool(self.flags & RecordFlags.IN_USE)

    @property
    def is_directory(self) -> bool:
        return bool(self.flags & RecordFlags.DIRECTORY)

    @property
    def is_extension(self) -> bool:
        """다른 레코드의 확장이다. 독립된 파일이 아니므로 건너뛴다."""
        return self.base_record_reference != 0

    @classmethod
    def unpack(cls, data: bytes) -> "RecordHeader":
        if len(data) < cls.SIZE:
            raise StructError(f"헤더가 짧음: {len(data)}바이트 (필요 {cls.SIZE})")
        signature = bytes(data[0:4])
        if signature not in (FILE_SIGNATURE, BAAD_SIGNATURE):
            raise StructError(f"레코드 시그니처 불일치: {signature!r}")

        (
            usa_offset,
            usa_count,
            lsn,
            sequence_number,
            hard_link_count,
            first_attribute_offset,
            flags,
            used_size,
            allocated_size,
            base_record_reference,
            next_attribute_id,
            _align,
            record_number,
        ) = struct.unpack_from("<HHQHHHHIIQHHI", data, 0x04)

        return cls(
            signature=signature,
            usa_offset=usa_offset,
            usa_count=usa_count,
            lsn=lsn,
            sequence_number=sequence_number,
            hard_link_count=hard_link_count,
            first_attribute_offset=first_attribute_offset,
            flags=RecordFlags(flags & 0x0F),
            used_size=used_size,
            allocated_size=allocated_size,
            base_record_reference=base_record_reference,
            next_attribute_id=next_attribute_id,
            record_number=record_number,
        )


# ---------------------------------------------------------- 속성 헤더

@dataclass(frozen=True)
class AttributeHeader:
    """속성 헤더. 상주/비상주 공통부 + 각각의 추가 필드.

    **공통부**

    ==============  ====  ==============================================
    오프셋           크기   내용
    ==============  ====  ==============================================
    ``0x00``          4   속성 타입 (``AttributeType``)
    ``0x04``          4   속성 전체 길이
    ``0x08``          1   비상주 플래그
    ``0x09``          1   이름 길이 (문자 수)
    ``0x0A``          2   이름 오프셋
    ``0x0C``          2   플래그 (압축/암호화/희소)
    ``0x0E``          2   속성 ID
    ==============  ====  ==============================================

    **상주 (``non_resident == 0``)**

    ``0x10`` 4 내용 길이 / ``0x14`` 2 내용 오프셋 / ``0x16`` 1 인덱스 플래그

    **비상주 (``non_resident == 1``)**

    ``0x10`` 8 시작 VCN / ``0x18`` 8 마지막 VCN / ``0x20`` 2 런리스트 오프셋 /
    ``0x22`` 2 압축 단위 / ``0x28`` 8 할당 크기 / ``0x30`` 8 실제 크기 /
    ``0x38`` 8 초기화된 크기

    본 버전은 **상주 속성만 우선** 처리합니다(``work-guide.md`` 3.3).
    ``$DATA``가 비상주면 런리스트를 해석해야 하는데, 그 로직은
    ``parsers/mft.py``의 몫입니다. 압축·희소 파일은 범위 밖이며
    ``docs/limitations.md``에 남깁니다.
    """

    COMMON_SIZE = 0x10

    type: int
    length: int
    non_resident: bool
    name: str
    flags: int
    attribute_id: int
    #: 상주일 때만. 레코드 시작 기준 오프셋과 길이.
    content_offset: int | None = None
    content_length: int | None = None
    #: 비상주일 때만.
    start_vcn: int | None = None
    last_vcn: int | None = None
    runlist_offset: int | None = None
    allocated_size: int | None = None
    real_size: int | None = None

    @property
    def type_name(self) -> str:
        try:
            return AttributeType(self.type).name
        except ValueError:
            return f"UNKNOWN_0x{self.type:X}"

    @classmethod
    def unpack(cls, data: bytes, offset: int) -> "AttributeHeader":
        """``offset`` 위치의 속성 헤더를 읽는다."""
        if offset + cls.COMMON_SIZE > len(data):
            raise StructError(f"속성 헤더가 레코드를 벗어남 (오프셋 {offset})")

        type_, length, non_resident, name_length, name_offset, flags, attribute_id = (
            struct.unpack_from("<IIBBHHH", data, offset)
        )
        if type_ == END_OF_ATTRIBUTES:
            raise StructError("속성 목록의 끝")
        if length == 0 or offset + length > len(data):
            raise StructError(f"속성 길이가 이상함: {length} (오프셋 {offset})")

        name = ""
        if name_length:
            start = offset + name_offset
            name = bytes(data[start : start + name_length * 2]).decode("utf-16-le", "replace")

        common = {
            "type": type_,
            "length": length,
            "non_resident": bool(non_resident),
            "name": name,
            "flags": flags,
            "attribute_id": attribute_id,
        }

        if not non_resident:
            content_length, content_offset = struct.unpack_from("<IH", data, offset + 0x10)
            return cls(**common, content_length=content_length, content_offset=offset + content_offset)

        start_vcn, last_vcn = struct.unpack_from("<QQ", data, offset + 0x10)
        runlist_offset = struct.unpack_from("<H", data, offset + 0x20)[0]
        allocated_size, real_size = struct.unpack_from("<QQ", data, offset + 0x28)
        return cls(
            **common,
            start_vcn=start_vcn,
            last_vcn=last_vcn,
            runlist_offset=offset + runlist_offset,
            allocated_size=allocated_size,
            real_size=real_size,
        )


# ------------------------------------------------ $STANDARD_INFORMATION

@dataclass(frozen=True)
class StandardInformation:
    """``$STANDARD_INFORMATION`` (타입 ``0x10``).

    ==============  ====  ==============================
    오프셋           크기   내용
    ==============  ====  ==============================
    ``0x00``          8   생성 (btime)
    ``0x08``          8   수정 (mtime)
    ``0x10``          8   MFT 변경 (ctime)
    ``0x18``          8   접근 (atime)
    ``0x20``          4   DOS 파일 속성
    ==============  ====  ==============================

    **이 네 값이 타임스탬프 조작의 대상입니다.** 일반 도구로 바꿀 수
    있으므로 ``$FILE_NAME``의 값과 비교해 조작 여부를 판정합니다.
    """

    MIN_SIZE = 0x24

    btime: datetime | None
    mtime: datetime | None
    ctime: datetime | None
    atime: datetime | None
    dos_attributes: int

    @classmethod
    def unpack(cls, data: bytes, offset: int = 0) -> "StandardInformation":
        if offset + cls.MIN_SIZE > len(data):
            raise StructError(f"$SI가 짧음 (오프셋 {offset})")
        btime, mtime, ctime, atime, dos_attributes = struct.unpack_from("<QQQQI", data, offset)
        return cls(
            btime=filetime_to_datetime(btime),
            mtime=filetime_to_datetime(mtime),
            ctime=filetime_to_datetime(ctime),
            atime=filetime_to_datetime(atime),
            dos_attributes=dos_attributes,
        )


# ------------------------------------------------------------ $FILE_NAME

@dataclass(frozen=True)
class FileName:
    """``$FILE_NAME`` (타입 ``0x30``).

    ==============  ====  ================================================
    오프셋           크기   내용
    ==============  ====  ================================================
    ``0x00``          8   부모 디렉터리 참조 (하위 48비트가 레코드 번호)
    ``0x08``          8   생성 (btime)
    ``0x10``          8   수정 (mtime)
    ``0x18``          8   MFT 변경 (ctime)
    ``0x20``          8   접근 (atime)
    ``0x28``          8   할당 크기
    ``0x30``          8   실제 크기
    ``0x38``          4   플래그
    ``0x3C``          4   재분석 지점 / EA
    ``0x40``          1   이름 길이 (문자 수)
    ``0x41``          1   이름 공간 (``FileNameNamespace``)
    ``0x42``          ?   이름 (UTF-16LE)
    ==============  ====  ================================================

    ``parent_reference``의 **하위 48비트가 레코드 번호**, 상위 16비트가
    시퀀스 번호입니다. 마스킹을 빼먹으면 부모를 못 찾아 경로가 끊깁니다.

    타임스탬프 네 개는 커널이 갱신하며 일반 도구로 바꾸기 어렵습니다.
    그래서 ``$SI``와의 불일치가 조작의 신호가 됩니다.
    """

    MIN_SIZE = 0x42

    parent_record_number: int
    parent_sequence_number: int
    btime: datetime | None
    mtime: datetime | None
    ctime: datetime | None
    atime: datetime | None
    allocated_size: int
    real_size: int
    flags: int
    name: str
    namespace: FileNameNamespace

    @property
    def is_dos_short_name(self) -> bool:
        """8.3 단축 이름인가. 경로를 만들 때 이것만 있는 게 아니면 피한다."""
        return self.namespace == FileNameNamespace.DOS

    @classmethod
    def unpack(cls, data: bytes, offset: int = 0) -> "FileName":
        if offset + cls.MIN_SIZE > len(data):
            raise StructError(f"$FN이 짧음 (오프셋 {offset})")

        (
            parent_reference,
            btime,
            mtime,
            ctime,
            atime,
            allocated_size,
            real_size,
            flags,
            _reparse,
            name_length,
            namespace,
        ) = struct.unpack_from("<QQQQQQQIIBB", data, offset)

        name_start = offset + cls.MIN_SIZE
        name_end = name_start + name_length * 2
        if name_end > len(data):
            raise StructError(f"$FN 이름이 레코드를 벗어남 (끝 {name_end})")
        name = bytes(data[name_start:name_end]).decode("utf-16-le", "replace")

        try:
            resolved_namespace = FileNameNamespace(namespace)
        except ValueError:
            resolved_namespace = FileNameNamespace.POSIX

        return cls(
            # 하위 48비트가 레코드 번호. 마스킹을 빼먹으면 부모를 못 찾는다.
            parent_record_number=parent_reference & 0x0000_FFFF_FFFF_FFFF,
            parent_sequence_number=parent_reference >> 48,
            btime=filetime_to_datetime(btime),
            mtime=filetime_to_datetime(mtime),
            ctime=filetime_to_datetime(ctime),
            atime=filetime_to_datetime(atime),
            allocated_size=allocated_size,
            real_size=real_size,
            flags=flags,
            name=name,
            namespace=resolved_namespace,
        )
