"""참조 $MFT 파서 — analyzeMFT(MIT) 기반. **임시입니다.**

자체 파서(``mft.py``)가 완성될 때까지 쓰는 대체물입니다. 세 가지를
동시에 줍니다.

- 파서가 없어도 팀이 실제 증거로 작업할 수 있다
- 자체 파서가 나오면 **대조군**이 된다 (MFTECmd 없이 ``pytest`` 안에서)
- 발표에서 "자체 구현이 참조 구현과 N건 전부 일치"를 보일 수 있다

레코드 하나를 뜯는 일만 ``third_party/analyzeMFT``에 맡기고, **나머지는
전부 우리가 합니다.**

============================  ==========================================
우리                           analyzeMFT
============================  ==========================================
파일 순회 · 오프셋 계산         ―
fixup 적용                     ―
타임스탬프 정수 변환            ―
경로 재구성                    ―
``scope`` 필터                 ―
―                             레코드 바이트 → 속성 해석
============================  ==========================================

원본을 고치지 않는 것이 원칙입니다(``third_party/README.md``). 아래 두
가지는 원본의 한계라 어댑터에서 우회합니다.

**fixup 미적용** — ``MftRecord``는 업데이트 시퀀스를 읽기만 하고
되돌리지 않습니다. 그대로 쓰면 섹터 경계(1024바이트 레코드의 오프셋
510, 1022)의 2바이트가 깨진 채 파싱됩니다. 넘기기 전에 우리
``apply_fixups()``를 적용합니다.

**타임스탬프 정밀도** — ``WindowsTime.get_unix_time()``이 float 나눗셈을
씁니다. FILETIME은 18자리인데 float 유효숫자는 15~16자리라 마이크로초가
조용히 틀어집니다. ``low``/``high`` 원시 값에서 정수로 다시 계산합니다.
"""

from __future__ import annotations

import logging
from typing import Any, BinaryIO, Iterator

# 절대 경로로 부른다. third_party 는 src 바깥이라 상대 import 로는 닿지 않는다.
from third_party.analyzeMFT.mft_record import MftRecord  # type: ignore[import-untyped]

from ...common import refs
from ..structs import mft_record as structs
from .base import ParseError, Scope

__all__ = ["ReferenceMftParser", "ROOT_RECORD_NUMBER", "DEFAULT_RECORD_SIZE"]

# 원본이 정상 레코드에도 "Large attribute detected" 경고를 낸다
# ($INDEX_ROOT 584바이트를 1024 레코드에서 "크다"고 판정). 실제 문제가
# 아니고 파싱 진행 상황을 가리므로 낮춘다. 원본을 고치지 않는 방법이다.
logging.getLogger("third_party.analyzeMFT").setLevel(logging.ERROR)

#: 볼륨 루트(``.``)의 MFT 레코드 번호. 경로 재구성이 여기서 멈춘다.
ROOT_RECORD_NUMBER = 5

DEFAULT_RECORD_SIZE = 1024

#: 레코드 크기로 인정할 값. 헤더의 할당 크기가 이 밖이면 기본값을 쓴다.
_VALID_RECORD_SIZES = (512, 1024, 2048, 4096)


class ReferenceMftParser:
    """``$MFT`` 파일을 읽어 우리 레코드 형식으로 낸다.

    **두 번 순회합니다.** 전체 경로를 만들려면 부모 레코드의 이름을 알아야
    하는데, 부모가 뒤에 나올 수 있기 때문입니다. 1회차는 이름·부모만 모으고
    2회차에 범위에 드는 레코드를 냅니다.

    자체 파서는 이보다 나은 방법을 쓸 수 있습니다. 임시 구현이라 정확성을
    우선했습니다.
    """

    artifact = "$MFT"

    def __init__(self, volume_letter: str = "C:", record_size: int | None = None) -> None:
        #: 재구성한 경로 앞에 붙일 드라이브 문자. ``$MFT``에는 이 정보가
        #: 없다. 한 실행은 한 볼륨이므로 증거 경로에서 유추해 넘긴다.
        self.volume_letter = volume_letter
        self.record_size = record_size

    # ------------------------------------------------------------ 공개

    def parse(self, stream: BinaryIO, scope: Scope) -> Iterator[dict[str, Any]]:
        if not stream.seekable():
            raise ParseError(
                "참조 파서는 되감을 수 있는 스트림이 필요합니다 "
                "(경로 재구성을 위해 두 번 순회)."
            )

        record_size = self.record_size or self._detect_record_size(stream)
        index = self._build_index(stream, record_size)
        yield from self._emit(stream, scope, record_size, index)

    # ------------------------------------------------------------ 내부

    def _detect_record_size(self, stream: BinaryIO) -> int:
        """첫 레코드 헤더의 할당 크기에서 읽는다. 이상하면 기본값."""
        stream.seek(0)
        head = stream.read(structs.RecordHeader.SIZE)
        try:
            allocated = structs.RecordHeader.unpack(head).allocated_size
        except structs.StructError:
            return DEFAULT_RECORD_SIZE
        return allocated if allocated in _VALID_RECORD_SIZES else DEFAULT_RECORD_SIZE

    @staticmethod
    def _data_size(data: bytes) -> int | None:
        """``$DATA``의 실제 크기. 없으면 ``None``.

        원본의 ``filesize``는 ``$FN``에서 읽은 값인데, 그것은 **이름이
        만들어진 시점의 크기**라 나중에 쓰인 파일은 0으로 남습니다.
        39KB 문서를 0바이트로 보고하는 것은 증거 레코드로서 틀린 값입니다.

        이름 없는 ``$DATA``만 봅니다. 이름 있는 것은 대체 데이터
        스트림(ADS)이고 본 버전의 범위 밖입니다.
        """
        try:
            header = structs.RecordHeader.unpack(data)
        except structs.StructError:
            return None

        offset = header.first_attribute_offset
        while offset < len(data):
            try:
                attribute = structs.AttributeHeader.unpack(data, offset)
            except structs.StructError:
                return None
            if attribute.type == structs.AttributeType.DATA and not attribute.name:
                return (
                    attribute.real_size if attribute.non_resident else attribute.content_length
                )
            offset += attribute.length
        return None

    def _records(
        self, stream: BinaryIO, record_size: int
    ) -> Iterator[tuple[int, int, bytes, MftRecord]]:
        """``(순번, 오프셋, 파싱된 레코드)``를 흘려보낸다.

        시그니처가 다르거나 fixup이 깨진 레코드는 건너뜁니다. 손상된
        레코드 하나 때문에 나머지를 못 읽으면 안 됩니다.
        """
        stream.seek(0)
        position = 0
        while True:
            raw = stream.read(record_size)
            if len(raw) < record_size:
                return
            offset = position * record_size
            position += 1

            if raw[:4] not in (structs.FILE_SIGNATURE, structs.BAAD_SIGNATURE):
                continue  # 미사용 슬롯. 0으로 채워져 있다
            try:
                fixed = bytes(structs.apply_fixups(raw))
            except structs.StructError:
                continue
            try:
                yield position - 1, offset, fixed, MftRecord(fixed)
            except Exception:  # noqa: BLE001 — 남의 코드가 무엇을 던질지 모른다
                continue

    def _build_index(
        self, stream: BinaryIO, record_size: int
    ) -> dict[int, tuple[str, int]]:
        """1회차. ``레코드번호 → (이름, 부모번호)``."""
        index: dict[int, tuple[str, int]] = {}
        for position, _offset, _raw, record in self._records(stream, record_size):
            number = self._record_number(record, position)
            name = record.filename or ""
            if name:
                index[number] = (name, record.get_parent_record_num())
        return index

    def _emit(
        self,
        stream: BinaryIO,
        scope: Scope,
        record_size: int,
        index: dict[int, tuple[str, int]],
    ) -> Iterator[dict[str, Any]]:
        """2회차. 범위에 드는 레코드를 우리 형식으로 낸다."""
        for position, offset, raw, record in self._records(stream, record_size):
            number = self._record_number(record, position)
            if not record.filename:
                continue  # 이름 없는 레코드는 경로를 만들 수 없다

            path = self._full_path(number, index)
            if not scope.matches_path(path):
                continue

            si = self._times(record.si_times)
            fn = self._times(record.fn_times)
            # $DATA를 우선한다. 원본의 filesize는 $FN 값이라 대개 0이다.
            size = self._data_size(raw)
            if size is None:
                size = int(record.filesize or 0)

            yield {
                "ref": refs.make_ref(self.artifact, number),
                "artifact": self.artifact,
                "record_num": number,
                "offset": f"0x{offset:X}",
                "path": path,
                "allocated": bool(record.flags & structs.RecordFlags.IN_USE),
                "is_directory": bool(record.flags & structs.RecordFlags.DIRECTORY),
                "size": int(size),
                "si_btime": si["crtime"],
                "si_ctime": si["ctime"],
                "si_mtime": si["mtime"],
                "si_atime": si["atime"],
                "fn_btime": fn["crtime"],
                "fn_ctime": fn["ctime"],
                "fn_mtime": fn["mtime"],
            }

    @staticmethod
    def _record_number(record: MftRecord, position: int) -> int:
        """헤더의 레코드 번호. 없거나 0이면 순회 순번을 쓴다.

        ``ref``의 근거가 되는 값이라 틀리면 06단계 검증이 통째로 어긋납니다.
        헤더의 번호는 XP 이상에서만 유효하므로 확인이 필요합니다.
        """
        number = getattr(record, "recordnum", 0) or 0
        return number if number > 0 else position

    def _full_path(self, number: int, index: dict[int, tuple[str, int]]) -> str:
        """부모 참조를 따라 전체 경로를 만든다.

        고아 레코드(부모가 재할당된 삭제 파일 등)는 체인이 끊깁니다.
        그때는 만들 수 있는 만큼만 냅니다 — 경로가 없다고 레코드를 버리면
        삭제 흔적을 통째로 놓칩니다.
        """
        parts: list[str] = []
        current = number
        seen: set[int] = set()

        while current not in seen and current != ROOT_RECORD_NUMBER:
            seen.add(current)
            entry = index.get(current)
            if entry is None:
                break
            name, parent = entry
            parts.append(name)
            if parent == current:
                break
            current = parent

        return "\\".join([self.volume_letter, *reversed(parts)])

    @staticmethod
    def _times(times: dict[str, Any]) -> dict[str, str | None]:
        """``WindowsTime``을 ISO 문자열로. **정수 연산으로 다시 계산한다.**

        원본의 ``get_unix_time()``은 float 나눗셈이라 마이크로초가 틀어집니다.
        ``low``/``high``가 노출되어 있어 우회할 수 있습니다.
        """
        converted: dict[str, str | None] = {}
        for key, value in times.items():
            filetime = (int(getattr(value, "high", 0)) << 32) | int(getattr(value, "low", 0))
            moment = structs.filetime_to_datetime(filetime)
            converted[key] = (
                moment.strftime("%Y-%m-%dT%H:%M:%S.%f0Z") if moment is not None else None
            )
        return converted


