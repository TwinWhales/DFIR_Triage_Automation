"""$UsnJrnl:$J 파서 — USN 변경 저널.

레코드 하나를 뜯는 일은 ``structs/usn_record.py``가 하고, 여기서는
**스트림을 어떻게 걸어갈 것인가**만 다룹니다. 그게 이 아티팩트의
어려운 부분 전부입니다.

## $MFT와 다른 세 가지

**한 번만 순회합니다.** ``$MFT``는 부모 이름을 알아야 경로를 만들 수
있어 두 번 돌지만, USN 레코드는 서로를 참조하지 않습니다. 앞에서
뒤로 한 번 흘려보내면 끝입니다.

**레코드 크기가 가변입니다.** ``$MFT``는 1024바이트 고정이라 ``번호 ×
1024``로 위치가 나오는데, USN은 각 레코드가 자기 길이를 들고 있습니다.
그 길이가 깨지면 다음 레코드를 못 찾습니다 — 그래서 재동기화가 필요합니다.

**경로가 없습니다.** 레코드에는 파일 **이름**만 있고 부모 참조로
``$MFT``를 되짚어야 전체 경로가 나옵니다. 이 파서는 그것을 하지
않습니다. 아래 "범위 필터의 한계" 참조.

## 스파스 구간

``$J``는 스파스 파일입니다. 저널이 최대 크기에 닿으면 앞쪽 오래된
레코드가 잘려 나가고 그 자리가 스파스 데이터 런으로 바뀝니다
(``[LIBFSNTFS]`` "USN change journal entries").

추출 도구가 그 구멍을 **실제 0바이트로 물질화해서** 저장하는 경우가
흔합니다. 수십 GB 파일의 앞부분 대부분이 0인 상태로 옵니다. 그래서
0 구간을 8바이트씩 걸어가면 끝나지 않습니다 — ``bytes.lstrip``으로
한 번에 건너뜁니다.

레코드 사이의 정렬 패딩도 같은 0바이트라 같은 경로로 처리됩니다.
구멍인지 패딩인지 구분할 필요가 없습니다. 둘 다 "여기엔 레코드가
없다"는 뜻이니까요.

## 재동기화

길이 값이 깨졌거나 손상된 구간을 만나면 **8바이트씩 전진하며 유효한
레코드를 다시 찾습니다.** ``UsnRecord.unpack``이 길이·버전·이름 범위를
모두 검사하므로, 아무 위치에서나 그럴듯한 레코드가 만들어지지는
않습니다.

건너뛴 횟수는 ``stats``에 남고 ``_manifest.json``의 ``parse_errors``로
보고됩니다. **조용히 넘어가지 않습니다** — 저널의 어느 구간을 못 읽었는지
모르면 "이 시각에 아무 일도 없었다"고 잘못 읽게 됩니다.

## 범위 필터의 한계

``scope``의 조건 중 **``path_prefix``는 적용할 수 없습니다.** 레코드에
경로가 없기 때문입니다. ``extensions``는 이름에 적용되고, 시간 범위는
설계대로 거르지 않고 ``outside_time_range`` 플래그로 표시됩니다.

경로로 좁히지 못하니 03단계가 요청한 것보다 **넓게** 나옵니다. 좁히는
쪽으로 틀리는 것보다 낫다는 것이 이 프로젝트의 판단입니다
(``parsers/base.py`` ``Scope`` 참조) — 선별 실패로 증거를 놓치는 것이
최대 리스크입니다. 다만 이 사실은 알고 쓰셔야 합니다.
"""

from __future__ import annotations

import logging
from typing import Any, BinaryIO, Iterator

from ...common import refs
from ..structs import usn_record as structs
from .base import Scope

__all__ = ["UsnJrnlParser", "DEFAULT_CHUNK_SIZE"]

_log = logging.getLogger(__name__)

#: 한 번에 읽어 들일 크기. 레코드 최대 크기보다 충분히 커야 버퍼 경계에
#: 걸친 레코드를 이어 붙일 수 있다.
DEFAULT_CHUNK_SIZE = 1 << 20  # 1 MiB


class UsnJrnlParser:
    """``$UsnJrnl:$J`` 스트림을 읽어 우리 레코드 형식으로 낸다.

    ``stats``에 이번 실행의 집계가 남습니다. ``parse()``를 부를 때마다
    초기화됩니다.
    """

    artifact = "$UsnJrnl"

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        if chunk_size < structs.MAX_RECORD_SIZE * 2:
            raise ValueError(
                "chunk_size는 최대 레코드 크기의 두 배 이상이어야 합니다 "
                "(버퍼 경계에 걸친 레코드를 이어 붙여야 함): "
                "{} < {}".format(chunk_size, structs.MAX_RECORD_SIZE * 2)
            )
        self.chunk_size = chunk_size
        self.stats: dict[str, int] = self._new_stats()

    @staticmethod
    def _new_stats() -> dict[str, int]:
        return {
            "records": 0,
            "parse_errors": 0,
            "unsupported_version": 0,
            "zero_bytes_skipped": 0,
        }

    # ------------------------------------------------------------ 공개

    def parse(self, stream: BinaryIO, scope: Scope) -> Iterator[dict[str, Any]]:
        self.stats = self._new_stats()
        for offset, record in self._records(stream):
            # 이름으로만 거른다. path_prefix 는 적용할 수 없다 (모듈 설명 참조).
            if not scope.matches_extension(record.name):
                continue
            self.stats["records"] += 1
            yield self._as_dict(offset, record)

        if self.stats["parse_errors"]:
            _log.warning(
                "%s: 재동기화 %d회 — 저널 일부를 읽지 못했습니다",
                self.artifact,
                self.stats["parse_errors"],
            )

    # ------------------------------------------------------------ 내부

    def _records(self, stream: BinaryIO) -> Iterator[tuple[int, structs.UsnRecord]]:
        """``(절대 오프셋, 레코드)``를 흘려보낸다.

        버퍼를 굴리며 한 번만 순회합니다. ``base``는 버퍼 첫 바이트의
        스트림 내 절대 위치고, ``cursor``는 버퍼 안 현재 위치입니다.
        내보내는 오프셋은 **항상 절대값**입니다 — ``offset`` 필드로
        원본을 되짚어야 하므로 버퍼 상대값을 내면 안 됩니다.
        """
        buf = bytearray()
        base = 0
        cursor = 0
        eof = False

        while True:
            # 소비한 앞부분을 버리고 뒤를 채운다.
            if cursor:
                del buf[:cursor]
                base += cursor
                cursor = 0
            if not eof and len(buf) < self.chunk_size:
                chunk = stream.read(self.chunk_size)
                if chunk:
                    buf += chunk
                else:
                    eof = True
            if not buf:
                return

            progressed = False
            while cursor < len(buf):
                if len(buf) - cursor < structs.V2_HEADER_SIZE:
                    if eof:
                        return  # 헤더도 안 되는 꼬리 조각
                    break  # 더 읽어 와서 이어 붙인다

                # 0 구간 — 스파스 홀이거나 정렬 패딩이다. 구분할 필요 없다.
                if not int.from_bytes(buf[cursor : cursor + 4], "little"):
                    cursor = self._skip_zeros(buf, base, cursor)
                    progressed = True
                    continue

                try:
                    record = structs.UsnRecord.unpack(buf, cursor)
                except structs.UnsupportedVersion as e:
                    # V3/V4. 손상이 아니라 지원 범위 밖이므로 따로 센다.
                    # **레코드 하나를 통째로** 건너뛴다 — 8바이트씩 걸어
                    # 들어가면 본문을 레코드로 오해해 가짜 손상이 잡힌다.
                    self.stats["unsupported_version"] += 1
                    _log.warning("%s @ 0x%X: %s", self.artifact, base + cursor, e)
                    cursor += max(e.record_length, structs.RECORD_ALIGNMENT)
                    progressed = True
                    continue
                except structs.StructError:
                    # 레코드가 아니다. 8바이트 전진해 다시 찾는다.
                    self.stats["parse_errors"] += 1
                    cursor += structs.RECORD_ALIGNMENT
                    progressed = True
                    continue

                if len(buf) - cursor < record.record_length:
                    if eof:
                        return  # 잘린 마지막 레코드
                    break  # 뒷부분을 더 읽어 온다

                yield base + cursor, record
                cursor += record.record_length
                progressed = True

            if eof and not progressed:
                return

    def _skip_zeros(self, buf: bytearray, base: int, cursor: int) -> int:
        """0 구간을 건너뛰고 다음 레코드 후보 위치를 돌려준다.

        ``lstrip``으로 한 번에 넘깁니다. 8바이트씩 걸어가면 물질화된
        스파스 구간(수 GB)에서 사실상 끝나지 않습니다.

        **반드시 전진합니다.** 8바이트 경계로 내림했을 때 제자리에
        머무르면 무한 루프가 되므로 최소 한 칸은 나아갑니다.
        """
        tail = bytes(buf[cursor:])
        zeros = len(tail) - len(tail.lstrip(b"\x00"))
        self.stats["zero_bytes_skipped"] += zeros

        if zeros == len(tail):
            return len(buf)  # 버퍼 끝까지 전부 0

        # 레코드 크기는 4바이트 미만 값이라 0이 아닌 첫 바이트는 레코드
        # 시작에서 0~1바이트 안쪽이다. 8바이트 경계로 내려 맞춘다.
        target = base + cursor + zeros
        target -= target % structs.RECORD_ALIGNMENT
        return max(cursor + structs.RECORD_ALIGNMENT, target - base)

    def _as_dict(self, offset: int, record: structs.UsnRecord) -> dict[str, Any]:
        """레코드를 04단계 출력 형식으로.

        ``record_num``이 곧 USN입니다. USN은 저널 스트림 안의 자기
        오프셋이라 고유 식별자로 그대로 쓸 수 있습니다
        (``refs.py``: "아티팩트 내부의 고유 번호를 그대로 쓴다").

        ``offset``은 **우리가 읽은 파일 안의 실제 위치**입니다. 추출
        도구가 스파스 구간을 잘라냈다면 ``record_num``과 어긋나는데,
        그 차이 자체가 "이 파일은 원본 스트림이 아니다"라는 신호입니다.
        """
        out: dict[str, Any] = {
            "ref": refs.make_ref(self.artifact, record.usn),
            "artifact": self.artifact,
            "record_num": record.usn,
            "offset": "0x{:X}".format(offset),
            "name": record.name,
            "reason": record.reason_names,
            "source": record.source_names,
            "file_entry": record.file_reference.entry,
            "file_sequence": record.file_reference.sequence,
            "parent_entry": record.parent_reference.entry,
            "parent_sequence": record.parent_reference.sequence,
            "is_directory": record.is_directory,
        }
        # FILETIME 0이면 키를 넣지 않는다. null을 넣으면 스키마가 막고,
        # 레코드를 버리면 이상함 자체가 증거인 경우를 놓친다.
        if record.timestamp is not None:
            out["timestamp"] = record.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f0Z")
        return out
