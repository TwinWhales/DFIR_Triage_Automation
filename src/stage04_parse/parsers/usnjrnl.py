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


class _Rewound:
    """앞에서 미리 읽은 바이트를 되돌려 놓은 스트림.

    빈 스트림 판정을 위해 헤더 크기만큼 읽었으므로, 순회가 그것을 다시
    보게 해야 합니다. ``seek``을 쓰지 않는 이유는 ``EvidenceSource``가
    되감을 수 없는 스트림을 줄 수 있기 때문입니다.
    """

    def __init__(self, head: bytes, rest: BinaryIO) -> None:
        self._head = head
        self._rest = rest

    def read(self, size: int = -1) -> bytes:
        if not self._head:
            return self._rest.read(size)
        if size < 0:
            out, self._head = self._head + self._rest.read(), b""
            return out
        if size <= len(self._head):
            out, self._head = self._head[:size], self._head[size:]
            return out
        out, self._head = self._head, b""
        return out + self._rest.read(size - len(out))


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
            # **연속된 실패는 한 덩어리로 센다.** 8바이트씩 걸어간 횟수를
            # 세면 비저널 구간 하나가 수만 건으로 부풀어, 매니페스트를 읽는
            # 사람이 "저널이 심하게 손상됐다"고 정반대로 판단한다.
            #
            # 실측(evidence/[root]): 꼬리에 붙은 남의 데이터 503,752바이트가
            # 503752 / 8 = 62,969건으로 집계됐다. 실제로는 못 읽은 구간 1곳이고
            # 나머지 306,857레코드는 전부 정상이었다.
            "parse_errors": 0,
            #: 못 읽은 총 바이트. 구간 수(``parse_errors``)와 함께 봐야
            #: 규모를 알 수 있다. 구간 1곳이 8바이트인 것과 500KB인 것은 다르다.
            "unreadable_bytes": 0,
            "unsupported_version": 0,
            "zero_bytes_skipped": 0,
            #: 이름에 짝 없는 서로게이트가 있어 원본 바이트를 따로 실은 레코드.
            #: 0 이 아니면 그 레코드들의 ``name`` 은 U+FFFD 로 바뀐 것이다.
            "name_unencodable": 0,
        }

    # ------------------------------------------------------------ 공개

    def parse(self, stream: BinaryIO, scope: Scope) -> Iterator[dict[str, Any]]:
        self.stats = self._new_stats()

        # 빈 스트림은 "변경이 없었다"가 아니라 "저널을 못 받았다"이다.
        # 조용히 0건을 내면 매니페스트에 record_count 0 으로만 남아
        # 두 경우가 구별되지 않는다. evidence 계층이 0바이트 파일을
        # 걸러 주지만, 다른 경로로 빈 스트림이 들어올 수 있으므로
        # 파서도 자기 앞을 지킨다.
        head = stream.read(structs.V2_HEADER_SIZE)
        if not head:
            raise ValueError(
                f"{self.artifact}: 저널이 비어 있습니다. "
                "$UsnJrnl:$J 의 내용이 아니라 이름 없는 $DATA 스트림을 "
                "뽑았을 수 있습니다 — 추출을 확인하십시오."
            )
        stream = _Rewound(head, stream)

        for offset, record in self._records(stream):
            # 이름으로만 거른다. path_prefix 는 적용할 수 없다 (모듈 설명 참조).
            if not scope.matches_extension(record.name):
                continue
            self.stats["records"] += 1
            yield self._as_dict(offset, record)

        if self.stats["parse_errors"]:
            # 구간 수와 바이트를 함께 냅니다. 둘 중 하나만으로는 규모를
            # 판단할 수 없습니다 — 구간 1곳이 8바이트일 수도, 500KB일 수도
            # 있고, 후자는 대개 저널 손상이 아니라 꼬리에 붙은 남의
            # 데이터입니다(docs/artifact-notes.md).
            _log.warning(
                "%s: 읽지 못한 구간 %d곳 / 총 %d바이트 — 레코드 %d건은 정상입니다",
                self.artifact,
                self.stats["parse_errors"],
                self.stats["unreadable_bytes"],
                self.stats["records"],
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

        # 못 읽은 구간 하나의 시작과 끝(절대 오프셋). ``bad_end`` 가 현재
        # 위치와 같으면 실패가 이어지는 중이므로 같은 구간이다.
        bad_start = -1
        bad_end = -1

        def close_bad_run() -> None:
            """열려 있던 구간을 로그로 남긴다.

            **위치와 크기를 함께 적습니다.** 구간 수만으로는 8바이트가
            깨진 것과 500KB가 통째로 저널이 아닌 것을 구별할 수 없습니다.
            """
            nonlocal bad_start
            if bad_start < 0:
                return
            _log.warning(
                "%s: @0x%X 부터 %d바이트를 읽지 못했습니다 (레코드가 아님)",
                self.artifact,
                bad_start,
                bad_end - bad_start,
            )
            bad_start = -1

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
                        close_bad_run()
                        return  # 헤더도 안 되는 꼬리 조각
                    break  # 더 읽어 와서 이어 붙인다

                # 0 구간 — 스파스 홀이거나 정렬 패딩이다. 구분할 필요 없다.
                if not int.from_bytes(buf[cursor : cursor + 4], "little"):
                    close_bad_run()
                    cursor = self._skip_zeros(buf, base, cursor)
                    progressed = True
                    continue

                try:
                    record = structs.UsnRecord.unpack(buf, cursor)
                except structs.UnsupportedVersion as e:
                    # V3/V4. 손상이 아니라 지원 범위 밖이므로 따로 센다.
                    # **레코드 하나를 통째로** 건너뛴다 — 8바이트씩 걸어
                    # 들어가면 본문을 레코드로 오해해 가짜 손상이 잡힌다.
                    close_bad_run()
                    self.stats["unsupported_version"] += 1
                    _log.warning("%s @ 0x%X: %s", self.artifact, base + cursor, e)
                    cursor += max(e.record_length, structs.RECORD_ALIGNMENT)
                    progressed = True
                    continue
                except structs.StructError:
                    # 레코드가 아니다. 8바이트 전진해 다시 찾는다.
                    #
                    # **집계는 구간 단위다.** 직전 위치도 실패였다면 같은
                    # 구간이 이어지는 것이므로 건수를 올리지 않고 바이트만
                    # 더한다. 새 구간일 때만 parse_errors 가 1 오른다.
                    if bad_end != base + cursor:
                        self.stats["parse_errors"] += 1
                        bad_start = base + cursor
                    self.stats["unreadable_bytes"] += structs.RECORD_ALIGNMENT
                    cursor += structs.RECORD_ALIGNMENT
                    bad_end = base + cursor
                    progressed = True
                    continue

                if len(buf) - cursor < record.record_length:
                    if eof:
                        close_bad_run()
                        return  # 잘린 마지막 레코드
                    break  # 뒷부분을 더 읽어 온다

                # 유효한 레코드를 만났으므로 못 읽던 구간이 여기서 끝난다.
                close_bad_run()
                yield base + cursor, record
                cursor += record.record_length
                progressed = True

            if eof and not progressed:
                close_bad_run()
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
        name, name_raw = self._encodable_name(record.name)
        out: dict[str, Any] = {
            "ref": refs.make_ref(self.artifact, record.usn),
            "artifact": self.artifact,
            "record_num": record.usn,
            "offset": "0x{:X}".format(offset),
            "name": name,
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
        if name_raw is not None:
            # 최상위에 새 키를 만들지 않는다 — 스키마가 동결이고
            # ``additionalProperties: false`` 다. ``fields`` 는 자유 형식으로
            # 선언된 자리라 여기 싣는 것이 스키마 변경이 아니다.
            out["fields"] = {"name_raw_utf16le": name_raw}
        return out

    def _encodable_name(self, name: str) -> "tuple[str, str | None]":
        """UTF-8 로 쓸 수 있는 이름과, 못 쓰면 원본 바이트의 hex.

        **NTFS 이름은 짝 없는 서로게이트를 허용하는데 UTF-8 은 아닙니다.**
        구조 계층은 ``errors="surrogatepass"`` 로 읽습니다(``usn_record.py``)
        — strict 로 읽으면 그런 이름을 가진 레코드만 조용히 사라지기
        때문입니다. 그런데 그 문자열을 그대로 내보내면 ``io.write_jsonl``
        이 ``ensure_ascii=False`` 로 dump 한 뒤 UTF-8 로 쓰다 터집니다.

        **터지면 레코드 하나가 아니라 아티팩트 전체가 사라집니다.**
        ``write_jsonl`` 은 임시 파일에 쓰다 예외가 나면 그것을 지우므로
        ``usnjrnl.jsonl`` 이 아예 생기지 않습니다(실측 148,409건).

        그래서 여기서 가른다 — ``name`` 은 U+FFFD 로 바꿔 쓸 수 있게 하고,
        **원본은 hex 로 함께 싣습니다.** 바이트를 버리지 않으므로
        ``bytes.fromhex(...).decode("utf-16-le", "surrogatepass")`` 로 원래
        문자열을 정확히 되돌릴 수 있습니다.

        다른 파서들은 처음부터 ``errors="replace"`` 라 이 자리가 없습니다.
        USN 만 ``surrogatepass`` 이고, 그 판단 자체는 옳습니다 — 이상한
        이름이 붙은 레코드가 사라지는 편이 더 나쁩니다.
        """
        try:
            name.encode("utf-8")
        except UnicodeEncodeError:
            pass
        else:
            return name, None

        raw = name.encode("utf-16-le", "surrogatepass")
        self.stats["name_unencodable"] += 1
        _log.warning(
            "%s: 이름에 짝 없는 서로게이트가 있어 U+FFFD 로 바꿉니다 "
            "(원본은 fields.name_raw_utf16le 에 hex 로 남습니다) — %s",
            self.artifact,
            raw.hex(),
        )
        return raw.decode("utf-16-le", "replace"), raw.hex()
