"""``RecentFileCache.bcf`` 온디스크 구조 — Windows 7 전용.

## 이것이 무엇인가

`%SystemRoot%\\AppCompat\\Programs\\RecentFileCache.bcf`. 응용 프로그램
호환성 하위 시스템이 **최근에 처음 실행된 실행 파일의 전체 경로**를
쌓아 두는 파일입니다. Windows 8부터 `Amcache.hve`가 이 자리를 대신하며,
Win7에는 Amcache가 없습니다(`osinfo.AVAILABILITY`).

Amcache와 달리 **경로 목록뿐입니다.** SHA1도 크기도 실행 시각도 없습니다.
파일의 수정 시각이 "마지막으로 뭔가 추가된 시각"이고, 그것이 이 아티팩트가
가진 유일한 시간 정보입니다.

## 구조

헤더 20바이트 뒤에 항목이 이어 붙습니다. 길이 필드가 있어 구분자를 찾을
필요가 없습니다.

==============  ====  ====================================================
오프셋           크기   내용
==============  ====  ====================================================
``0x00``          4   시그니처 ``FE FF EE FF``
``0x04``          4   미상
``0x08``          4   미상
``0x0C``          4   미상
``0x10``          4   미상
==============  ====  ====================================================

항목 하나::

    4바이트   경로 길이 (UTF-16 **문자 수**, 종결자 제외)
    N*2바이트 경로 (UTF-16LE)
    2바이트   종결자 0x0000

**길이가 바이트가 아니라 문자 수입니다.** 바이트로 읽으면 경로가 절반에서
잘리고, 그래도 그럴듯한 문자열이 나와서 조용히 틀립니다.

## 대조 상태 — 아직 실물로 확인하지 않았다

**이 파일은 명세만 보고 썼습니다.** 저장소에 Windows 7 이미지가 없습니다
(`evidence/`에 남은 것은 Win10 하나뿐). `docs/limitations.md`에 같은
내용이 적혀 있습니다.

그래서 **틀릴 수 있다는 전제로** 짰습니다. 어긋나면 그럴듯한 값을 내는
대신 **거부합니다.**

- 시그니처가 다르면 파일 전체를 거부하고 **실제로 본 4바이트를 메시지에
  담습니다.** 위 표가 틀렸다면 한 줄 고치면 되는 일임이 드러나야 합니다.
- 길이가 0이거나 파일 밖을 가리키면 그 항목에서 멈춥니다.
- 종결자 자리가 ``0x0000``이 아니면 항목 구조가 우리 가정과 다른
  것이므로 멈춥니다. **가장 중요한 검사입니다** — 길이 필드의 단위를
  잘못 잡았다면 여기가 어긋납니다.
- 경로 안에 널 문자가 있으면 그 항목만 건너뜁니다.
- 끝까지 읽고 남은 바이트가 있으면 세어서 냅니다. 조용히 버리면 "여기서
  끝났다"와 "여기서부터 못 읽었다"가 구별되지 않습니다.

Win7 실물이 들어오면 `RecentFileCacheParser`(Eric Zimmerman)와 대조하고
`docs/artifact-notes.md`에 기록해야 합니다. 그 전까지 이 파서의 산출물은
**검증되지 않은 것**입니다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

__all__ = [
    "SIGNATURE",
    "HEADER_SIZE",
    "LENGTH_FIELD_SIZE",
    "TERMINATOR_SIZE",
    "MAX_PATH_CHARS",
    "RecentFileCacheError",
    "Entry",
    "read_header",
    "read_entries",
]


class RecentFileCacheError(ValueError):
    """구조를 읽을 수 없다."""


#: 헤더 0x00. 이 값이 아니면 RecentFileCache.bcf 가 아니다.
SIGNATURE = b"\xfe\xff\xee\xff"

#: 헤더 크기. 항목이 바로 뒤에 붙는다.
HEADER_SIZE = 20

#: 항목의 길이 필드 크기.
LENGTH_FIELD_SIZE = 4

#: 항목 끝 종결자 크기.
TERMINATOR_SIZE = 2

#: 경로 길이 상한(문자 수). 길이 필드를 잘못 읽었는지 보는 기준이다.
#:
#: Win32 확장 경로가 32,767자까지 가능하므로 그 값을 그대로 쓴다. 실제
#: 값은 보통 40~120자이고, 자리를 잘못 잡으면 대개 수억이 나온다.
MAX_PATH_CHARS = 32_767


@dataclass(frozen=True)
class Entry:
    """항목 하나 — 실행 파일 전체 경로.

    ``offset``은 **길이 필드의 시작**이다. 항목 안에서 유일한 값이 이것뿐이라
    ``ref``의 레코드 번호로도 쓴다(레지스트리가 nk 오프셋을 쓰는 것과 같다).
    """

    offset: int
    path: str

    @property
    def end(self) -> int:
        """이 항목 **다음** 바이트의 위치.

        부르는 쪽이 "다 읽고 얼마가 남았나"를 세는 데 씁니다. 같은 걸음을
        두 번 걷지 않으려고 항목이 자기 끝을 들고 있습니다.
        """
        return self.offset + LENGTH_FIELD_SIZE + len(self.path) * 2 + TERMINATOR_SIZE


def read_header(data: bytes) -> None:
    """헤더를 확인한다. 읽을 값이 없어 아무것도 돌려주지 않는다.

    헤더 20바이트 중 시그니처 말고는 무엇인지 모릅니다. **모르는 값을
    ``fields``에 담지 않습니다** — 이름을 붙이는 순간 그것이 우리 해석이
    되고, 05단계 모델이 그 이름을 근거로 문장을 만들 수 있습니다.
    """
    if len(data) < HEADER_SIZE:
        raise RecentFileCacheError(
            f"헤더가 잘렸습니다 ({len(data)}바이트, 최소 {HEADER_SIZE})"
        )
    if data[:4] != SIGNATURE:
        raise RecentFileCacheError(
            f"RecentFileCache.bcf 가 아닙니다 (시그니처 {data[:4].hex()}, "
            f"기대 {SIGNATURE.hex()}). 파일이 맞다면 "
            "structs/recentfilecache_record.py 의 SIGNATURE 를 확인하십시오 — "
            "이 구조는 아직 실물로 대조하지 않았습니다."
        )


def read_entries(data: bytes) -> Iterator[Entry]:
    """항목을 차례로 낸다. 구조가 어긋나면 그 자리에서 멈춘다.

    **멈추되 앞의 것은 이미 냈습니다.** 절반이라도 읽은 경로는 증거이고,
    남은 바이트는 부르는 쪽이 세어 매니페스트에 남깁니다.
    """
    read_header(data)
    cursor = HEADER_SIZE

    while cursor + LENGTH_FIELD_SIZE <= len(data):
        entry_start = cursor
        char_count = struct.unpack_from("<I", data, cursor)[0]
        if char_count == 0 or char_count > MAX_PATH_CHARS:
            raise RecentFileCacheError(
                f"오프셋 0x{cursor:X}: 경로 길이가 비정상입니다 ({char_count}자). "
                "길이 필드의 자리나 단위가 다를 수 있습니다."
            )

        start = cursor + LENGTH_FIELD_SIZE
        end = start + char_count * 2
        if end + TERMINATOR_SIZE > len(data):
            raise RecentFileCacheError(
                f"오프셋 0x{cursor:X}: 항목이 파일 밖으로 나갑니다 "
                f"(길이 {char_count}자, 남은 바이트 {len(data) - start})"
            )

        terminator = data[end : end + TERMINATOR_SIZE]
        if terminator != b"\x00\x00":
            # 길이 단위를 잘못 잡았다면 여기가 어긋난다. 문자 수를
            # 바이트로 읽으면 경로 한가운데에서 끊겨 종결자가 안 나온다.
            raise RecentFileCacheError(
                f"오프셋 0x{end:X}: 종결자가 0x0000 이 아닙니다 "
                f"({terminator.hex()}). 항목 구조가 가정과 다릅니다."
            )

        path = data[start:end].decode("utf-16-le", "replace")
        cursor = end + TERMINATOR_SIZE
        if "\x00" in path:
            # 길이 안에 널이 들어 있다. 이 항목만 버리고 계속한다 —
            # 다음 항목의 자리는 길이 필드가 이미 말해 줬다.
            continue
        yield Entry(offset=entry_start, path=path)
