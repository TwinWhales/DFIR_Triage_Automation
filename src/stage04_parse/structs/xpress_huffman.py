"""LZXPRESS Huffman 압축 해제 (MS-XCA).

Windows 10 이후의 프리패치 파일은 ``MAM\\x04`` 헤더가 붙은 이 형식으로
압축돼 있습니다. 압축을 풀지 못하면 **Win10/11 증거에서는 프리패치가
통째로 0건**이 되므로, 온디스크 구조를 읽기 전에 이것이 먼저 필요합니다.

## 왜 직접 구현하나

파이썬에서 이 형식을 푸는 표준 라이브러리가 없습니다. 선택지는 셋이었고
앞의 둘을 버렸습니다.

* ``ctypes``로 ``RtlDecompressBufferEx`` 호출 — **Windows에서만 됩니다.**
  이 프로젝트는 추출된 증거를 리눅스에서 분석하는 것을 전제로 하고
  (``evidence.py`` ``_resolve``의 대소문자 처리가 그 때문입니다),
  플랫폼에 따라 읽을 수 있는 아티팩트가 달라지면 "봤는데 없었다"와
  "볼 줄 몰라 못 봤다"의 구분이 실행 환경에 좌우됩니다.
* 외부 패키지 추가 — 유지되는 순수 파이썬 구현을 찾지 못했습니다.

## 출처

* ``[MS-XCA]`` Xpress Compression Algorithm, 2.2절 — LZ77 + 허프만.
  비트 판독기(32비트 선행 판독, 16비트 워드 보충)의 의사코드가 여기 있고
  아래 ``_BitReader``는 그 구조를 그대로 옮긴 것입니다.

## 대조

명세를 옮긴 코드는 **조용히 틀리는 것**이 가장 위험합니다. 그래서
Windows의 ``RtlCompressBuffer``로 압축한 것을 이 구현으로 풀어 원본과
비교하는 왕복 시험을 씁니다(``tests/test_xpress_huffman.py``). 실물
MAM 프리패치 샘플이 없으므로 이것이 유일한 근거이며, 그 사실은
``docs/artifact-notes.md``에 적혀 있습니다.

## 청크 경계가 이 형식의 함정이다

압축 스트림은 **64KB짜리 청크의 연속**이고 청크마다 허프만 테이블이
새로 옵니다. 비트 판독기는 32비트를 미리 읽어 두므로, 청크가 끝났을 때
판독 위치는 실제 소비 지점보다 최대 4바이트 앞서 있습니다. 그대로 다음
청크의 테이블을 읽으면 **두 번째 청크부터 통째로 깨집니다.**

인코더가 청크 끝을 16비트 워드 경계로 맞추므로, 소비되지 않은 **온전한
워드 수만큼** 되감으면 정확히 다음 청크의 시작입니다. 남은 자투리 비트는
현재 청크의 패딩이라 되감지 않습니다(``_BitReader.rewind_to_word``).
"""

from __future__ import annotations

import struct

__all__ = [
    "XpressError",
    "CHUNK_SIZE",
    "SYMBOL_COUNT",
    "TABLE_SIZE",
    "MAX_CODE_LENGTH",
    "decompress",
]


class XpressError(ValueError):
    """압축 스트림을 풀 수 없다."""


#: 청크 하나가 푸는 최대 바이트 수. 마지막 청크만 이보다 작을 수 있다.
CHUNK_SIZE = 65536

#: 허프만 심볼 수. 0~255 리터럴, 256~511 일치(길이·거리 조합).
SYMBOL_COUNT = 512

#: 청크 앞에 붙는 테이블 크기. 심볼당 4비트라 512/2 = 256바이트.
TABLE_SIZE = SYMBOL_COUNT // 2

#: 부호 길이 상한. 판독기가 상위 15비트만 보면 되는 근거다.
MAX_CODE_LENGTH = 15

#: 일치 최소 길이. 3바이트 미만은 리터럴로 내는 편이 짧다.
_MIN_MATCH = 3

#: 길이 헤더가 이 값이면 추가 바이트를 읽는다.
_LENGTH_ESCAPE = 15

#: 추가 바이트가 이 값이면 다시 16비트를 읽는다.
_LENGTH_ESCAPE_2 = 255


class _BitReader:
    """MS-XCA 2.2.4절의 비트 판독기.

    상위 16비트가 지금 읽는 워드, 하위 16비트가 선행 판독분입니다.
    비트는 **MSB부터** 나갑니다.

    ``pos``는 다음에 읽을 바이트 위치이므로 이미 선행 판독한 만큼
    앞서 있습니다. 청크 경계를 계산할 때 그 사실을 감안해야 합니다
    (``rewind_to_word``).
    """

    def __init__(self, data: bytes, pos: int) -> None:
        self.data = data
        self.pos = pos
        #: 하위 절반에 남은 유효 비트 수. 상위 16비트는 항상 유효하다.
        self.extra = 16
        self.buffer = (self._read_word() << 16) | self._read_word()

    def _read_word(self) -> int:
        if self.pos + 2 > len(self.data):
            raise XpressError(
                f"압축 스트림이 잘렸습니다 (오프셋 {self.pos}, 전체 {len(self.data)}바이트)"
            )
        value = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return value

    def peek(self, count: int) -> int:
        """상위 ``count`` 비트를 소비하지 않고 본다."""
        return self.buffer >> (32 - count)

    def consume(self, count: int) -> None:
        """``count`` 비트를 버린다. 모자라면 16비트를 보충한다."""
        self.buffer = (self.buffer << count) & 0xFFFFFFFF
        self.extra -= count
        if self.extra < 0:
            self.buffer |= self._read_word() << (-self.extra)
            self.extra += 16

    def read_bits(self, count: int) -> int:
        """``count`` 비트를 읽어 정수로. ``count``가 0이면 0이다."""
        if count == 0:
            return 0
        value = self.peek(count)
        self.consume(count)
        return value

    def read_byte(self) -> int:
        """바이트 하나를 **비트 스트림과 무관하게** 읽는다.

        일치 길이가 15를 넘을 때 쓰는 확장 필드입니다. 비트 스트림이
        아니라 현재 판독 위치의 바이트를 그대로 가져가는 것이 명세이며,
        선행 판독한 워드 뒤에서 읽힙니다.
        """
        if self.pos >= len(self.data):
            raise XpressError(f"압축 스트림이 잘렸습니다 (오프셋 {self.pos})")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read_uint16(self) -> int:
        return self.read_byte() | (self.read_byte() << 8)

    def read_uint32(self) -> int:
        return self.read_uint16() | (self.read_uint16() << 16)


def _code_lengths(table: bytes) -> list[int]:
    """256바이트 테이블을 심볼 512개의 부호 길이로 편다.

    **낮은 니블이 먼저입니다.** 순서를 뒤집으면 테이블 전체가 어긋나
    첫 심볼부터 엉뚱한 값이 나옵니다.
    """
    lengths: list[int] = []
    for byte in table:
        lengths.append(byte & 0x0F)
        lengths.append(byte >> 4)
    return lengths


def _canonical(lengths: list[int]) -> tuple[list[int], list[int], list[int], list[int]]:
    """정규 허프만 부호를 길이별 표로 만든다.

    표 전체(32768칸)를 펴지 않고 길이를 1씩 늘려 가며 맞춰 보는 방식입니다.
    청크마다 테이블이 새로 오므로, 청크 수가 많을 때 표를 펴는 비용이
    복호 비용보다 커집니다.
    """
    counts = [0] * (MAX_CODE_LENGTH + 1)
    for length in lengths:
        counts[length] += 1
    counts[0] = 0

    symbols: list[int] = []
    for length in range(1, MAX_CODE_LENGTH + 1):
        symbols.extend(sym for sym, own in enumerate(lengths) if own == length)

    first_code = [0] * (MAX_CODE_LENGTH + 1)
    first_index = [0] * (MAX_CODE_LENGTH + 1)
    code = 0
    index = 0
    for length in range(1, MAX_CODE_LENGTH + 1):
        first_code[length] = code
        first_index[length] = index
        code += counts[length]
        index += counts[length]
        code <<= 1
    return counts, first_code, first_index, symbols


def _decode_symbol(
    reader: _BitReader,
    counts: list[int],
    first_code: list[int],
    first_index: list[int],
    symbols: list[int],
) -> int:
    code = 0
    for length in range(1, MAX_CODE_LENGTH + 1):
        code = (code << 1) | reader.read_bits(1)
        if counts[length] and code - first_code[length] < counts[length]:
            return symbols[first_index[length] + code - first_code[length]]
    raise XpressError("허프만 부호가 테이블에 없습니다 (테이블이 깨졌거나 스트림이 어긋났습니다)")


def decompress(data: bytes, uncompressed_size: int) -> bytes:
    """LZXPRESS Huffman 스트림을 푼다.

    ``uncompressed_size``는 호출자가 압니다 — 프리패치는 ``MAM`` 헤더가
    들고 있습니다. 스트림 자체에는 전체 길이가 없어서 이 값이 없으면
    어디서 멈춰야 할지 알 수 없습니다.

    푼 길이가 기대와 다르면 **예외입니다.** 짧은 채로 돌려주면 잘린
    구조체를 파싱하다 엉뚱한 곳에서 실패하고, 원인이 압축 해제였다는
    사실이 드러나지 않습니다.
    """
    if uncompressed_size < 0:
        raise XpressError(f"압축 해제 크기가 음수입니다: {uncompressed_size}")
    if uncompressed_size == 0:
        return b""

    out = bytearray()
    pos = 0

    while len(out) < uncompressed_size:
        if pos + TABLE_SIZE > len(data):
            raise XpressError(
                f"허프만 테이블이 잘렸습니다 (오프셋 {pos}, 남은 {len(data) - pos}바이트, "
                f"{len(out)}/{uncompressed_size}바이트 해제됨)"
            )
        counts, first_code, first_index, symbols = _canonical(
            _code_lengths(data[pos : pos + TABLE_SIZE])
        )
        reader = _BitReader(data, pos + TABLE_SIZE)
        chunk_end = min(len(out) + CHUNK_SIZE, uncompressed_size)

        while len(out) < chunk_end:
            symbol = _decode_symbol(reader, counts, first_code, first_index, symbols)
            if symbol < 256:
                out.append(symbol)
                continue

            symbol -= 256
            length = symbol & 0x0F
            offset_bits = symbol >> 4

            if length == _LENGTH_ESCAPE:
                length = reader.read_byte()
                if length == _LENGTH_ESCAPE_2:
                    length = reader.read_uint16()
                    if length == 0:
                        # 16비트로도 모자란 경우다. 청크가 64KB이므로 일치
                        # 길이는 최대 65536인데, 여기 담기는 값은 이미
                        # +15 된 것이라 65535를 넘을 수 있다. 실측에서
                        # 같은 바이트 70,000개를 압축하면 이 경로로 온다.
                        length = reader.read_uint32()
                    if length < _LENGTH_ESCAPE:
                        raise XpressError(f"일치 길이가 비정상입니다: {length}")
                    length -= _LENGTH_ESCAPE
                length += _LENGTH_ESCAPE
            length += _MIN_MATCH

            offset = (1 << offset_bits) + reader.read_bits(offset_bits)
            if offset > len(out):
                raise XpressError(
                    f"일치 거리가 출력 밖을 가리킵니다 (거리 {offset}, 출력 {len(out)}바이트)"
                )

            # 겹치는 복사가 정상이다. 거리 1로 길이 100이면 같은 바이트를
            # 100번 늘리는 것이므로 한 바이트씩 옮겨야 한다.
            start = len(out) - offset
            for _ in range(length):
                out.append(out[start])
                start += 1

        # **되감지 않는다.** 판독기가 32비트를 미리 읽어 두므로 여기가
        # 소비 지점보다 앞서 있을 것 같지만, 인코더가 청크 끝에 그만큼을
        # 패딩으로 채워 두어 판독 위치가 정확히 다음 청크의 시작이다.
        # 되감으면 두 번째 청크부터 테이블이 어긋난다 —
        # docs/artifact-notes.md 에 실측 기록이 있다.
        pos = reader.pos

    if len(out) != uncompressed_size:
        raise XpressError(f"해제 결과가 {len(out)}바이트, 기대는 {uncompressed_size}바이트입니다")
    return bytes(out)
