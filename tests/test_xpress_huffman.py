"""LZXPRESS Huffman 압축 해제 테스트.

명세를 옮긴 코드라 **틀려도 조용합니다.** 그래서 두 층으로 봅니다.

1. **고정 벡터** — Windows의 ``RtlCompressBuffer``로 압축해 둔 것을
   여기 박아 두고 풉니다. 어느 플랫폼에서도 돌아가므로, 리팩터링이
   복호기를 망가뜨리면 CI에서 바로 걸립니다.
2. **왕복 대조** — Windows에서만 돕니다. 그 자리에서 압축하고 우리
   구현으로 풀어 원본과 비교합니다. 청크 경계·길이 확장처럼 고정 벡터
   하나로는 건드리지 못하는 경로가 여기서 밟힙니다.

실물 MAM 프리패치 샘플이 없어 2번이 유일한 근거입니다. 기록은
``docs/artifact-notes.md``에 있습니다.
"""

from __future__ import annotations

import base64
import random

import pytest

from src.stage04_parse.structs.xpress_huffman import (
    CHUNK_SIZE,
    TABLE_SIZE,
    XpressError,
    decompress,
)

# ``RtlCompressBuffer`` 로 압축해 둔 고정 벡터. 반복이 많은 경로 문자열이라
# 일치(match) 경로를 밟고, 마지막의 'A' 40개가 거리 1짜리 긴 복사를 만든다.
PLAIN = (b"\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\CMD.EXE" * 40) + b"A" * 40
COMPRESSED = base64.b64decode(
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAGUAAAAAAABQUDMARmBGVgBGZlVmAAMAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANlAVqjo040GXu1zPHYlVuSj8Ozosr"
    "5xVPShwqz8eP9MBwAAFQ=="
)


def test_the_fixed_vector_decompresses_to_the_original():
    assert decompress(COMPRESSED, len(PLAIN)) == PLAIN


def test_zero_length_needs_no_input():
    # 길이가 0이면 청크가 아예 없다. 테이블을 읽으러 가면 안 된다.
    assert decompress(b"", 0) == b""


def test_a_negative_size_is_rejected():
    with pytest.raises(XpressError):
        decompress(COMPRESSED, -1)


def test_a_truncated_stream_says_so():
    # 짧은 채로 돌려주면 잘린 구조체를 파싱하다 엉뚱한 곳에서 실패한다.
    with pytest.raises(XpressError):
        decompress(COMPRESSED[:100], len(PLAIN))


def test_a_missing_table_says_so():
    with pytest.raises(XpressError) as e:
        decompress(b"\x00" * (TABLE_SIZE - 1), 10)
    assert "테이블" in str(e.value)


def test_an_all_zero_table_has_no_valid_code():
    # 부호 길이가 전부 0이면 어떤 비트열도 심볼이 되지 않는다. 조용히
    # 아무 심볼이나 고르면 그럴듯한 쓰레기가 나온다.
    with pytest.raises(XpressError):
        decompress(b"\x00" * (TABLE_SIZE + 64), 10)


# ==================================================== Windows 왕복 대조


def _compressor():
    """``RtlCompressBuffer``를 쓰는 압축 함수. 못 쓰면 ``None``."""
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:  # pragma: no cover - Windows 아님
        return None
    if not hasattr(ctypes, "WinDLL"):  # pragma: no cover - Windows 아님
        return None

    try:
        ntdll = ctypes.WinDLL("ntdll")
        # COMPRESSION_FORMAT_XPRESS_HUFF | COMPRESSION_ENGINE_MAXIMUM
        fmt = wintypes.USHORT(4 | 0x0100)
        size = wintypes.ULONG()
        fragment = wintypes.ULONG()
        if ntdll.RtlGetCompressionWorkSpaceSize(fmt, ctypes.byref(size), ctypes.byref(fragment)):
            return None
        workspace = ctypes.create_string_buffer(size.value)
    except OSError:  # pragma: no cover
        return None

    def compress(data: bytes) -> bytes:
        out = ctypes.create_string_buffer(len(data) * 2 + CHUNK_SIZE)
        final = wintypes.ULONG()
        status = ntdll.RtlCompressBuffer(
            fmt,
            data,
            wintypes.ULONG(len(data)),
            out,
            wintypes.ULONG(len(out)),
            wintypes.ULONG(4096),
            ctypes.byref(final),
            workspace,
        )
        assert status == 0, f"RtlCompressBuffer 실패: 0x{status & 0xFFFFFFFF:08X}"
        return out.raw[: final.value]

    return compress


compress = _compressor()
needs_windows = pytest.mark.skipif(
    compress is None, reason="RtlCompressBuffer 를 쓸 수 없음 (Windows 전용 대조)"
)


@needs_windows
@pytest.mark.parametrize(
    "size",
    # 청크 경계 앞뒤를 노린다. 되감기 규칙이 틀리면 두 번째 청크부터
    # 테이블이 어긋나 65536바이트째에서 깨진다 — 실제로 밟은 버그다.
    [1, 255, 256, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 7],
)
def test_incompressible_data_survives_the_round_trip(size):
    # 난수는 거의 전부 리터럴이라 압축하면 오히려 커진다. 청크가 여럿
    # 생기는 가장 확실한 방법이다.
    rnd = random.Random(size)
    data = bytes(rnd.getrandbits(8) for _ in range(size))
    assert decompress(compress(data), len(data)) == data


@needs_windows
def test_a_very_long_match_takes_the_32bit_length_escape():
    # 같은 바이트 7만 개. 일치 길이가 16비트에 안 들어가 길이 확장이
    # 두 번 일어난다(바이트 → 16비트 → 32비트).
    data = b"Z" * 70_000 + b"end"
    assert decompress(compress(data), len(data)) == data


@needs_windows
def test_compressible_data_over_several_chunks():
    data = b"".join(b"log line %d: something repeated here\n" % i for i in range(8000))
    assert len(data) > 3 * CHUNK_SIZE
    assert decompress(compress(data), len(data)) == data


@needs_windows
def test_a_wrong_expected_size_is_not_silently_accepted():
    data = b"prefetch-like content " * 200
    with pytest.raises(XpressError):
        decompress(compress(data), len(data) + 1)
