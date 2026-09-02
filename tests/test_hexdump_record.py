"""``tools/hexdump_record.py`` — 오프셋으로 원본을 되짚는다.

이 도구가 하는 주장은 하나입니다 — **04단계가 남긴 ``offset``으로 원본
바이트에 내려가면 거기 그 레코드가 있다.** 그래서 테스트도 두 방향입니다.

- 맞는 오프셋은 **통과해야 한다** (그러지 않으면 도구가 쓸모없다)
- 틀린 오프셋은 **걸려야 한다** (그러지 않으면 도구가 거짓말을 한다)

둘째가 더 중요합니다. 통과만 시키는 대조는 대조가 아니라 장식입니다.
그래서 어긋난 경우를 아티팩트마다 하나씩 만들어 둡니다 — 한 섹터 밀린
``$MFT``, 남의 USN, 다른 레코드의 EventRecordID.

바이너리는 픽스처로 두지 않고 여기서 합성합니다(``test_recentfilecache_parser``
와 같은 규약). 실물 대조는 ``docs/artifact-notes.md`` 2026-08-30 절에
있습니다 — 60GB 이미지는 저장소에 없어 테스트가 들고 있을 수 없습니다.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from tools.hexdump_record import (
    Check,
    HexdumpError,
    Window,
    find_record,
    hexdump,
    main,
    natural_length,
    sample_refs,
    verify,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Sysmon 을 켠 실물 이미지. 없으면 실물 대조를 건너뛴다(gitignore 대상).
REAL_IMAGE = REPO_ROOT / "evidence" / "win10_sysmon_testimage.001"
#: 이 이미지의 시스템 볼륨. 0은 0.4GiB 복구 파티션이다(``work.md``).
REAL_VOLUME = 1

RECORD_SIZE = 1024
SECTOR_SIZE = 512


# =============================================================== 합성


def build_mft_record(number: int, name: str, *, usn: bytes = b"\x07\x00") -> bytes:
    """``FILE`` 레코드 하나. 업데이트 시퀀스까지 실제와 같게 만든다.

    섹터 끝 2바이트를 USN으로 덮는 것이 핵심입니다 — 도구가 그것으로
    "레코드 경계에 정확히 내려앉았다"를 판정하므로, 여기서 대충 만들면
    테스트가 통과해도 아무것도 확인하지 못합니다.
    """
    record = bytearray(RECORD_SIZE)
    record[0:4] = b"FILE"
    struct.pack_into("<H", record, 0x4, 0x30)  # 업데이트 시퀀스 배열 위치
    struct.pack_into("<H", record, 0x6, RECORD_SIZE // SECTOR_SIZE + 1)  # USN 자신 포함
    struct.pack_into("<H", record, 0x14, 0x38)  # 첫 속성 오프셋
    struct.pack_into("<H", record, 0x16, 0x01)  # IN_USE
    struct.pack_into("<I", record, 0x18, 0x100)
    struct.pack_into("<I", record, 0x1C, RECORD_SIZE)
    struct.pack_into("<I", record, 0x2C, number)

    encoded = name.encode("utf-16-le")
    record[0x100 : 0x100 + len(encoded)] = encoded

    record[0x30:0x32] = usn
    for sector in range(RECORD_SIZE // SECTOR_SIZE):
        end = (sector + 1) * SECTOR_SIZE
        record[end - 2 : end] = usn
    return bytes(record)


def build_usn_record(usn: int, name: str) -> bytes:
    """``USN_RECORD_V2`` 하나. 구조는 ``structs/usn_record.py``의 표 그대로."""
    encoded = name.encode("utf-16-le")
    length = 0x3C + len(encoded)
    length += (-length) % 8
    record = bytearray(length)
    struct.pack_into("<I", record, 0x0, length)
    struct.pack_into("<H", record, 0x4, 2)
    struct.pack_into("<H", record, 0x6, 0)
    struct.pack_into("<Q", record, 0x18, usn)
    struct.pack_into("<H", record, 0x38, len(encoded))
    struct.pack_into("<H", record, 0x3A, 0x3C)
    record[0x3C : 0x3C + len(encoded)] = encoded
    return bytes(record)


def build_evtx_record(record_id: int, payload: int = 0x60) -> bytes:
    """evtx 레코드 하나. 크기가 앞뒤로 두 번 적히는 것까지 만든다."""
    size = 0x18 + payload
    record = bytearray(size)
    record[0:4] = b"\x2a\x2a\x00\x00"
    struct.pack_into("<I", record, 0x4, size)
    struct.pack_into("<Q", record, 0x8, record_id)
    struct.pack_into("<I", record, size - 4, size)
    return bytes(record)


def build_nk_record(name: str, *, ascii_name: bool = True) -> bytes:
    """``nk`` 셀 하나. 이름 길이는 ``0x48``, 이름은 ``0x4C``."""
    encoded = name.encode("windows-1252" if ascii_name else "utf-16-le")
    record = bytearray(0x4C + len(encoded))
    record[0:2] = b"nk"
    struct.pack_into("<H", record, 0x2, 0x0020 if ascii_name else 0x0000)
    struct.pack_into("<H", record, 0x48, len(encoded))
    record[0x4C : 0x4C + len(encoded)] = encoded
    return bytes(record)


def build_bcf_entry(path: str) -> bytes:
    """``RecentFileCache.bcf`` 항목 하나. 길이는 **문자 수**다."""
    encoded = path.encode("utf-16-le")
    return struct.pack("<I", len(path)) + encoded + b"\x00\x00"


def write_case(tmp_path: Path, records: "list[dict]", mft: bytes) -> "tuple[Path, Path]":
    """볼륨 루트 하나와 ``04_parsed/`` 하나를 만든다."""
    volume = tmp_path / "volume"
    volume.mkdir(exist_ok=True)
    (volume / "$MFT").write_bytes(mft)

    parsed = tmp_path / "04_parsed"
    parsed.mkdir(exist_ok=True)
    with (parsed / "mft.jsonl").open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return volume, parsed


def mft_row(ref: str, number: int, offset: int, name: str) -> dict:
    return {
        "ref": ref,
        "artifact": "$MFT",
        "record_num": number,
        "offset": f"0x{offset:X}",
        "path": f"C:\\Users\\Public\\{name}",
        "name": name,
        "flags": [],
    }


def window_for(
    artifact: str, offset: int, data: bytes, ref: str = "X#0", context: "dict | None" = None
) -> Window:
    return Window(
        ref=ref,
        artifact=artifact,
        offset=offset,
        data=data,
        source="합성",
        method="test",
        context=context or {},
    )


#: SRUM 대조가 창 밖에서 받아야 하는 사실. 실물 ``SRUDB.dat`` 의 값이다
#: (매직 0x89ABCDEF, 페이지 4096, 파일 0x90000) — ``artifact-notes.md`` 2026-08-30.
ESE_CONTEXT = {"ese_magic": 0x89ABCDEF, "page_size": 4096, "file_size": 0x90000}


def hard_failures(checks: "list[Check]") -> "list[str]":
    return [c.label for c in checks if c.hard and not c.ok]


# =============================================================== 관통


def test_offset_leads_back_to_the_same_record(tmp_path, capsys):
    """맞는 오프셋은 통과한다 — 이 도구의 존재 이유."""
    mft = build_mft_record(0, "$MFT") + build_mft_record(41, "banker.exe")
    volume, parsed = write_case(
        tmp_path, [mft_row("MFT#41", 41, RECORD_SIZE, "banker.exe")], mft
    )

    code = main(["MFT#41", "--parsed", str(parsed), "--evidence", str(volume)])
    out = capsys.readouterr().out

    assert code == 0
    assert "되짚음 1/1건" in out
    # 덤프의 왼쪽 열은 파일 안의 절대 위치다. 상대 위치를 찍으면 되짚을 수 없다.
    assert "0x00000400" in out
    assert "|FILE" in out


def test_wrong_offset_is_caught(tmp_path, capsys):
    """다른 레코드를 가리키는 오프셋은 걸린다.

    앞 레코드는 자기 번호를 헤더에 들고 있으므로(5), ``MFT#41``이 그 자리를
    가리키면 헤더가 바로 아니라고 말합니다.
    """
    mft = build_mft_record(5, "hosts") + build_mft_record(41, "banker.exe")
    volume, parsed = write_case(tmp_path, [mft_row("MFT#41", 41, 0, "banker.exe")], mft)

    code = main(["MFT#41", "--parsed", str(parsed), "--evidence", str(volume), "--no-dump"])
    out = capsys.readouterr().out

    assert code == 1
    assert "✗ 헤더의 레코드 번호" in out


def test_offset_past_end_of_file_is_not_a_dump_of_nothing(tmp_path, capsys):
    """파일 끝을 넘는 오프셋은 빈 덤프가 아니라 실패다."""
    mft = build_mft_record(0, "$MFT")
    volume, parsed = write_case(
        tmp_path, [mft_row("MFT#41", 41, RECORD_SIZE * 9, "banker.exe")], mft
    )

    code = main(["MFT#41", "--parsed", str(parsed), "--evidence", str(volume)])
    assert code == 1
    assert "파일 크기" in capsys.readouterr().err


def test_missing_ref_says_which_file_it_looked_in(tmp_path):
    """"없다"만 말하면 다음 행동이 안 나온다. 어디를 봤는지 말한다."""
    mft = build_mft_record(0, "$MFT")
    _volume, parsed = write_case(tmp_path, [mft_row("MFT#0", 0, 0, "$MFT")], mft)

    with pytest.raises(HexdumpError) as e:
        find_record(parsed, "MFT#999")
    assert "mft.jsonl" in str(e.value)


def test_unparsed_artifact_does_not_look_like_a_tool_bug(tmp_path):
    """그 아티팩트를 파싱한 적이 없는 경우와 도구 결함을 구별한다."""
    parsed = tmp_path / "04_parsed"
    parsed.mkdir()
    with pytest.raises(HexdumpError) as e:
        find_record(parsed, "EVTX-SEC#1")
    assert "evtx_security.jsonl" in str(e.value)


# =============================================================== $MFT


def test_update_sequence_catches_a_half_record_slip():
    """한 섹터 밀린 오프셋은 시그니처와 업데이트 시퀀스 양쪽에서 걸린다.

    번호 대조만으로는 부족한 경우가 이것입니다 — 엉뚱한 자리의 4바이트가
    우연히 그 번호일 수 있습니다. 섹터 끝마다 같은 USN이 있는 것은
    우연으로 만들어지지 않습니다.
    """
    record = build_mft_record(41, "banker.exe")
    slipped = record[SECTOR_SIZE:] + b"\x00" * SECTOR_SIZE

    checks = verify(
        mft_row("MFT#41", 41, RECORD_SIZE + SECTOR_SIZE, "banker.exe"),
        window_for("$MFT", RECORD_SIZE + SECTOR_SIZE, slipped),
    )
    assert "시그니처" in hard_failures(checks)


def test_update_sequence_is_checked_not_reverted():
    """되돌리지 않는다 — 이 도구가 보여야 하는 것은 디스크에 있는 그대로다."""
    record = build_mft_record(41, "banker.exe", usn=b"\x2a\x00")
    checks = verify(
        mft_row("MFT#41", 41, 0, "banker.exe"), window_for("$MFT", 0, record)
    )
    sequence = next(c for c in checks if c.label == "업데이트 시퀀스")
    assert sequence.ok
    # 섹터 끝이 여전히 USN이다. 되돌렸다면 원본 바이트가 아니다.
    assert record[SECTOR_SIZE - 2 : SECTOR_SIZE] == b"\x2a\x00"


def test_broken_update_sequence_is_reported():
    """섹터 하나만 어긋나도 잡는다."""
    record = bytearray(build_mft_record(41, "banker.exe"))
    record[SECTOR_SIZE - 2 : SECTOR_SIZE] = b"\xff\xff"
    checks = verify(
        mft_row("MFT#41", 41, 0, "banker.exe"), window_for("$MFT", 0, bytes(record))
    )
    assert "업데이트 시퀀스" in hard_failures(checks)


def test_zero_header_number_falls_back_to_the_position():
    """헤더 번호가 0이면 파서도 순번을 썼다. 대조도 같은 근거로 간다."""
    record = build_mft_record(0, "boot")
    ok = verify(mft_row("MFT#3", 3, RECORD_SIZE * 3, "boot"), window_for("$MFT", RECORD_SIZE * 3, record))
    bad = verify(mft_row("MFT#3", 3, RECORD_SIZE * 5, "boot"), window_for("$MFT", RECORD_SIZE * 5, record))

    assert not hard_failures(ok)
    assert "순번(오프셋 ÷ 레코드 크기)" in hard_failures(bad)


def test_name_mismatch_is_not_counted_as_a_wrong_offset():
    """이름은 보강 검사다. 어긋나도 오프셋이 틀렸다고 말하지 않는다.

    ``$MFT``는 업데이트 시퀀스가 덮은 2바이트가 이름에 걸릴 수 있습니다.
    그것을 실패로 세면 "대조 실패"가 무엇을 뜻하는지 흐려집니다.
    """
    record = build_mft_record(41, "banker.exe")
    checks = verify(mft_row("MFT#41", 41, 0, "other.exe"), window_for("$MFT", 0, record))

    assert not hard_failures(checks)
    assert any(c.label == "이름 문자열" and not c.ok for c in checks)


# =============================================================== 나머지 아티팩트


def test_usn_is_matched_by_its_own_usn():
    """USN이 곧 ``record_num``이다(``refs.py``). 남의 USN은 걸린다."""
    record = build_usn_record(5063392, "webshell.aspx")
    row = {
        "ref": "USN#5063392",
        "artifact": "$UsnJrnl",
        "record_num": 5063392,
        "offset": "0x18",
        "name": "webshell.aspx",
        "flags": [],
    }
    assert not hard_failures(verify(row, window_for("$UsnJrnl", 0x18, record)))

    row["record_num"] = 5063400
    assert "USN" in hard_failures(verify(row, window_for("$UsnJrnl", 0x18, record)))


def test_evtx_is_matched_by_event_record_id():
    """``0x8``의 EventRecordID. 크기가 앞뒤로 두 번 적힌 것도 본다."""
    record = build_evtx_record(4624)
    row = {
        "ref": "EVTX-SEC#4624",
        "artifact": "evtx:Security",
        "record_num": 4624,
        "offset": "0x1000",
        "flags": [],
    }
    checks = verify(row, window_for("evtx:Security", 0x1000, record))
    assert not hard_failures(checks)
    assert any(c.label == "레코드 끝의 크기 반복" and c.ok for c in checks)

    row["record_num"] = 4625
    assert "EventRecordID" in hard_failures(verify(row, window_for("evtx:Security", 0x1000, record)))


def test_registry_offset_is_the_identifier():
    """레지스트리는 일련번호가 없어 오프셋 자신이 식별자다. 이름까지 맞춘다."""
    record = build_nk_record("Run")
    row = {
        "ref": "REG-SW#294912",
        "artifact": "registry:SOFTWARE",
        "record_num": 294912,
        "offset": "0x48000",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "name": "Run",
        "flags": [],
    }
    assert not hard_failures(verify(row, window_for("registry:SOFTWARE", 0x48000, record)))

    row["name"] = "RunOnce"
    assert "키 이름" in hard_failures(verify(row, window_for("registry:SOFTWARE", 0x48000, record)))


def test_registry_reads_utf16_names_too():
    """ASCII 플래그가 없으면 UTF-16LE다. 플래그를 무시하면 이름이 깨진다."""
    record = build_nk_record("한글키", ascii_name=False)
    row = {
        "ref": "REG-SYS#4096",
        "artifact": "registry:SYSTEM",
        "record_num": 4096,
        "offset": "0x1000",
        "name": "한글키",
        "flags": [],
    }
    assert not hard_failures(verify(row, window_for("registry:SYSTEM", 0x1000, record)))


def test_recentfilecache_length_is_in_characters():
    """길이를 바이트로 읽으면 경로가 절반에서 잘린다. 종결자로 걸린다."""
    path = "C:\\Users\\Public\\banker.exe"
    record = build_bcf_entry(path)
    row = {
        "ref": "RFCACHE#20",
        "artifact": "recentfilecache",
        "record_num": 20,
        "offset": "0x14",
        "path": path,
        "name": "banker.exe",
        "flags": [],
    }
    checks = verify(row, window_for("recentfilecache", 0x14, record))
    assert not hard_failures(checks)
    assert any(c.label == "종결자" and c.ok for c in checks)


def test_prefetch_falls_back_to_the_filename_hash():
    """``offset``이 항상 ``0x0``이라 오프셋으로 가릴 것이 없다.

    대신 ``.pf`` 파일명 뒤 8자리 해시가 ``record_num``과 같아야 합니다.
    그 값은 Windows가 쓴 것이라 우리 해석과 독립입니다.
    """
    header = bytearray(0x100)
    struct.pack_into("<I", header, 0x0, 30)
    header[4:8] = b"SCCA"
    struct.pack_into("<I", header, 0x4C, 0x89305D47)
    row = {
        "ref": f"PF#{0x89305D47}",
        "artifact": "prefetch",
        "record_num": 0x89305D47,
        "offset": "0x0",
        "name": "CMD.EXE",
        "fields": {"prefetch_file": "CMD.EXE-89305D47.pf"},
        "flags": [],
    }
    assert not hard_failures(verify(row, window_for("prefetch", 0, bytes(header))))

    row["fields"] = {"prefetch_file": "CMD.EXE-12345678.pf"}
    assert "파일명의 경로 해시" in hard_failures(verify(row, window_for("prefetch", 0, bytes(header))))


def test_compressed_prefetch_says_what_it_cannot_check():
    """MAM 압축본은 헤더가 압축돼 있다. 못 하는 것을 말하고 넘어간다."""
    data = b"MAM\x04" + b"\x00" * 0x40
    row = {
        "ref": f"PF#{0x89305D47}",
        "artifact": "prefetch",
        "record_num": 0x89305D47,
        "offset": "0x0",
        "fields": {"prefetch_file": "CMD.EXE-89305D47.pf"},
        "flags": [],
    }
    checks = verify(row, window_for("prefetch", 0, data))
    assert not hard_failures(checks)
    assert any("압축" in c.detail for c in checks)


def test_srum_admits_it_is_page_granular():
    """페이지까지만 성립한다는 것을 감추지 않는다(``parsers/srum.py``)."""
    row = {
        "ref": "SRUM-NET#12",
        "artifact": "srum:NetworkUsage",
        "record_num": 12,
        "offset": "0x30000",
        "flags": [],
    }
    checks = verify(row, window_for("srum:NetworkUsage", 0x30000, b"\x00" * 64, context=ESE_CONTEXT))
    assert not hard_failures(checks)
    assert any("페이지" in c.detail for c in checks)


def test_srum_page_size_comes_from_the_header_not_a_guess():
    """8KB DB에서 4KB 배수만 보면 절반이 엉뚱한 오프셋도 통과한다."""
    row = {
        "ref": "SRUM-NET#12",
        "artifact": "srum:NetworkUsage",
        "record_num": 12,
        "offset": "0x31000",
        "flags": [],
    }
    context = dict(ESE_CONTEXT, page_size=8192)
    assert "페이지 경계" in hard_failures(
        verify(row, window_for("srum:NetworkUsage", 0x31000, b"\x00" * 64, context=context))
    )


def test_srum_rejects_the_reserved_pages():
    """앞의 두 페이지는 DB 헤더와 그 그림자다. 레코드가 있을 수 없다."""
    row = {
        "ref": "SRUM-NET#12",
        "artifact": "srum:NetworkUsage",
        "record_num": 12,
        "offset": "0x1000",
        "flags": [],
    }
    assert "예약 페이지" in hard_failures(
        verify(row, window_for("srum:NetworkUsage", 0x1000, b"\x00" * 64, context=ESE_CONTEXT))
    )


def test_srum_rejects_a_page_past_the_end_and_a_non_ese_file():
    """파일 밖 페이지와, 애초에 ESE 가 아닌 파일."""
    row = {
        "ref": "SRUM-NET#12",
        "artifact": "srum:NetworkUsage",
        "record_num": 12,
        "offset": "0x90000",
        "flags": [],
    }
    assert "파일 범위" in hard_failures(
        verify(row, window_for("srum:NetworkUsage", 0x90000, b"\x00" * 64, context=ESE_CONTEXT))
    )

    row["offset"] = "0x30000"
    context = dict(ESE_CONTEXT, ese_magic=0xDEADBEEF)
    assert "ESE 데이터베이스" in hard_failures(
        verify(row, window_for("srum:NetworkUsage", 0x30000, b"\x00" * 64, context=context))
    )


#: 어느 파서의 접두어도 아닌 이름. 아래 테스트가 쓴다.
UNKNOWN_ARTIFACT = "browsercache:Edge"


def test_unknown_artifact_is_not_silently_passed():
    """아티팩트가 늘었는데 대조를 안 넣은 경우. 통과시키면 거짓말이 된다.

    예시로 쓰던 ``sqlite:POS`` 는 2026-09-02 에 ``sqlite:`` 파서가 생기며
    더 이상 미지원이 아니게 됐다. **카탈로그를 늘리면 "미지원이란 이런
    것"의 예시가 조용히 무효가 된다** — 여기서 쓰는 이름은 어느 파서의
    접두어도 아닌 것이어야 한다.
    """
    row = {"ref": "X#1", "artifact": UNKNOWN_ARTIFACT, "record_num": 1, "offset": "0x0", "flags": []}
    assert "대조" in hard_failures(verify(row, window_for(UNKNOWN_ARTIFACT, 0, b"\x00" * 16)))


# =============================================================== 부속


def test_natural_length_does_not_trust_nonsense():
    """엉뚱한 자리를 가리키면 그 자리의 아무 숫자나 길이로 읽힌다."""
    assert natural_length("$MFT", struct.pack("<I", 1024).rjust(0x20, b"\x00")) == 1024
    # 할당 크기 자리에 말이 안 되는 값이 있으면 기본값으로 떨어진다.
    absurd = bytearray(0x20)
    struct.pack_into("<I", absurd, 0x1C, 0xDEADBEEF)
    assert natural_length("$MFT", bytes(absurd)) == 1024
    assert natural_length("$UsnJrnl", struct.pack("<I", 0xFFFFFF)) == 256


def test_sample_is_deterministic(tmp_path):
    """같은 산출물이면 언제 돌려도 같은 레코드를 고른다."""
    parsed = tmp_path / "04_parsed"
    parsed.mkdir()
    with (parsed / "mft.jsonl").open("w", encoding="utf-8") as fh:
        for i in range(50):
            fh.write(json.dumps(mft_row(f"MFT#{i}", i, i * RECORD_SIZE, f"f{i}.exe")) + "\n")

    first = sample_refs(parsed, 5)
    assert first == sample_refs(parsed, 5)
    assert len(first) == 5
    assert first[0] == "MFT#0"


def test_hexdump_shows_absolute_offsets():
    """왼쪽 열이 상대 위치면 되짚을 수 없다."""
    lines = list(hexdump(b"FILE" + b"\x00" * 12, 0x400))
    assert lines[0].startswith("  0x00000400")
    assert "|FILE" in lines[0]


# ========================================================= 실물 증거 대조


@pytest.mark.skipif(not REAL_IMAGE.is_file(), reason="evidence/ 없음 (gitignore)")
def test_real_offsets_lead_back_to_the_same_records():
    """실물 이미지에서 되짚는다. 합성 바이트로는 증명되지 않는 것이다.

    ``evtx:BITS``를 고른 이유는 작아서입니다(실측 99건). 여기서 확인하는
    것은 채널의 내용이 아니라 **파서가 적은 오프셋으로 그 레코드에 다시
    도달하는가** 하나뿐이므로, 큰 아티팩트를 돌릴 이유가 없습니다.
    2026-08-30 에 7종 280건으로 넓혀 확인한 기록이
    ``docs/artifact-notes.md``에 있습니다.
    """
    from src.stage04_parse import evidence, parsers
    from src.stage04_parse.parsers.base import Scope
    from tools.hexdump_record import read_window

    source = evidence.open_source(REAL_IMAGE, volume=REAL_VOLUME)
    stream = source.open("evtx:BITS")
    try:
        records = list(parsers.PARSERS["evtx:BITS"].parse(stream, Scope()))
    finally:
        stream.close()

    assert records
    for record in records:
        window = read_window(source, record)
        assert not hard_failures(verify(record, window)), record["ref"]


@pytest.mark.skipif(not REAL_IMAGE.is_file(), reason="evidence/ 없음 (gitignore)")
def test_real_srum_offsets_land_on_real_ese_pages():
    """SRUM 은 페이지 단위라 대조가 다르다. 그것도 실물에서 본다.

    ``dissect.esedb`` 가 없으면 04단계가 `ParseError` 로 멈추므로 여기서도
    건너뜁니다. requirements.txt 에는 있으나 설치되지 않은 기계가 실재해
    2026-08-30 대조에서 한 번 걸렸습니다.
    """
    pytest.importorskip("dissect.esedb", reason="requirements.txt 의 dissect.esedb 미설치")

    from src.stage04_parse import evidence, parsers
    from src.stage04_parse.parsers.base import Scope
    from tools.hexdump_record import ESE_MAGIC, read_window

    source = evidence.open_source(REAL_IMAGE, volume=REAL_VOLUME)
    stream = source.open("srum:NetworkUsage")
    try:
        records = list(parsers.PARSERS["srum:NetworkUsage"].parse(stream, Scope()))
    finally:
        stream.close()

    assert records
    for record in records:
        window = read_window(source, record)
        assert not hard_failures(verify(record, window)), record["ref"]
        # 페이지 크기를 추측하지 않았다는 것 자체를 고정한다.
        assert window.context["ese_magic"] == ESE_MAGIC
        assert window.context["page_size"] > 0


# =============================================================== CLI 가드


def test_sample_and_refs_together_is_refused(tmp_path, capsys):
    """조용히 무시하면 "골라 준 레코드를 봤다"고 오해한다."""
    mft = build_mft_record(41, "banker.exe")
    volume, parsed = write_case(tmp_path, [mft_row("MFT#41", 41, 0, "banker.exe")], mft)

    code = main(
        ["MFT#41", "--sample", "2", "--parsed", str(parsed), "--evidence", str(volume)]
    )
    assert code == 1
    assert "같이 줄 수 없다" in capsys.readouterr().err


def test_unknown_artifact_name_does_not_look_like_an_empty_case(tmp_path, capsys):
    """이름 오타와 "그 아티팩트를 파싱한 적이 없다"는 조치가 다르다."""
    mft = build_mft_record(41, "banker.exe")
    volume, parsed = write_case(tmp_path, [mft_row("MFT#41", 41, 0, "banker.exe")], mft)

    code = main(
        ["--sample", "2", "--artifact", "evtx:없는채널", "--parsed", str(parsed),
         "--evidence", str(volume)]
    )
    assert code == 1
    assert "아는 이름이 아니다" in capsys.readouterr().err


def test_every_parsed_artifact_has_a_verifier():
    """04단계가 내는 아티팩트인데 대조를 모르면 그 자리는 구멍이다.

    파서가 늘 때 이 테스트가 먼저 걸립니다 — 도구는 모르는 아티팩트를
    통과시키지 않지만, 그 사실을 실행해 봐야 아는 것과 여기서 아는 것은
    다릅니다.
    """
    from src.stage04_parse.parse import OUTPUT_FILENAMES

    for artifact in OUTPUT_FILENAMES:
        row = {"ref": "X#1", "artifact": artifact, "record_num": 1, "offset": "0x0", "flags": []}
        labels = [c.label for c in verify(row, window_for(artifact, 0, b"\x00" * 64))]
        assert labels != ["대조"], f"{artifact} 를 대조할 줄 모른다"
