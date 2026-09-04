"""$MFT 구조 정의와 MFTECmd 대조 하네스 테스트.

메인 파서(``parsers/mft.py``)가 딛고 서는 바닥을 고정합니다 —
구조 오프셋, fixup 처리, FILETIME 변환, 그리고 정확도를 채점하는 장치.

``build_record()``는 합성 MFT 레코드를 만듭니다. **실제 증거 없이도
구조 파싱을 검증할 수 있습니다.** 무엇이 들어 있는지 우리가 알고
있으므로 정답이 확실합니다.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

import pytest

from src.stage04_parse.structs import mft_record as m
from tools import compare_mft

# ==================================================== 합성 레코드 생성기


def _filetime(moment: datetime) -> int:
    """datetime → FILETIME(100ns 단위).

    ``total_seconds()``를 쓰면 안 된다. float는 유효숫자가 15~16자리인데
    FILETIME은 18자리라 마이크로초가 조용히 틀어진다. 정수로만 계산한다.
    """
    delta = moment - datetime(1601, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def _resident_attribute(type_: int, content: bytes, attribute_id: int = 0) -> bytes:
    """상주 속성 하나를 만든다. 헤더 0x18 + 내용, 8바이트 정렬."""
    header_size = 0x18
    length = header_size + len(content)
    padding = (-length) % 8
    length += padding

    header = struct.pack(
        "<IIBBHHH", type_, length, 0, 0, 0, 0, attribute_id
    ) + struct.pack("<IHBB", len(content), header_size, 0, 0)
    return header + content + b"\x00" * padding


def build_record(
    *,
    record_number: int = 12345,
    name: str = "shell.aspx",
    parent_record: int = 5,
    si_times: dict[str, datetime] | None = None,
    fn_times: dict[str, datetime] | None = None,
    in_use: bool = True,
    is_directory: bool = False,
    real_size: int = 4821,
    namespace: int = 1,
    total_size: int = 1024,
    sector_size: int = 512,
) -> bytes:
    """fixup까지 적용된 FILE 레코드를 만든다.

    파서는 이걸 받아 ``apply_fixups`` → 헤더 → 속성 순회 순으로 읽습니다.
    """
    # **마이크로초를 준다.** 초 단위로 딱 떨어지는 시각은 실물에 없다 —
    # Win7·Win10 실측 170,946 레코드에서 $SI 서브초가 0인 것이 0건이었다
    # (docs/artifact-notes.md). 0으로 두면 timestamp_truncated 가 붙어,
    # "정상 파일"을 표현하려는 픽스처가 조작된 파일이 된다.
    default = datetime(2026, 7, 20, 3, 14, 22, 123456, tzinfo=timezone.utc)
    si = {k: default for k in ("btime", "mtime", "ctime", "atime")} | (si_times or {})
    fn = {k: default for k in ("btime", "mtime", "ctime", "atime")} | (fn_times or {})

    si_content = struct.pack(
        "<QQQQI",
        _filetime(si["btime"]),
        _filetime(si["mtime"]),
        _filetime(si["ctime"]),
        _filetime(si["atime"]),
        0x20,
    ) + b"\x00" * 0x24

    encoded = name.encode("utf-16-le")
    fn_content = (
        struct.pack(
            "<QQQQQQQII",
            parent_record | (1 << 48),
            _filetime(fn["btime"]),
            _filetime(fn["mtime"]),
            _filetime(fn["ctime"]),
            _filetime(fn["atime"]),
            (real_size + 4095) // 4096 * 4096,
            real_size,
            0x20,
            0,
        )
        + bytes([len(name), namespace])
        + encoded
    )

    attributes = (
        _resident_attribute(m.AttributeType.STANDARD_INFORMATION, si_content, 0)
        + _resident_attribute(m.AttributeType.FILE_NAME, fn_content, 1)
        # 섹터 경계(510바이트)를 넘기려는 채움용 $DATA. fixup이 실제
        # 데이터를 덮는 상황을 만든다.
        + _resident_attribute(m.AttributeType.DATA, b"A" * 400, 2)
        + struct.pack("<I", m.END_OF_ATTRIBUTES)
    )

    usa_offset = 0x30
    usa_count = total_size // sector_size + 1
    first_attribute_offset = (usa_offset + usa_count * 2 + 7) // 8 * 8

    flags = (m.RecordFlags.IN_USE if in_use else 0) | (
        m.RecordFlags.DIRECTORY if is_directory else 0
    )

    data = bytearray(total_size)
    data[0:4] = m.FILE_SIGNATURE
    struct.pack_into(
        "<HHQHHHHIIQHHI",
        data,
        0x04,
        usa_offset,
        usa_count,
        0,
        1,
        1,
        first_attribute_offset,
        int(flags),
        first_attribute_offset + len(attributes),
        total_size,
        0,
        3,
        0,
        record_number,
    )
    data[first_attribute_offset : first_attribute_offset + len(attributes)] = attributes

    # 섹터 끝 2바이트를 USN으로 덮고 원본을 배열에 보관한다.
    usn = b"\x07\x00"
    data[usa_offset : usa_offset + 2] = usn
    for index in range(1, usa_count):
        end = index * sector_size - 2
        data[usa_offset + index * 2 : usa_offset + index * 2 + 2] = data[end : end + 2]
        data[end : end + 2] = usn

    return bytes(data)


# ============================================================ FILETIME


def test_filetime_round_trips():
    moment = datetime(2026, 7, 20, 3, 14, 22, tzinfo=timezone.utc)
    assert m.filetime_to_datetime(_filetime(moment)) == moment


def test_filetime_keeps_sub_second_precision():
    moment = datetime(2026, 7, 20, 3, 14, 22, 123456, tzinfo=timezone.utc)
    assert m.filetime_to_datetime(_filetime(moment)) == moment


@pytest.mark.parametrize("value", [0, -1, 0x7FFF_FFFF_FFFF_FFFF + 1])
def test_unusable_filetime_becomes_none(value):
    # 조작 도구가 넣은 쓰레기 값이 예외를 던져 파싱 전체를 멈추면 안 된다.
    # 그런 레코드는 zero_timestamp 플래그로 표시된다.
    assert m.filetime_to_datetime(value) is None


# ============================================================== fixup


def test_fixups_restore_the_bytes_the_usn_overwrote():
    # 이걸 안 되돌리면 512바이트마다 2바이트가 엉뚱한 값이다. 레코드
    # 대부분은 멀쩡해서 원인을 찾기 어렵다.
    raw = build_record()
    assert raw[510:512] == b"\x07\x00"  # USN으로 덮인 상태

    fixed = m.apply_fixups(raw)
    assert fixed[510:512] != b"\x07\x00"
    assert bytes(fixed[510:512]) == b"AA"  # 채움용 $DATA의 내용


def test_a_wrong_usn_is_reported():
    raw = bytearray(build_record())
    raw[510:512] = b"\xff\xff"
    with pytest.raises(m.FixupError, match="USN 불일치"):
        m.apply_fixups(bytes(raw))


def test_a_truncated_record_is_rejected():
    with pytest.raises(m.StructError):
        m.apply_fixups(b"FILE" + b"\x00" * 8)


def test_fixups_do_not_mutate_the_input():
    raw = build_record()
    before = bytes(raw)
    m.apply_fixups(raw)
    assert raw == before


# ======================================================== 레코드 헤더


def test_header_reads_the_declared_fields():
    header = m.RecordHeader.unpack(m.apply_fixups(build_record(record_number=12345)))
    assert header.signature == m.FILE_SIGNATURE
    assert header.record_number == 12345
    assert header.in_use
    assert not header.is_directory
    assert not header.is_extension


def test_deleted_record_is_not_in_use():
    header = m.RecordHeader.unpack(m.apply_fixups(build_record(in_use=False)))
    assert not header.in_use


def test_directory_flag():
    header = m.RecordHeader.unpack(m.apply_fixups(build_record(is_directory=True)))
    assert header.is_directory


def test_a_foreign_signature_is_rejected():
    with pytest.raises(m.StructError, match="시그니처"):
        m.RecordHeader.unpack(b"XXXX" + b"\x00" * 0x40)


def test_chkdsk_marked_records_are_recognised():
    raw = bytearray(build_record())
    raw[0:4] = m.BAAD_SIGNATURE
    assert m.RecordHeader.unpack(bytes(raw)).signature == m.BAAD_SIGNATURE


# ============================================================ 속성 순회


def _attributes(data: bytes) -> list[m.AttributeHeader]:
    header = m.RecordHeader.unpack(data)
    found: list[m.AttributeHeader] = []
    offset = header.first_attribute_offset
    while offset < len(data):
        try:
            attribute = m.AttributeHeader.unpack(data, offset)
        except m.StructError:
            break
        found.append(attribute)
        offset += attribute.length
    return found


def test_every_attribute_is_reachable_by_walking_lengths():
    found = _attributes(m.apply_fixups(build_record()))
    assert [a.type for a in found] == [
        m.AttributeType.STANDARD_INFORMATION,
        m.AttributeType.FILE_NAME,
        m.AttributeType.DATA,
    ]
    assert all(not a.non_resident for a in found)


def test_attribute_lengths_are_eight_byte_aligned():
    # 정렬이 어긋나면 다음 속성 오프셋이 틀어져 순회가 통째로 깨진다.
    for attribute in _attributes(m.apply_fixups(build_record())):
        assert attribute.length % 8 == 0


def test_unknown_attribute_type_still_reports_a_name():
    data = m.apply_fixups(build_record())
    attribute = m.AttributeHeader.unpack(data, m.RecordHeader.unpack(data).first_attribute_offset)
    assert attribute.type_name == "STANDARD_INFORMATION"


# =============================================== $SI / $FN 내용


def _content(data: bytes, type_: int) -> bytes:
    attribute = next(a for a in _attributes(data) if a.type == type_)
    assert attribute.content_offset is not None
    return data[attribute.content_offset : attribute.content_offset + attribute.content_length]


def test_standard_information_timestamps():
    created = datetime(2026, 7, 20, 3, 14, 22, tzinfo=timezone.utc)
    data = m.apply_fixups(build_record(si_times={"btime": created}))
    si = m.StandardInformation.unpack(_content(data, m.AttributeType.STANDARD_INFORMATION))
    assert si.btime == created


def test_file_name_carries_the_name_and_parent():
    data = m.apply_fixups(build_record(name="shell.aspx", parent_record=12300))
    fn = m.FileName.unpack(_content(data, m.AttributeType.FILE_NAME))
    assert fn.name == "shell.aspx"
    # 하위 48비트만 레코드 번호다. 마스킹을 빼먹으면 부모를 못 찾는다.
    assert fn.parent_record_number == 12300
    assert fn.parent_sequence_number == 1


def test_non_ascii_names_survive():
    data = m.apply_fixups(build_record(name="한글파일.aspx"))
    assert m.FileName.unpack(_content(data, m.AttributeType.FILE_NAME)).name == "한글파일.aspx"


def test_dos_short_names_are_identifiable():
    # 경로를 만들 때 DOS 이름을 고르면 PROGRA~1 같은 값이 나온다.
    data = m.apply_fixups(build_record(name="PROGRA~1", namespace=2))
    assert m.FileName.unpack(_content(data, m.AttributeType.FILE_NAME)).is_dos_short_name

    data = m.apply_fixups(build_record(name="Program Files", namespace=1))
    assert not m.FileName.unpack(_content(data, m.AttributeType.FILE_NAME)).is_dos_short_name


def test_si_and_fn_can_disagree():
    # 이 불일치가 타임스탬프 조작의 신호다.
    data = m.apply_fixups(
        build_record(
            si_times={"ctime": datetime(2026, 7, 20, 3, 14, 22, tzinfo=timezone.utc)},
            fn_times={"ctime": datetime(2026, 7, 21, 9, 2, 11, tzinfo=timezone.utc)},
        )
    )
    si = m.StandardInformation.unpack(_content(data, m.AttributeType.STANDARD_INFORMATION))
    fn = m.FileName.unpack(_content(data, m.AttributeType.FILE_NAME))
    assert si.ctime is not None and fn.ctime is not None and si.ctime < fn.ctime


# ================================================= MFTECmd 대조 하네스


def _write_csv(path, rows):
    columns = [
        "EntryNumber", "ParentPath", "FileName", "IsAds",
        "Created0x10", "LastModified0x10", "LastRecordChange0x10", "LastAccess0x10",
        "Created0x30", "LastModified0x30", "LastRecordChange0x30",
    ]
    lines = [",".join(columns)]
    for row in rows:
        lines.append(",".join(str(row.get(c, "")) for c in columns))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _mftecmd_row(entry=12345, parent=".\\inetpub\\wwwroot\\upload", name="shell.aspx",
                 created="2026-07-20 03:14:22.1234567", is_ads="False"):
    return {
        "EntryNumber": entry,
        "ParentPath": parent,
        "FileName": name,
        # MFTECmd 는 스트림마다 한 행을 내고 ADS 행은 본체와 EntryNumber 가
        # 같다. 열이 없으면 대조기가 아예 멈추므로 픽스처에도 있어야 한다.
        "IsAds": is_ads,
        "Created0x10": created,
        "LastModified0x10": created,
        "LastRecordChange0x10": created,
        "LastAccess0x10": created,
        "Created0x30": created,
        "LastModified0x30": created,
        "LastRecordChange0x30": created,
    }


def _ours_row(record_num=12345, path="C:\\inetpub\\wwwroot\\upload\\shell.aspx",
              created="2026-07-20T03:14:22.1234567Z"):
    return {
        "ref": f"MFT#{record_num}", "artifact": "$MFT", "record_num": record_num,
        "offset": "0x1E000", "path": path, "allocated": True, "is_directory": False,
        "size": 4821,
        "si_btime": created, "si_ctime": created, "si_mtime": created, "si_atime": created,
        "fn_btime": created, "fn_ctime": created, "fn_mtime": created, "flags": [],
    }


def test_drive_letter_difference_is_not_a_mismatch():
    # MFTECmd는 $MFT만 읽으므로 드라이브 문자를 모른다. 그대로 비교하면
    # 모든 레코드가 불일치로 나온다.
    assert compare_mft.normalize_path("C:\\inetpub\\wwwroot\\x.aspx") == compare_mft.normalize_path(
        ".\\inetpub\\wwwroot\\x.aspx"
    )


def test_matching_output_passes(tmp_path):
    from src.common import io

    ours = tmp_path / "mft.jsonl"
    io.write_jsonl(ours, [_ours_row()])
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, [_mftecmd_row()])

    report = compare_mft.compare(
        compare_mft.load_ours(ours), compare_mft.load_mftecmd(csv_path).records, full=True
    )
    assert report.passed(), report.summary()


def test_a_wrong_timestamp_is_caught(tmp_path):
    from src.common import io

    ours = tmp_path / "mft.jsonl"
    io.write_jsonl(ours, [_ours_row(created="2026-07-19T22:00:00Z")])
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, [_mftecmd_row()])

    report = compare_mft.compare(
        compare_mft.load_ours(ours), compare_mft.load_mftecmd(csv_path).records
    )
    assert not report.passed()
    assert {mismatch.field for mismatch in report.mismatches} >= {"si_btime"}


def test_a_wrong_path_is_caught(tmp_path):
    from src.common import io

    ours = tmp_path / "mft.jsonl"
    io.write_jsonl(ours, [_ours_row(path="C:\\wrong\\shell.aspx")])
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, [_mftecmd_row()])

    report = compare_mft.compare(
        compare_mft.load_ours(ours), compare_mft.load_mftecmd(csv_path).records
    )
    assert [mismatch.field for mismatch in report.mismatches] == ["path"]


def test_a_record_we_invented_always_fails(tmp_path):
    from src.common import io

    ours = tmp_path / "mft.jsonl"
    io.write_jsonl(ours, [_ours_row(record_num=99999)])
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, [_mftecmd_row()])

    report = compare_mft.compare(
        compare_mft.load_ours(ours), compare_mft.load_mftecmd(csv_path).records
    )
    assert report.extra_in_ours == [99999]
    assert not report.passed()


def test_scoped_output_is_not_penalised_for_missing_records(tmp_path):
    # 우리 파서는 선별된 범위만 낸다. --full이 아니면 정상이다.
    from src.common import io

    ours = tmp_path / "mft.jsonl"
    io.write_jsonl(ours, [_ours_row()])
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, [_mftecmd_row(), _mftecmd_row(entry=12346, name="index.aspx")])

    loaded = (compare_mft.load_ours(ours), compare_mft.load_mftecmd(csv_path).records)
    assert compare_mft.compare(*loaded).passed()
    assert not compare_mft.compare(*loaded, full=True).passed()


def test_a_missing_column_names_what_it_found(tmp_path):
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text("EntryNumber,FileName\n1,x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="TIMESTAMP_COLUMNS"):
        compare_mft.load_mftecmd(csv_path)


def test_summary_is_pasteable_into_notes(tmp_path):
    from src.common import io

    ours = tmp_path / "mft.jsonl"
    io.write_jsonl(ours, [_ours_row()])
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, [_mftecmd_row()])

    summary = compare_mft.compare(
        compare_mft.load_ours(ours), compare_mft.load_mftecmd(csv_path).records, full=True
    ).summary()
    assert "판정: 통과" in summary
    assert summary.startswith("- ")


def test_an_ads_row_does_not_overwrite_the_file_it_belongs_to(tmp_path):
    # MFTECmd 는 Sysmon.exe 와 Sysmon.exe:Zone.Identifier 를 **같은
    # EntryNumber 의 두 행**으로 낸다. 걸러 내지 않으면 나중 행이 앞 행을
    # 덮어써 경로가 ADS 이름으로 바뀐다 — 레코드 수로는 드러나지 않는다.
    from src.common import io

    ours = tmp_path / "mft.jsonl"
    io.write_jsonl(ours, [_ours_row()])
    csv_path = tmp_path / "mft.csv"
    _write_csv(
        csv_path,
        [
            _mftecmd_row(),
            _mftecmd_row(name="shell.aspx:Zone.Identifier", is_ads="True"),
        ],
    )

    loaded = compare_mft.load_mftecmd(csv_path)
    assert loaded.ads_rows == 1
    assert set(loaded.records) == {12345}
    assert loaded.records[12345].path.endswith("shell.aspx")

    report = compare_mft.compare(
        compare_mft.load_ours(ours), loaded.records, full=True, ads_rows=loaded.ads_rows
    )
    assert report.passed(), report.summary()
    # 조건이 요약에 남아야 같은 CSV 로 같은 숫자가 재현된다.
    assert "ADS 행 1건 제외" in report.summary()


def test_a_duplicate_entry_number_stops_instead_of_overwriting(tmp_path):
    # ADS 를 걸러 낸 뒤에도 중복이 남으면 이유가 다른 것이다. 조용히
    # 덮으면 어느 행과 대조했는지 알 수 없다.
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, [_mftecmd_row(), _mftecmd_row(name="other.aspx")])

    with pytest.raises(ValueError, match="EntryNumber 가 중복"):
        compare_mft.load_mftecmd(csv_path)


def test_a_missing_ads_column_stops_instead_of_guessing(tmp_path):
    # 콜론으로 대신 가려낼 수는 있지만 그것은 표기에 기대는 판정이다.
    csv_path = tmp_path / "mft.csv"
    columns = [
        "EntryNumber", "ParentPath", "FileName",
        "Created0x10", "LastModified0x10", "LastRecordChange0x10", "LastAccess0x10",
    ]
    csv_path.write_text(
        ",".join(columns) + "\n" + ",".join(["1", ".", "x"] + ["2026-07-20 03:14:22"] * 4) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="IsAds"):
        compare_mft.load_mftecmd(csv_path)


def test_an_unknown_ads_value_is_not_read_as_false(tmp_path):
    # MFTECmd 가 표기를 바꿨는데 False 로 넘기면 ADS 행이 대조에 섞인다.
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, [_mftecmd_row(is_ads="Y")])

    with pytest.raises(ValueError, match="IsAds"):
        compare_mft.load_mftecmd(csv_path)


def test_the_reference_comparison_does_not_claim_an_ads_condition(tmp_path):
    # 참조 구현은 우리 형식이라 ADS 개념이 없다. "0건 제외"라고 적으면
    # 하지도 않은 조건을 기록에 남기는 것이다.
    from src.common import io

    ours = tmp_path / "mft.jsonl"
    io.write_jsonl(ours, [_ours_row()])

    summary = compare_mft.compare(
        compare_mft.load_ours(ours), compare_mft.load_ours(ours), against="참조 구현"
    ).summary()
    assert "ADS" not in summary


# ==================================================== 섹터 크기


def test_the_sector_size_comes_from_the_record_not_a_constant():
    """업데이트 시퀀스 배열은 항목이 ``섹터 수 + 1``개다. 나누면 나온다."""
    assert m.sector_size_of(b"\x00" * 1024, usa_count=3) == 512
    assert m.sector_size_of(b"\x00" * 4096, usa_count=2) == 4096
    assert m.sector_size_of(b"\x00" * 4096, usa_count=9) == 512


def test_a_4kn_record_is_read_without_being_told_the_sector_size():
    """**512로 고정하면 4Kn 이미지의 레코드가 전부 FixupError 가 된다.**

    그리고 호출부가 그것을 건너뛰므로 나오는 것은 오류가 아니라
    ``$MFT: 0건`` 이다. 부트섹터를 읽지 않고 레코드에서 유도한다 —
    추출된 ``$MFT`` 만 받는 경우에는 부트섹터가 아예 없다.
    """
    raw = build_record(total_size=4096, sector_size=4096, record_number=777)
    header = m.RecordHeader.unpack(m.apply_fixups(raw))

    assert header.record_number == 777


def test_an_array_that_does_not_divide_the_record_is_refused():
    """추측해서 넘어가면 뒤의 USN 대조가 엉뚱한 자리를 본다."""
    # 섹터 3개로는 1024를 나눌 수 없다. 배열이 깨진 것이다.
    with pytest.raises(m.FixupError, match="맞지 않음"):
        m.sector_size_of(b"\x00" * 1024, usa_count=4)


def test_an_explicit_sector_size_still_wins():
    """아는 값이 따로 있으면 그것을 쓴다."""
    raw = build_record(total_size=1024, sector_size=512)
    assert m.RecordHeader.unpack(m.apply_fixups(raw, sector_size=512)).record_number == 12345
