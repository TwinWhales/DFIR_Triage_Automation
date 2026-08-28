"""$UsnJrnl:$J 구조 정의와 파서 테스트.

``build_usn_record()``는 합성 레코드를 만듭니다. **실제 증거 없이도
구조 파싱을 검증할 수 있습니다** — 무엇을 넣었는지 우리가 아니까요.

여기서 특히 고정하는 것은 스트림 순회입니다. 레코드 하나를 뜯는 것보다
**스파스 구간을 건너뛰고 손상 뒤 재동기화하는 쪽이 훨씬 자주 틀립니다.**
그리고 그 실패는 조용합니다 — 레코드가 몇 건 덜 나올 뿐 예외가 나지
않습니다.
"""

from __future__ import annotations

import datetime as dt
import io as _io
import struct

import pytest

from src.common import schema
from src.stage04_parse import flagging
from src.stage04_parse.parsers import usnjrnl
from src.stage04_parse.parsers.base import Scope
from src.stage04_parse.structs import usn_record as u

UTC = dt.timezone.utc

#: FILETIME 기준 시각. 1601-01-01 부터 100ns 단위.
_FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=UTC)


def to_filetime(moment: dt.datetime) -> int:
    return int((moment - _FILETIME_EPOCH).total_seconds() * 10_000_000)


def build_usn_record(
    *,
    usn: int,
    name: str,
    reason: int = u.UsnReason.FILE_CREATE,
    source: int = 0,
    timestamp: dt.datetime | None = None,
    file_entry: int = 100,
    file_sequence: int = 1,
    parent_entry: int = 5,
    parent_sequence: int = 5,
    file_attributes: int = 0x20,  # FILE_ATTRIBUTE_ARCHIVE
    major_version: int = 2,
    minor_version: int = 0,
    record_length: int | None = None,
) -> bytes:
    """USN_RECORD_V2 하나를 만든다. 8바이트 정렬 패딩까지 붙인다.

    ``record_length``를 직접 주면 **일부러 깨진 레코드**를 만들 수
    있습니다. 재동기화 테스트에 씁니다.
    """
    # surrogatepass — NTFS 이름은 짝 없는 서로게이트를 허용하므로 그런
    # 이름도 만들 수 있어야 한다. 정상 이름에는 영향이 없다.
    encoded = name.encode("utf-16-le", "surrogatepass")
    name_offset = u.V2_HEADER_SIZE
    unpadded = name_offset + len(encoded)
    padded = (unpadded + u.RECORD_ALIGNMENT - 1) // u.RECORD_ALIGNMENT * u.RECORD_ALIGNMENT
    length = padded if record_length is None else record_length

    moment = timestamp if timestamp is not None else dt.datetime(2026, 7, 20, 3, 14, 22, tzinfo=UTC)

    header = struct.pack(
        "<IHHQQQQIIIIHH",
        length,
        major_version,
        minor_version,
        (file_sequence << 48) | file_entry,
        (parent_sequence << 48) | parent_entry,
        usn,
        0 if timestamp is None and False else to_filetime(moment),
        int(reason),
        int(source),
        0,  # security id
        file_attributes,
        len(encoded),
        name_offset,
    )
    return header + encoded + b"\x00" * (padded - unpadded)


def build_journal(records: list[bytes], *, leading_zeros: int = 0) -> bytes:
    """레코드를 이어 붙인 ``$J`` 스트림.

    ``leading_zeros``는 물질화된 스파스 구간을 흉내 냅니다.
    """
    return b"\x00" * leading_zeros + b"".join(records)


def parse(data: bytes, scope: Scope | None = None, **kwargs) -> list[dict]:
    parser = usnjrnl.UsnJrnlParser(**kwargs)
    return list(parser.parse(_io.BytesIO(data), scope or Scope()))


# ==================================================== 구조 정의


def test_header_size_matches_the_spec():
    # 60바이트. 하나라도 틀리면 뒤 필드가 전부 밀린다.
    assert struct.calcsize("<IHHQQQQIIIIHH") == u.V2_HEADER_SIZE == 60


def test_a_record_round_trips():
    raw = build_usn_record(usn=4096, name="shell.aspx")
    record = u.UsnRecord.unpack(raw)

    assert record.usn == 4096
    assert record.name == "shell.aspx"
    assert record.major_version == 2
    assert record.file_reference.entry == 100
    assert record.file_reference.sequence == 1
    assert record.parent_reference.entry == 5
    assert record.timestamp == dt.datetime(2026, 7, 20, 3, 14, 22, tzinfo=UTC)


def test_name_size_is_bytes_not_characters():
    """$FILE_NAME은 문자 수, USN은 바이트 수다. 옮겨 적다 밟는 함정."""
    name = "한글이름.txt"  # UTF-16으로 문자당 2바이트
    raw = build_usn_record(usn=8, name=name)
    stored_size = struct.unpack_from("<H", raw, 0x38)[0]

    assert stored_size == len(name) * 2
    assert u.UsnRecord.unpack(raw).name == name


def test_unpaired_surrogates_survive():
    """NTFS 이름은 짝 없는 서로게이트를 허용한다. strict면 조용히 사라진다."""
    raw = bytearray(build_usn_record(usn=8, name="ab"))
    raw[u.V2_HEADER_SIZE : u.V2_HEADER_SIZE + 2] = struct.pack("<H", 0xD800)

    assert u.UsnRecord.unpack(bytes(raw)).name[0] == "\ud800"


def test_the_directory_bit_is_read():
    plain = u.UsnRecord.unpack(build_usn_record(usn=8, name="f", file_attributes=0x20))
    folder = u.UsnRecord.unpack(build_usn_record(usn=8, name="d", file_attributes=0x10))

    assert plain.is_directory is False
    assert folder.is_directory is True


@pytest.mark.parametrize(
    "kwargs, reason",
    [
        ({"record_length": 8}, "헤더보다 작음"),
        ({"record_length": u.MAX_RECORD_SIZE + 8}, "상한"),
        ({"record_length": 71}, "정렬"),
    ],
)
def test_a_broken_length_is_refused(kwargs, reason):
    """틀린 위치에서 그럴듯한 레코드를 만들어 내는 것이 최악이다."""
    raw = build_usn_record(usn=8, name="x", **kwargs)
    with pytest.raises(u.StructError):
        u.UsnRecord.unpack(raw)


def test_a_v3_record_is_refused_as_unsupported_not_corrupt():
    """V3를 V2로 오해하면 필드가 통째로 밀린다. 손상과는 구분해야 한다."""
    raw = build_usn_record(usn=8, name="x", major_version=3)
    with pytest.raises(u.UnsupportedVersion):
        u.UsnRecord.unpack(raw)


def test_unknown_reason_bits_are_kept():
    # 0x00800000은 정의되지 않은 비트. 버리면 새 플래그가 생겨도 모른다.
    assert u.reason_names(0x00800000) == ["unknown_0x00800000"]
    assert u.reason_names(u.UsnReason.FILE_CREATE | 0x00800000) == [
        "file_create",
        "unknown_0x00800000",
    ]


# ==================================================== 스트림 순회


def test_consecutive_records_are_all_read():
    data = build_journal(
        [
            build_usn_record(usn=0, name="a.txt"),
            build_usn_record(usn=80, name="b.txt"),
            build_usn_record(usn=160, name="c.txt"),
        ]
    )
    assert [r["name"] for r in parse(data)] == ["a.txt", "b.txt", "c.txt"]


def test_a_materialized_sparse_hole_is_skipped():
    """추출 도구가 스파스 구멍을 0으로 채워 놓아도 레코드를 찾아낸다."""
    data = build_journal([build_usn_record(usn=65536, name="late.txt")], leading_zeros=65536)
    records = parse(data)

    assert [r["name"] for r in records] == ["late.txt"]
    # offset은 파일 안 실제 위치다.
    assert records[0]["offset"] == "0x10000"


def test_padding_between_records_is_skipped():
    data = build_journal(
        [
            build_usn_record(usn=0, name="a.txt"),
            b"\x00" * 512,  # 블록 끝 패딩
            build_usn_record(usn=1024, name="b.txt"),
        ]
    )
    assert [r["name"] for r in parse(data)] == ["a.txt", "b.txt"]


def test_a_corrupt_region_does_not_swallow_the_rest():
    """손상 하나에 나머지를 통째로 잃으면 안 된다."""
    good = build_usn_record(usn=0, name="before.txt")
    later = build_usn_record(usn=4096, name="after.txt")
    data = good + b"\xff" * 64 + later

    parser = usnjrnl.UsnJrnlParser()
    records = list(parser.parse(_io.BytesIO(data), Scope()))

    assert [r["name"] for r in records] == ["before.txt", "after.txt"]
    # 조용히 넘어가지 않는다 — 못 읽은 구간이 있었음을 남긴다.
    assert parser.stats["parse_errors"] > 0


def test_one_bad_region_counts_as_one_not_once_per_step(caplog):
    """**집계 단위 회귀 (docs/limitations.md 4-0-1).**

    파서는 레코드가 아닌 바이트를 만나면 8바이트씩 걸으며 재동기화한다.
    걸음마다 세면 구간 하나가 수만 건으로 부풀어, 매니페스트를 읽는
    사람이 "저널이 심하게 손상됐다"고 정반대로 판단한다.

    실측(evidence/[root]): 꼬리에 붙은 비저널 데이터 503,752바이트가
    503752 / 8 = 62,969건으로 집계됐다. 실제로는 구간 1곳이고 나머지
    306,857레코드는 전부 정상이었다.
    """
    junk = 800  # 8바이트씩이면 100걸음
    data = (
        build_usn_record(usn=0, name="before.txt")
        + b"\xff" * junk
        + build_usn_record(usn=4096, name="after.txt")
    )

    parser = usnjrnl.UsnJrnlParser()
    records = list(parser.parse(_io.BytesIO(data), Scope()))

    assert [r["name"] for r in records] == ["before.txt", "after.txt"]
    assert parser.stats["parse_errors"] == 1, "연속된 실패는 한 구간이다"
    assert parser.stats["unreadable_bytes"] >= junk


def test_two_separate_bad_regions_count_as_two():
    """묶는다고 해서 서로 다른 손상을 하나로 합치면 안 된다."""
    data = (
        build_usn_record(usn=0, name="a.txt")
        + b"\xff" * 64
        + build_usn_record(usn=4096, name="b.txt")
        + b"\xff" * 64
        + build_usn_record(usn=8192, name="c.txt")
    )

    parser = usnjrnl.UsnJrnlParser()
    records = list(parser.parse(_io.BytesIO(data), Scope()))

    assert [r["name"] for r in records] == ["a.txt", "b.txt", "c.txt"]
    assert parser.stats["parse_errors"] == 2


def test_unreadable_bytes_reports_the_scale():
    """구간 수만으로는 8바이트짜리와 500KB짜리를 구별할 수 없다."""
    small = usnjrnl.UsnJrnlParser()
    list(small.parse(_io.BytesIO(
        build_usn_record(usn=0, name="a.txt") + b"\xff" * 64
        + build_usn_record(usn=4096, name="b.txt")
    ), Scope()))

    big = usnjrnl.UsnJrnlParser()
    list(big.parse(_io.BytesIO(
        build_usn_record(usn=0, name="a.txt") + b"\xff" * 8192
        + build_usn_record(usn=16384, name="b.txt")
    ), Scope()))

    assert small.stats["parse_errors"] == big.stats["parse_errors"] == 1
    assert big.stats["unreadable_bytes"] > small.stats["unreadable_bytes"] * 10


def test_a_clean_journal_reports_no_unreadable_bytes():
    parser = usnjrnl.UsnJrnlParser()
    list(parser.parse(_io.BytesIO(build_journal([
        build_usn_record(usn=0, name="a.txt"),
        build_usn_record(usn=80, name="b.txt"),
    ])), Scope()))
    assert parser.stats["parse_errors"] == 0
    assert parser.stats["unreadable_bytes"] == 0


def test_a_record_straddling_the_buffer_boundary_is_read():
    """버퍼 경계에 걸친 레코드를 잃지 않는가. 청크 방식의 대표 버그다."""
    chunk = u.MAX_RECORD_SIZE * 2
    filler = (chunk // 80) + 2
    records = [build_usn_record(usn=i * 80, name="f{}.txt".format(i)) for i in range(filler)]
    data = build_journal(records)

    parsed = parse(data, chunk_size=chunk)
    assert len(parsed) == filler
    assert [r["name"] for r in parsed] == [r["name"] for r in parse(data)]


def test_a_truncated_tail_record_is_dropped_not_guessed():
    data = build_journal([build_usn_record(usn=0, name="whole.txt")])
    data += build_usn_record(usn=80, name="cut.txt")[:40]

    assert [r["name"] for r in parse(data)] == ["whole.txt"]


def test_an_all_zero_stream_yields_nothing_and_terminates():
    # 무한 루프 회귀 테스트. 0만 있는 스트림에서 멈추지 못하면 여기서 걸린다.
    assert parse(b"\x00" * 100_000) == []


def test_an_empty_stream_is_an_error_not_an_empty_result():
    """빈 저널은 "변경이 없었다"가 아니라 "저널을 못 받았다"이다.

    조용히 0건을 내면 매니페스트에 ``record_count: 0`` 으로만 남아 두
    경우가 구별되지 않는다. 실제로 밟았다 — FTK Imager 추출본이
    ``$Extend/$UsnJrnl`` 에 이름 없는 ``$DATA``(0바이트)를 쓰고 실제
    저널은 ``$J`` 로 따로 내놓는데, 파이프라인이 30만 건짜리 저널을
    옆에 두고 "레코드 0건"을 보고했다. (docs/limitations.md 4-0)
    """
    with pytest.raises(ValueError, match="비어 있습니다"):
        parse(b"")


def test_a_nonempty_stream_still_sees_its_first_record():
    """빈 스트림 판정을 위해 앞을 읽어도 순회가 그것을 다시 봐야 한다."""
    data = build_journal([build_usn_record(usn=0, name="first.txt")])
    records = parse(data)
    assert [r["name"] for r in records] == ["first.txt"]
    assert records[0]["offset"] == "0x0"


def test_a_v3_record_is_counted_separately_from_corruption():
    data = build_journal(
        [
            build_usn_record(usn=0, name="v2.txt"),
            build_usn_record(usn=80, name="v3.txt", major_version=3),
            build_usn_record(usn=160, name="after.txt"),
        ]
    )
    parser = usnjrnl.UsnJrnlParser()
    records = list(parser.parse(_io.BytesIO(data), Scope()))

    assert [r["name"] for r in records] == ["v2.txt", "after.txt"]
    assert parser.stats["unsupported_version"] == 1


# ==================================================== 범위와 출력 형식


def test_the_extension_filter_applies_to_the_name():
    data = build_journal(
        [
            build_usn_record(usn=0, name="shell.aspx"),
            build_usn_record(usn=80, name="notes.txt"),
        ]
    )
    scope = Scope(extensions=(".aspx",))

    assert [r["name"] for r in parse(data, scope)] == ["shell.aspx"]


def test_records_outside_the_time_range_are_kept_not_dropped():
    """시간 범위 밖은 버리지 않고 표시만 한다 (base.py Scope 규약)."""
    scope = Scope(
        start=dt.datetime(2026, 7, 1, tzinfo=UTC),
        end=dt.datetime(2026, 7, 2, tzinfo=UTC),
    )
    data = build_journal([build_usn_record(usn=0, name="late.aspx")])

    records = list(flagging.apply_all(iter(parse(data, scope)), scope))
    assert len(records) == 1
    assert "outside_time_range" in records[0]["flags"]


def test_the_path_prefix_cannot_narrow_and_does_not_silently_drop():
    """USN에는 경로가 없다. 좁히지 못하면 넓게 내는 것이 이 프로젝트의 판단."""
    scope = Scope(path_prefix=("c:/inetpub/wwwroot",))
    data = build_journal([build_usn_record(usn=0, name="shell.aspx")])

    assert [r["name"] for r in parse(data, scope)] == ["shell.aspx"]


def test_record_num_is_the_usn_and_offset_is_the_file_position():
    """추출 도구가 스파스 구간을 잘라내면 둘이 어긋난다. 그 차이가 신호다."""
    data = build_journal([build_usn_record(usn=1_048_576, name="a.txt")], leading_zeros=64)
    record = parse(data)[0]

    assert record["record_num"] == 1_048_576
    assert record["ref"] == "USN#1048576"
    assert record["offset"] == "0x40"


def test_a_record_validates_against_the_schema():
    data = build_journal([build_usn_record(usn=0, name="shell.aspx")])
    record = next(flagging.apply_all(iter(parse(data)), None))

    schema.validate(record, "parsed_record")


def test_a_record_without_a_readable_timestamp_omits_the_key():
    """null을 넣으면 스키마가 막고, 레코드를 버리면 이상함을 놓친다."""
    raw = bytearray(build_usn_record(usn=0, name="a.txt"))
    struct.pack_into("<Q", raw, 0x20, 0)  # FILETIME 0

    record = parse(bytes(raw))[0]
    assert "timestamp" not in record
    schema.validate(next(flagging.apply_all(iter([record]), None)), "parsed_record")


# ==================================================== 플래그


def test_file_create_becomes_the_file_created_flag():
    data = build_journal(
        [build_usn_record(usn=0, name="shell.aspx", reason=u.UsnReason.FILE_CREATE)]
    )
    record = next(flagging.apply_all(iter(parse(data)), None))

    assert record["reason"] == ["file_create"]
    assert "file_created" in record["flags"]


def test_file_delete_becomes_the_deleted_flag():
    """Tier 2 유예 조건이 이 이름을 보므로 $MFT와 같은 어휘를 써야 한다."""
    data = build_journal(
        [build_usn_record(usn=0, name="gone.txt", reason=u.UsnReason.FILE_DELETE)]
    )
    record = next(flagging.apply_all(iter(parse(data)), None))

    assert "deleted" in record["flags"]


def test_create_and_delete_in_one_record_keep_both_flags():
    data = build_journal(
        [
            build_usn_record(
                usn=0,
                name="tmp.dat",
                reason=u.UsnReason.FILE_CREATE | u.UsnReason.FILE_DELETE,
            )
        ]
    )
    record = next(flagging.apply_all(iter(parse(data)), None))

    assert {"file_created", "deleted"} <= set(record["flags"])


def test_an_uninteresting_reason_gets_no_signal_flag():
    """남발하면 필터가 일을 안 한다. 접근 시각 갱신 따위는 신호가 아니다."""
    data = build_journal(
        [build_usn_record(usn=0, name="a.txt", reason=u.UsnReason.BASIC_INFO_CHANGE)]
    )
    record = next(flagging.apply_all(iter(parse(data)), None))

    assert record["flags"] == []


# ==================================================== 짝 없는 서로게이트


def test_a_lone_surrogate_name_does_not_break_jsonl_writing(tmp_path):
    """**이 레코드 하나가 아티팩트 전체를 날릴 수 있었다.**

    NTFS 이름은 짝 없는 서로게이트를 허용하는데 UTF-8 은 아닙니다. 구조
    계층이 ``surrogatepass`` 로 읽는 것은 그런 이름의 레코드가 조용히
    사라지지 않게 하려는 것인데, 그 문자열을 그대로 내보내면
    ``io.write_jsonl`` 이 UTF-8 로 쓰다 ``UnicodeEncodeError`` 를 냅니다.

    그러면 임시 파일이 지워져 ``usnjrnl.jsonl`` 이 **아예 생기지
    않습니다** — 실측 이미지에서 148,409건이 통째로 사라지는 자리입니다.
    """
    from src.common import io as common_io

    data = build_journal(
        [
            build_usn_record(usn=0, name="normal.txt"),
            build_usn_record(usn=1, name="bad\udcffname.txt"),
        ]
    )
    records = parse(data)

    written = common_io.write_jsonl(tmp_path / "usnjrnl.jsonl", records)
    assert written == 2
    assert (tmp_path / "usnjrnl.jsonl").is_file()


def test_the_original_bytes_survive_next_to_the_replaced_name():
    """이름은 읽을 수 있게 바꾸되 **원본은 버리지 않는다.**

    hex 를 되돌리면 원래 문자열이 정확히 나와야 합니다. 그러지 않으면
    "원본에 충실하다"가 깨집니다.
    """
    original = "bad\udcffname.txt"
    data = build_journal([build_usn_record(usn=0, name=original)])
    record = parse(data)[0]

    assert record["name"] == "bad\ufffdname.txt"
    restored = bytes.fromhex(record["fields"]["name_raw_utf16le"])
    assert restored.decode("utf-16-le", "surrogatepass") == original


def test_a_normal_name_gets_no_raw_field():
    """멀쩡한 이름에까지 붙으면 프롬프트만 커진다."""
    data = build_journal([build_usn_record(usn=0, name="한글이름.txt")])
    record = parse(data)[0]

    assert record["name"] == "한글이름.txt"
    assert "fields" not in record


def test_the_unencodable_name_is_counted():
    """조용히 바꾸지 않는다. 매니페스트를 읽는 사람이 알아야 한다."""
    data = build_journal(
        [
            build_usn_record(usn=0, name="a.txt"),
            build_usn_record(usn=1, name="x\udc00y.txt"),
            build_usn_record(usn=2, name="z\udfffw.txt"),
        ]
    )
    parser = usnjrnl.UsnJrnlParser()
    list(parser.parse(_io.BytesIO(data), Scope()))

    assert parser.stats["name_unencodable"] == 2


def test_the_replaced_record_still_validates_against_the_schema():
    """``fields`` 는 자유 형식이라 여기 싣는 것이 스키마 변경이 아니다."""
    data = build_journal([build_usn_record(usn=0, name="bad\udcffname.txt")])
    record = next(flagging.apply_all(iter(parse(data)), None))

    schema.validate(record, "parsed_record")
