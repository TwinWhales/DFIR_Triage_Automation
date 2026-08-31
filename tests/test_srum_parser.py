"""SRUM 파서.

라이브러리(`dissect.esedb`)를 쓰는 파서라 **그 위에 우리가 얹은 판단만**
고정한다 — 시각 인코딩 해석, `AppId` 풀기, 페이지 → 파일 오프셋, 컬럼
확인, `ref` 규약. ESE 의 B-tree 를 다시 시험하지 않는다
(`tests/test_registry_parser.py` 와 같은 형태).

실물 대조는 맨 아래 통합 테스트가 맡고, `evidence/` 가 없으면 건너뛴다.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from src.common import refs, schema
from src.stage04_parse import flagging, osinfo
from src.stage04_parse.parsers import srum
from src.stage04_parse.parsers.base import ParseError, Scope

NET = "srum:NetworkUsage"
APP = "srum:AppResourceUsage"
CONN = "srum:NetworkConnectivity"

#: 실측(`0824test.001`)에서 가져온 값. 2022-10-24 15:30:00 UTC 다.
REAL_TIMESTAMP_RAW = 4676398138920708779
REAL_TIMESTAMP_ISO = "2022-10-24T15:30:00.0000000Z"


# ============================================================ 가짜 객체


class FakePage:
    def __init__(self, num: int) -> None:
        self.num = num


class FakeTag:
    def __init__(self, num: int) -> None:
        self.page = FakePage(num)


class FakeNode:
    def __init__(self, page_num: int) -> None:
        self.tag = FakeTag(page_num)


class FakeRecord:
    """``record.get(name)`` 과 ``record._node.tag.page`` 만 흉내 낸다."""

    def __init__(self, values: dict, page_num: int = 49, raises: dict | None = None) -> None:
        self._values = values
        self._node = FakeNode(page_num)
        self._raises = raises or {}

    def get(self, name):
        if name in self._raises:
            raise self._raises[name]
        return self._values.get(name)


class FakeColumn:
    def __init__(self, name: str) -> None:
        self.name = name


class FakeTable:
    def __init__(self, name: str, columns: list[str], rows: list[FakeRecord]) -> None:
        self.name = name
        self.columns = [FakeColumn(c) for c in columns]
        self._rows = rows

    def records(self):
        return iter(self._rows)


class FakeDb:
    def __init__(self, tables: dict, page_size: int = 4096) -> None:
        self._tables = tables
        self.page_size = page_size

    def table(self, name: str):
        try:
            return self._tables[name]
        except KeyError:
            raise KeyError(name) from None


def _id_map(rows: list[tuple[int, int, bytes | None]]) -> FakeTable:
    return FakeTable(
        srum.ID_MAP_TABLE,
        ["IdType", "IdIndex", "IdBlob"],
        [FakeRecord({"IdType": t, "IdIndex": i, "IdBlob": b}) for t, i, b in rows],
    )


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


NET_COLUMNS = ["AutoIncId", "TimeStamp", "AppId", "UserId", "BytesSent", "BytesRecvd"]


def _net_db(rows: list[FakeRecord], id_rows=(), columns=None) -> FakeDb:
    return FakeDb(
        {
            srum.TABLE_OF[NET]: FakeTable(srum.TABLE_OF[NET], columns or NET_COLUMNS, rows),
            srum.ID_MAP_TABLE: _id_map(list(id_rows)),
        }
    )


def _run(artifact: str, db: FakeDb) -> list[dict]:
    parser = srum.SrumParser(artifact)
    table = parser._open_table(db)
    columns = tuple(c.name for c in table.columns)
    parser._check_columns(columns)
    identities = parser._read_id_map(db)
    return [
        parser._build(r, columns, identities, db.page_size) for r in table.records()
    ], parser


# ============================================================ 등록


def test_every_artifact_has_a_table_and_a_required_column_set():
    """둘이 갈라지면 새 아티팩트가 컬럼 확인 없이 통과한다."""
    assert set(srum.TABLE_OF) == set(srum.REQUIRED_COLUMNS)
    assert set(srum.ARTIFACTS) == set(srum.TABLE_OF)


def test_every_artifact_has_a_ref_prefix():
    for artifact in srum.ARTIFACTS:
        assert refs.prefix_for(artifact)


def test_the_three_artifacts_do_not_share_a_prefix():
    """AutoIncId 는 테이블 안에서만 유일하다. 접두어를 공유하면 ref 가 겹친다."""
    prefixes = {refs.prefix_for(a) for a in srum.ARTIFACTS}

    assert len(prefixes) == len(srum.ARTIFACTS)


def test_an_unknown_artifact_is_refused_at_construction():
    with pytest.raises(ValueError, match="알 수 없는 SRUM 아티팩트"):
        srum.SrumParser("srum:Nope")


def test_srum_is_marked_unavailable_before_windows_eight():
    """Win7 에 없는 것은 수집 누락이 아니다. 안 적으면 '다시 수집하라'고 나간다."""
    win7 = osinfo.WindowsVersion(build=7601, family="win7", product_name="Windows 7")

    for artifact in srum.ARTIFACTS:
        assert osinfo.applicability(artifact, win7) is not None


# ============================================================ 시각


def test_the_timestamp_is_an_ole_date_not_a_filetime():
    """실측값이다. FILETIME 으로 읽으면 OverflowError 가 난다."""
    assert srum._ole_timestamp(REAL_TIMESTAMP_RAW) == REAL_TIMESTAMP_ISO


def test_the_raw_int_is_reinterpreted_as_a_double_not_cast():
    """float(값) 으로 하면 조용히 실패한다 — 실측에서 76건 전부가 시각을 잃었다."""
    as_double = struct.unpack("<d", struct.pack("<q", REAL_TIMESTAMP_RAW))[0]

    # 캐스팅한 값과 비트를 다시 읽은 값은 전혀 다른 수다.
    assert as_double != float(REAL_TIMESTAMP_RAW)
    assert srum._ole_timestamp(as_double) == srum._ole_timestamp(REAL_TIMESTAMP_RAW)


def test_an_unreadable_timestamp_drops_the_key_instead_of_null():
    """null 은 스키마가 막는다. 다른 파서와 같은 규약이다."""
    (record,), _ = _run(
        NET, _net_db([FakeRecord({"AutoIncId": 1, "TimeStamp": None, "AppId": 3})])
    )

    assert "timestamp" not in record
    assert "TimeStamp" not in record["fields"]


def test_the_raw_timestamp_stays_in_fields():
    """우리 해석이 틀렸을 때 되짚을 자리가 있어야 한다."""
    (record,), _ = _run(
        NET, _net_db([FakeRecord({"AutoIncId": 1, "TimeStamp": REAL_TIMESTAMP_RAW})])
    )

    assert record["fields"]["TimeStamp"] == REAL_TIMESTAMP_RAW
    assert record["timestamp"] == REAL_TIMESTAMP_ISO


# ============================================================ 오프셋


def test_the_offset_is_the_page_position_in_the_file():
    """논리 페이지 n 은 (n+1)*page_size 에 있다 — 앞 두 페이지가 헤더와 그림자다.

    실측으로 확인했다: 76건 전부에서 그 위치의 바이트가 라이브러리의 페이지
    버퍼와 일치했고, 보정 없는 n*page_size 는 어긋났다.
    """
    (record,), _ = _run(
        NET, _net_db([FakeRecord({"AutoIncId": 1}, page_num=49)])
    )

    assert record["offset"] == f"0x{(49 + 1) * 4096:X}"
    assert record["offset"] == "0x32000"


def test_a_record_without_a_page_is_refused_not_given_offset_zero():
    """0 으로 조용히 내보내면 '파일 맨 앞'이라는 거짓말이 산출물에 실린다."""
    record = FakeRecord({"AutoIncId": 1})
    del record._node

    with pytest.raises(ParseError, match="페이지를 알 수 없습니다"):
        srum._file_offset(record, 4096)


# ============================================================ AppId 풀기


def test_the_app_id_is_resolved_to_a_name():
    (record,), _ = _run(
        NET,
        _net_db(
            [FakeRecord({"AutoIncId": 1, "AppId": 3, "UserId": 4})],
            id_rows=[(0, 3, _utf16("System")), (3, 4, bytes([1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]))],
        ),
    )

    assert record["fields"]["AppName"] == "System"
    assert record["fields"]["UserSid"] == "S-1-5-18"


def test_a_service_name_and_a_package_id_resolve_too():
    """IdType 0·1·2 를 한 사전에 합친다 — AppId 는 셋 중 어느 것이든 가리킨다."""
    (svc,), _ = _run(
        NET, _net_db([FakeRecord({"AutoIncId": 1, "AppId": 142})], id_rows=[(1, 142, _utf16("Dnscache"))])
    )
    (pkg,), _ = _run(
        NET, _net_db([FakeRecord({"AutoIncId": 1, "AppId": 6})], id_rows=[(2, 6, _utf16("svc.ownproc.s0"))])
    )

    assert svc["fields"]["AppName"] == "Dnscache"
    assert pkg["fields"]["AppName"] == "svc.ownproc.s0"


def test_an_unresolved_app_id_keeps_the_integer_and_is_counted():
    """실측에서 IdBlob 이 DB 안에서 이미 None 인 행이 둘 있었다 — 원본의 결손이다.

    풀지 못한 것을 조용히 넘기면 "이름 없는 앱이 10MB 를 보냈다"가
    산출물에서 사라진다. 정수는 남기고 센다.
    """
    (record,), parser = _run(
        NET, _net_db([FakeRecord({"AutoIncId": 1, "AppId": 1})], id_rows=[(0, 1, None)])
    )

    assert record["fields"]["AppId"] == 1
    assert "AppName" not in record["fields"]
    assert parser.stats["unresolved_app_id"] == 1


def test_a_user_index_is_not_mistaken_for_an_app_name():
    """SID 를 UTF-16 으로 읽으면 깨진 글자가 보고서에 실린다."""
    (record,), parser = _run(
        NET,
        _net_db(
            [FakeRecord({"AutoIncId": 1, "AppId": 4})],
            id_rows=[(3, 4, bytes([1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]))],
        ),
    )

    assert "AppName" not in record["fields"]
    assert parser.stats["unresolved_app_id"] == 1


def test_a_missing_id_map_does_not_stop_the_parse():
    """AppId 정수만으로도 '같은 것이 반복해 통신했다'는 사실은 남는다."""
    db = FakeDb({srum.TABLE_OF[NET]: FakeTable(srum.TABLE_OF[NET], NET_COLUMNS, [])})
    parser = srum.SrumParser(NET)

    assert parser._read_id_map(db) == {}


# ============================================================ 컬럼 확인


def test_a_table_missing_our_columns_is_refused_loudly():
    """조용히 비어 나가는 것이 최악이다 — 파싱은 성공했다는데 근거가 없다."""
    with pytest.raises(ParseError, match="BytesSent"):
        _run(NET, _net_db([], columns=["AutoIncId", "TimeStamp", "AppId"]))


def test_a_provider_table_that_is_absent_is_refused_loudly():
    parser = srum.SrumParser(NET)

    with pytest.raises(ParseError, match="공급자 테이블"):
        parser._open_table(FakeDb({}))


# ============================================================ 레코드 형식


def test_the_ref_uses_the_auto_inc_id():
    (record,), _ = _run(NET, _net_db([FakeRecord({"AutoIncId": 77})]))

    assert record["ref"] == "SRUM-NET#77"
    assert record["record_num"] == 77


def test_a_record_without_an_auto_inc_id_is_refused():
    """ref 를 만들 수 없다. 자체 일련번호를 매기면 원본 대조가 불가능해진다."""
    with pytest.raises(ParseError, match="AutoIncId"):
        _run(NET, _net_db([FakeRecord({"TimeStamp": REAL_TIMESTAMP_RAW})]))


def test_binary_columns_become_hex_not_bytes():
    """json.dumps 가 bytes 에서 TypeError 로 04단계 전체를 세운다."""
    (record,), _ = _run(
        NET,
        _net_db(
            [FakeRecord({"AutoIncId": 1, "BytesSent": b"\x01\x02"})],
            columns=NET_COLUMNS + ["BinaryData"],
        ),
    )

    assert record["fields"]["BytesSent"] == "0102"
    json.dumps(record)


def test_a_null_column_drops_the_key():
    (record,), _ = _run(NET, _net_db([FakeRecord({"AutoIncId": 1, "BytesRecvd": None})]))

    assert "BytesRecvd" not in record["fields"]


def test_one_unreadable_column_refuses_that_record_only():
    parser = srum.SrumParser(NET)
    bad = FakeRecord({"AutoIncId": 1}, raises={"BytesSent": ValueError("셀 손상")})

    with pytest.raises(ParseError, match="BytesSent"):
        parser._build(bad, tuple(NET_COLUMNS), {}, 4096)


def test_records_match_the_parsed_record_schema():
    records, _ = _run(
        NET,
        _net_db(
            [FakeRecord({"AutoIncId": 1, "TimeStamp": REAL_TIMESTAMP_RAW, "AppId": 3, "BytesSent": 9})],
            id_rows=[(0, 3, _utf16("System"))],
        ),
    )

    for record in flagging.apply_all(records, None):
        schema.validate(record, "parsed_record")


# ============================================================ 실물 대조


@pytest.mark.skipif(
    not Path("evidence/0824test.001").is_file(),
    reason="실물 이미지 없음 (evidence/ 는 저장소에 없다)",
)
def test_the_real_srudb_parses_and_the_two_time_encodings_agree():
    """같은 DB 의 OLE 시각과 FILETIME 시각이 서로를 지지하는가.

    ``TimeStamp`` 는 OLE Automation date, ``ConnectStartTime`` 은 진짜
    FILETIME 이다. 독립적인 두 인코딩이 같은 시각대를 가리키면 해석이 맞다.
    """
    import io

    from dissect.target import Target
    from dissect.util.ts import wintimestamp

    from src.common.io import parse_timestamp

    target = Target.open("evidence/0824test.001")
    stream = list(target.filesystems)[1].get("Windows/System32/sru/SRUDB.dat").open()
    parser = srum.SrumParser(CONN)
    records = list(parser.parse(io.BytesIO(stream.read()), Scope()))

    assert records, "실물 SRUDB 에서 연결 이력이 한 건도 안 나왔다"
    record = records[0]
    ours = parse_timestamp(record["timestamp"])
    theirs = wintimestamp(record["fields"]["ConnectStartTime"])

    assert abs((ours - theirs).total_seconds()) < 3600
