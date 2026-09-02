"""SQLite 엔진 테스트 — 페이지·셀·레코드를 직접 걷는 부분.

**정답지가 표준 라이브러리입니다.** 여기서 만드는 DB 는 ``sqlite3`` 가
쓰고, 같은 파일을 우리 엔진이 읽어 값이 같은지 봅니다. 라이브러리가 이미
하는 일을 다시 시험하는 것이 아니라 **우리 b-tree 순회가 라이브러리와
같은 것을 보는가**를 고정합니다.

실물 대조는 따로 했습니다 — 이미지 둘의 SQLite 64개, 2,368테이블,
209,393행이 ``sqlite3`` 와 전수 일치했습니다(``docs/artifact-notes.md``
2026-09-02). 여기서 고정하는 것은 그때 **실제로 틀렸던 자리들**입니다.

- ``GENERATED ALWAYS AS (...) VIRTUAL`` 컬럼은 레코드에 없다 — 세면
  그 뒤 컬럼 이름이 전부 한 칸씩 밀린다
- ``CREATE TABLE`` 안의 ``--`` 주석이 컬럼으로 둔갑한다
- ``CONSTRAINT[]``·``UNIQUE([Id])`` 처럼 키워드와 대괄호 사이에 공백이
  없는 SQL 을 Windows 가 쓴다
- ``INTEGER PRIMARY KEY`` 는 본문에 NULL 로 있고 진짜 값은 rowid 다
- 넘침(overflow) 계산은 **긴 값에서만** 틀린다
"""

from __future__ import annotations

import io
import sqlite3
import struct

import pytest

from src.stage04_parse.structs import sqlite_page as sp


def build(path, statements, *, page_size=4096, encoding=None):
    """``sqlite3`` 로 DB 를 만든다. 정답지 겸 픽스처."""
    conn = sqlite3.connect(str(path))
    if encoding is not None:
        conn.execute(f"PRAGMA encoding = '{encoding}'")
    conn.execute(f"PRAGMA page_size = {page_size}")
    conn.execute("VACUUM")
    for statement, params in statements:
        if params is None:
            conn.execute(statement)
        else:
            conn.executemany(statement, params)
    conn.commit()
    conn.close()
    return path


def rows_by_rowid(path, table):
    """우리 엔진이 읽은 ``{rowid: 값들}``."""
    with open(path, "rb") as fh:
        db = sp.Database(fh)
        found = next(t for t in db.tables() if t.name == table)
        return {row.rowid: row.values for row in db.rows(found)}, found


def reference(path, table):
    """``sqlite3`` 가 읽은 ``{rowid: 값들}``."""
    conn = sqlite3.connect(f"file:{path.as_posix()}?immutable=1", uri=True)
    try:
        return {r[0]: tuple(r[1:]) for r in conn.execute(f'SELECT rowid, * FROM "{table}"')}
    finally:
        conn.close()


# ------------------------------------------------------------------ varint


def test_varint_한_바이트():
    assert sp.read_varint(b"\x7f") == (127, 1)


def test_varint_두_바이트():
    assert sp.read_varint(b"\x81\x00") == (128, 2)


def test_varint_아홉_바이트는_마지막_바이트를_여덟_비트로_쓴다():
    """9번째 바이트만 8비트를 전부 싣는다. 7비트로 읽으면 큰 값에서 틀린다."""
    data = b"\xff" * 8 + b"\xff"
    value, size = sp.read_varint(data)
    assert size == 9
    assert value == -1  # 64비트 전부 1


def test_varint_가_잘리면_거부한다():
    with pytest.raises(sp.SQLiteError):
        sp.read_varint(b"\x81")


# ------------------------------------------------------------- serial type


@pytest.mark.parametrize(
    "serial,size",
    [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 6), (6, 8), (7, 8), (8, 0), (9, 0), (12, 0), (13, 0), (14, 1), (15, 1)],
)
def test_serial_크기(serial, size):
    assert sp.serial_size(serial) == size


def test_serial_8과_9는_본문에_바이트가_없다():
    """1로 잡으면 그 뒤 컬럼이 전부 밀린다."""
    assert sp.serial_size(8) == 0
    assert sp.serial_size(9) == 0


def test_내부_예약_serial_은_거부한다():
    for serial in (10, 11):
        with pytest.raises(sp.SQLiteError):
            sp.serial_size(serial)


# ------------------------------------------------------------ 컬럼 이름


def test_공백_없는_테이블_제약을_컬럼으로_읽지_않는다():
    """실물 wpndatabase.db 가 쓴 형태다 (2026-09-02)."""
    sql = "CREATE TABLE [Metadata]( [Key] TEXT, [Value] INT64, CONSTRAINT[] PRIMARY KEY([Key]) ON CONFLICT REPLACE)"
    names, alias, without_rowid = sp.column_names(sql)
    assert names == ("Key", "Value")
    assert alias is None
    assert without_rowid is False


def test_공백_없는_UNIQUE_도_마찬가지다():
    sql = (
        "CREATE TABLE [Notification]( [Order] INTEGER NOT NULL PRIMARY KEY, "
        "[Id] INTEGER NOT NULL, [Payload] BLOB, UNIQUE([Id]) ON CONFLICT REPLACE)"
    )
    names, alias, _ = sp.column_names(sql)
    assert names == ("Order", "Id", "Payload")
    assert alias == 0


def test_주석은_컬럼이_아니다():
    """실물 OneDrive DB 의 CREATE TABLE 에 주석이 들어 있다."""
    sql = (
        "CREATE TABLE PathPeriodicRetry (\n"
        "    RelativePath TEXT NOT NULL,\n"
        "    IsProcessing BOOLEAN DEFAULT 0,\n"
        "    -- 주석이다, 쉼표도 들어 있다\n"
        "    PRIMARY KEY(RelativePath)\n"
        ")"
    )
    names, alias, _ = sp.column_names(sql)
    assert names == ("RelativePath", "IsProcessing")
    assert alias is None


def test_VIRTUAL_계산_컬럼은_레코드에_없으므로_세지_않는다():
    sql = (
        "CREATE TABLE t (\n"
        "    a TEXT,\n"
        "    b TEXT,\n"
        "    ab TEXT GENERATED ALWAYS AS (a || b) VIRTUAL,\n"
        "    c TEXT\n"
        ")"
    )
    names, _, _ = sp.column_names(sql)
    assert names == ("a", "b", "c")


def test_STORED_계산_컬럼은_레코드에_있으므로_센다():
    sql = "CREATE TABLE t (a TEXT, ab TEXT GENERATED ALWAYS AS (a || a) STORED, c TEXT)"
    names, _, _ = sp.column_names(sql)
    assert names == ("a", "ab", "c")


def test_INT64_는_rowid_별명이_아니다():
    """정확히 INTEGER 여야 한다. INT64 자리에 rowid 를 넣으면 값을 지어낸다."""
    sql = "CREATE TABLE t (a INT64 PRIMARY KEY, b TEXT)"
    _, alias, _ = sp.column_names(sql)
    assert alias is None


def test_테이블_제약으로_뺀_INTEGER_PRIMARY_KEY_도_별명이다():
    sql = "CREATE TABLE t (a INTEGER, b TEXT, PRIMARY KEY(a))"
    _, alias, _ = sp.column_names(sql)
    assert alias == 0


def test_WITHOUT_ROWID_면_별명이_없다():
    sql = "CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT) WITHOUT ROWID"
    _, alias, without_rowid = sp.column_names(sql)
    assert without_rowid is True
    assert alias is None


# ------------------------------------------------------------------ 헤더


def test_SQLite_가_아니면_거부한다():
    with pytest.raises(sp.NotADatabase):
        sp.Database(io.BytesIO(b"NOT A DATABASE" + b"\x00" * 200))


def test_페이지_크기_1은_65536이다():
    head = bytearray(sp.MAGIC + b"\x00" * 84)
    struct.pack_into(">H", head, 16, 1)
    struct.pack_into(">I", head, 56, 1)
    header = sp.DatabaseHeader.parse(bytes(head), file_size=65536)
    assert header.page_size == 65536


def test_페이지_크기가_2의_거듭제곱이_아니면_거부한다():
    head = bytearray(sp.MAGIC + b"\x00" * 84)
    struct.pack_into(">H", head, 16, 4095)
    with pytest.raises(sp.NotADatabase):
        sp.DatabaseHeader.parse(bytes(head), file_size=1 << 20)


def test_헤더의_페이지_수가_낡았으면_파일_크기로_센다():
    """실물 Win7 이미지의 .vdf 42건이 이 경우다 — 헤더 페이지 수가 0이다."""
    head = bytearray(sp.MAGIC + b"\x00" * 84)
    struct.pack_into(">H", head, 16, 1024)
    struct.pack_into(">I", head, 24, 7)  # 변경 카운터
    struct.pack_into(">I", head, 28, 0)  # 페이지 수 = 0 (낡음)
    struct.pack_into(">I", head, 56, 1)
    struct.pack_into(">I", head, 92, 3)  # 카운터와 다르다
    header = sp.DatabaseHeader.parse(bytes(head), file_size=1024 * 40)
    assert header.page_count == 40


# ------------------------------------------------------- sqlite3 와 대조


@pytest.mark.parametrize("page_size", [512, 1024, 4096, 65536])
def test_페이지_크기별로_sqlite3_와_같은_행을_읽는다(tmp_path, page_size):
    path = tmp_path / f"p{page_size}.db"
    build(
        path,
        [
            ("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, n INTEGER, f REAL, b BLOB)", None),
            (
                "INSERT INTO t (name, n, f, b) VALUES (?,?,?,?)",
                [(f"이름{i}", i * -7, i / 3, bytes([i % 256]) * (i % 40)) for i in range(400)],
            ),
        ],
        page_size=page_size,
    )
    ours, _ = rows_by_rowid(path, "t")
    assert ours == reference(path, "t")
    assert len(ours) == 400


def test_넘치는_페이로드를_오버플로_체인까지_따라간다(tmp_path):
    """작은 픽스처로는 안 걸리는 자리다. 긴 값에서만 어긋난다."""
    path = tmp_path / "overflow.db"
    build(
        path,
        [
            ("CREATE TABLE big (id INTEGER PRIMARY KEY, blob BLOB, text TEXT)", None),
            (
                "INSERT INTO big (blob, text) VALUES (?,?)",
                [(bytes(i % 251 for i in range(size)), "가" * size) for size in (10, 500, 5000, 60000)],
            ),
        ],
        page_size=512,
    )
    ours, _ = rows_by_rowid(path, "big")
    assert ours == reference(path, "big")
    with open(path, "rb") as fh:
        db = sp.Database(fh)
        table = next(t for t in db.tables() if t.name == "big")
        chained = [row for row in db.rows(table) if row.overflow_pages > 0]
    assert len(chained) == 3  # 500 바이트부터 512 페이지를 넘는다


def test_UTF16_DB_의_문자열도_같게_읽는다(tmp_path):
    """실물 configuration.sqlite 가 utf-16le 다."""
    path = tmp_path / "u16.db"
    build(
        path,
        [
            ("CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)", None),
            ("INSERT INTO t (s) VALUES (?)", [("한글 テスト emoji 🙂",), ("plain",)]),
        ],
        encoding="UTF-16le",
    )
    with open(path, "rb") as fh:
        assert sp.Database(fh).header.encoding_name == "utf-16-le"
    ours, _ = rows_by_rowid(path, "t")
    assert ours == reference(path, "t")


def test_INTEGER_PRIMARY_KEY_자리에_rowid_를_채운다(tmp_path):
    path = tmp_path / "alias.db"
    build(
        path,
        [
            ("CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)", None),
            ("INSERT INTO t (s) VALUES (?)", [("a",), ("b",)]),
        ],
    )
    ours, table = rows_by_rowid(path, "t")
    assert table.rowid_alias == 0
    assert ours[1][0] == 1 and ours[2][0] == 2
    assert ours == reference(path, "t")


def test_WITHOUT_ROWID_테이블은_조용히_0건이_아니라_거부한다(tmp_path):
    path = tmp_path / "wr.db"
    build(
        path,
        [
            ("CREATE TABLE wr (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID", None),
            ("INSERT INTO wr VALUES (?,?)", [(f"k{i}", f"v{i}") for i in range(30)]),
        ],
    )
    with open(path, "rb") as fh:
        db = sp.Database(fh)
        table = next(t for t in db.tables() if t.name == "wr")
        assert table.without_rowid is True
        assert table.readable is False
        with pytest.raises(sp.UnsupportedTable):
            list(db.rows(table))


def test_offset_은_원본에서_그_셀을_가리킨다(tmp_path):
    """되짚을 수 없는 값은 보고서에 실릴 수 없다. hexdump_record 가 쓰는 규약."""
    path = tmp_path / "offset.db"
    build(
        path,
        [
            ("CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)", None),
            ("INSERT INTO t (s) VALUES (?)", [(f"값{i}" * 3,) for i in range(200)]),
        ],
        page_size=512,
    )
    raw = path.read_bytes()
    with open(path, "rb") as fh:
        db = sp.Database(fh)
        table = next(t for t in db.tables() if t.name == "t")
        for row in db.rows(table):
            payload_size, n1 = sp.read_varint(raw, row.offset)
            rowid, _ = sp.read_varint(raw, row.offset + n1)
            assert rowid == row.rowid
            assert 0 < payload_size < len(raw)


def test_손상된_셀_포인터는_거부한다(tmp_path):
    """그럴듯한 값을 내는 것보다 소리를 내는 편이 낫다."""
    path = tmp_path / "broken.db"
    build(
        path,
        [
            ("CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)", None),
            ("INSERT INTO t (s) VALUES (?)", [("a",), ("b",)]),
        ],
        page_size=512,
    )
    raw = bytearray(path.read_bytes())
    # 페이지 2의 첫 셀 포인터를 페이지 밖으로 밀어 버린다.
    struct.pack_into(">H", raw, 512 + 8, 0xFFFF)
    with open(path, "wb") as fh:
        fh.write(raw)
    with open(path, "rb") as fh:
        db = sp.Database(fh)
        table = next(t for t in db.tables() if t.name == "t")
        with pytest.raises(sp.SQLiteError):
            list(db.rows(table))


def test_여러_페이지에_걸친_테이블을_전부_읽는다(tmp_path):
    """내부 페이지를 타고 내려가는 경로. 한 페이지짜리로는 안 밟힌다."""
    path = tmp_path / "deep.db"
    build(
        path,
        [
            ("CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)", None),
            ("INSERT INTO t (s) VALUES (?)", [(f"row-{i:06d}",) for i in range(5000)]),
        ],
        page_size=512,
    )
    ours, _ = rows_by_rowid(path, "t")
    assert len(ours) == 5000
    assert ours == reference(path, "t")


def test_행_순서는_rowid_순이다(tmp_path):
    """같은 파일에서 산출물 줄 순서가 실행마다 같아야 대조가 된다."""
    path = tmp_path / "order.db"
    build(
        path,
        [
            ("CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)", None),
            ("INSERT INTO t (s) VALUES (?)", [(f"v{i}",) for i in range(1200)]),
        ],
        page_size=512,
    )
    with open(path, "rb") as fh:
        db = sp.Database(fh)
        table = next(t for t in db.tables() if t.name == "t")
        rowids = [row.rowid for row in db.rows(table)]
    assert rowids == sorted(rowids)
