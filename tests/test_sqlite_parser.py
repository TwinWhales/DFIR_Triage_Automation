"""SQLite 파서 테스트 — 엔진 **위에 우리가 얹은 판단**만 고정한다.

b-tree 순회가 ``sqlite3`` 와 같은지는 ``tests/test_sqlite_engine.py`` 가
봅니다. 여기서 고정하는 것은 그 위의 넷입니다.

- ``ref``/``offset`` 규약 — 레코드 번호가 셀의 절대 오프셋인가
- 프로파일 — 낼 테이블을 고르는가, 없으면 전부 내는가
- 시각 — 인코딩별로 맞게 읽는가, **모르면 채우지 않는가**
- 참조 풀기 — 다른 테이블의 이름을 넣는가, 못 풀면 키를 빼는가

맨 아래 통합 테스트가 실물을 맡습니다. ``evidence/`` 는 저장소에 없으므로
(gitignore) 없으면 건너뜁니다.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from src.common import refs, schema
from src.stage04_parse import flagging
from src.stage04_parse.parsers import sqlite as sqlite_parser
from src.stage04_parse.parsers.base import ParseError, Scope

REPO_ROOT = Path(__file__).resolve().parents[1]

#: 실물 Windows 10 이미지. 없으면 통합 테스트를 건너뛴다(gitignore 대상).
REAL_IMAGE = REPO_ROOT / "evidence" / "0824test.001"
REAL_VOLUME = 1


def build(path: Path, statements) -> Path:
    conn = sqlite3.connect(str(path))
    for statement, params in statements:
        if params is None:
            conn.execute(statement)
        else:
            conn.executemany(statement, params)
    conn.commit()
    conn.close()
    return path


def run(parser, path: Path, scope: "Scope | None" = None):
    with open(path, "rb") as fh:
        return list(parser.parse(fh, scope or Scope()))


@pytest.fixture
def notifications(tmp_path):
    """``wpndatabase.db`` 의 모양을 줄여 만든 것.

    컬럼 이름과 시각 인코딩은 실물에서 확인한 그대로입니다 — 텍스트 하나,
    FILETIME 하나(2026-09-02, ``docs/artifact-notes.md``).
    """
    path = tmp_path / "wpndatabase.db"
    return build(
        path,
        [
            (
                "CREATE TABLE [NotificationHandler]( [RecordId] INTEGER PRIMARY KEY, "
                "[PrimaryId] TEXT, [CreatedTime] TEXT, CONSTRAINT[] UNIQUE([PrimaryId]))",
                None,
            ),
            (
                "INSERT INTO NotificationHandler (PrimaryId, CreatedTime) VALUES (?,?)",
                [("Mail", "2022-10-24 15:32:53"), ("Calendar", "2022-10-24 15:33:10")],
            ),
            (
                "CREATE TABLE [Notification]( [Order] INTEGER NOT NULL PRIMARY KEY, "
                "[HandlerId] INTEGER, [Payload] BLOB, [Tag] TEXT, [ArrivalTime] INT64)",
                None,
            ),
            (
                "INSERT INTO Notification (HandlerId, Payload, Tag, ArrivalTime) VALUES (?,?,?,?)",
                [
                    (1, b"\x01\x02", "tag-a", 133110992407038172),
                    (2, b"\xff", "tag-b", 133110992407112886),
                    # 참조가 깨진 행. 풀리지 않아야 한다.
                    (99, b"", "tag-c", 133110992407112886),
                ],
            ),
            ("CREATE TABLE HandlerSettings (HandlerId INTEGER, SettingKey TEXT)", None),
            (
                "INSERT INTO HandlerSettings VALUES (?,?)",
                [(1, f"key{i}") for i in range(50)],
            ),
        ],
    )


# ------------------------------------------------------------ 등록·규약


def test_등록된_아티팩트만_받는다():
    with pytest.raises(ValueError):
        sqlite_parser.SqliteParser("sqlite:없는것")


def test_아티팩트마다_인스턴스가_따로다():
    """공유하면 한쪽 레코드가 다른 쪽 접두어로 나간다."""
    from src.stage04_parse import parsers

    a = parsers.get("sqlite:StateRepository")
    b = parsers.get("sqlite:Notifications")
    assert a is not b
    assert a.artifact != b.artifact


def test_두_아티팩트_모두_reference_에도_등록돼_있다():
    """reference 쪽을 비우면 --parser reference 에서 조용히 빠진다."""
    from src.stage04_parse import parsers

    for artifact in sqlite_parser.ARTIFACTS:
        assert parsers.get(artifact, "reference") is not None


def test_ref_와_record_num_은_셀의_절대_오프셋이다(notifications):
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    records = run(parser, notifications)
    assert records
    raw = notifications.read_bytes()
    for record in records:
        assert record["record_num"] == refs.record_num_of(record["ref"])
        assert record["offset"] == f"0x{record['record_num']:X}"
        # 그 자리에서 셀 헤더가 읽히고 rowid 가 레코드의 것과 같다.
        from src.stage04_parse.structs import sqlite_page as engine

        payload, used = engine.read_varint(raw, record["record_num"])
        rowid, _ = engine.read_varint(raw, record["record_num"] + used)
        assert payload > 0
        assert rowid == record["fields"]["sqlite_rowid"]


def test_ref_가_유일하다(notifications):
    """겹치면 io.read_parsed_records 가 05·06단계를 통째로 세운다."""
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    records = run(parser, notifications)
    assert len({r["ref"] for r in records}) == len(records)


def test_산출물이_스키마를_통과한다(notifications):
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    for record in flagging.apply_all(iter(run(parser, notifications)), Scope()):
        schema.validate(record, "parsed_record")


# ---------------------------------------------------------------- 프로파일


def test_프로파일이_고른_테이블만_낸다(notifications):
    """HandlerSettings 50건은 설정 키·값이라 증거가 아니다."""
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    tables = {r["fields"]["sqlite_table"] for r in run(parser, notifications)}
    assert tables == {"Notification", "NotificationHandler"}


def test_프로파일이_없으면_모든_테이블을_낸다(tmp_path, monkeypatch):
    """모르는 DB 도 돈다. 시각만 빈다 — 거래 DB 가 생기면 이 경로로 붙는다."""
    path = build(
        tmp_path / "unknown.db",
        [
            ("CREATE TABLE a (id INTEGER PRIMARY KEY, v TEXT)", None),
            ("INSERT INTO a (v) VALUES (?)", [("x",), ("y",)]),
            ("CREATE TABLE b (id INTEGER PRIMARY KEY, v TEXT)", None),
            ("INSERT INTO b (v) VALUES (?)", [("z",)]),
        ],
    )
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    monkeypatch.setattr(parser, "profile", None)
    records = run(parser, path)
    assert {r["fields"]["sqlite_table"] for r in records} == {"a", "b"}
    assert len(records) == 3
    assert all("timestamp" not in r for r in records)


def test_프로파일이_아는_테이블이_없으면_센다(tmp_path):
    """빌드가 달라 스키마가 바뀌면 조용히 0건이 나오면 안 된다."""
    path = build(
        tmp_path / "other.db",
        [
            ("CREATE TABLE 엉뚱한것 (id INTEGER PRIMARY KEY, v TEXT)", None),
            ("INSERT INTO 엉뚱한것 (v) VALUES (?)", [("x",)]),
        ],
    )
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    assert run(parser, path) == []
    assert parser.stats["missing_tables"] == len(parser.profile.tables)


def test_SQLite_가_아니면_ParseError(tmp_path):
    path = tmp_path / "not.db"
    path.write_bytes(b"NOT A DATABASE" + b"\x00" * 200)
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    with pytest.raises(ParseError):
        run(parser, path)


def test_WITHOUT_ROWID_테이블은_건너뛰고_센다(tmp_path, monkeypatch):
    """조용히 0건을 내면 '봤는데 없었다'와 구별되지 않는다."""
    path = build(
        tmp_path / "wr.db",
        [
            ("CREATE TABLE k (a TEXT PRIMARY KEY, b TEXT) WITHOUT ROWID", None),
            ("INSERT INTO k VALUES (?,?)", [(f"a{i}", "b") for i in range(10)]),
            ("CREATE TABLE ok (id INTEGER PRIMARY KEY, v TEXT)", None),
            ("INSERT INTO ok (v) VALUES (?)", [("x",)]),
        ],
    )
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    monkeypatch.setattr(parser, "profile", None)
    records = run(parser, path)
    assert [r["fields"]["sqlite_table"] for r in records] == ["ok"]
    assert parser.stats["unsupported_tables"] == 1


# ------------------------------------------------------------------ 시각


def test_FILETIME_과_텍스트를_모두_읽는다(notifications):
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    by_table = {}
    for record in run(parser, notifications):
        by_table.setdefault(record["fields"]["sqlite_table"], []).append(record)

    assert by_table["Notification"][0]["timestamp"] == "2022-10-24T15:34:00Z"
    assert by_table["NotificationHandler"][0]["timestamp"] == "2022-10-24T15:32:53Z"


@pytest.mark.parametrize(
    "value,encoding,expected",
    [
        (133110992407038172, "filetime", "2022-10-24T15:34:00Z"),
        (1666625573, "unix_s", "2022-10-24T15:32:53Z"),
        (1666625573000, "unix_ms", "2022-10-24T15:32:53Z"),
        ("2022-10-24 15:32:53", "text", "2022-10-24T15:32:53Z"),
        ("2022-10-24T15:32:53Z", "text", "2022-10-24T15:32:53Z"),
    ],
)
def test_인코딩별_시각(value, encoding, expected):
    assert sqlite_parser._decode_time(value, encoding) == expected


@pytest.mark.parametrize(
    "value,encoding",
    [
        (0, "filetime"),  # 1601년. 실물 StateRepository 의 _Created 가 이렇다
        (-1, "filetime"),
        ("어제", "text"),
        (None, "filetime"),
        ("2022-10-24 15:32:53", "filetime"),  # 인코딩을 잘못 적은 경우
        (1 << 62, "filetime"),
    ],
)
def test_말이_안_되는_시각은_채우지_않는다(value, encoding):
    """1601년으로 적힌 줄이 타임라인에 실리면 없는 것보다 나쁘다."""
    assert sqlite_parser._decode_time(value, encoding) is None


def test_해석하지_못한_시각을_센다(tmp_path):
    path = build(
        tmp_path / "badtime.db",
        [
            (
                "CREATE TABLE [NotificationHandler]( [RecordId] INTEGER PRIMARY KEY, "
                "[PrimaryId] TEXT, [CreatedTime] TEXT)",
                None,
            ),
            (
                "INSERT INTO NotificationHandler (PrimaryId, CreatedTime) VALUES (?,?)",
                [("Mail", "언젠가"), ("Calendar", "2022-10-24 15:33:10")],
            ),
        ],
    )
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    records = run(parser, path)
    assert len(records) == 2
    assert sum("timestamp" in r for r in records) == 1
    assert parser.stats["unparsed_timestamps"] == 1
    # 원시 값은 남는다 — 우리 판단이 틀렸을 때 되짚을 수 있어야 한다.
    assert any(r["fields"]["CreatedTime"] == "언젠가" for r in records)


# ------------------------------------------------------------- 참조 풀기


def test_참조를_풀어_이름을_넣는다(notifications):
    """05단계는 레코드를 한 건씩 보내므로 조인을 그때 할 수 없다."""
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    rows = [
        r for r in run(parser, notifications) if r["fields"]["sqlite_table"] == "Notification"
    ]
    assert rows[0]["fields"]["PrimaryId"] == "Mail"
    assert rows[0]["name"] == "Mail"
    assert rows[1]["fields"]["PrimaryId"] == "Calendar"


def test_풀리지_않으면_키를_빼고_센다(notifications):
    """원시 정수는 남는다. '풀지 못했다'가 산출물에 드러나야 한다."""
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    rows = [
        r for r in run(parser, notifications) if r["fields"]["sqlite_table"] == "Notification"
    ]
    broken = rows[2]
    assert "PrimaryId" not in broken["fields"]
    assert broken["fields"]["HandlerId"] == 99
    assert parser.stats["unresolved_lookups"] == 1


def test_BLOB_은_16진_문자열로_나간다(notifications):
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    rows = [
        r for r in run(parser, notifications) if r["fields"]["sqlite_table"] == "Notification"
    ]
    assert rows[0]["fields"]["Payload"] == "0102"


def test_null_은_키를_뺀다(notifications):
    """스키마가 null 을 막는다. 다른 파서와 같은 규약이다."""
    parser = sqlite_parser.SqliteParser("sqlite:Notifications")
    for record in run(parser, notifications):
        assert all(v is not None for v in record["fields"].values())


# ------------------------------------------------------------- 실물 대조


@pytest.mark.skipif(not REAL_IMAGE.exists(), reason="실물 이미지가 없다 (gitignore)")
def test_실물_이미지에서_두_아티팩트를_읽는다():
    """사용자 프로필 경로(user_paths)와 고정 경로를 한 번에 밟는다."""
    from src.stage04_parse import evidence

    source = evidence.open_source(REAL_IMAGE, volume=REAL_VOLUME)
    for artifact in sqlite_parser.ARTIFACTS:
        parser = sqlite_parser.SqliteParser(artifact)
        with source.open(artifact) as stream:
            records = list(parser.parse(stream, Scope()))
        assert records, artifact
        assert len({r["ref"] for r in records}) == len(records), artifact
        for record in flagging.apply_all(iter(records), Scope()):
            schema.validate(record, "parsed_record")


@pytest.mark.skipif(not REAL_IMAGE.exists(), reason="실물 이미지가 없다 (gitignore)")
def test_알림_DB_는_사용자_프로필에서_찾는다():
    """``relative_paths`` 로는 표현할 수 없는 자리다."""
    from src.stage04_parse import evidence

    source = evidence.open_source(REAL_IMAGE, volume=REAL_VOLUME)
    located = source.locate("sqlite:Notifications")
    assert located is not None
    assert located.method == "user_path"
    assert "Users" in str(located.path)
