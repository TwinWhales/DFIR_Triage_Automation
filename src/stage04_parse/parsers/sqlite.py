"""SQLite DB 파서 — 엔진은 범용, 아는 DB 는 프로파일로 좁힌다.

## 왜 두 층인가

구조를 읽는 일(``structs/sqlite_page.py``)은 DB 가 무엇이든 같습니다.
그런데 **파서가 되려면 두 가지를 더 알아야 하고, 그 둘은 DB 마다 다릅니다.**

* 어느 테이블이 증거인가 — 브라우저 History 한 파일에 테이블이 스무 개
  넘고 대부분은 증거가 아닙니다. 전부 내면 05단계 쿼터를 잡아먹습니다.
* 어느 컬럼이 시각이고 무슨 인코딩인가 — 같은 DB 안에서도 갈립니다.
  실측 ``wpndatabase.db`` 는 ``Notification.ArrivalTime`` 이 FILETIME,
  ``NotificationHandler.CreatedTime`` 이 ``'2022-10-24 15:32:53'`` 텍스트
  입니다(2026-09-02).

그래서 **엔진은 범용이고 프로파일은 얇은 표**입니다. 프로파일이 없는 DB 도
돕니다 — 모든 테이블을 내고 ``timestamp`` 만 비웁니다. 스키마가
``timestamp`` 를 필수로 두지 않아 가능한 설계이고, 새 DB(예: 거래 DB)가
생기면 **카탈로그 한 줄과 프로파일 몇 줄로** 붙습니다.

## 텍스트 시각이 UTC 라는 근거

``NotificationHandler.CreatedTime`` 은 시간대가 없는 문자열입니다. 같은
DB 의 ``Notification.ArrivalTime`` 은 FILETIME 이라 정의상 UTC 인데,
실측에서 텍스트가 ``15:32:53``, 이웃한 FILETIME 이 ``15:34:00`` 이었습니다.
**1분 차이**입니다 — 텍스트가 현지 시각(KST)이었다면 9시간이 어긋납니다.
두 인코딩이 서로를 지지하므로 UTC 로 읽습니다(SRUM 의 OLE/FILETIME 대조와
같은 논리).

## 레코드 번호는 셀의 절대 오프셋이다

SQLite 에 파일 전역 일련번호가 없고 ``rowid`` 는 테이블 안에서만
유일합니다. 한 접두어로 묶으면 서로 다른 테이블의 1번이 같은 ``ref`` 가
되므로, **파일 안에서 유일한 값**인 셀의 파일 내 오프셋을 씁니다.
레지스트리(NK 오프셋)·프리패치(경로 해시)와 같은 논리입니다.

``rowid`` 와 테이블 이름은 ``fields`` 에 남으므로 되짚을 수 있습니다.

## 못 읽는 테이블은 조용히 넘기지 않는다

``WITHOUT ROWID`` 테이블은 행이 인덱스 b-tree 에 있어 이 구현이 읽지
못합니다. 0건을 내면 "봤는데 없었다"와 구별되지 않으므로 ``stats`` 에
세고 경고를 남깁니다. 실측에서 드물지 않습니다 — OneDrive
``SyncEngineDatabase.db`` 는 21개 중 14개가 그 형태였습니다
(``docs/limitations.md``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, BinaryIO, Iterator

from ...common import refs
from ..structs import sqlite_page as sqlite
from .base import ParseError, Scope

__all__ = [
    "ARTIFACTS",
    "PROFILES",
    "TableProfile",
    "Profile",
    "SqliteParser",
]

_log = logging.getLogger(__name__)

#: FILETIME 의 기준. 1601-01-01 UTC 부터 100나노초 단위.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

#: 시각으로 인정할 범위. 밖이면 그 컬럼이 시각이 아니거나 우리 인코딩
#: 판단이 틀린 것이므로 **채우지 않습니다.** 1970년이나 2200년으로 적힌
#: 타임라인은 없는 것보다 나쁩니다.
_MIN_YEAR = 1990
_MAX_YEAR = 2100


@dataclass(frozen=True)
class Lookup:
    """다른 테이블의 값을 이 레코드에 풀어 넣는다.

    **05단계는 레코드를 한 건씩 모델에 보냅니다.** 조인은 그때 할 수 없고
    보고서에 실릴 문장이 근거로 삼는 것도 레코드 한 줄입니다. 그래서
    ``PackageUser.Package = 182`` 대신 ``PackageFullName`` 을 함께 넣습니다 —
    SRUM 이 ``AppId`` 정수를 ``SruDbIdMapTable`` 로 풀었던 것과 같습니다.

    **풀리지 않으면 키를 뺍니다.** 원래의 정수는 그대로 남으므로 "풀지
    못했다"가 산출물에 드러납니다.
    """

    #: 이 레코드에서 참조 값이 들어 있는 컬럼.
    column: str
    #: 참조가 가리키는 테이블.
    table: str
    #: 그 테이블에서 참조 값과 맞출 컬럼.
    key_column: str
    #: 가져올 컬럼.
    value_column: str
    #: 가져온 값을 넣을 이름. 비면 ``value_column`` 을 그대로 쓴다.
    into: str = ""

    @property
    def target(self) -> str:
        return self.into or self.value_column


@dataclass(frozen=True)
class TableProfile:
    """아는 테이블 하나를 어떻게 읽을지."""

    #: 시각 컬럼과 그 인코딩. ``filetime`` / ``unix_s`` / ``unix_ms`` / ``text``
    time_column: "str | None" = None
    time_encoding: str = "filetime"
    #: ``name`` 에 쓸 컬럼. 사람이 줄을 훑을 때의 표지다.
    #: 풀어 넣은 이름(``Lookup.target``)도 쓸 수 있다.
    label_column: "str | None" = None
    #: 파일 경로가 담긴 컬럼. 있으면 ``path`` 에 넣고 **선별의 경로
    #: 조건이 적용됩니다** — 없으면 경로로 좁힐 수 없다.
    path_column: "str | None" = None
    #: 다른 테이블에서 풀어 올 값들.
    lookups: "tuple[Lookup, ...]" = ()


@dataclass(frozen=True)
class Profile:
    """DB 하나를 어떻게 읽을지.

    ``tables`` 가 비면 **모든 테이블**을 냅니다. 프로파일 자체가 없는
    DB 와 같은 동작입니다.
    """

    tables: "dict[str, TableProfile]" = field(default_factory=dict)


#: 이 파서가 맡는 아티팩트. 인스턴스는 아티팩트마다 따로 만든다 —
#: ``artifact`` 가 ``ref`` 접두어와 출력 파일명을 정하기 때문이다.
ARTIFACTS = ("sqlite:StateRepository", "sqlite:Notifications")

#: 아는 DB 의 프로파일. 여기 없는 아티팩트도 돈다(모든 테이블, 시각 없음).
#:
#: 컬럼 이름과 인코딩은 전부 **실물에서 확인한 값**입니다
#: (``0824test.001``, 2026-09-02). 다른 빌드에서 컬럼이 없으면 그 자리만
#: 비고 레코드는 그대로 나갑니다 — 이름을 못 찾았다고 행을 버리지 않습니다.
PROFILES: "dict[str, Profile]" = {
    # UWP 앱·패키지 인벤토리. Assigned Access 가 지정하는 것이 UWP 앱이라
    # 키오스크에서 "무엇이 언제 설치·변경됐나"가 여기 있다.
    #
    # 테이블 68개 중 다섯만 낸다. 나머지는 리소스·번들 메타데이터로
    # 4,700행이 넘는데 증거가 아니다.
    #
    # **시각은 PackageUser.InstallTime 하나뿐이다.** Package._Created 와
    # _Modified 는 컬럼이 있는데 실측에서 전부 0 이었다 — 있다고 믿고
    # 적으면 1601년이 타임라인에 실린다.
    "sqlite:StateRepository": Profile(
        tables={
            "Package": TableProfile(label_column="PackageFullName"),
            # 이 테이블이 설치 시각을 들고 있고, 무엇이 설치됐는지는
            # Package 에 있다. 풀어 넣지 않으면 "2022-10-24 에 182번이
            # 설치됨" 이 되어 한 줄로는 쓸모가 없다.
            "PackageUser": TableProfile(
                time_column="InstallTime",
                time_encoding="filetime",
                label_column="PackageFullName",
                lookups=(
                    Lookup("Package", "Package", "_PackageID", "PackageFullName"),
                ),
            ),
            "PackageLocation": TableProfile(
                label_column="InstalledLocation",
                path_column="InstalledLocation",
                lookups=(
                    Lookup("Package", "Package", "_PackageID", "PackageFullName"),
                ),
            ),
            "Application": TableProfile(
                label_column="ApplicationUserModelId",
                lookups=(
                    Lookup("Package", "Package", "_PackageID", "PackageFullName"),
                ),
            ),
            "ApplicationExtension": TableProfile(
                label_column="ApplicationUserModelId",
                lookups=(
                    Lookup(
                        "Application",
                        "Application",
                        "_ApplicationID",
                        "ApplicationUserModelId",
                    ),
                ),
            ),
        }
    ),
    # 토스트 알림. 어느 앱이 언제 알림을 등록·발생시켰나.
    #
    # HandlerSettings(2,737행)는 뺀다 — 앱별 설정 키·값이라 증거가 아니고
    # 이 DB 행의 대부분을 차지한다.
    "sqlite:Notifications": Profile(
        tables={
            # 알림이 어느 앱의 것인지는 HandlerId 가 가리키는 다른
            # 테이블에 있다. 풀어 넣지 않으면 "무언가가 15:34 에 알림을
            # 띄웠다"까지밖에 못 쓴다.
            "Notification": TableProfile(
                time_column="ArrivalTime",
                time_encoding="filetime",
                label_column="PrimaryId",
                lookups=(
                    Lookup("HandlerId", "NotificationHandler", "RecordId", "PrimaryId"),
                ),
            ),
            "NotificationHandler": TableProfile(
                time_column="CreatedTime",
                time_encoding="text",
                label_column="PrimaryId",
            ),
            "NotificationData": TableProfile(),
            "WNSPushChannel": TableProfile(
                time_column="CreatedTime", time_encoding="filetime", label_column="Uri"
            ),
            "HandlerAssets": TableProfile(),
        }
    ),
}


class SqliteParser:
    """SQLite DB 하나를 레코드 여러 개로.

    아티팩트마다 인스턴스를 따로 만듭니다. ``artifact`` 가 ``ref`` 접두어와
    출력 파일명을 정하므로, 공유하면 한쪽 레코드가 다른 쪽 접두어로 나가고
    06단계가 그것을 환각으로 집계합니다(SRUM 과 같은 이유).
    """

    def __init__(self, artifact: str) -> None:
        if artifact not in ARTIFACTS:
            known = ", ".join(ARTIFACTS)
            raise ValueError(
                f"알 수 없는 SQLite 아티팩트: {artifact!r} (등록된 값: {known})"
            )
        self.artifact = artifact
        self.profile = PROFILES.get(artifact)
        self.stats = self._new_stats()

    @staticmethod
    def _new_stats() -> "dict[str, int]":
        return {
            "records": 0,
            "parse_errors": 0,
            #: WITHOUT ROWID 라 읽지 못한 테이블 수. 0 이 아니면 이 DB 의
            #: 일부를 못 본 것이고, 보고서의 분석 범위 한계에 실려야 한다.
            "unsupported_tables": 0,
            #: 프로파일이 아는 이름인데 이 파일에 없던 테이블 수.
            #: 빌드가 다르면 생긴다.
            "missing_tables": 0,
            #: 시각 컬럼은 있는데 값을 해석하지 못한 레코드 수.
            "unparsed_timestamps": 0,
            #: 참조를 풀지 못한 자리 수. 0 이 아니면 참조 테이블이
            #: 불완전한 것이고, 그때 원시 정수만 나간다.
            "unresolved_lookups": 0,
        }

    # ------------------------------------------------------------ 진입점

    def parse(self, stream: BinaryIO, scope: Scope) -> "Iterator[dict[str, Any]]":
        self.stats = self._new_stats()

        try:
            db = sqlite.Database(stream)
        except sqlite.SQLiteError as e:
            raise ParseError(f"{self.artifact}: SQLite 파일이 아닙니다 — {e}") from e

        if db.header.wal:
            # 내용은 못 보지만 사실은 남긴다. -wal 에 아직 본 DB 로 넘어가지
            # 않은 변경이 있을 수 있다(docs/limitations.md).
            _log.warning(
                "%s: WAL 모드 DB 입니다. -wal 파일의 미반영 변경은 읽지 않습니다.",
                self.artifact,
            )

        tables = db.tables()
        wanted = self._wanted_tables(tables)
        lookups = self._read_lookups(db, tables, wanted)

        for table in tables:
            if table.name not in wanted:
                continue
            table_profile = wanted[table.name]
            if table.without_rowid:
                self.stats["unsupported_tables"] += 1
                _log.warning(
                    "%s: 테이블 %s 는 WITHOUT ROWID 라 읽지 못합니다 "
                    "(행이 인덱스 b-tree 에 있습니다).",
                    self.artifact,
                    table.name,
                )
                continue
            if table.root_page == 0:
                # 가상 테이블. 저장 공간이 없으므로 읽을 것이 없다.
                continue
            yield from self._rows(db, table, table_profile, scope, lookups)

    # ------------------------------------------------------------ 보조

    def _wanted_tables(
        self, tables: "list[sqlite.TableDef]"
    ) -> "dict[str, TableProfile]":
        """낼 테이블과 그 프로파일.

        프로파일이 없거나 ``tables`` 가 비면 **전부** 냅니다. 아는 DB 인데
        아는 테이블이 하나도 없으면 그 사실을 셉니다 — 빌드가 달라 스키마가
        바뀌었을 때 조용히 0건이 나오지 않게 하려는 것입니다.
        """
        present = {table.name for table in tables}
        if self.profile is None or not self.profile.tables:
            return {name: TableProfile() for name in present}

        missing = [name for name in self.profile.tables if name not in present]
        if missing:
            self.stats["missing_tables"] += len(missing)
            _log.warning(
                "%s: 프로파일이 아는 테이블 %s 가 이 파일에 없습니다 "
                "(빌드가 다를 수 있습니다).",
                self.artifact,
                ", ".join(sorted(missing)),
            )
        return {
            name: profile
            for name, profile in self.profile.tables.items()
            if name in present
        }

    def _read_lookups(
        self,
        db: "sqlite.Database",
        tables: "list[sqlite.TableDef]",
        wanted: "dict[str, TableProfile]",
    ) -> "dict[tuple[str, str, str], dict[Any, Any]]":
        """참조 테이블을 **먼저 통째로** 읽어 사전으로.

        레코드마다 다시 뒤지면 O(n·m) 이 됩니다(SRUM 의 IdMap 과 같은
        이유). 참조 테이블은 실측에서 152행·114행이라 통째로 올려도
        가볍습니다.

        읽지 못해도 파싱은 계속합니다 — 원시 정수만으로도 "같은 것이
        반복해서 나왔다"는 사실은 남습니다. 대신 셉니다.
        """
        needed = {
            (lookup.table, lookup.key_column, lookup.value_column)
            for profile in wanted.values()
            for lookup in profile.lookups
        }
        if not needed:
            return {}

        by_name = {table.name: table for table in tables}
        out: "dict[tuple[str, str, str], dict[Any, Any]]" = {}
        for key in needed:
            name, key_column, value_column = key
            table = by_name.get(name)
            if table is None or not table.readable:
                _log.warning(
                    "%s: 참조 테이블 %s 를 읽을 수 없습니다. %s 가 정수로 나갑니다.",
                    self.artifact,
                    name,
                    value_column,
                )
                out[key] = {}
                continue
            columns = self._column_names(table)
            try:
                key_index = columns.index(key_column)
                value_index = columns.index(value_column)
            except ValueError:
                _log.warning(
                    "%s: 참조 테이블 %s 에 컬럼 %s/%s 가 없습니다 (빌드가 다를 수 있습니다).",
                    self.artifact,
                    name,
                    key_column,
                    value_column,
                )
                out[key] = {}
                continue

            mapping: "dict[Any, Any]" = {}
            try:
                for row in db.rows(table):
                    if key_index >= len(row.values) or value_index >= len(row.values):
                        continue
                    identifier, value = row.values[key_index], row.values[value_index]
                    if identifier is not None and value is not None:
                        mapping[identifier] = _jsonable(value)
            except sqlite.SQLiteError as e:
                self.stats["parse_errors"] += 1
                _log.warning("%s: 참조 테이블 %s 를 다 읽지 못했습니다 — %s", self.artifact, name, e)
            out[key] = mapping
        return out

    def _rows(
        self,
        db: "sqlite.Database",
        table: "sqlite.TableDef",
        profile: TableProfile,
        scope: Scope,
        lookups: "dict[tuple[str, str, str], dict[Any, Any]]",
    ) -> "Iterator[dict[str, Any]]":
        """테이블 하나의 행을 레코드로.

        **행 하나를 못 읽어도 그 행만 건너뜁니다.** 순회 자체가 깨지면
        (b-tree 사이클 등) 그 테이블에서 멈추고 셉니다 — 다음 테이블은
        읽을 수 있습니다.
        """
        columns = self._column_names(table)
        rows = db.rows(table)
        while True:
            try:
                row = next(rows)
            except StopIteration:
                return
            except sqlite.SQLiteError as e:
                self.stats["parse_errors"] += 1
                _log.warning(
                    "%s: 테이블 %s 순회를 중단했습니다 — %s", self.artifact, table.name, e
                )
                return
            record = self._build(table, columns, profile, row, lookups)
            if record is None:
                continue
            if profile.path_column and not scope.matches_path(record.get("path", "")):
                continue
            self.stats["records"] += 1
            yield record

    @staticmethod
    def _column_names(table: "sqlite.TableDef") -> "tuple[str, ...]":
        """이름을 못 뽑은 자리에 자리 이름을 준다.

        지어내는 것이 아니라 **자리를 표시하는 것**입니다 — 값은 디스크에
        있는 그대로이고, 이름만 모른다는 사실이 ``col3`` 이라는 이름에
        드러납니다.
        """
        return tuple(
            name if name is not None else f"col{index}"
            for index, name in enumerate(table.columns)
        )

    def _build(
        self,
        table: "sqlite.TableDef",
        columns: "tuple[str, ...]",
        profile: TableProfile,
        row: "sqlite.Row",
        lookups: "dict[tuple[str, str, str], dict[Any, Any]]",
    ) -> "dict[str, Any] | None":
        fields: "dict[str, Any]" = {
            "sqlite_table": table.name,
            "sqlite_rowid": row.rowid,
        }
        # 컬럼이 뒤에 온다. 이름이 겹치면 **디스크의 값이 이깁니다** —
        # 레코드가 실제로 들고 있던 것을 떨어뜨리지 않기 위해서다.
        for index, value in enumerate(row.values):
            if value is None:
                # null 은 스키마가 막는다. 다른 파서와 같은 규약으로 키를 뺀다.
                continue
            name = columns[index] if index < len(columns) else f"col{index}"
            fields[name] = _jsonable(value)

        for lookup in profile.lookups:
            identifier = fields.get(lookup.column)
            if identifier is None:
                continue
            table_map = lookups.get(
                (lookup.table, lookup.key_column, lookup.value_column), {}
            )
            value = table_map.get(identifier)
            if value is None:
                # 못 풀면 키를 뺀다. 원시 값은 fields 에 그대로 남는다.
                self.stats["unresolved_lookups"] += 1
                continue
            fields[lookup.target] = value

        record: "dict[str, Any]" = {
            "ref": refs.make_ref(self.artifact, row.offset),
            "artifact": self.artifact,
            "record_num": row.offset,
            "offset": f"0x{row.offset:X}",
            "fields": fields,
        }

        if profile.label_column:
            label = fields.get(profile.label_column)
            if label is not None:
                record["name"] = str(label)

        if profile.path_column:
            path = fields.get(profile.path_column)
            if isinstance(path, str) and path:
                record["path"] = path

        if profile.time_column:
            raw = fields.get(profile.time_column)
            timestamp = _decode_time(raw, profile.time_encoding)
            if timestamp is not None:
                record["timestamp"] = timestamp
            elif raw is not None:
                # 원시 값은 fields 에 그대로 남는다. 우리 인코딩 판단이
                # 틀렸을 때 되짚을 수 있어야 한다.
                self.stats["unparsed_timestamps"] += 1

        return record


# =========================================================== 값 변환


def _jsonable(value: Any) -> Any:
    """``json.dumps`` 가 받을 수 있는 형태로.

    BLOB 은 16진 문자열로 바꿉니다 — ``registry.py``·``srum.py`` 와 같은
    규약입니다.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _decode_time(value: Any, encoding: str) -> "str | None":
    """시각 값을 스키마가 받는 ISO ``...Z`` 문자열로. 못 읽으면 ``None``.

    **범위를 벗어나면 채우지 않습니다.** 컬럼이 시각이 아니거나 인코딩
    판단이 틀린 것인데, 1601년으로 적힌 줄이 타임라인에 실리면 없는
    것보다 나쁩니다.
    """
    if value is None:
        return None
    try:
        moment = _to_datetime(value, encoding)
    except (ValueError, OverflowError, OSError, TypeError):
        return None
    if moment is None or not _MIN_YEAR < moment.year < _MAX_YEAR:
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_datetime(value: Any, encoding: str) -> "datetime | None":
    if encoding == "text":
        if not isinstance(value, str):
            return None
        # '2022-10-24 15:32:53' 형태. 시간대 표기가 없고 UTC 다
        # (모듈 docstring 의 대조 참조).
        text = value.strip().replace("T", " ")
        if text.endswith("Z"):
            text = text[:-1].strip()
        return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    if not isinstance(value, (int, float)):
        return None
    if encoding == "filetime":
        return _FILETIME_EPOCH + timedelta(microseconds=value / 10)
    if encoding == "unix_s":
        return _UNIX_EPOCH + timedelta(seconds=value)
    if encoding == "unix_ms":
        return _UNIX_EPOCH + timedelta(milliseconds=value)
    raise ValueError(f"모르는 시각 인코딩: {encoding!r}")
