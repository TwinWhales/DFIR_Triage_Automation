"""SQLite 파일을 **우리 엔진과 ``sqlite3`` 양쪽으로** 읽어 대조한다.

프리패치·RecentFileCache 때는 정답지를 직접 만들어야 했습니다. SQLite 는
사정이 다릅니다 — **표준 라이브러리가 그대로 정답지입니다.** 같은 파일을
``src/stage04_parse/structs/sqlite_page.py`` 의 b-tree 순회와 ``sqlite3``
의 ``SELECT`` 로 각각 읽어 행 단위로 맞춰 봅니다.

## 무엇이 다른 길인가

우리 엔진은 페이지 헤더 → 셀 포인터 배열 → 셀 → 레코드 순으로 **바이트를
직접** 걷습니다. ``sqlite3`` 는 자기 구현으로 b-tree 를 타고 값을
돌려줍니다. 둘이 전부 일치하면 다음 넷이 동시에 지지됩니다.

* 넘침(overflow) 계산 — 틀리면 긴 문자열만 깨지므로 개수는 맞고 값이 어긋난다
* serial type 크기 — ``8``·``9`` 를 1바이트로 잡으면 뒤 컬럼이 밀린다
* ``INTEGER PRIMARY KEY`` rowid 채워 넣기 — 안 하면 그 컬럼만 NULL 이 된다
* 컬럼 이름 추출 — ``PRAGMA table_info`` 와 이름·순서를 맞춘다

**``immutable=1`` 로 엽니다.** WAL 파일을 읽지 않고 본 DB 만 보게 하려는
것입니다. 우리 엔진도 본 DB 만 보므로 같은 조건에서 비교해야 합니다.
증거 파일에 쓰지 않는다는 뜻이기도 합니다.

## 대조하지 않는 것

* ``WITHOUT ROWID`` 테이블 — 엔진이 지원하지 않는다. 건너뛰고 보고한다
* 가상 테이블(``rootpage`` 0) — 저장 공간이 없다. 건너뛴다
* 삭제 레코드 — 양쪽 다 안 본다. 1차 범위 밖이다

사용법::

    # 로컬 파일
    .venv/Scripts/python.exe tools/scan_sqlite.py --db some.db

    # 디스크 이미지 안의 파일 (임시로 뽑아 sqlite3 에 먹인다)
    .venv/Scripts/python.exe tools/scan_sqlite.py \\
        --evidence evidence/0824test.001 --volume 1 \\
        --path "/Users/kisec/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db"

어긋나면 종료 코드 1 입니다.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.stage04_parse.structs import sqlite_page  # noqa: E402

#: 값이 어긋났을 때 화면에 보일 예시 수. 전부 찍으면 터미널이 죽는다.
MAX_EXAMPLES = 5

#: 우리 엔진이 만든 컬럼 이름이 없을 때 쓰는 자리 이름.
PLACEHOLDER = "col{}"


class CheckError(RuntimeError):
    """대조를 시작조차 못 했다."""


def _normalize(value: Any) -> Any:
    """양쪽 표현 차이를 없앤다.

    ``sqlite3`` 는 ``memoryview`` 대신 ``bytes`` 를 주고 우리도 ``bytes``
    를 줍니다. 남는 차이는 부동소수 하나뿐인데, 그것은 같은 8바이트를
    같은 방식으로 푼 것이라 비트까지 같아야 합니다 — 여기서 반올림하지
    않습니다. 반올림하면 우리가 틀린 것을 덮습니다.
    """
    if isinstance(value, memoryview):
        return bytes(value)
    return value


def read_ours(path: Path) -> "tuple[dict[str, dict[int, tuple]], dict[str, Any]]":
    """우리 엔진으로 읽는다. ``({테이블: {rowid: 값들}}, 메모)``."""
    tables: "dict[str, dict[int, tuple]]" = {}
    notes: "dict[str, Any]" = {"skipped": {}, "columns": {}, "offsets": {}, "errors": {}}
    with path.open("rb") as fh:
        db = sqlite_page.Database(fh)
        notes["header"] = {
            "page_size": db.header.page_size,
            "page_count": db.header.page_count,
            "encoding": db.header.encoding_name,
            "wal": db.header.wal,
            "reserved": db.header.reserved_space,
        }
        for table in db.tables():
            if table.root_page == 0:
                notes["skipped"][table.name] = "가상 테이블 (rootpage 0)"
                continue
            if table.without_rowid:
                notes["skipped"][table.name] = "WITHOUT ROWID"
                continue
            notes["columns"][table.name] = [
                name if name is not None else PLACEHOLDER.format(i)
                for i, name in enumerate(table.columns)
            ]
            rows: "dict[int, tuple]" = {}
            offsets: "dict[int, int]" = {}
            try:
                for row in db.rows(table):
                    rows[row.rowid] = tuple(_normalize(v) for v in row.values)
                    offsets[row.rowid] = row.offset
            except sqlite_page.SQLiteError as e:
                notes["errors"][table.name] = str(e)
            tables[table.name] = rows
            notes["offsets"][table.name] = offsets
    return tables, notes


def read_reference(
    path: Path,
) -> "tuple[dict[str, dict[int, tuple]], dict[str, list[str]], dict[str, list[Any]]]":
    """``sqlite3`` 로 읽는다. 정답지. ``(행, 컬럼 이름, 컬럼 기본값)``."""
    uri = f"file:{path.as_posix()}?immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    # ``text_factory`` 는 건드리지 않는다. 기본값이 텍스트를 ``str`` 로,
    # BLOB 을 ``bytes`` 로 돌려주므로 우리 엔진의 표현과 그대로 맞는다.
    # ``bytes`` 로 바꿔 받으면 둘의 구별이 사라져 BLOB 을 텍스트로 오해한다
    # (2026-09-02, 실제로 이 도구가 그렇게 틀렸다).
    #
    # DB 인코딩이 UTF-16 이어도 ``sqlite3`` 는 ``str`` 로 풀어 주므로,
    # 우리가 인코딩을 잘못 잡았다면 문자열이 어긋나 드러난다.
    tables: "dict[str, dict[int, tuple]]" = {}
    columns: "dict[str, list[str]]" = {}
    defaults: "dict[str, list[Any]]" = {}
    try:
        names = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        for name in names:
            info = list(conn.execute(f'PRAGMA table_info("{_quote(name)}")'))
            columns[name] = [c[1] for c in info]
            defaults[name] = [_literal(c[4]) for c in info]
            rows: "dict[int, tuple]" = {}
            try:
                cursor = conn.execute(f'SELECT rowid, * FROM "{_quote(name)}"')
            except sqlite3.DatabaseError:
                # WITHOUT ROWID 테이블은 rowid 가 없다. 우리도 안 읽으므로
                # 여기서도 비운다 — 건너뛴 사실은 ours 쪽 notes 가 말한다.
                continue
            for record in cursor:
                rows[record[0]] = tuple(record[1:])
            tables[name] = rows
    finally:
        conn.close()
    return tables, columns, defaults


def _quote(name: str) -> str:
    return name.replace('"', '""')


#: 해석하지 못한 기본값. ``None`` 과 구별해야 한다 — ``None`` 은 "기본값이
#: NULL 이다"라는 뜻이고 이쪽은 "무슨 값인지 모른다"는 뜻이다.
UNKNOWN_DEFAULT = object()


def _literal(text: "str | None") -> Any:
    """``PRAGMA table_info`` 의 ``dflt_value`` 를 파이썬 값으로.

    **DB 에 들어 있는 SQL 을 실행하지 않습니다.** 증거 파일이 쓴 문자열을
    ``SELECT`` 에 넣어 평가하면 그 파일이 우리 프로세스에서 SQL 을 돌리는
    셈입니다. 흔한 리터럴만 손으로 풀고, 나머지는 모른다고 말합니다.
    """
    if text is None:
        return None
    text = text.strip()
    if text.upper() == "NULL":
        return None
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return UNKNOWN_DEFAULT


def compare(
    ours: "dict[str, dict[int, tuple]]",
    theirs: "dict[str, dict[int, tuple]]",
    our_columns: "dict[str, list[str]]",
    their_columns: "dict[str, list[str]]",
    their_defaults: "dict[str, list[Any]]",
    skipped: "dict[str, str]",
) -> "list[str]":
    """어긋난 것들을 사람이 읽을 줄로 돌려준다. 비면 일치."""
    problems: "list[str]" = []

    only_ours = set(ours) - set(theirs)
    only_theirs = set(theirs) - set(ours) - set(skipped)
    if only_ours:
        problems.append(f"우리만 읽은 테이블: {sorted(only_ours)}")
    if only_theirs:
        problems.append(f"sqlite3 만 읽은 테이블: {sorted(only_theirs)}")

    for name in sorted(set(ours) & set(theirs)):
        mine, reference = ours[name], theirs[name]

        our_cols = our_columns.get(name, [])
        their_cols = their_columns.get(name, [])
        if our_cols != their_cols:
            problems.append(
                f"[{name}] 컬럼 이름이 다르다\n"
                f"    우리:    {our_cols}\n"
                f"    sqlite3: {their_cols}"
            )

        missing = set(reference) - set(mine)
        extra = set(mine) - set(reference)
        if missing:
            problems.append(
                f"[{name}] 우리가 놓친 행 {len(missing)}건 "
                f"(rowid 예: {sorted(missing)[:MAX_EXAMPLES]})"
            )
        if extra:
            problems.append(
                f"[{name}] 우리만 낸 행 {len(extra)}건 "
                f"(rowid 예: {sorted(extra)[:MAX_EXAMPLES]})"
            )

        differing = []
        unresolved: "list[int]" = []
        for rowid in sorted(set(mine) & set(reference)):
            a, b = mine[rowid], reference[rowid]
            if len(a) < len(b):
                # ALTER TABLE ADD COLUMN 으로 컬럼이 늘기 전에 쓰인 레코드는
                # 뒤 컬럼이 **디스크에 아예 없습니다.** sqlite3 는 그 자리를
                # 컬럼의 기본값으로 채워 주고, 우리 엔진은 디스크에 있는
                # 것만 냅니다. 어느 쪽도 틀린 게 아니라 보는 층이 다릅니다.
                #
                # 기본값이 NULL 이라고 가정하면 안 됩니다 — 실물
                # SyncEngineDatabase.db 에 기본값이 '' 인 컬럼이 있었습니다
                # (2026-09-02). PRAGMA 가 말한 기본값으로 채워 비교합니다.
                filler = their_defaults.get(name, [])
                a = a + tuple(
                    filler[i] if i < len(filler) else None for i in range(len(a), len(b))
                )
                if any(v is UNKNOWN_DEFAULT for v in a):
                    unresolved.append(rowid)
                    continue
            if a != b:
                differing.append((rowid, a, b))
        if unresolved:
            problems.append(
                f"[{name}] 컬럼 기본값을 해석하지 못해 비교를 건너뛴 행 "
                f"{len(unresolved)}건 (rowid 예: {unresolved[:MAX_EXAMPLES]})"
            )
        if differing:
            lines = [f"[{name}] 값이 다른 행 {len(differing)}건"]
            for rowid, a, b in differing[:MAX_EXAMPLES]:
                for i, (x, y) in enumerate(zip(a, b)):
                    if x != y:
                        col = our_cols[i] if i < len(our_cols) else f"#{i}"
                        lines.append(
                            f"    rowid={rowid} {col}: 우리={_short(x)} sqlite3={_short(y)}"
                        )
            problems.append("\n".join(lines))

    return problems


def _short(value: Any, limit: int = 60) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _extract(evidence: str, volume: "int | None", inner: str) -> Path:
    """이미지 안의 파일을 임시로 뽑는다. ``sqlite3`` 는 경로를 요구한다."""
    from src.stage04_parse import evidence as ev

    source = ev.open_source(evidence, volume=volume)
    fs = getattr(source, "filesystem", None)
    if fs is None:
        raise CheckError("추출된 폴더 소스에는 --path 를 쓰지 않는다. --db 를 쓴다.")
    entry = fs.path(inner)
    if not entry.exists():
        raise CheckError(f"{inner}: 볼륨에 없다")
    handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    with entry.open("rb") as src:
        while True:
            chunk = src.read(1 << 20)
            if not chunk:
                break
            handle.write(chunk)
    handle.close()
    return Path(handle.name)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", help="로컬 SQLite 파일")
    ap.add_argument("--evidence", help="디스크 이미지 또는 볼륨 폴더")
    ap.add_argument("--volume", type=int, default=None)
    ap.add_argument("--path", help="이미지 안에서의 경로")
    ap.add_argument("--quiet", action="store_true", help="일치하면 아무것도 찍지 않는다")
    args = ap.parse_args()

    temporary: "Path | None" = None
    try:
        if args.db:
            target = Path(args.db)
            label = args.db
        elif args.evidence and args.path:
            temporary = _extract(args.evidence, args.volume, args.path)
            target = temporary
            label = f"{args.evidence}:{args.path}"
        else:
            ap.error("--db 또는 (--evidence 와 --path) 가 필요하다")

        if not target.exists():
            print(f"{target}: 없다", file=sys.stderr)
            return 2

        ours, notes = read_ours(target)
        theirs, their_columns, their_defaults = read_reference(target)
        problems = compare(
            ours,
            theirs,
            notes["columns"],
            their_columns,
            their_defaults,
            notes["skipped"],
        )

        header = notes["header"]
        total = sum(len(rows) for rows in ours.values())
        if not args.quiet or problems:
            print(f"== {label}")
            print(
                f"   페이지 {header['page_size']}B × {header['page_count']} · "
                f"{header['encoding']} · WAL={header['wal']} · "
                f"예약 {header['reserved']}B"
            )
            print(f"   테이블 {len(ours)}개 · 행 {total:,}건")
            for name, reason in sorted(notes["skipped"].items()):
                print(f"   건너뜀: {name} ({reason})")
            for name, message in sorted(notes["errors"].items()):
                print(f"   순회 중단: {name} — {message}")

        if notes["errors"]:
            problems.append(f"순회 중 오류: {sorted(notes['errors'])}")

        if problems:
            print(f"\n어긋남 {len(problems)}건:", file=sys.stderr)
            for line in problems:
                print(f"  {line}", file=sys.stderr)
            return 1

        if not args.quiet:
            print("   sqlite3 와 전수 일치")
        return 0
    except (CheckError, sqlite_page.SQLiteError) as e:
        print(f"대조 실패: {e}", file=sys.stderr)
        return 2
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
