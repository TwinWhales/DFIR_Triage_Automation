"""SQLite 데이터베이스 파일의 온디스크 구조 — 페이지와 셀.

## 왜 ``sqlite3`` 를 쓰지 않나

표준 라이브러리로 열면 세 줄이면 끝납니다. 그런데 이 프로젝트가 파서에게
요구하는 것 중 **둘을 그 경로로는 지킬 수 없습니다.**

1. **``offset`` 은 원본 바이트 위치다** (``parsers/base.py`` 둘째 계율).
   ``sqlite3`` 는 행을 주지만 그 행이 파일 어디에 있었는지는 말하지
   않습니다. 위치가 없으면 ``tools/hexdump_record.py`` 로 되짚을 수 없고,
   되짚을 수 없는 값은 이 도구의 보고서에 실릴 자격이 없습니다.
2. **파서는 바이트 스트림을 받는다.** ``sqlite3`` 는 파일 경로를
   요구합니다. 디스크 이미지 안의 DB 를 열려면 임시 파일로 뽑아야 하는데,
   그러고도 1번은 해결되지 않습니다.

그래서 페이지와 셀을 직접 걷습니다. 대신 ``sqlite3`` 는 **대조 상대**로
씁니다 — 같은 파일을 양쪽으로 읽어 행이 일치하는지 봅니다
(``tools/scan_sqlite.py``). 프리패치 때는 만들어야 했던 정답지가 여기서는
표준 라이브러리로 공짜입니다.

## 이 모듈의 범위

**정상 레코드만 읽습니다.** freeblock·unallocated 영역의 삭제 레코드 복구는
1차 범위에 없습니다 — 정상 경로가 ``sqlite3`` 와 100% 일치하는 것을 먼저
증명해야 복구본이 맞는지도 판정할 수 있습니다 (``docs/limitations.md``).

**WAL 도 읽지 않습니다.** ``-wal`` 파일이 따로 있고 본 DB 에 아직 반영되지
않은 변경이 거기 있을 수 있습니다. 헤더에서 WAL 모드인지는 읽어 두므로
파서가 그 사실을 산출물에 남길 수 있습니다.

## 파일 헤더 (100바이트, 오프셋 0)

==============  ====  ====================================================
오프셋           크기   내용
==============  ====  ====================================================
``0x00``         16   시그니처 ``SQLite format 3`` + 널
``0x10``          2   페이지 크기. 512..32768 의 2의 거듭제곱, **또는 1**
``0x12``          1   쓰기 버전 (1 = 롤백 저널, 2 = WAL)
``0x13``          1   읽기 버전 (1 = 롤백 저널, 2 = WAL)
``0x14``          1   페이지 끝의 예약 바이트 수 (보통 0)
``0x18``          4   파일 변경 카운터
``0x1C``          4   페이지 수 (헤더가 유효할 때만 믿을 수 있다)
``0x38``          4   텍스트 인코딩 (1 = UTF-8, 2 = UTF-16LE, 3 = UTF-16BE)
``0x5C``          4   변경 카운터가 유효한 버전
==============  ====  ====================================================

**페이지 크기 ``1`` 은 65536 을 뜻합니다.** 2바이트에 안 들어가서 그렇게
씁니다. 그대로 1로 읽으면 모든 오프셋 계산이 무너집니다.

**``0x1C`` 의 페이지 수를 무조건 믿지 않습니다.** ``0x18`` 의 변경
카운터와 ``0x5C`` 가 다르면 그 값은 옛날 것입니다(SQLite 3.7.0 이전이 쓴
파일은 아예 0 입니다). 어긋나면 파일 크기로 계산합니다 — 둘 중 실측
가능한 쪽이 파일 크기입니다.

실측에서 둘 다 나왔습니다 (2026-09-02 조사). ``0824test.001`` 의
``wpndatabase.db`` 는 헤더 값이 유효했고, ``windows7_testimage.001`` 의
HP 드라이버 ``.vdf`` 42건은 **페이지 수가 0** 이라 파일 크기로 계산해야
읽힙니다.

## b-tree 페이지

페이지 번호는 **1부터** 셉니다. 페이지 1 은 파일 헤더 100바이트를 앞에
달고 있어 b-tree 헤더가 ``0x64`` 에서 시작합니다. 나머지 페이지는 0 입니다.

==============  ====  ====================================================
오프셋           크기   내용
==============  ====  ====================================================
``+0``            1   페이지 타입 (2/5 = 내부, 10/13 = 리프)
``+1``            2   첫 freeblock 오프셋 (0 = 없음)
``+3``            2   셀 개수
``+5``            2   셀 내용 시작 오프셋 (**0 = 65536**)
``+7``            1   조각난 빈 바이트 수
``+8``            4   가장 오른쪽 자식 페이지 (**내부 페이지만**)
==============  ====  ====================================================

그 뒤가 셀 포인터 배열입니다 — 셀 개수만큼의 2바이트 오프셋이고, 페이지
시작(파일 헤더 포함) 기준입니다.

타입 값 넷은 다음과 같습니다.

=====  ==========================  =========================================
값      뜻                          이 모듈의 처리
=====  ==========================  =========================================
``2``   인덱스 b-tree 내부 페이지    테이블 순회에서 만나면 거부
``5``   테이블 b-tree 내부 페이지    자식 페이지로 내려간다
``10``  인덱스 b-tree 리프 페이지    ``WITHOUT ROWID`` 테이블. 지원하지 않는다
``13``  테이블 b-tree 리프 페이지    여기에 행이 있다
=====  ==========================  =========================================

``WITHOUT ROWID`` 테이블은 행이 인덱스 b-tree 에 들어가고 rowid 가 없어
레코드 번호로 쓸 값이 다릅니다. 조용히 0건을 내지 않고 **거부합니다** —
그런 테이블을 만나면 파서가 그 사실을 ``errors.jsonl`` 에 남깁니다.

## 테이블 리프 셀

::

    varint  페이로드 전체 크기 (P)
    varint  rowid
    바이트   페이로드 (일부만 여기 있을 수 있다)
    4바이트  첫 오버플로 페이지 번호 (넘칠 때만)

**넘침 계산이 이 포맷에서 가장 조용히 틀리는 자리입니다.** 사용 가능
크기 ``U = 페이지 크기 - 예약 바이트`` 라 할 때::

    X = U - 35
    P <= X 이면          전부 이 페이지에 있다
    아니면 M = ((U - 12) * 32 / 255) - 23
           K = M + ((P - M) % (U - 4))
           이 페이지에 있는 양 = K <= X 이면 K, 아니면 M

이 식을 대충 "X 바이트까지"로 줄이면 **대부분의 행은 맞고 큰 행만
틀립니다.** 그래서 작은 픽스처로는 안 잡히고, 실물에서 긴 문자열 하나가
깨져서 드러납니다. ``sqlite3`` 전수 대조를 대조 상대로 삼는 이유가
이것입니다.

오버플로 페이지는 앞 4바이트가 다음 페이지 번호(0 = 끝)이고 나머지
``U - 4`` 바이트가 데이터입니다.

## 레코드 (페이로드 안쪽)

::

    varint  헤더 크기 (자기 자신 포함)
    varint  serial type × 컬럼 수
    바이트   본문 (serial type 순서대로)

============  =========================  ==================================
serial        크기                        값
============  =========================  ==================================
``0``          0                          NULL
``1..6``       1, 2, 3, 4, 6, 8           부호 있는 정수 (빅엔디언)
``7``          8                          IEEE 754 배정밀도
``8`` ``9``    0                          정수 0 / 1 (본문에 없다)
``10`` ``11``  --                         내부 예약. 만나면 거부
``N>=12``      ``(N-12)/2`` (짝수)        BLOB
``N>=13``      ``(N-13)/2`` (홀수)        텍스트 (파일 헤더의 인코딩)
============  =========================  ==================================

**``8``·``9`` 는 본문에 바이트가 없습니다.** 크기를 1로 잡으면 그 뒤
컬럼이 전부 한 칸씩 밀립니다.

## ``INTEGER PRIMARY KEY`` 는 본문에 NULL 로 들어 있다

``INTEGER PRIMARY KEY`` 컬럼은 rowid 의 별명이라 레코드 본문에는 값을
쓰지 않고 NULL 을 씁니다. 진짜 값은 셀 헤더의 rowid 입니다. 이것을
채워 넣지 않으면 **테이블의 ``id`` 컬럼이 전부 NULL 로 나갑니다** —
그럴듯해서 눈으로는 안 걸립니다. ``sqlite3`` 대조가 잡는 대표적인
항목입니다.

## 컬럼 이름은 ``CREATE TABLE`` 문에서 꺼낸다

``sqlite_master`` 의 ``sql`` 컬럼에 원문이 그대로 들어 있습니다. 여기서
컬럼 이름을 뽑는 것은 SQL 파싱이라 완전할 수 없습니다 — 그래서
``tools/scan_sqlite.py`` 가 ``PRAGMA table_info`` 와 대조합니다.
뽑지 못하면 지어내지 않고 ``None`` 을 두고, 파서가 자리 이름을 붙입니다.
이름을 잘못 붙이는 것보다 없는 편이 낫습니다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, BinaryIO, Iterator

__all__ = [
    "MAGIC",
    "HEADER_SIZE",
    "MIN_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "PAGE_INDEX_INTERIOR",
    "PAGE_TABLE_INTERIOR",
    "PAGE_INDEX_LEAF",
    "PAGE_TABLE_LEAF",
    "SQLiteError",
    "NotADatabase",
    "UnsupportedTable",
    "DatabaseHeader",
    "TableDef",
    "Row",
    "Database",
    "read_varint",
    "serial_size",
    "column_names",
]

#: 파일 첫 16바이트. 이것이 아니면 SQLite 가 아니다.
MAGIC = b"SQLite format 3\x00"

#: 파일 헤더 크기. 페이지 1 의 b-tree 헤더는 이 뒤에서 시작한다.
HEADER_SIZE = 100

MIN_PAGE_SIZE = 512
MAX_PAGE_SIZE = 65536

PAGE_INDEX_INTERIOR = 2
PAGE_TABLE_INTERIOR = 5
PAGE_INDEX_LEAF = 10
PAGE_TABLE_LEAF = 13

#: 한 테이블을 순회하며 방문할 페이지 수 상한. 손상된 파일에서 자식
#: 포인터가 서로를 가리키면 영원히 돈다. 방문 집합으로 사이클은 막지만
#: 상한도 함께 둔다 — 페이지 수가 파일 크기와 맞지 않는 경우가 있다.
MAX_PAGES_PER_TABLE = 1 << 22

#: 오버플로 체인 길이 상한. 같은 이유다.
MAX_OVERFLOW_PAGES = 1 << 16

_TEXT_ENCODINGS = {1: "utf-8", 2: "utf-16-le", 3: "utf-16-be"}

#: 컬럼 정의가 아니라 테이블 제약이 시작되는 자리. 여기부터는 컬럼이 아니다.
_TABLE_CONSTRAINTS = frozenset({"constraint", "primary", "unique", "check", "foreign"})


class SQLiteError(ValueError):
    """이 파일 또는 이 레코드를 우리 해석으로 읽을 수 없다."""


class NotADatabase(SQLiteError):
    """SQLite 파일이 아니거나 헤더가 우리 가정과 다르다.

    파일 전체를 거부합니다. 그럴듯한 값을 내는 것보다 낫습니다.
    """


class UnsupportedTable(SQLiteError):
    """실재하지만 이 구현이 읽지 않는 테이블(``WITHOUT ROWID``).

    파일이 아니라 **그 테이블만** 건너뜁니다.
    """


# --------------------------------------------------------------- varint


def read_varint(data: bytes, offset: int = 0) -> "tuple[int, int]":
    """SQLite varint 하나를 읽는다. ``(값, 소비한 바이트 수)``.

    빅엔디언이고 최대 9바이트입니다. 앞 8바이트는 최상위 비트가 "더
    있다"는 표시이고 7비트씩 싣습니다. **9번째 바이트는 8비트 전부를
    싣습니다** — 7비트로 읽으면 큰 값에서만 틀립니다.

    값은 64비트 부호 있는 정수로 해석합니다.
    """
    value = 0
    for i in range(8):
        if offset + i >= len(data):
            raise SQLiteError(f"varint 가 잘렸다 (오프셋 {offset}, {i}바이트 읽음)")
        byte = data[offset + i]
        if byte & 0x80:
            value = (value << 7) | (byte & 0x7F)
            continue
        value = (value << 7) | byte
        return _signed64(value), i + 1
    if offset + 8 >= len(data):
        raise SQLiteError(f"varint 가 잘렸다 (오프셋 {offset}, 9바이트째 없음)")
    value = (value << 8) | data[offset + 8]
    return _signed64(value), 9


def _signed64(value: int) -> int:
    value &= 0xFFFFFFFFFFFFFFFF
    return value - 0x10000000000000000 if value & 0x8000000000000000 else value


def serial_size(serial: int) -> int:
    """serial type 이 본문에서 차지하는 바이트 수."""
    if serial < 0:
        raise SQLiteError(f"serial type 이 음수다: {serial}")
    if serial <= 4:
        return serial
    if serial == 5:
        return 6
    if serial in (6, 7):
        return 8
    if serial in (8, 9):
        return 0
    if serial in (10, 11):
        raise SQLiteError(f"내부 예약 serial type: {serial}")
    return (serial - 12) // 2


def _decode_value(serial: int, body: bytes, encoding: str) -> Any:
    if serial == 0:
        return None
    if serial == 8:
        return 0
    if serial == 9:
        return 1
    if 1 <= serial <= 6:
        return int.from_bytes(body, "big", signed=True)
    if serial == 7:
        return struct.unpack(">d", body)[0]
    if serial % 2 == 0:
        return body
    # 텍스트. 디코드 실패는 값을 버리지 않고 바이트로 남긴다 —
    # 인코딩이 어긋난 것도 증거다.
    try:
        return body.decode(encoding)
    except UnicodeDecodeError:
        return body


# --------------------------------------------------------------- 헤더


@dataclass(frozen=True)
class DatabaseHeader:
    """파일 헤더 100바이트."""

    page_size: int
    write_version: int
    read_version: int
    reserved_space: int
    change_counter: int
    header_page_count: int
    text_encoding: int
    version_valid_for: int
    file_size: int

    @classmethod
    def parse(cls, data: bytes, file_size: int) -> "DatabaseHeader":
        if len(data) < HEADER_SIZE:
            raise NotADatabase(f"헤더가 짧다: {len(data)}바이트 (필요 {HEADER_SIZE})")
        if not data.startswith(MAGIC):
            raise NotADatabase(f"시그니처가 다르다: {data[:16]!r}")

        raw_page_size = struct.unpack(">H", data[16:18])[0]
        page_size = MAX_PAGE_SIZE if raw_page_size == 1 else raw_page_size
        if page_size < MIN_PAGE_SIZE or page_size & (page_size - 1):
            raise NotADatabase(f"페이지 크기가 2의 거듭제곱이 아니다: {page_size}")

        reserved = data[20]
        if reserved > page_size - MIN_PAGE_SIZE:
            raise NotADatabase(f"예약 바이트가 과하다: {reserved} (페이지 {page_size})")

        encoding = struct.unpack(">I", data[56:60])[0]
        if encoding not in _TEXT_ENCODINGS:
            # 0 은 "아직 안 정해졌다" — 테이블이 없는 DB 다. UTF-8 로 본다.
            if encoding != 0:
                raise NotADatabase(f"모르는 텍스트 인코딩: {encoding}")
            encoding = 1

        return cls(
            page_size=page_size,
            write_version=data[18],
            read_version=data[19],
            reserved_space=reserved,
            change_counter=struct.unpack(">I", data[24:28])[0],
            header_page_count=struct.unpack(">I", data[28:32])[0],
            text_encoding=encoding,
            version_valid_for=struct.unpack(">I", data[92:96])[0],
            file_size=file_size,
        )

    @property
    def usable_size(self) -> int:
        """페이지에서 실제로 쓰는 크기. 넘침 계산의 ``U``."""
        return self.page_size - self.reserved_space

    @property
    def encoding_name(self) -> str:
        return _TEXT_ENCODINGS[self.text_encoding]

    @property
    def wal(self) -> bool:
        """WAL 모드인가. ``-wal`` 에 반영 안 된 변경이 있을 수 있다."""
        return self.write_version == 2 or self.read_version == 2

    @property
    def page_count(self) -> int:
        """페이지 수. 헤더 값이 유효할 때만 그것을 쓴다.

        변경 카운터와 ``version_valid_for`` 가 다르면 헤더의 페이지 수는
        옛날 값입니다. 그때는 파일 크기로 계산합니다 — 둘 중 실측
        가능한 쪽이 파일 크기입니다.
        """
        by_size = self.file_size // self.page_size
        if self.header_page_count and self.change_counter == self.version_valid_for:
            return self.header_page_count
        return by_size


# --------------------------------------------------------------- 스키마


@dataclass(frozen=True)
class TableDef:
    """``sqlite_master`` 한 줄에서 온 테이블 정의."""

    name: str
    root_page: int
    sql: str
    columns: "tuple[str | None, ...]"
    rowid_alias: "int | None"
    without_rowid: bool

    @property
    def readable(self) -> bool:
        return self.root_page > 0 and not self.without_rowid


def column_names(sql: str) -> "tuple[tuple[str | None, ...], int | None, bool]":
    """``CREATE TABLE`` 문에서 ``(컬럼 이름들, rowid 별명 인덱스, WITHOUT ROWID)``.

    완전한 SQL 파서가 아닙니다. 컬럼 정의 목록을 최상위 콤마로 자르고
    각 조각의 첫 식별자를 가져옵니다. 따옴표 네 종류와 중첩 괄호를 셉니다.

    뽑지 못한 자리는 ``None`` 입니다 — 지어내지 않습니다.
    """
    sql = _strip_sql_comments(sql)
    body_start = sql.find("(")
    if body_start < 0:
        return (), None, False

    depth = 0
    quote: "str | None" = None
    end = -1
    for i in range(body_start, len(sql)):
        ch = sql[i]
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'`":
            quote = ch
            continue
        if ch == "[":
            quote = "]"
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        return (), None, False

    tail = sql[end:].lower()
    without_rowid = "without" in tail and "rowid" in tail

    parts: "list[str]" = []
    current: "list[str]" = []
    depth = 0
    quote = None
    for ch in sql[body_start + 1 : end]:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'`":
            quote = ch
            current.append(ch)
            continue
        if ch == "[":
            quote = "]"
            current.append(ch)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    if "".join(current).strip():
        parts.append("".join(current))

    names: "list[str | None]" = []
    declared: "list[str]" = []
    constraints: "list[str]" = []
    for part in parts:
        text = part.strip()
        if not text:
            continue
        if constraints or _is_table_constraint(text):
            # 테이블 제약이 시작됐다. 뒤는 전부 컬럼이 아니다.
            constraints.append(text)
            continue
        if _is_virtual_column(text):
            # 계산 컬럼 중 VIRTUAL 은 **레코드에 저장되지 않는다.** 세면
            # 그 뒤 컬럼이 전부 한 칸씩 밀려 값에 남의 이름이 붙는다
            # (2026-09-02, Microsoft.LocalContent.db 의 FullPath).
            continue
        name = _identifier(text)
        names.append(name)
        declared.append(text)

    alias = None if without_rowid else _rowid_alias(names, declared, constraints)
    return tuple(names), alias, without_rowid


def _is_table_constraint(text: str) -> bool:
    """이 조각이 컬럼 정의가 아니라 테이블 제약인가.

    실물에서 ``CONSTRAINT[]``·``UNIQUE([Id])`` 처럼 **키워드와 대괄호
    사이에 공백이 없는** SQL 이 나옵니다(``wpndatabase.db``, 2026-09-02).
    공백으로 잘라 첫 토큰을 보면 ``constraint[]`` 가 되어 걸러지지 않고,
    제약 이름이 컬럼으로 둔갑합니다. 그래서 **앞쪽 영문자만** 떼어 봅니다.

    따옴표로 시작하면 무조건 컬럼입니다 — ``[Check]`` 라는 이름의 컬럼이
    제약으로 오해받지 않아야 합니다.
    """
    if text[0] in "\"'`[":
        return False
    keyword = []
    for ch in text:
        if ch.isalpha():
            keyword.append(ch)
            continue
        break
    return "".join(keyword).lower() in _TABLE_CONSTRAINTS


def _strip_sql_comments(sql: str) -> str:
    """``--`` 와 ``/* */`` 주석을 지운다. 문자열 리터럴 안은 건드리지 않는다.

    실물 ``CREATE TABLE`` 에 주석이 들어 있습니다(OneDrive 의
    ``PathPeriodicRetry``, 2026-09-02). 지우지 않으면 주석 한 줄이 이름
    없는 컬럼 하나로 둔갑하고, 같은 조각에 붙어 있던 ``PRIMARY KEY(...)``
    는 제약으로 인식되지 않습니다.
    """
    out = []
    i = 0
    quote: "str | None" = None
    while i < len(sql):
        ch = sql[i]
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "[":
            quote = "]"
            out.append(ch)
            i += 1
            continue
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            if end < 0:
                break
            out.append("\n")
            i = end + 1
            continue
        if sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            out.append(" ")
            i = len(sql) if end < 0 else end + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _is_virtual_column(text: str) -> bool:
    """``GENERATED ALWAYS AS (...) VIRTUAL`` 인가 — 저장되지 않는 컬럼인가.

    ``STORED`` 는 레코드에 실제로 들어 있으므로 **세야 합니다.** 기본값이
    ``VIRTUAL`` 이라 ``AS (...)`` 만 쓰고 아무 말이 없으면 저장되지
    않습니다.

    ``AS`` 는 괄호 밖에서만 봅니다 — ``CHECK(x AS ...)`` 같은 표현식 안의
    단어를 집지 않으려는 것입니다.
    """
    rest = _strip_parens(text[len(_identifier_span(text)) :]).lower().split()
    if "as" not in rest:
        return False
    return "stored" not in rest


def _strip_parens(text: str) -> str:
    """괄호 안을 지운다. 최상위 토큰만 보려는 용도."""
    out = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def _rowid_alias(
    names: "list[str | None]", declared: "list[str]", constraints: "list[str]"
) -> "int | None":
    """``INTEGER PRIMARY KEY`` 컬럼의 인덱스. 없으면 ``None``.

    두 가지 형태를 봅니다.

    * 컬럼 정의에 붙은 것 — ``[Order] INTEGER NOT NULL PRIMARY KEY``
    * 테이블 제약으로 뺀 것 — ``PRIMARY KEY([Id])`` 이고 그 컬럼이 INTEGER

    **타입이 정확히 ``INTEGER`` 여야 합니다.** ``INT``·``INT64`` 는 rowid
    별명이 아니라 보통 컬럼이고, 그 자리에 rowid 를 채워 넣으면 없는 값을
    지어내는 것이 됩니다. 실물 ``wpndatabase.db`` 에 ``INT64`` 컬럼이
    여럿 있습니다.

    ``PRIMARY KEY`` 는 괄호 밖에서만 찾습니다 — ``REFERENCES tbl(pk)``
    같은 절 안의 단어를 집지 않으려는 것입니다.
    """
    for i, text in enumerate(declared):
        rest = _strip_parens(text[len(_identifier_span(text)) :]).lower()
        if _first_type(rest) != "integer":
            continue
        if "primary key" in " ".join(rest.split()):
            return i

    for text in constraints:
        # ``PRIMARY KEY(...)`` 와 ``CONSTRAINT <이름> PRIMARY KEY(...)`` 둘 다.
        if "primary key" not in " ".join(_strip_parens(text).lower().split()):
            continue
        inner = _inner_columns(text)
        if len(inner) != 1:
            continue
        try:
            index = names.index(inner[0])
        except ValueError:
            continue
        rest = _strip_parens(
            declared[index][len(_identifier_span(declared[index])) :]
        ).lower()
        if _first_type(rest) == "integer":
            return index
    return None


def _identifier_span(text: str) -> str:
    """조각의 앞쪽에서 식별자가 차지한 원문 그대로의 조각."""
    text = text.strip()
    closing = {'"': '"', "'": "'", "`": "`", "[": "]"}
    if text and text[0] in closing:
        end = text.find(closing[text[0]], 1)
        return text[: end + 1] if end >= 0 else text
    for i, ch in enumerate(text):
        if ch.isalnum() or ch in "_$":
            continue
        return text[:i]
    return text


def _first_type(rest: str) -> str:
    """식별자 뒤 첫 토큰(선언 타입). 없으면 빈 문자열."""
    tokens = rest.split()
    return tokens[0] if tokens else ""


def _inner_columns(text: str) -> "list[str]":
    """``PRIMARY KEY([a], [b])`` 의 괄호 안 이름들."""
    start = text.find("(")
    if start < 0:
        return []
    depth = 0
    end = -1
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        return []
    found = []
    for piece in text[start + 1 : end].split(","):
        name = _identifier(piece)
        if name is not None:
            found.append(name)
    return found


def _identifier(text: str) -> "str | None":
    """컬럼 정의 조각의 첫 식별자."""
    text = text.strip()
    if not text:
        return None
    closing = {'"': '"', "'": "'", "`": "`", "[": "]"}
    if text[0] in closing:
        close = closing[text[0]]
        end = text.find(close, 1)
        if end < 0:
            return None
        return text[1:end]
    token = []
    for ch in text:
        if ch.isalnum() or ch in "_$":
            token.append(ch)
            continue
        break
    return "".join(token) or None


# --------------------------------------------------------------- 행


@dataclass(frozen=True)
class Row:
    """테이블 리프 셀 하나.

    ``offset`` 은 **파일 시작 기준 셀의 절대 바이트 위치**입니다. 이 값이
    ``parsed_record.offset`` 이자 ``ref`` 의 레코드 번호가 됩니다 — 파일
    안에서 유일하고, ``hexdump_record.py`` 가 그대로 내려가 대조합니다.
    """

    page_number: int
    offset: int
    rowid: int
    values: "tuple[Any, ...]"
    overflow_pages: int


# --------------------------------------------------------------- DB


class Database:
    """열린 SQLite 파일 하나. 페이지를 필요할 때 읽는다.

    스트림은 ``seek`` 가능해야 합니다. 파일을 통째로 메모리에 올리지
    않습니다 — 실물에 수MB 짜리가 있고, 디스크 이미지 안에서는
    ``RunlistStream`` 위에서 도는 경우가 있습니다.
    """

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        stream.seek(0, 2)
        file_size = stream.tell()
        stream.seek(0)
        head = stream.read(HEADER_SIZE)
        self.header = DatabaseHeader.parse(head, file_size)

    # -------------------------------------------------------- 페이지

    def read_page(self, number: int) -> bytes:
        """페이지 하나(1부터)."""
        if number < 1:
            raise SQLiteError(f"페이지 번호가 1보다 작다: {number}")
        offset = (number - 1) * self.header.page_size
        if offset >= self.header.file_size:
            raise SQLiteError(
                f"페이지 {number} 가 파일 밖이다 "
                f"(오프셋 {offset}, 파일 {self.header.file_size}바이트)"
            )
        self.stream.seek(offset)
        data = self.stream.read(self.header.page_size)
        if len(data) < self.header.page_size:
            raise SQLiteError(
                f"페이지 {number} 가 잘렸다: {len(data)}바이트 "
                f"(필요 {self.header.page_size})"
            )
        return data

    def _cell_offsets(self, page: bytes, number: int) -> "tuple[int, list[int]]":
        """``(페이지 타입, 셀 오프셋 목록)``. 오프셋은 페이지 기준이다."""
        base = HEADER_SIZE if number == 1 else 0
        page_type = page[base]
        if page_type not in (
            PAGE_INDEX_INTERIOR,
            PAGE_TABLE_INTERIOR,
            PAGE_INDEX_LEAF,
            PAGE_TABLE_LEAF,
        ):
            raise SQLiteError(f"페이지 {number}: 모르는 페이지 타입 {page_type}")
        count = struct.unpack(">H", page[base + 3 : base + 5])[0]
        interior = page_type in (PAGE_INDEX_INTERIOR, PAGE_TABLE_INTERIOR)
        array = base + (12 if interior else 8)
        offsets = []
        for i in range(count):
            at = array + i * 2
            if at + 2 > len(page):
                raise SQLiteError(f"페이지 {number}: 셀 포인터 배열이 페이지 밖이다")
            cell = struct.unpack(">H", page[at : at + 2])[0]
            if not base < cell < len(page):
                raise SQLiteError(f"페이지 {number}: 셀 포인터가 페이지 밖이다 ({cell})")
            offsets.append(cell)
        return page_type, offsets

    @staticmethod
    def _right_child(page: bytes, number: int) -> int:
        base = HEADER_SIZE if number == 1 else 0
        return struct.unpack(">I", page[base + 8 : base + 12])[0]

    # -------------------------------------------------------- 스키마

    def tables(self) -> "list[TableDef]":
        """``sqlite_master``(페이지 1)에서 테이블 정의를 읽는다.

        인덱스·뷰·트리거는 뺍니다 — 행이 없거나 우리가 읽을 대상이
        아닙니다. ``sqlite_master`` 자체는 목록에 넣지 않습니다.
        """
        found: "list[TableDef]" = []
        for row in self._walk(1, seen=set()):
            # sqlite_master: type, name, tbl_name, rootpage, sql
            if len(row.values) < 5:
                continue
            kind, name, _tbl, root, sql = row.values[:5]
            if kind != "table" or not isinstance(name, str):
                continue
            if not isinstance(root, int):
                continue
            text = sql if isinstance(sql, str) else ""
            names, alias, without_rowid = column_names(text)
            found.append(
                TableDef(
                    name=name,
                    root_page=root,
                    sql=text,
                    columns=names,
                    rowid_alias=alias,
                    without_rowid=without_rowid,
                )
            )
        return found

    # -------------------------------------------------------- 순회

    def rows(self, table: TableDef) -> Iterator[Row]:
        """테이블 하나의 행 전부. b-tree 를 왼쪽부터 걷는다."""
        if table.without_rowid:
            raise UnsupportedTable(
                f"{table.name}: WITHOUT ROWID 테이블은 지원하지 않는다 "
                "(행이 인덱스 b-tree 에 있고 rowid 가 없다)"
            )
        if table.root_page <= 0:
            return
        alias = table.rowid_alias
        for row in self._walk(table.root_page, seen=set()):
            if alias is not None and alias < len(row.values) and row.values[alias] is None:
                values = list(row.values)
                values[alias] = row.rowid
                yield Row(
                    page_number=row.page_number,
                    offset=row.offset,
                    rowid=row.rowid,
                    values=tuple(values),
                    overflow_pages=row.overflow_pages,
                )
                continue
            yield row

    def _walk(self, page_number: int, seen: "set[int]") -> Iterator[Row]:
        """테이블 b-tree 를 깊이 우선으로 걷는다.

        재귀 대신 스택입니다. 깊은 b-tree 에서 파이썬 재귀 한도에 걸리지
        않게 하려는 것이고, 방문한 페이지를 기억해 **사이클에서 영원히
        돌지 않습니다** — 손상된 파일에서 실제로 일어납니다.
        """
        stack = [page_number]
        while stack:
            number = stack.pop()
            if number in seen:
                raise SQLiteError(f"페이지 {number} 가 두 번 나온다 (b-tree 사이클)")
            seen.add(number)
            if len(seen) > MAX_PAGES_PER_TABLE:
                raise SQLiteError("한 테이블에서 방문한 페이지가 상한을 넘었다")

            page = self.read_page(number)
            page_type, offsets = self._cell_offsets(page, number)

            if page_type == PAGE_TABLE_INTERIOR:
                children = []
                for cell in offsets:
                    children.append(struct.unpack(">I", page[cell : cell + 4])[0])
                right = self._right_child(page, number)
                if right:
                    children.append(right)
                # 왼쪽부터 나오도록 뒤집어 넣는다 — rowid 순서가 유지되면
                # 같은 이미지에서 산출물 줄 순서가 실행마다 같다.
                stack.extend(reversed(children))
                continue

            if page_type != PAGE_TABLE_LEAF:
                raise SQLiteError(
                    f"페이지 {number}: 테이블 b-tree 에 인덱스 페이지가 있다 "
                    f"(타입 {page_type})"
                )

            for cell in offsets:
                yield self._leaf_cell(page, number, cell)

    def _leaf_cell(self, page: bytes, number: int, cell: int) -> Row:
        payload_size, n1 = read_varint(page, cell)
        rowid, n2 = read_varint(page, cell + n1)
        start = cell + n1 + n2

        usable = self.header.usable_size
        max_local = usable - 35
        if payload_size <= max_local:
            local_size, overflow = payload_size, 0
        else:
            min_local = ((usable - 12) * 32 // 255) - 23
            k = min_local + ((payload_size - min_local) % (usable - 4))
            local_size = k if k <= max_local else min_local
            if start + local_size + 4 > len(page):
                raise SQLiteError(f"페이지 {number} 셀 {cell}: 넘침 포인터가 페이지 밖이다")
            overflow = struct.unpack(">I", page[start + local_size : start + local_size + 4])[0]

        if start + local_size > len(page):
            raise SQLiteError(f"페이지 {number} 셀 {cell}: 페이로드가 페이지 밖이다")

        payload = page[start : start + local_size]
        overflow_pages = 0
        next_page = overflow
        while len(payload) < payload_size:
            if next_page == 0:
                raise SQLiteError(
                    f"페이지 {number} 셀 {cell}: 넘침 체인이 일찍 끝났다 "
                    f"({len(payload)}/{payload_size}바이트)"
                )
            overflow_pages += 1
            if overflow_pages > MAX_OVERFLOW_PAGES:
                raise SQLiteError(f"페이지 {number} 셀 {cell}: 넘침 체인이 너무 길다")
            chunk = self.read_page(next_page)
            next_page = struct.unpack(">I", chunk[:4])[0]
            payload += chunk[4:usable]
        payload = payload[:payload_size]

        return Row(
            page_number=number,
            offset=(number - 1) * self.header.page_size + cell,
            rowid=rowid,
            values=self._record(payload),
            overflow_pages=overflow_pages,
        )

    def _record(self, payload: bytes) -> "tuple[Any, ...]":
        header_size, n = read_varint(payload, 0)
        if not 0 < header_size <= len(payload):
            raise SQLiteError(f"레코드 헤더 크기가 이상하다: {header_size}")
        serials = []
        at = n
        while at < header_size:
            serial, k = read_varint(payload, at)
            serials.append(serial)
            at += k
        if at != header_size:
            raise SQLiteError(f"레코드 헤더가 경계에서 끝나지 않았다 ({at} != {header_size})")

        encoding = self.header.encoding_name
        values: "list[Any]" = []
        body = header_size
        for serial in serials:
            size = serial_size(serial)
            if body + size > len(payload):
                raise SQLiteError(
                    f"레코드 본문이 잘렸다 (serial {serial}, {body}+{size} > {len(payload)})"
                )
            values.append(_decode_value(serial, payload[body : body + size], encoding))
            body += size
        return tuple(values)
