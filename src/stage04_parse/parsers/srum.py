"""SRUM(`SRUDB.dat`) 파서 — 앱별 자원·네트워크 사용량.

`Windows\\System32\\sru\\SRUDB.dat`. Windows 8부터 있는 ESE 데이터베이스로,
**어떤 실행 파일이 언제 네트워크로 얼마나 보냈는가**를 시간당 한 줄씩
적어 둡니다. 실행 흔적(프리패치·Amcache)이 "돌았다"까지만 말하는 데
비해, 이쪽은 **밖으로 나간 바이트 수**를 말합니다 — T1041·T1048(유출)에
지금 이 도구가 가진 것 중 가장 직접적인 증거입니다.

## 왜 라이브러리를 쓰나

`work-guide.md` 3.1의 방침을 그대로 따릅니다 — 파일시스템 계층은 직접
구현해 오프셋을 보존하고, **로그 계층은 검증된 라이브러리를 씁니다.**
ESE는 B-tree에 long value와 다중 페이지 레코드가 얹힌 포맷이라 evtx의
바이너리 XML과 같은 부류입니다. `dissect.esedb`를 씁니다 —
`dissect.target`이 이미 의존성에 있어 **새 벤더를 들이는 것이 아닙니다.**

라이브러리를 써도 ``offset``은 포기하지 않았습니다. 아래 참조.

## 한 테이블이 한 아티팩트다

SRUM은 공급자마다 테이블을 따로 두고, 테이블 이름이 공급자 GUID입니다.
**아티팩트를 테이블마다 나눕니다**(evtx가 채널마다 나눈 것과 같습니다).

이유는 ``ref``입니다. 레코드 번호로 쓸 값은 ``AutoIncId`` 뿐인데 그것은
**테이블 안에서만** 유일합니다. 한 아티팩트로 묶으면 서로 다른 테이블의
1번이 같은 ``ref``가 되어 05·06단계가 통째로 섭니다.

## GUID로 찾고, 컬럼으로 확인한다

테이블은 GUID로 찾되 **기대한 컬럼이 실제로 있는지 확인하고 시작합니다**
(`REQUIRED_COLUMNS`). GUID만 믿으면 다른 빌드에서 컬럼 구성이 달라졌을 때
값이 조용히 비어 나갑니다. 없으면 ``ParseError``로 소리를 냅니다.

## 시각이 두 종류다 (실측)

``TimeStamp``는 FILETIME이 **아닙니다.** ESE의 ``JET_coltyp.DateTime``,
즉 OLE Automation date(float64)입니다. FILETIME으로 읽으면
``OverflowError``가 나거나 엉뚱한 연도가 됩니다.

같은 DB의 ``ConnectStartTime``은 **진짜 FILETIME**입니다. 둘이 섞여
있습니다. 실측에서 이 둘이 서로를 지지했습니다 — 같은 레코드 무리에서
OLE로 읽은 ``TimeStamp``가 2022-10-24 15:30:00, FILETIME으로 읽은
``ConnectStartTime``이 2022-10-24 15:29:48로 **12초 차이**였습니다.
독립적인 두 인코딩이 같은 시각을 가리키므로 해석이 맞습니다
(`docs/artifact-notes.md`).

## 앱 이름은 다른 테이블에 있다

사용량 테이블의 ``AppId``·``UserId``는 정수이고, 실제 문자열은
``SruDbIdMapTable``에 있습니다. 그것을 먼저 통째로 읽어 사전을 만든 뒤
레코드마다 풀어 넣습니다(``fields.AppName``·``fields.UserSid``).

풀리지 않으면 **키를 뺍니다.** 정수 ``AppId``는 원본 그대로 남으므로
"풀지 못했다"가 산출물에 드러납니다.

## 앱 경로는 장치 이름이다 — 바꾸지 않는다

``IdType`` 0의 값은 ``\\Device\\HarddiskVolume4\\Windows\\System32\\smss.exe``
형태입니다. 프리패치와 같은 부류인데, **프리패치와 달리 바꿀 근거가
없습니다** — SRUM에는 볼륨 표가 없어서 ``HarddiskVolume4``가 우리가 분석
중인 볼륨인지 알 방법이 없습니다.

그래서 그대로 둡니다. 틀린 드라이브 문자를 단 경로가 보고서에 실리는
것보다 매칭이 안 되는 편이 낫습니다(프리패치 파서와 같은 판단).
**대가는 06단계입니다** — 모델이 ``C:\\Windows\\...``라고 쓰면 그 문장은
기각됩니다. `docs/limitations.md`에 적혀 있습니다.
"""

from __future__ import annotations

import logging
import struct
from typing import Any, BinaryIO, Iterator

from ...common import refs
from .base import ParseError, Scope

__all__ = [
    "SrumParser",
    "ARTIFACTS",
    "TABLE_OF",
    "REQUIRED_COLUMNS",
    "ID_MAP_TABLE",
    "APP_ID_TYPES",
    "USER_ID_TYPE",
]

_log = logging.getLogger(__name__)

#: 아티팩트 이름 → 공급자 테이블 GUID.
#:
#: 이름은 컬럼이 말하는 것을 그대로 옮겼습니다. 실측
#: (``0824test.001``, Win10 15063)에서 확인한 컬럼 구성입니다.
#:
#: 공급자가 이 셋만 있는 것은 아닙니다. 에너지 사용량과 푸시 알림
#: 테이블도 있으나 조사 가치가 낮아 **일부러 뺐습니다** — 늘리려면
#: 여기와 ``REQUIRED_COLUMNS``, ``refs.py``, 스키마 둘, 등록소,
#: ``OUTPUT_FILENAMES``, 카탈로그를 함께 고칩니다
#: (`.claude/skills/add-parser/SKILL.md`).
TABLE_OF: dict[str, str] = {
    "srum:NetworkUsage": "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
    "srum:AppResourceUsage": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
    "srum:NetworkConnectivity": "{DD6636C4-8929-4683-974E-22C046A43763}",
}

ARTIFACTS: tuple[str, ...] = tuple(TABLE_OF)

#: 테이블이 우리가 아는 그 테이블인지 확인할 컬럼.
#:
#: **GUID만 믿지 않습니다.** 빌드가 다르면 컬럼이 바뀔 수 있고, 그때
#: 값이 조용히 비어 나가는 것이 최악입니다. 없으면 ``ParseError``입니다.
#:
#: 전부를 적지 않고 **그 테이블을 그 테이블이게 하는 것만** 적습니다.
#: 넓게 적으면 마이너 빌드 차이로 읽을 수 있는 것도 못 읽습니다.
REQUIRED_COLUMNS: dict[str, tuple[str, ...]] = {
    "srum:NetworkUsage": ("AutoIncId", "TimeStamp", "AppId", "BytesSent", "BytesRecvd"),
    "srum:AppResourceUsage": ("AutoIncId", "TimeStamp", "AppId", "ForegroundCycleTime"),
    "srum:NetworkConnectivity": ("AutoIncId", "TimeStamp", "AppId", "ConnectStartTime"),
}

#: ``AppId``·``UserId``의 문자열이 사는 곳.
ID_MAP_TABLE = "SruDbIdMapTable"

#: ``SruDbIdMapTable.IdType`` 중 앱을 가리키는 값. 실측 분포는
#: 0=실행 파일 경로 또는 의사 이름(126건), 1=서비스 이름(18건),
#: 2=패키지·서비스 식별자(114건), 3=사용자 SID(107건)였습니다.
#:
#: 셋을 한 사전에 합칩니다 — ``AppId``는 이 셋 중 어느 것이든 가리킬 수
#: 있고, ``IdIndex``는 타입과 무관하게 유일합니다(실측에서 겹침 0건).
APP_ID_TYPES: frozenset[int] = frozenset({0, 1, 2})

#: 사용자 SID를 가리키는 ``IdType``. 값이 UTF-16 문자열이 아니라
#: **바이너리 SID**라 다른 경로로 푼다.
USER_ID_TYPE = 3

#: ``AppId``/``UserId``를 푼 값이 들어갈 필드 이름.
APP_NAME_FIELD = "AppName"
USER_SID_FIELD = "UserSid"

#: 페이지 번호를 파일 오프셋으로 바꾸는 보정.
#:
#: ESE의 논리 페이지 ``n``은 파일의 ``(n + 1) * page_size`` 에 있습니다.
#: 앞의 두 페이지가 DB 헤더와 그 그림자이기 때문입니다. **실측으로
#: 확인했습니다** — 76개 레코드 전부에서 그 위치의 바이트가 라이브러리가
#: 들고 있는 페이지 버퍼와 정확히 일치했고, 보정 없는 ``n * page_size``는
#: 어긋났습니다(`docs/artifact-notes.md`).
PAGE_NUMBER_BIAS = 1


class SrumParser:
    """SRUM 공급자 테이블 하나를 레코드 여러 개로.

    아티팩트마다 인스턴스를 따로 만듭니다. ``artifact``가 ``ref`` 접두어와
    출력 파일명을 정하므로, 공유하면 한쪽 레코드가 다른 쪽 접두어로 나가고
    06단계가 그것을 환각으로 집계합니다.
    """

    def __init__(self, artifact: str) -> None:
        if artifact not in TABLE_OF:
            known = ", ".join(sorted(TABLE_OF))
            raise ValueError(
                f"알 수 없는 SRUM 아티팩트: {artifact!r} (등록된 값: {known})"
            )
        self.artifact = artifact
        self.stats = self._new_stats()

    @staticmethod
    def _new_stats() -> dict[str, int]:
        return {
            "records": 0,
            "parse_errors": 0,
            # AppId 를 문자열로 풀지 못한 레코드. 0 이 아니면 IdMap 이
            # 불완전한 것이고, 그때 AppName 없이 정수만 나간다.
            "unresolved_app_id": 0,
            "unresolved_user_id": 0,
            "out_of_scope": 0,
        }

    # ------------------------------------------------------------ 진입점

    def parse(self, stream: BinaryIO, scope: Scope) -> Iterator[dict[str, Any]]:
        self.stats = self._new_stats()

        try:
            from dissect.esedb import EseDB
        except ImportError as e:  # pragma: no cover - 의존성이 빠진 환경
            raise ParseError(
                "dissect.esedb 가 없습니다. requirements.txt 를 설치하십시오 — "
                f"{e}"
            ) from e

        db = EseDB(stream)
        table = self._open_table(db)
        columns = tuple(c.name for c in table.columns)
        self._check_columns(columns)

        identities = self._read_id_map(db)
        page_size = db.page_size

        for record in table.records():
            try:
                built = self._build(record, columns, identities, page_size)
            except ParseError as e:
                self.stats["parse_errors"] += 1
                _log.warning("%s: 레코드 하나를 읽지 못했습니다 — %s", self.artifact, e)
                continue
            if built is None:
                continue
            self.stats["records"] += 1
            yield built

    # ------------------------------------------------------------ 보조

    def _open_table(self, db: Any) -> Any:
        name = TABLE_OF[self.artifact]
        try:
            return db.table(name)
        except Exception as e:  # noqa: BLE001 - 라이브러리가 무엇을 던질지 모른다
            raise ParseError(
                f"{self.artifact}: 공급자 테이블 {name} 을 열지 못했습니다. "
                "이 빌드의 SRUM 이 그 공급자를 안 쓰거나 DB 가 손상됐습니다 — "
                f"{e}"
            ) from e

    def _check_columns(self, columns: tuple[str, ...]) -> None:
        """기대한 컬럼이 있는가. 없으면 소리를 낸다.

        조용히 비어 나가는 것이 최악입니다 — 파싱은 성공했다고 보고되는데
        보고서에는 아무 근거도 안 실립니다.
        """
        missing = [c for c in REQUIRED_COLUMNS[self.artifact] if c not in columns]
        if missing:
            raise ParseError(
                f"{self.artifact}: 컬럼 {', '.join(missing)} 이 없습니다. "
                f"이 빌드의 테이블 구성이 다릅니다 (실제 컬럼: {', '.join(columns)})"
            )

    def _read_id_map(self, db: Any) -> dict[int, tuple[str, Any]]:
        """``SruDbIdMapTable``을 ``IdIndex`` → (종류, 값) 사전으로.

        **먼저 통째로 읽습니다.** 레코드마다 다시 뒤지면 O(n·m)이 되고,
        SRUM 은 사용량 레코드가 수만 건까지 갑니다.

        이 표가 없어도 파싱은 계속합니다 — ``AppId`` 정수만으로도 "무언가
        같은 것이 반복해서 통신했다"는 사실은 남습니다. 대신 셉니다.
        """
        out: dict[int, tuple[str, Any]] = {}
        try:
            table = db.table(ID_MAP_TABLE)
        except Exception as e:  # noqa: BLE001
            _log.warning(
                "%s: %s 를 열지 못했습니다. AppId 가 정수로 나갑니다 — %s",
                self.artifact,
                ID_MAP_TABLE,
                e,
            )
            return out

        for row in table.records():
            try:
                id_type = row.get("IdType")
                index = row.get("IdIndex")
                blob = row.get("IdBlob")
            except Exception as e:  # noqa: BLE001
                self.stats["parse_errors"] += 1
                _log.warning("%s: %s 의 행 하나를 읽지 못했습니다 — %s", self.artifact, ID_MAP_TABLE, e)
                continue
            if index is None or blob is None:
                continue
            if id_type in APP_ID_TYPES:
                name = _utf16(blob)
                if name:
                    out[index] = (APP_NAME_FIELD, name)
            elif id_type == USER_ID_TYPE:
                sid = _sid(blob)
                if sid:
                    out[index] = (USER_SID_FIELD, sid)
        return out

    def _build(
        self,
        record: Any,
        columns: tuple[str, ...],
        identities: dict[int, tuple[str, Any]],
        page_size: int,
    ) -> "dict[str, Any] | None":
        fields: dict[str, Any] = {}
        for name in columns:
            try:
                value = record.get(name)
            except Exception as e:  # noqa: BLE001 - 손상 셀에서 무엇이 나올지 모른다
                raise ParseError(f"컬럼 {name} — {e}") from e
            if value is None:
                # null 은 스키마가 막는다. 다른 파서와 같은 규약으로 키를 뺀다.
                continue
            fields[name] = _jsonable(value)

        auto_inc = fields.get("AutoIncId")
        if not isinstance(auto_inc, int):
            raise ParseError("AutoIncId 가 정수가 아닙니다 — ref 를 만들 수 없습니다")

        self._resolve(fields, "AppId", APP_NAME_FIELD, identities, "unresolved_app_id")
        self._resolve(fields, "UserId", USER_SID_FIELD, identities, "unresolved_user_id")

        record_out: dict[str, Any] = {
            "ref": refs.make_ref(self.artifact, auto_inc),
            "artifact": self.artifact,
            "record_num": auto_inc,
            "offset": f"0x{_file_offset(record, page_size):X}",
            "name": str(fields.get(APP_NAME_FIELD) or fields.get("AppId", "")),
            "fields": fields,
        }

        # null 은 스키마가 막는다. 읽지 못하면 키를 빼고 낸다 — 다른
        # 파서와 같은 규약이다. 원시 TimeStamp 는 fields 에 그대로 남으므로
        # 우리 해석이 틀렸을 때 되짚을 수 있다.
        timestamp = _ole_timestamp(fields.get("TimeStamp"))
        if timestamp is not None:
            record_out["timestamp"] = timestamp
        return record_out

    def _resolve(
        self,
        fields: dict[str, Any],
        source: str,
        target: str,
        identities: dict[int, tuple[str, Any]],
        counter: str,
    ) -> None:
        """``AppId`` 정수를 문자열로. 못 풀면 **키를 빼고** 센다."""
        index = fields.get(source)
        if not isinstance(index, int):
            return
        found = identities.get(index)
        if found is None or found[0] != target:
            self.stats[counter] += 1
            return
        fields[target] = found[1]


# =========================================================== 값 변환


def _file_offset(record: Any, page_size: int) -> int:
    """레코드가 실린 ESE 페이지의 파일 내 바이트 위치.

    라이브러리를 써도 ``offset``은 포기하지 않습니다(``parsers/base.py``의
    세 가지 중 둘째). **페이지 단위입니다** — ESE 레코드는 페이지 안에서
    태그로 가리켜지고 압축된 키 접두어를 공유해서, 레코드 하나의 시작
    바이트를 파일 좌표로 말하는 것이 evtx 만큼 깔끔하지 않습니다. 페이지
    위치까지가 우리가 정직하게 말할 수 있는 범위입니다.

    되짚을 수 있는가가 기준인데, 4KB 페이지 하나와 ``AutoIncId``가 있으면
    그 레코드에 도달합니다.
    """
    try:
        page = record._node.tag.page
        return (page.num + PAGE_NUMBER_BIAS) * page_size
    except AttributeError:
        # 라이브러리 내부 구조가 바뀌면 여기서 드러난다. 0 으로 조용히
        # 내보내면 "파일 맨 앞"이라는 거짓말이 산출물에 실린다.
        raise ParseError(
            "레코드가 실린 페이지를 알 수 없습니다 — dissect.esedb 의 내부 "
            "구조가 바뀌었을 수 있습니다 (record._node.tag.page)"
        ) from None


def _ole_timestamp(value: Any) -> "str | None":
    """OLE Automation date → 이 프로젝트의 표기. 읽을 수 없으면 ``None``.

    ``TimeStamp`` 는 FILETIME 이 **아닙니다** — 모듈 docstring 참조.

    **``float(value)`` 로는 안 됩니다.** ``dissect.esedb`` 는
    ``JET_coltyp.DateTime`` 컬럼을 **원시 int64 로** 돌려줍니다. 그것을
    십진수로 읽으면 4676398138920708779 같은 값이고, ``float()`` 를 씌워
    봐야 같은 크기의 실수일 뿐입니다. 그 8바이트를 **IEEE 754 double 로
    다시 읽어야** 44858.6458... 이라는 OLE 날짜가 나옵니다.

    이것을 놓치면 조용히 실패합니다 — 실측에서 76건 전부가
    ``timestamp`` 없이 나갔고, 시각 없는 사용량 레코드는 05단계에서
    타임라인에 놓이지 못합니다.

    끝에 ``0`` 을 붙여 7자리를 만드는 것은 다른 파서와 같은 규약입니다 —
    "100ns 자릿수는 버렸다"는 뜻입니다.
    """
    if value is None:
        return None
    try:
        from dissect.util.ts import oatimestamp

        if isinstance(value, int) and not isinstance(value, bool):
            # 라이브러리가 원시 int64 를 준 경우. 비트를 그대로 double 로.
            value = struct.unpack("<d", struct.pack("<q", value))[0]
        moment = oatimestamp(float(value))
    except Exception:  # noqa: BLE001 - 범위를 벗어난 값이 무엇을 던질지 모른다
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f0Z")


def _utf16(blob: Any) -> "str | None":
    """``IdBlob`` 의 UTF-16LE 문자열. 널 종결자를 떼어 낸다."""
    if not isinstance(blob, (bytes, bytearray)):
        return None
    try:
        return bytes(blob).decode("utf-16-le").rstrip("\x00") or None
    except UnicodeDecodeError:
        return None


def _sid(blob: Any) -> "str | None":
    """바이너리 SID → ``S-1-5-21-...``.

    ``IdType`` 3 의 값은 UTF-16 문자열이 아니라 SID 구조체입니다.
    문자열로 읽으면 깨진 글자가 산출물에 실립니다.
    """
    if not isinstance(blob, (bytes, bytearray)):
        return None
    try:
        from dissect.util.sid import read_sid

        return read_sid(bytes(blob))
    except Exception:  # noqa: BLE001 - 잘린 SID 가 무엇을 던질지 모른다
        return None


def _jsonable(value: Any) -> Any:
    """``json.dumps`` 가 받을 수 있는 형태로.

    ESE 는 바이너리 컬럼을 그대로 돌려줍니다(``BinaryData`` 등). 다른
    파서와 같은 규약으로 16진 문자열로 바꿉니다 — ``registry.py`` 참조.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
