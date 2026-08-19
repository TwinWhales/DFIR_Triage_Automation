"""evtx 파서 — Windows 이벤트 로그.

온디스크 계층(바이너리 XML + 청크 압축)은 **python-evtx가 소유합니다.**
직접 구현하지 않는 이유는 ``work-guide.md`` 3.1에 있습니다 — 난이도가
파일시스템 계층과 차원이 다르고, 이 프로젝트가 직접 구현으로 얻으려는
것(원본 오프셋 보존)은 라이브러리를 써도 얻어집니다. ``Record``가
``offset()``을 주기 때문입니다.

그래서 이 아티팩트에는 ``structs/`` 파일이 없습니다. 우리가 정의한
온디스크 구조가 없는데 빈 껍데기를 두면 "우리가 구조를 해석했다"는
인상만 남습니다(``third_party/README.md``의 경계와 같은 이유).

여기서 하는 일은 셋뿐입니다.

1. 청크를 걸으며 **라이브러리가 조용히 버린 구간을 센다**
2. 렌더된 XML에서 우리 레코드 형식으로 값을 옮긴다
3. ``scope``의 ``event_ids``로 거른다

## 라이브러리가 조용히 삼키는 것

``ChunkHeader.records()``는 레코드 하나가 깨지면 ``InvalidRecordException``을
잡아 **그냥 ``return``합니다.** 그 청크의 나머지가 통째로 사라지는데 아무
소리도 나지 않습니다.

이 프로젝트는 조용한 실패를 금지합니다(``work-guide.md`` 3.4). 그래서
``Evtx.records()``를 쓰지 않고 청크를 직접 걸으며, 마지막 레코드의 끝이
청크가 선언한 ``next_record_offset`` 경계에 못 미치면 그 차이를
``parse_errors``로 셉니다. ``$UsnJrnl``이 ``zero_bytes_skipped``를 센 것과
같은 이유입니다 — 못 읽은 구간을 모르면 "이 시각엔 아무 일도 없었다"로
잘못 읽게 됩니다.

## chunk_count를 믿지 않는다

``FileHeader.chunks()``는 헤더가 선언한 ``chunk_count``까지만 냅니다.
로그가 깨끗하게 닫히지 않았으면 이 값이 실제보다 작을 수 있고, 그러면
**가장 최근 이벤트가 담긴 꼬리 청크가 조용히 빠집니다.** 사고 대응에서
가장 보고 싶은 구간이 그쪽입니다.

그래서 ``include_inactive=True``로 물리 슬롯을 전부 훑고 ``verify()``로
거릅니다. 선언 밖 슬롯은 대개 빈 공간이라 체크섬에서 걸러지며, 통과한
것은 ``recovered_chunks``로 세어 매니페스트에 남깁니다.

## FileHeader.verify()로 게이팅하지 않는다

``verify()``는 매직·버전·헤더 크기·체크섬을 전부 봅니다. 그런데 **정상
로그에서도 False가 나옵니다** — ``wevtutil epl``로 갓 내보낸 멀쩡한
로그(103청크, is_dirty=False)에서 확인했습니다. 이걸로 파일을 거부하면
멀쩡한 증거를 통째로 버립니다.

파일 수준에서는 매직만 봅니다(evtx가 아니면 읽을 이유가 없다). 엄격한
판정은 청크 단위로 내리고, 그 결과를 셉니다.

## fields는 전량 싣는다

``<EventData>``의 값을 골라 담지 않습니다. 화이트리스트에서 빠뜨린 필드를
모델이 정확히 인용하면, 06단계가 ``field_not_found``로 기각합니다 —
**파서 누락이 환각률에 섞여 들어갑니다.** 컨텍스트를 줄이는 일은
05단계 ``record_filter``의 몫입니다.

같은 이유로 ``<UserData>``도 읽습니다. 실측한 Application 로그 8,257건 중
266건(3.2%)이 ``<EventData>`` 없이 ``<UserData>``만 가지고 있었습니다.
이쪽을 안 읽으면 그 레코드는 ``fields``가 빈 채로 나갑니다.

## 전량을 메모리에 올린다

``$MFT``와 다른 판단입니다. evtx는 채널마다 최대 크기가 정해진 로그라
크기에 상한이 있지만, ``$MFT``는 볼륨에 비례해 무한정 커집니다. 상한을
넘는 로그를 만나면 ``mmap``으로 바꾸면 됩니다 — ``FileHeader``는 슬라이싱만
되는 버퍼면 동작합니다.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any, BinaryIO, Iterator

from Evtx.Evtx import FileHeader

from ...common import refs
from ..structs.mft_record import filetime_to_datetime
from .base import Scope

__all__ = [
    "EvtxParser",
    "CHANNEL_FALLBACK",
    "TIMESTAMP_OFFSET",
    "event_fields",
    "record_timestamp",
    "strip_namespace",
]

_log = logging.getLogger(__name__)

#: 레코드 안에서 FILETIME 이 있는 위치. magic(4) + size(4) + record_num(8).
TIMESTAMP_OFFSET = 0x10

#: ``<Channel>``이 비었을 때 쓸 값. 파일에서 유추하는 것이지 지어내는
#: 것이 아니다 — ``evtx:Security``로 연 파일의 채널은 Security다.
CHANNEL_FALLBACK = {"evtx:Security": "Security", "evtx:System": "System"}

#: 청크 하나의 크기. python-evtx가 같은 값을 쓰고 있으며, 여기서는
#: 슬롯 수를 로그로 남길 때만 쓴다.
CHUNK_SIZE = 0x10000


def strip_namespace(tag: str) -> str:
    """``{http://...}EventID`` → ``EventID``.

    네임스페이스를 하나로 못 박지 않는 이유는 ``<UserData>`` 하위가
    **제공자 고유 네임스페이스**를 쓰기 때문입니다. 실측에서
    ``http://manifests.microsoft.com/win/2006/windows/WMI``가 나왔습니다.
    """
    return tag.rsplit("}", 1)[-1] if tag.startswith("{") else tag


def _find(parent: "ET.Element", name: str) -> "ET.Element | None":
    """네임스페이스를 무시하고 직계 자식을 찾는다."""
    for child in parent:
        if strip_namespace(child.tag) == name:
            return child
    return None


def _text(element: "ET.Element | None") -> str:
    return (element.text or "").strip() if element is not None else ""


def record_timestamp(record: Any) -> str | None:
    """레코드의 기록 시각. ``record.timestamp()`` 를 쓰지 않는다.

    **python-evtx가 float로 변환하기 때문입니다.**::

        # Evtx/BinaryParser.py
        datetime.fromtimestamp(float(qword) * 1e-7 - 11644473600, ...)

    이건 ``docs/artifact-notes.md``의 "밟은 함정"에 이미 적혀 있는 문제입니다.
    float는 유효숫자가 15~16자리인데 FILETIME은 18자리라 마이크로초가
    조용히 틀어집니다. 우리 ``$MFT``·``$UsnJrnl`` 파서는 이걸 피하려고
    정수 연산만 씁니다.

    실측으로 확인했습니다. Application 로그 8,257건을 ``wevtutil``(마이크로
    소프트 자체 파서)과 대조하니 **7,938건에서 −1.6 µs ~ +2.8 µs 차이**가
    났고, 오차가 양방향이라 100ns 절삭으로는 설명되지 않았습니다.

    그래서 원시 FILETIME qword 를 직접 읽어 ``filetime_to_datetime``(정수
    연산)으로 넘깁니다. 남는 차이는 ``datetime``이 마이크로초까지만 담아
    생기는 100ns 절삭뿐이며, 이는 ``$MFT``·``$UsnJrnl``과 동일한 규약입니다.

    값이 0이거나 범위를 벗어나면 ``None``. 레코드를 버리지는 않습니다 —
    타임스탬프가 이상한 것 자체가 증거인 경우가 있습니다.
    """
    moment = filetime_to_datetime(record.unpack_qword(TIMESTAMP_OFFSET))
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f0Z") if moment is not None else None


def _put(out: dict[str, str], key: str, value: str) -> None:
    """같은 키가 이미 있으면 버리지 않고 번호를 붙인다.

    실측 로그에서는 ``Name`` 중복이 0건이었지만, 중복이 나왔을 때
    나중 값이 앞 값을 덮으면 **증거가 조용히 사라집니다.**
    """
    if key not in out:
        out[key] = value
        return
    index = 2
    while f"{key}#{index}" in out:
        index += 1
    out[f"{key}#{index}"] = value


def event_fields(root: "ET.Element") -> dict[str, str]:
    """``<Event>``에서 ``fields``를 만든다. 값은 XML 문자열 그대로.

    타입 변환을 하지 않는 이유는 06단계 ``comparators``가 이미 ``"4821"``과
    ``4821``을 같게 보기 때문입니다. 여기서 숫자로 바꾸면 원본과 다른 값이
    기록되는데, 얻는 것이 없습니다.

    담기는 키는 네 갈래입니다.

    - ``<Data Name="X">`` → ``X``
    - 이름 없는 ``<Data>`` → ``Data[0]``, ``Data[1]`` … (실측 Application
      로그에서는 이쪽이 91%였습니다. 예외가 아니라 다수입니다)
    - ``<Binary>`` 등 다른 태그 → 태그 이름
    - ``<UserData>`` 하위 잎 요소 → 잎의 태그 이름

    ``Provider``도 넣습니다. 이벤트 ID는 **제공자 안에서만 유일**하기
    때문입니다. System.evtx의 7045는 Service Control Manager의 것인데,
    제공자를 모르면 원칙적으로 모호합니다. 스키마가
    ``additionalProperties: false``라 최상위에 키를 더할 수 없어
    ``fields`` 안에 두는 것이며, 이는 타협입니다.
    """
    out: dict[str, str] = {}

    system = _find(root, "System")
    if system is not None:
        provider = _find(system, "Provider")
        if provider is not None:
            name = provider.get("Name") or provider.get("EventSourceName") or ""
            if name:
                _put(out, "Provider", name)

    data = _find(root, "EventData")
    if data is not None:
        unnamed = 0
        for child in data:
            tag = strip_namespace(child.tag)
            named = child.get("Name")
            if tag == "Data" and named:
                key = named
            elif tag == "Data":
                key = f"Data[{unnamed}]"
                unnamed += 1
            else:
                key = tag
            # 빈 값도 키를 남긴다. 키를 빼면 "필드가 없다"와 "값이 비었다"가
            # 구분되지 않고, 후자를 전자로 읽으면 06단계가 정상 문장을
            # field_not_found 로 기각한다.
            _put(out, key, (child.text or "").strip())

    user = _find(root, "UserData")
    if user is not None:
        for wrapper in user:
            leaves = list(wrapper)
            if not leaves:
                _put(out, strip_namespace(wrapper.tag), (wrapper.text or "").strip())
                continue
            for leaf in leaves:
                _put(out, strip_namespace(leaf.tag), (leaf.text or "").strip())

    return out


class EvtxParser:
    """evtx 파일 하나를 읽어 우리 레코드 형식으로 낸다.

    **아티팩트마다 인스턴스를 따로 만듭니다.** ``artifact``가 ``ref``
    접두어와 출력 파일명을 정하므로, Security와 System이 인스턴스를
    공유하면 ``EVTX-SYS`` 레코드가 ``EVTX-SEC#``으로 나갑니다. 그건
    06단계에서 "존재하지 않는 레코드" = 환각으로 집계됩니다.

    ``stats``에 이번 실행의 집계가 남고 ``parse.py``가 매니페스트로
    옮깁니다. ``parse()``를 부를 때마다 초기화됩니다.
    """

    def __init__(self, artifact: str) -> None:
        if artifact not in CHANNEL_FALLBACK:
            raise ValueError(
                f"알 수 없는 evtx 아티팩트: {artifact!r} "
                f"(등록된 값: {', '.join(sorted(CHANNEL_FALLBACK))})"
            )
        self.artifact = artifact
        self.stats: dict[str, int] = self._new_stats()

    @staticmethod
    def _new_stats() -> dict[str, int]:
        return {
            "records": 0,
            "parse_errors": 0,
            "bad_chunks": 0,
            "recovered_chunks": 0,
            "xml_errors": 0,
            "filtered_out": 0,
        }

    def parse(self, stream: BinaryIO, scope: Scope) -> Iterator[dict[str, Any]]:
        self.stats = self._new_stats()

        buf = stream.read()
        if not buf:
            raise ValueError(f"{self.artifact}: 파일이 비어 있습니다")

        header = FileHeader(buf, 0x0)
        if not header.check_magic():
            raise ValueError(
                f"{self.artifact}: evtx 파일이 아닙니다 (매직 불일치). "
                "증거 경로가 맞는지 확인하십시오."
            )

        declared = header.chunk_count()

        for index, chunk in enumerate(header.chunks(include_inactive=True)):
            if not chunk.verify():
                # 선언 범위 밖은 대개 빈 공간이다. 실패로 셀 일이 아니다.
                if index < declared:
                    self.stats["bad_chunks"] += 1
                    _log.warning(
                        "%s: 청크 %d @0x%X 체크섬 불일치, 건너뜀",
                        self.artifact,
                        index,
                        chunk.offset(),
                    )
                continue

            if index >= declared:
                # 헤더가 선언하지 않았는데 유효한 청크. 더티 로그의 꼬리다.
                self.stats["recovered_chunks"] += 1
                _log.warning(
                    "%s: 선언(chunk_count=%d) 밖 청크 %d @0x%X 를 복구했습니다",
                    self.artifact,
                    declared,
                    index,
                    chunk.offset(),
                )

            yield from self._chunk_records(chunk, scope)

        if self.stats["parse_errors"]:
            _log.warning(
                "%s: 레코드 %d건을 읽지 못했습니다 (라이브러리가 청크를 조기 종료)",
                self.artifact,
                self.stats["parse_errors"],
            )

    def _chunk_records(self, chunk: Any, scope: Scope) -> Iterator[dict[str, Any]]:
        """청크 하나를 걷고, 조기 종료된 구간을 센다."""
        last_end = chunk.offset() + chunk.header_size()

        for record in chunk.records():
            last_end = record.offset() + record.length()
            built = self._build(record)
            if built is None:
                continue
            if not scope.matches_event_id(built["event_id"]):
                # 시간 범위는 여기서 거르지 않는다. parsers/base.py 계약대로
                # flagging 이 outside_time_range 를 붙여 내보낸다 — 02단계의
                # 시간 추론이 틀렸을 때 되짚을 레코드가 남아야 한다.
                self.stats["filtered_out"] += 1
                continue
            self.stats["records"] += 1
            yield built

        boundary = chunk.offset() + chunk.next_record_offset()
        if last_end < boundary:
            # 라이브러리가 InvalidRecordException 을 잡고 조용히 멈춘 구간.
            # 몇 건인지는 알 수 없으므로 바이트가 아니라 "구간 1건"으로 센다.
            self.stats["parse_errors"] += 1
            _log.warning(
                "%s: 청크 @0x%X 가 0x%X 에서 끊겼습니다 (경계 0x%X, %d바이트 미판독)",
                self.artifact,
                chunk.offset(),
                last_end,
                boundary,
                boundary - last_end,
            )

    def _build(self, record: Any) -> "dict[str, Any] | None":
        """레코드 하나를 우리 형식으로. 읽을 수 없으면 ``None``."""
        try:
            root = ET.fromstring(record.xml())
        except ET.ParseError as e:
            # 렌더는 됐는데 XML 로 안 읽히는 경우다. 레코드 하나만 버리고
            # 계속한다. 조용히 넘어가지 않도록 센다.
            self.stats["xml_errors"] += 1
            self.stats["parse_errors"] += 1
            _log.warning("%s @0x%X: XML 파싱 실패 — %s", self.artifact, record.offset(), e)
            return None

        system = _find(root, "System")
        if system is None:
            self.stats["parse_errors"] += 1
            _log.warning("%s @0x%X: <System> 없음", self.artifact, record.offset())
            return None

        raw_id = _text(_find(system, "EventID"))
        try:
            event_id = int(raw_id)
        except ValueError:
            self.stats["parse_errors"] += 1
            _log.warning("%s @0x%X: EventID 를 읽을 수 없음 %r", self.artifact, record.offset(), raw_id)
            return None

        computer = _text(_find(system, "Computer"))
        if not computer:
            # 스키마가 minLength 1 을 요구한다. 값을 지어내는 대신 버리고
            # 센다 — 실측 8,257건에서는 한 건도 없었다.
            self.stats["parse_errors"] += 1
            _log.warning("%s @0x%X: <Computer> 가 비어 있어 건너뜀", self.artifact, record.offset())
            return None

        timestamp = record_timestamp(record)
        if timestamp is None:
            # evtx 스키마는 $UsnJrnl 과 달리 timestamp 를 필수로 둔다.
            # 키를 빼고 낼 수 없으므로 버리고 센다.
            self.stats["parse_errors"] += 1
            _log.warning("%s @0x%X: 기록 시각을 읽을 수 없어 건너뜀", self.artifact, record.offset())
            return None

        return {
            "ref": refs.make_ref(self.artifact, record.record_num()),
            "artifact": self.artifact,
            "record_num": record.record_num(),
            "offset": f"0x{record.offset():X}",
            "event_id": event_id,
            "timestamp": timestamp,
            "channel": _text(_find(system, "Channel")) or CHANNEL_FALLBACK[self.artifact],
            "computer": computer,
            "fields": event_fields(root),
        }
