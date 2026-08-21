"""레지스트리 파서 — SYSTEM / SOFTWARE 하이브.

온디스크 계층(regf 셀 구조)은 **python-registry가 소유합니다.** evtx와
같은 판단이지만 근거는 다릅니다. regf는 evtx처럼 어렵지 않습니다 —
압축도 바이너리 XML도 픽스업도 없고, 셀 헤더 4바이트 뒤에 ``nk``/``vk``
시그니처가 붙는 평범한 구조체라 ``$UsnJrnl`` 정도 난이도입니다.

직접 구현하지 않는 이유는 **오프셋을 이미 얻을 수 있기 때문**입니다.
``work-guide.md`` 3.1이 직접 구현의 근거로 든 것이 "기존 파서는 원본
오프셋을 주지 않는다"인데, python-registry는 ``_nkrecord.offset()``으로
줍니다. 근거 추적 구조가 성립하므로 직접 구현할 이유가 없습니다.

그래서 이 아티팩트에도 ``structs/`` 파일이 없습니다(evtx와 같습니다).

## 다른 파서와 근본적으로 다른 점

기존 파서 셋은 **"전부 훑고 재미있는 것에 플래그"** 모델입니다.
레지스트리는 반대입니다 — **가치가 레코드가 아니라 경로에 있습니다.**

``$MFT`` 레코드 12345는 맥락 없이도 의미가 있지만
``Services\\XYZ\\ImagePath``는 그 경로가 무엇을 뜻하는지 알아야 의미가
생깁니다. 그래서 이 파서는 ``scope``의 ``path_prefix``에 거의 전적으로
의존하고, 범위 밖 서브트리는 **가지치기로 아예 걷지 않습니다.**

`work-guide.md` 3.1이 말한 "웹루트 하위 .aspx만 같은 범위 한정 읽기"가
이 아티팩트에서 가장 크게 작동하는 자리입니다.

**결과적으로 이 파서가 낸 레코드에는 ``flags``가 거의 붙지 않습니다.**
신호가 플래그가 아니라 선별에서 나오기 때문입니다. 05단계
``record_filter``는 플래그 없는 레코드를 버리므로, 지금 구조 그대로면
레지스트리 레코드는 모델에 도달하지 않습니다. 파싱 계층의 결함이
아니라 **아직 정하지 않은 설계**입니다(``docs/limitations.md`` 6장).

## 레코드 단위는 키다

값(vk)이 아니라 키(nk) 하나가 레코드 하나입니다. 값들은 ``fields``에
담깁니다. evtx 레코드와 같은 모양이라 06단계의 ``fields.ImagePath`` 점
표기가 그대로 동작합니다.

값 단위로 하지 않은 이유는 둘입니다. 값이 없는 키도 **존재 자체와
LastWrite가 증거**라 버릴 수 없고, 값마다 레코드를 만들면 같은 키의
값들이 흩어져 "이 키는 이런 상태였다"를 모델이 재구성해야 합니다.

## 값에는 타임스탬프가 없다

``timestamp``는 **키의 LastWrite이며 그 키의 모든 값이 공유합니다.**
python-registry도 값에 시각을 물으면 거부합니다::

    ValueError: value does not have a timestamp

즉 "ImagePath가 이 시각에 설정되었다"는 문장은 **원리적으로 검증할 수
없습니다.** 키 타임스탬프는 "그 키 아래 무언가가 바뀌었다"까지만
말합니다. ``$MFT``·evtx는 레코드 하나에 시각 하나가 대응하는데
레지스트리만 N:1입니다. ``docs/limitations.md``에 적혀 있습니다.

## CurrentControlSet은 디스크에 없다

부팅 때 만들어지는 링크라 하이브에는 ``ControlSet001``/``ControlSet002``만
있습니다. 모든 DFIR 문서가 ``CurrentControlSet``이라고 쓰므로,
``Select\\Current``를 읽어 ``scope``의 접두어를 **실제 이름으로 바꿔
준 뒤** 매칭합니다. 매핑 작성자가 하이브 내부 사정을 몰라도 되게
하려는 것입니다.

## 경로를 다시 만든다

``RegistryKey.path()``는 하이브 내부 루트 이름을 앞에 답니다::

    CMI-CreateHive{2A7FB991-...}\\ControlSet001\\services\\Dnscache

이대로 내면 ``scope`` 매칭도 06단계 값 비교도 분석가가 쓰는 경로와
어긋납니다. 그래서 순회하며 경로를 직접 조립하고 앞에 하이브 이름을
답니다 — ``SYSTEM\\ControlSet001\\services\\Dnscache``.

**대소문자는 디스크에 있는 그대로 둡니다.** 위 ``services``가 소문자인
것은 실제 저장된 이름입니다. 대소문자 무시 비교는 ``normalize_path``가
양쪽에 적용하므로 여기서 손댈 이유가 없고, 손대면 원본과 다른 값을
기록하게 됩니다.
"""

from __future__ import annotations

import logging
import struct
from typing import Any, BinaryIO, Iterator

from Registry import Registry

from ...common import refs
from ...common.io import normalize_path
from ..structs.mft_record import filetime_to_datetime
from .base import Scope

__all__ = [
    "RegistryParser",
    "HIVE_OF",
    "DEFAULT_VALUE_NAME",
    "STRING_TYPES",
    "MULTI_STRING_TYPE",
    "MAX_DEPTH",
    "NK_TIMESTAMP_OFFSET",
    "hive_designator",
    "value_to_field",
]

_log = logging.getLogger(__name__)

#: 아티팩트 이름 → 경로 앞에 붙일 하이브 이름.
HIVE_OF: dict[str, str] = {
    "registry:SYSTEM": "SYSTEM",
    "registry:SOFTWARE": "SOFTWARE",
}

#: 이름 없는 값(기본값)을 ``fields``에 담을 때 쓸 키.
#:
#: 빈 문자열을 키로 쓰면 06단계가 ``fields.`` 로 끝나는 필드를 가리켜야
#: 하는데, ``get_field``의 점 표기로는 표현할 수 없습니다.
#:
#: **값은 python-registry가 쓰는 것과 같아야 합니다.** 라이브러리의
#: ``RegistryValue.name()``이 이름 없는 값에 이 문자열을 이미 돌려주므로,
#: 다른 값을 쓰면 상수는 죽은 코드가 되고 실제 키는 라이브러리 것이 됩니다.
#: 한때 ``"(Default)"``였고 정확히 그렇게 됐습니다.
#:
#: 이름이 실제로 이 문자열인 값과 충돌할 수 있으나, 실측 하이브
#: 20,512개 키에서 0건이었습니다.
DEFAULT_VALUE_NAME = "(default)"

#: 우리가 직접 디코딩할 문자열 타입. 라이브러리에 맡기면 한글이 잘린다.
STRING_TYPES = frozenset({"RegSZ", "RegExpandSZ"})
MULTI_STRING_TYPE = "RegMultiSZ"

#: nk 레코드 안에서 LastWrite FILETIME 이 있는 자리.
NK_TIMESTAMP_OFFSET = 0x04

#: 순회 깊이 상한. 손상된 하이브의 순환을 오프셋으로도 막지만,
#: 비정상적으로 깊은 체인에서 멈출 자리도 둡니다.
MAX_DEPTH = 512

#: ``Select\\Current``가 가리키는 컨트롤셋을 찾을 때 쓸 이름.
_SELECT_KEY = "Select"
_CURRENT_VALUE = "Current"

#: 스코프 접두어에서 바꿔 줄 가상 경로 조각(정규화된 형태).
_CURRENT_CONTROL_SET = "currentcontrolset"


def hive_designator(artifact: str) -> str:
    """``registry:SYSTEM`` → ``SYSTEM``."""
    try:
        return HIVE_OF[artifact]
    except KeyError:
        known = ", ".join(sorted(HIVE_OF))
        raise ValueError(
            f"알 수 없는 레지스트리 아티팩트: {artifact!r} (등록된 값: {known})"
        ) from None


def value_to_field(value: Any) -> Any:
    """``RegistryValue`` 하나를 ``fields``에 넣을 형태로.

    타입별로 이렇게 갑니다.

    - ``RegSZ`` / ``RegExpandSZ`` → 문자열 그대로
    - ``RegDWord`` / ``RegQWord`` → 정수 그대로
    - ``RegMultiSZ`` → **리스트.** 06단계 ``compare``가 리스트를 "원소 중
      하나라도 일치"로 보므로, 문장이 여러 값 중 하나를 지목해도 검증됩니다.
      문자열로 합치면 그 성질이 사라집니다. 끝의 빈 문자열은 뗍니다 —
      아래 참조.
    - ``RegBin`` / 리소스 목록 → **소문자 16진 문자열.** bytes 는 JSON 으로
      나가지 않고, base64 는 사람이 읽고 대조할 수 없습니다.

    **문자열 타입은 ``value.value()``를 쓰지 않습니다.** 라이브러리가
    한글을 자릅니다 — ``_decode_utf16le`` 참조.

    값을 읽다 실패하면 ``None``이 아니라 예외를 올립니다. 부르는 쪽이
    세고 기록합니다 — 조용히 빈 값이 되면 "값이 없었다"와 구별되지
    않습니다.
    """
    type_name = value.value_type_str()

    if type_name in STRING_TYPES:
        # 첫 널 문자까지가 값이다. 널은 종결자이지 내용이 아니다.
        return _decode_utf16le(value.raw_data()).split("\x00", 1)[0]

    if type_name == MULTI_STRING_TYPE:
        return _strip_terminators(_decode_utf16le(value.raw_data()).split("\x00"))

    raw = value.value()
    if isinstance(raw, bytes):
        return raw.hex()
    if isinstance(raw, list):
        return _strip_terminators(
            [item.hex() if isinstance(item, bytes) else item for item in raw]
        )
    return raw


def _decode_utf16le(blob: bytes) -> str:
    """UTF-16LE 로 디코딩한다. **정렬을 지킨다.**

    python-registry 의 ``decode_utf16le`` 는 종결자를 ``s.index(b"\\x00\\x00")``
    로 찾습니다. **바이트 검색이라 문자 경계를 보지 않습니다.** 앞이
    ASCII(고위 바이트 0x00)이고 뒤가 ``U+XX00`` 형태 문자면 두 문자에
    걸쳐 ``00 00`` 이 만들어지고, 거기서 문자열이 끊깁니다.

    한글에서 흔합니다. ``U+AC00``(가) ``U+AD00``(관) 처럼 하위 바이트가
    0x00 인 음절이 많고, 그 앞에 공백이 오는 것이 보통이기 때문입니다::

        '볼륨 관리자 드라이버'
         fc bc │ 68 b9 │ 20 00 │ 00 ad │ ...
          볼      륨    공백    관
                        └─ 00 00 ─┘   ← 오프셋 5(홀수)에서 끊긴다

        라이브러리 : '볼륨 '
        실제       : '볼륨 관리자 드라이버'

    실측 ``evidence/[root]`` SYSTEM 하이브: 문자열 값 42,578건 중
    **56건(0.13%)** 이 잘렸습니다. 전부 한글입니다. 서비스 표시명과
    드라이버 설명이 주로 걸립니다.

    조용히 잘리는 것이라 더 나쁩니다. 예외도 경고도 없고, 잘린 문자열은
    그 자체로 그럴듯해 보입니다.

    **홀수 길이면 마지막 바이트를 버립니다.** 반쪽짜리 문자는 어차피
    복원할 수 없고, 라이브러리처럼 ``\\x00`` 을 붙이면 없던 문자가 생깁니다.
    """
    if len(blob) % 2:
        blob = blob[:-1]
    return blob.decode("utf-16-le", "replace")


def _strip_terminators(items: list) -> list:
    """``RegMultiSZ`` 끝의 빈 문자열을 뗀다.

    ``MULTI_SZ``는 **각 문자열이 널로 끝나고 목록 전체가 널 하나로 더
    끝나는** 구조입니다. python-registry는 널 기준으로 그냥 쪼개므로
    종결자 두 개가 빈 문자열로 남습니다::

        raw_data : b'r\\x00p\\x00c\\x00s\\x00s\\x00\\x00\\x00\\x00\\x00'
        value()  : ['rpcss', '', '']      ← 라이브러리
        실제 내용 : ['rpcss']

    C 문자열의 널 종결자를 값에 포함시키지 않는 것과 같습니다. 실측
    ``SYSTEM\\ControlSet001\\Services`` 1,754개 키 중 **249개**가 이
    형태였습니다.

    **06단계에 실제 영향이 있습니다.** ``compare``는 리스트를 "원소 중
    하나라도 일치"로 보므로, 빈 문자열이 남아 있으면 모델이 지어낸
    ``value: ""`` 주장이 **검증을 통과합니다.**

    가운데 빈 문자열은 건드리지 않습니다. 구조적으로 있을 수 있고,
    종결자와 달리 위치가 의미를 가집니다.
    """
    out = list(items)
    while out and out[-1] == "":
        out.pop()
    return out


def _timestamp(key: Any) -> "str | None":
    """키의 LastWrite. 읽을 수 없으면 ``None``.

    **``key.timestamp()``를 쓰지 않습니다.** python-registry가 100ns를
    마이크로초로 줄이면서 ``ROUND_HALF_EVEN``으로 **반올림**하기 때문입니다
    (``RegistryParse.parse_timestamp``). 이 프로젝트의 나머지 파서는 전부
    ``filetime_to_datetime``으로 **절삭**합니다.

    1µs 차이라 허용 오차 안이지만, 문제는 값이 아니라 **표기가 사실과
    달라지는 것**입니다. 우리 형식은 끝에 ``0``을 붙여 7자리를 만듭니다 —
    "100ns 자릿수는 버렸다"는 뜻입니다. 반올림하면 그 자리가 6번째 자리에
    섞여 들어가는데 표기는 여전히 버렸다고 말합니다.

    실측: raw FILETIME ``128920208934228618`` (끝자리 8)
    → 라이브러리 ``.422862`` / 정수 절삭 ``.422861``.

    evtx 파서가 python-evtx의 ``timestamp()``를 우회한 것과 같은 이유입니다
    (``parsers/evtx.py`` ``record_timestamp``). 저쪽은 float 오차였고
    이쪽은 반올림이라 원인은 다르지만, 원본에 충실해야 한다는 결론은
    같습니다.

    레코드를 버리지는 않습니다. 시각이 이상한 것 자체가 증거일 수 있고,
    키가 거기 존재한다는 사실만으로도 값이 있습니다.
    """
    record = getattr(key, "_nkrecord", None)
    if record is None:
        return None
    try:
        # nk 레코드의 0x04 에 FILETIME qword 가 있다.
        moment = filetime_to_datetime(record.unpack_qword(NK_TIMESTAMP_OFFSET))
    except Exception:  # noqa: BLE001 - 손상 셀에서 무엇이 나올지 모른다
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f0Z") if moment is not None else None


class RegistryParser:
    """하이브 하나를 읽어 우리 레코드 형식으로 낸다.

    **아티팩트마다 인스턴스를 따로 만듭니다.** ``artifact``가 ``ref``
    접두어와 출력 파일명을 정하므로, SYSTEM과 SOFTWARE가 인스턴스를
    공유하면 ``REG-SW`` 레코드가 ``REG-SYS#``로 나갑니다. 그것은
    06단계에서 "존재하지 않는 레코드" = 환각으로 집계됩니다.
    """

    def __init__(self, artifact: str) -> None:
        self.artifact = artifact
        self.hive = hive_designator(artifact)
        self.stats: dict[str, int] = self._new_stats()

    @staticmethod
    def _new_stats() -> dict[str, int]:
        return {
            "records": 0,
            "parse_errors": 0,
            "value_errors": 0,
            "pruned_subtrees": 0,
            "dirty_hive": 0,
        }

    # ------------------------------------------------------------ 진입점

    def parse(self, stream: BinaryIO, scope: Scope) -> Iterator[dict[str, Any]]:
        self.stats = self._new_stats()

        buf = stream.read()
        if not buf:
            raise ValueError(f"{self.artifact}: 파일이 비어 있습니다")
        if buf[:4] != b"regf":
            raise ValueError(
                f"{self.artifact}: 레지스트리 하이브가 아닙니다 (매직 불일치). "
                "증거 경로가 맞는지 확인하십시오."
            )

        self._warn_if_dirty(buf)

        hive = Registry.Registry(_Buffer(buf))
        prefixes = self._resolve_prefixes(hive, scope)

        yield from self._walk(hive.root(), prefixes)

    # ------------------------------------------------------ 하이브 상태

    def _warn_if_dirty(self, buf: bytes) -> None:
        """기본 블록의 시퀀스 번호 두 개가 다르면 더티 하이브다.

        **조용히 넘어가면 안 되는 종류입니다.** 더티 하이브는 정상적으로
        열리고 정상적으로 파싱되는데 **값이 낡았습니다.** 최신 내용은
        ``.LOG1``/``.LOG2`` 트랜잭션 로그에 있고 우리는 그것을 재생하지
        않습니다. 서비스 설정이 바뀐 흔적을 찾는 중에 바뀌기 전 값을
        받아 놓고 그것을 현재 상태로 보고하게 됩니다.

        ``$UsnJrnl``의 0바이트 껍데기와 같은 유형입니다 — 파일이 있고,
        파서가 성공하고, 답이 틀립니다.
        """
        try:
            seq1, seq2 = struct.unpack_from("<II", buf, 4)
        except struct.error:
            return
        if seq1 != seq2:
            self.stats["dirty_hive"] = 1
            _log.warning(
                "%s: 더티 하이브입니다 (seq1=%d, seq2=%d). 트랜잭션 로그"
                "(.LOG1/.LOG2)가 재생되지 않았으므로 값이 최신이 아닐 수 "
                "있습니다. 본 버전은 로그를 재생하지 않습니다.",
                self.artifact,
                seq1,
                seq2,
            )

    # ------------------------------------------------------------ 범위

    def _resolve_prefixes(self, hive: Any, scope: Scope) -> tuple[str, ...]:
        """``scope.path_prefix``의 ``CurrentControlSet``을 실제 이름으로.

        ``Select\\Current``를 못 읽으면 접두어를 그대로 둡니다. 지어낸
        이름으로 바꾸면 아무것도 매칭되지 않아 **범위 안의 증거를 통째로
        놓치는데**, 그 사실이 "레코드 0건"으로만 나타나 원인을 알 수
        없게 됩니다. 바꾸지 않으면 최소한 로그에 이유가 남습니다.
        """
        prefixes = tuple(scope.path_prefix)
        if not any(_CURRENT_CONTROL_SET in p for p in prefixes):
            return prefixes

        actual = self._current_control_set(hive)
        if actual is None:
            _log.warning(
                "%s: Select\\Current 를 읽지 못해 CurrentControlSet 을 "
                "해석하지 못했습니다. 접두어를 그대로 씁니다 — 매칭되는 "
                "레코드가 없을 수 있습니다.",
                self.artifact,
            )
            return prefixes

        resolved = tuple(p.replace(_CURRENT_CONTROL_SET, actual) for p in prefixes)
        _log.info("%s: CurrentControlSet -> %s", self.artifact, actual)
        return resolved

    def _current_control_set(self, hive: Any) -> "str | None":
        """``Select\\Current``가 가리키는 컨트롤셋 이름(정규화된 형태).

        SOFTWARE 하이브에는 ``Select``가 없습니다. 그때는 ``None``이고,
        애초에 ``CurrentControlSet``이 나올 일도 없습니다.
        """
        try:
            number = hive.open(_SELECT_KEY).value(_CURRENT_VALUE).value()
            return f"controlset{int(number):03d}"
        except Exception:  # noqa: BLE001 - 키·값 부재와 파싱 실패를 같이 다룬다
            return None

    # ------------------------------------------------------------ 순회

    def _walk(self, root: Any, prefixes: tuple[str, ...]) -> Iterator[dict[str, Any]]:
        """반복자로 트리를 훑는다. 범위 밖 서브트리는 걷지 않는다.

        재귀가 아닌 이유는 깊은 체인에서 ``RecursionError``가 나면 파싱
        전체가 멈추기 때문입니다. 손상된 하이브에서 그런 일이 생깁니다.

        ``seen``은 순환을 막습니다. 같은 nk를 두 번 내면 ``ref``가 중복되고
        ``io.read_parsed_records``가 ``DuplicateRefError``로 05·06단계를
        통째로 세웁니다.
        """
        seen: set[int] = set()
        stack: list[tuple[Any, str, int]] = [(root, self.hive, 0)]

        while stack:
            key, path, depth = stack.pop()

            offset = self._offset_of(key)
            if offset is None:
                continue
            if offset in seen:
                self.stats["parse_errors"] += 1
                _log.warning("%s: nk @0x%X 를 다시 만났습니다 (순환)", self.artifact, offset)
                continue
            seen.add(offset)

            if self._in_scope(path, prefixes):
                built = self._build(key, path, offset)
                if built is not None:
                    self.stats["records"] += 1
                    yield built

            if depth >= MAX_DEPTH:
                self.stats["parse_errors"] += 1
                _log.warning("%s: %s 에서 깊이 상한 %d 도달", self.artifact, path, MAX_DEPTH)
                continue

            try:
                children = list(key.subkeys())
            except Exception as e:  # noqa: BLE001 - 손상 셀에서 무엇이 나올지 모른다
                self.stats["parse_errors"] += 1
                _log.warning("%s: %s 의 하위 키를 읽지 못했습니다 — %s", self.artifact, path, e)
                continue

            for child in children:
                try:
                    child_path = f"{path}\\{child.name()}"
                except Exception as e:  # noqa: BLE001
                    self.stats["parse_errors"] += 1
                    _log.warning("%s: %s 의 하위 키 이름을 읽지 못했습니다 — %s", self.artifact, path, e)
                    continue
                if self._prune(child_path, prefixes):
                    self.stats["pruned_subtrees"] += 1
                    continue
                stack.append((child, child_path, depth + 1))

    @staticmethod
    def _offset_of(key: Any) -> "int | None":
        """nk 레코드의 절대 오프셋.

        공개 API에 없어 비공개 속성을 씁니다. ``work-guide.md`` 원칙 4가
        요구하는 값이라 없으면 레코드를 낼 수 없습니다 — 오프셋이 곧
        ``ref``이고, ``ref`` 없는 문장은 06단계가 전부 기각합니다.
        """
        record = getattr(key, "_nkrecord", None)
        if record is None:
            return None
        try:
            return int(record.offset())
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _in_scope(path: str, prefixes: tuple[str, ...]) -> bool:
        """이 키 자체가 범위 안인가.

        ``Scope.matches_prefix``와 같은 규칙입니다. ``Scope``를 직접 쓰지
        않는 것은 접두어가 ``CurrentControlSet`` 해석으로 바뀌었기
        때문입니다.
        """
        if not prefixes:
            return True
        normalized = normalize_path(path)
        return any(
            normalized == prefix or normalized.startswith(prefix + "/") for prefix in prefixes
        )

    @staticmethod
    def _prune(path: str, prefixes: tuple[str, ...]) -> bool:
        """이 서브트리를 걷지 않아도 되는가.

        범위 안(또는 그 하위)도 아니고, 범위로 **내려가는 길목**도 아니면
        걸을 이유가 없습니다. 49MB SOFTWARE 하이브에서 키 서른 개를 읽는
        것이 이 아티팩트의 정상 사용례라, 가지치기가 곧 성능입니다.
        """
        if not prefixes:
            return False
        normalized = normalize_path(path)
        for prefix in prefixes:
            if normalized == prefix or normalized.startswith(prefix + "/"):
                return False  # 범위 안
            if prefix.startswith(normalized + "/"):
                return False  # 범위로 내려가는 길목
        return True

    # ------------------------------------------------------------ 레코드

    def _build(self, key: Any, path: str, offset: int) -> "dict[str, Any] | None":
        """키 하나를 우리 형식으로."""
        try:
            name = key.name()
        except Exception as e:  # noqa: BLE001
            self.stats["parse_errors"] += 1
            _log.warning("%s: nk @0x%X 의 이름을 읽지 못했습니다 — %s", self.artifact, offset, e)
            return None

        record: dict[str, Any] = {
            # 레지스트리에는 MFT 레코드 번호 같은 일련번호가 없다. 하이브
            # 안에서 유일한 값은 nk 오프셋이므로 그것을 10진수로 쓴다
            # (src/common/refs.py 규약). offset 필드에 같은 값이 16진수로 간다.
            "ref": refs.make_ref(self.artifact, offset),
            "artifact": self.artifact,
            "record_num": offset,
            "offset": f"0x{offset:X}",
            "path": path,
            "name": name,
            "fields": self._fields(key, path),
        }

        timestamp = _timestamp(key)
        if timestamp is not None:
            # null 은 스키마가 막는다. 읽지 못하면 키를 빼고 낸다 —
            # $UsnJrnl 과 같은 규약이다.
            record["timestamp"] = timestamp
        return record

    def _fields(self, key: Any, path: str) -> dict[str, Any]:
        """키의 값들을 ``fields``로.

        값 하나를 읽지 못해도 키를 버리지 않습니다. 나머지 값과 키의
        존재·LastWrite는 여전히 증거입니다. 대신 셉니다.
        """
        out: dict[str, Any] = {}
        try:
            values = list(key.values())
        except Exception as e:  # noqa: BLE001
            self.stats["parse_errors"] += 1
            _log.warning("%s: %s 의 값 목록을 읽지 못했습니다 — %s", self.artifact, path, e)
            return out

        for value in values:
            try:
                name = value.name() or DEFAULT_VALUE_NAME
                out[name] = value_to_field(value)
            except Exception as e:  # noqa: BLE001 - 손상 셀에서 무엇이 나올지 모른다
                self.stats["value_errors"] += 1
                self.stats["parse_errors"] += 1
                _log.warning("%s: %s 의 값 하나를 읽지 못했습니다 — %s", self.artifact, path, e)
        return out


class _Buffer:
    """이미 읽어 둔 바이트를 ``Registry``에 넘기기 위한 얇은 껍데기.

    ``Registry.Registry``는 ``.read()``가 있는 객체나 파일명을 받습니다.
    04단계는 스트림을 열어 주므로 바이트를 이미 손에 들고 있는데, 그것을
    다시 감싸 넘기는 편이 파일을 두 번 여는 것보다 낫습니다 — 증거
    파일의 위치는 ``evidence.py``만 알아야 합니다.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data
