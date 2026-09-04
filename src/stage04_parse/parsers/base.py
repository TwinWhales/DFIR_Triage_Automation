"""파서 공통 인터페이스.

파서가 하는 일은 하나입니다.

    (바이트 스트림, 읽을 범위)  →  레코드 여러 개

**범위를 좁히는 판단은 이미 03단계가 끝냈습니다.** 파서는 그 결정을
집행할 뿐 무엇을 볼지 다시 정하지 않습니다. 그래야 "선별이 무엇을
놓쳤는가"를 03단계 산출물만 보고 되짚을 수 있습니다.

## 파서가 지켜야 할 세 가지

1. **``ref``는 ``src/common/refs.py``를 경유해 만든다.** 문자열을 직접
   조립하면 접두어 오타가 06단계에서 "존재하지 않는 레코드"로 둔갑해
   환각률 통계를 오염시킨다.
2. **``offset``은 원본 바이트 위치다.** 기존 도구를 쓰지 않고 직접
   구현하는 이유가 이 필드다. 파싱된 값만 있고 위치가 없으면 근거를
   되짚을 수 없다.
3. **범위 밖 레코드는 내지 않는다.** 단, 시간 범위만 벗어난 것은
   ``outside_time_range`` 플래그를 달아 내보낸다 — 시간 추론이 틀렸을 때
   원인을 되짚으려면 레코드가 남아 있어야 한다.

``flags``는 파서가 붙이지 않습니다. ``flagging.py``가 일괄 적용합니다.
룰을 한 곳에 모아야 어휘가 갈라지지 않습니다.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from datetime import datetime
from typing import Any, BinaryIO, Iterator, Protocol

from ...common.io import normalize_path, parse_timestamp

__all__ = [
    "Scope",
    "Parser",
    "ParseError",
    "path_in_prefix",
    "path_leads_to_prefix",
]


def _segments_lead(path_parts: list[str], prefix_parts: list[str]) -> bool:
    """짧은 쪽 길이만큼 세그먼트가 앞에서부터 맞는가.

    ``zip`` 이 짧은 쪽에서 멈추는 것을 그대로 쓴다. 경로가 더 길면
    "범위 안", 접두어가 더 길면 "범위로 내려가는 길목"이 된다 — 두 판정이
    같은 비교를 쓰므로 갈라질 수 없다.
    """
    return all(
        fnmatch.fnmatchcase(actual, expected)
        for actual, expected in zip(path_parts, prefix_parts)
    )


def path_in_prefix(path: str, prefix: str) -> bool:
    r"""정규화된 경로가 접두어 범위 안인가.

    ``*`` 는 **세그먼트 하나 안에서만** 확장된다. 매핑이
    ``C:\Users\*\AppData\Local\Temp`` 라고 적으면 사용자 이름 자리만
    비워 둔 것이지 ``AppData`` 아래 전부를 뜻하지 않는다. 구분자를 넘는
    ``**`` 는 로드 시점에 거부한다(``mapping_loader``).

    두 인자 모두 ``normalize_path`` 를 이미 거친 값이어야 한다. 부르는
    쪽이 접두어 여럿을 도는 동안 경로를 한 번만 정규화하기 위해서다.
    """
    if "*" not in prefix:
        # 와일드카드가 없으면 뜻이 같고 훨씬 빠르다. 49MB 하이브를 걷는
        # 동안 키마다 부르는 자리라 이 분기가 그대로 시간이 된다.
        return path == prefix or path.startswith(prefix + "/")
    path_parts = path.split("/")
    prefix_parts = prefix.split("/")
    if len(path_parts) < len(prefix_parts):
        return False
    return _segments_lead(path_parts, prefix_parts)


def path_leads_to_prefix(path: str, prefix: str) -> bool:
    """이 경로를 더 내려가면 접두어에 닿을 수 있는가.

    가지치기용입니다. 범위 안인지는 보지 않고 **길목인지만** 봅니다.
    """
    if "*" not in prefix:
        return prefix.startswith(path + "/")
    path_parts = path.split("/")
    prefix_parts = prefix.split("/")
    if len(prefix_parts) <= len(path_parts):
        return False
    return _segments_lead(path_parts, prefix_parts)


class ParseError(Exception):
    """레코드 하나를 읽지 못했다.

    파일 전체를 포기하는 것이 아니라 **그 레코드만 건너뛰고** 계속합니다.
    손상된 레코드 하나 때문에 나머지를 못 읽으면 안 됩니다.
    ``errors.jsonl``에 ``parse_error`` / ``skip``으로 기록됩니다.
    """


@dataclass(frozen=True)
class Scope:
    """03단계가 정한 읽을 범위.

    ``03_selection.json``의 ``scope``를 파서가 쓰기 좋은 술어로 바꾼 것입니다.
    비어 있는 조건은 **제한 없음**입니다. 예를 들어 ``extensions``가 비면
    모든 확장자를 받습니다. 좁히는 조건이 없으면 넓게 보는 것이 맞습니다 —
    선별 실패로 증거를 놓치는 것이 이 프로젝트의 최대 리스크입니다.
    """

    path_prefix: tuple[str, ...] = ()
    extensions: tuple[str, ...] = ()
    event_ids: tuple[int, ...] = ()
    start: datetime | None = None
    end: datetime | None = None

    @classmethod
    def from_selection(cls, scope: dict[str, Any] | None) -> "Scope":
        """``03_selection.json``의 ``scope`` 하나를 변환한다."""
        scope = scope or {}
        time_range = scope.get("time_range") or {}
        return cls(
            path_prefix=tuple(normalize_path(p) for p in scope.get("path_prefix", ())),
            extensions=tuple(e.lower() for e in scope.get("extensions", ())),
            event_ids=tuple(int(e) for e in scope.get("event_ids", ())),
            start=parse_timestamp(time_range.get("start")),
            end=parse_timestamp(time_range.get("end")),
        )

    # ------------------------------------------------------------ 술어

    def matches_path(self, path: str) -> bool:
        """경로가 범위 안인가. 접두어와 확장자를 함께 본다."""
        return self.matches_prefix(path) and self.matches_extension(path)

    def matches_prefix(self, path: str) -> bool:
        if not self.path_prefix:
            return True
        normalized = normalize_path(path)
        return any(path_in_prefix(normalized, prefix) for prefix in self.path_prefix)

    def matches_extension(self, path: str) -> bool:
        if not self.extensions:
            return True
        lowered = normalize_path(path)
        return any(lowered.endswith(extension) for extension in self.extensions)

    def matches_event_id(self, event_id: int) -> bool:
        return not self.event_ids or event_id in self.event_ids

    def matches_time(self, moment: datetime | None) -> bool:
        """시각이 범위 안인가. 시각을 모르면 통과시킨다.

        읽을 수 없는 타임스탬프 때문에 레코드를 버리면, 정작 그 이상함이
        증거인 경우를 놓칩니다(``zero_timestamp``).
        """
        if moment is None:
            return True
        if self.start is not None and moment < self.start:
            return False
        if self.end is not None and moment > self.end:
            return False
        return True

    def in_any_time(self, moments: "list[datetime | None]") -> bool:
        """여러 시각 중 하나라도 범위 안이면 통과.

        MFT 레코드는 타임스탬프가 여덟 개입니다. 생성은 범위 밖인데 수정이
        범위 안인 파일은 봐야 합니다.
        """
        usable = [m for m in moments if m is not None]
        return True if not usable else any(self.matches_time(m) for m in usable)


class Parser(Protocol):
    """모든 파서가 따르는 형태.

    ``artifact``는 ``mappings/_artifacts.yaml``의 이름과 정확히 같아야
    합니다. 이 값으로 ``ref`` 접두어와 출력 파일명이 정해집니다.
    """

    artifact: str

    def parse(self, stream: BinaryIO, scope: Scope) -> Iterator[dict[str, Any]]:
        """범위에 드는 레코드를 흘려보낸다.

        ``flags``는 넣지 않아도 됩니다(``flagging.py``가 붙입니다).
        리스트로 모으지 말고 ``yield`` 하십시오 — ``$MFT``는 레코드가
        수십만 건이라 전부 메모리에 올릴 수 없습니다.
        """
        ...
