"""RecentFileCache 파서 — Windows 7의 실행 흔적.

온디스크 구조는 우리 구현입니다(`structs/recentfilecache_record.py`).
외부 라이브러리가 없고, 구조 자체가 `$UsnJrnl`보다 단순합니다 — 헤더
20바이트 뒤에 "길이 + UTF-16 경로 + 종결자"가 이어질 뿐입니다.

## 이 파서가 존재하는 이유

`Amcache.hve`는 Windows 8부터입니다. Win7 이미지에서는 그 자리에
`RecentFileCache.bcf`가 있고, 지금까지 우리는 그것을 읽지 못했습니다.
어느 쪽이 있어야 하는지는 `osinfo.AVAILABILITY`가 판정합니다.

**Amcache의 축소판이 아니라 다른 아티팩트입니다.** Amcache는 경로·SHA1·
크기·컴파일 시각을 주지만 이쪽은 **경로뿐**입니다. "이 실행 파일이 이
시스템에 처음 등장했다"까지만 말할 수 있고, 언제인지는 파일 하나의
수정 시각이 전부입니다.

## 시각이 레코드에 없다

레코드에 ``timestamp``를 넣지 않습니다. 항목에 시각이 없기 때문입니다.
지어내지 않습니다 — 파일 수정 시각을 레코드마다 복사해 넣으면 "이
프로그램이 그때 실행됐다"로 읽히는데, 그것은 **파일 전체가 마지막으로
갱신된 시각**이지 이 항목의 시각이 아닙니다.

`registry` 파서의 "값에는 타임스탬프가 없다"와 같은 자리입니다
(`docs/limitations.md`). 05단계가 시간 없는 레코드를 다룰 수 있어야
한다는 요구가 이미 처리돼 있습니다(4-0-2).

## 신호는 경로에서 나온다

레지스트리·프리패치와 같습니다. 카탈로그에 ``signal_source: scope``로
적혀 있고, 여기서 붙일 플래그가 없습니다. 목록의 모든 항목이 "실행된
적 있는 파일"이라 그 사실 자체는 변별력이 없고, **어느 경로인가**가
신호입니다 — 03단계의 ``path_prefix``가 그 판단을 이미 끝냅니다.

## 대조하지 않았다

`structs/recentfilecache_record.py` 모듈 docstring을 보십시오. Windows 7
실물이 없어 **명세만 보고 짰습니다.** 어긋나면 그럴듯한 값을 내는 대신
거부하도록 짰지만, 그것이 "맞다"의 증명은 아닙니다.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from ...common import refs
from ..structs import recentfilecache_record as rfc
from .base import Scope

__all__ = ["RecentFileCacheParser", "ARTIFACT"]

_log = logging.getLogger(__name__)

#: 카탈로그(``mappings/_artifacts.yaml``)의 이름과 같아야 한다.
ARTIFACT = "recentfilecache"


class RecentFileCacheParser:
    """``RecentFileCache.bcf`` 하나를 레코드 여러 개로.

    파일 하나가 아티팩트 하나라 ``begin_artifact``가 필요 없습니다
    (프리패치와 다른 점). 그래도 두 번 돌릴 때를 위해 ``parse``가 집계를
    비우고 시작합니다 — 레지스트리 파서와 같은 규약입니다.
    """

    def __init__(self, artifact: str = ARTIFACT) -> None:
        self.artifact = artifact
        #: 04단계가 넣어 준다. 레코드에 원본 파일명을 남긴다.
        self.source_path: Path | None = None
        self.stats: dict[str, int] = self._new_stats()

    @staticmethod
    def _new_stats() -> dict[str, int]:
        return {
            "records": 0,
            "parse_errors": 0,
            "out_of_scope": 0,
            "duplicate_refs": 0,
            #: 구조가 어긋나 멈춘 뒤 남은 바이트. 07단계가 "부분 판독"으로 싣는다.
            "unreadable_bytes": 0,
        }

    def parse(self, stream: BinaryIO, scope: Scope) -> Iterator[dict[str, Any]]:
        """항목을 차례로 낸다.

        헤더가 아니면 **파일 전체를 거부합니다**(``ValueError``). 04단계가
        아티팩트 단위로 실패를 처리하고, 이 아티팩트는 파일이 하나라
        읽을 것이 더 없기 때문입니다 — 프리패치가 파일 하나를 건너뛰고
        다음으로 가는 것과 다릅니다.

        항목 중간에서 구조가 어긋나면 **거기까지 낸 것은 유지하고** 멈춥니다.
        남은 바이트는 ``unreadable_bytes``로 셉니다. 조용히 버리면 "여기서
        끝났다"와 "여기서부터 못 읽었다"가 구별되지 않습니다.
        """
        self.stats = self._new_stats()
        name = self.source_path.name if self.source_path else "RecentFileCache.bcf"

        data = stream.read()
        if not data:
            raise ValueError(f"{self.artifact}: 파일이 비어 있습니다")

        try:
            rfc.read_header(data)
        except rfc.RecentFileCacheError as e:
            raise ValueError(f"{self.artifact}: {e}") from e

        seen: set[int] = set()
        cursor = rfc.HEADER_SIZE
        try:
            for entry in rfc.read_entries(data):
                cursor = entry.end
                record = self._build(entry, name, scope, seen)
                if record is not None:
                    self.stats["records"] += 1
                    yield record
        except rfc.RecentFileCacheError as e:
            # 구조가 어긋났다. 앞의 항목은 이미 나갔고, 여기부터는 못 읽는다.
            self.stats["parse_errors"] += 1
            self.stats["unreadable_bytes"] = len(data) - cursor
            _log.warning(
                "%s: %s 오프셋 0x%X 부터 %d바이트를 읽지 못했습니다 — %s",
                self.artifact,
                name,
                cursor,
                len(data) - cursor,
                e,
            )
            return

        # 정상 종료. 길이 필드 하나가 안 들어가는 꼬리는 패딩이라 보고
        # 세지 않는다 — 항목이 될 수 없는 크기다.
        remainder = len(data) - cursor
        if remainder >= rfc.LENGTH_FIELD_SIZE:
            self.stats["unreadable_bytes"] = remainder
            _log.warning(
                "%s: %s 끝에 %d바이트가 남았습니다 (항목으로 읽지 못함)",
                self.artifact,
                name,
                remainder,
            )

    # ------------------------------------------------------------ 레코드

    def _build(
        self, entry: rfc.Entry, name: str, scope: Scope, seen: set[int]
    ) -> "dict[str, Any] | None":
        if not scope.matches_path(entry.path):
            self.stats["out_of_scope"] += 1
            return None

        # 오프셋이 항목 안에서 유일한 값이다. 같은 값이 두 번 나오는 것은
        # 구조상 불가능하지만, 겹치면 05·06단계가 서므로 확인은 한다
        # (레지스트리·프리패치와 같은 규약).
        if entry.offset in seen:
            self.stats["duplicate_refs"] += 1
            return None
        seen.add(entry.offset)

        return {
            "ref": refs.make_ref(self.artifact, entry.offset),
            "artifact": self.artifact,
            "record_num": entry.offset,
            "offset": f"0x{entry.offset:X}",
            # 경로의 마지막 조각. $MFT·프리패치의 name 과 같은 뜻이다.
            "name": entry.path.rsplit("\\", 1)[-1],
            # **디스크에 있는 그대로다.** 대소문자를 접거나 구분자를 바꾸지
            # 않는다 — 비교는 normalize_path 가 양쪽에 적용하므로($MFT·
            # 프리패치와 같은 규약) 여기서 손대면 원본과 다른 값을 남기게 된다.
            "path": entry.path,
            "fields": {"source_file": name},
        }
