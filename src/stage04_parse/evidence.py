"""증거 접근 계층.

파서는 **증거가 어떤 형태로 왔는지 몰라야 합니다.** ``$MFT``를 파싱하는
코드가 "이게 추출된 파일인가, dd 이미지 속인가, E01 안인가"를 신경 쓰면
형식이 늘어날 때마다 모든 파서를 고쳐야 합니다. 접점을 하나로 좁힙니다.

    아티팩트 이름  →  읽을 수 있는 바이트 스트림

## 한 실행은 한 볼륨만 본다

``--evidence``는 **볼륨 루트**를 가리킵니다. KAPE 출력이라면
``<수집폴더>/C`` 이지 ``<수집폴더>`` 가 아닙니다.

볼륨이 여러 개면 케이스를 나눠 각각 돌립니다(``C-001-C``, ``C-001-D``).
도구가 어느 볼륨인지 추측하지 않게 하는 것이 목적입니다. 추측하고
기록으로 때우는 것보다 추측할 상황을 안 만드는 편이 낫습니다.

이 규칙 덕분에 ``ref``가 유일해집니다. 두 볼륨을 한 번에 읽으면
``MFT#12345``가 양쪽에 존재해 06단계가 어느 레코드를 검증했는지 알 수
없게 됩니다.

## 아티팩트를 이름이 아니라 경로로 찾는다

``SYSTEM``은 흔한 파일명입니다. 이름만으로 찾으면 사용자 다운로드 폴더의
동명 파일이 하이브를 선점할 수 있습니다. 그래서 볼륨 안에서의 제자리를
먼저 봅니다.

======================  =========================================
찾는 순서                예 (``registry:SYSTEM``)
======================  =========================================
1. 볼륨 기준 경로        ``Windows/System32/config/SYSTEM``
2. 루트 바로 아래 이름    ``SYSTEM`` (추출된 파일만 모아 둔 폴더)
3. 재귀 검색            마지막 수단. 정렬해 결정론적으로 고른다
======================  =========================================

3번까지 갔는데 후보가 여럿이면 **고른 것과 안 고른 것을 함께 돌려줍니다.**
매니페스트에 남아 나중에 되짚을 수 있습니다.

## 지원 계획

======================  ==========  ==========================================
형식                     상태        비고
======================  ==========  ==========================================
추출된 파일 단위          **구현**    볼륨 구조 보존형과 평탄형 모두
raw dd 이미지            미구현      파티션 테이블 → NTFS 부트섹터 → ``$MFT``
E01 / AFF4              미구현      ``pyewf``로 열어 raw처럼 다룸
======================  ==========  ==========================================

raw와 E01은 결국 같습니다. **E01은 raw로 펼쳐지는 컨테이너**이므로
``pyewf`` 핸들을 파일 같은 객체로 감싸면 ``VolumeSource``가 그대로 씁니다.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

__all__ = [
    "EvidenceError",
    "ArtifactNotFound",
    "NotAVolumeRoot",
    "ArtifactLocation",
    "Located",
    "EvidenceSource",
    "FileSource",
    "VolumeSource",
    "open_source",
    "FILE_LAYOUT",
    "MAX_SEARCH_MATCHES",
]


class EvidenceError(RuntimeError):
    """증거를 열 수 없다."""


class ArtifactNotFound(EvidenceError):
    """요청한 아티팩트가 이 볼륨에 없다.

    실패가 아니라 **정보**다. 선별이 요청했는데 수집되지 않은 경우이며,
    보고서의 "분석 범위 한계"에 실려야 한다. 조용히 빈 결과를 내면
    "봤는데 없었다"와 "아예 못 봤다"가 구별되지 않는다.
    """


class NotAVolumeRoot(EvidenceError):
    """볼륨 루트가 아니라 볼륨들을 담은 폴더를 지정했다.

    사용자가 가장 실수하기 쉬운 지점이라 안내를 메시지에 담는다.
    """


#: 재귀 검색에서 모을 후보 수 상한. 넘으면 거기서 멈춘다.
MAX_SEARCH_MATCHES = 8

#: 볼륨으로 보이는 폴더 이름. ``C``, ``C:``, ``C%3A``, ``C_``.
_VOLUME_DIR = re.compile(r"^[A-Za-z](:|%3[Aa]|_)?$")

#: 볼륨 루트 여부를 판정할 때 훑을 하위 폴더 수 상한.
_MAX_ROOT_ENTRIES = 200


@dataclass(frozen=True)
class ArtifactLocation:
    """볼륨 안에서 아티팩트가 있어야 할 자리."""

    #: 볼륨 루트 기준 경로. ``/`` 로 구분한다.
    relative_paths: tuple[str, ...]
    #: 평탄한 폴더용 파일명 후보. 수집 도구마다 이름이 다르다.
    filenames: tuple[str, ...]


#: 아티팩트 이름 → 있어야 할 자리.
#:
#: ``$UsnJrnl:$J``는 콜론이 파일명에 못 들어가 도구마다 다르게 저장된다.
FILE_LAYOUT: dict[str, ArtifactLocation] = {
    "$MFT": ArtifactLocation(
        relative_paths=("$MFT",),
        filenames=("$MFT", "MFT", "$MFT.bin", "mft.raw"),
    ),
    "$UsnJrnl": ArtifactLocation(
        relative_paths=(
            "$Extend/$UsnJrnl$J",
            "$Extend/$UsnJrnl%3A%24J",
            "$Extend/$J",
            "$Extend/$UsnJrnl",
        ),
        filenames=("$UsnJrnl$J", "$J", "$UsnJrnl", "UsnJrnl.bin"),
    ),
    "evtx:Security": ArtifactLocation(
        relative_paths=("Windows/System32/winevt/Logs/Security.evtx",),
        filenames=("Security.evtx",),
    ),
    "evtx:System": ArtifactLocation(
        relative_paths=("Windows/System32/winevt/Logs/System.evtx",),
        filenames=("System.evtx",),
    ),
    "registry:SYSTEM": ArtifactLocation(
        relative_paths=("Windows/System32/config/SYSTEM",),
        filenames=("SYSTEM", "SYSTEM.hiv"),
    ),
    "registry:SOFTWARE": ArtifactLocation(
        relative_paths=("Windows/System32/config/SOFTWARE",),
        filenames=("SOFTWARE", "SOFTWARE.hiv"),
    ),
}


@dataclass(frozen=True)
class Located:
    """찾아낸 아티팩트와 **어떻게 찾았는지**.

    매니페스트에 남겨 나중에 "이 결과가 어느 파일에서 나왔나"를 되짚습니다.
    ``method``가 ``search``면 제자리에 없던 것이므로 한 번 확인해 볼 값입니다.
    """

    path: Path
    #: ``volume_path`` / ``root_file`` / ``search``
    method: str
    #: 고르지 않은 후보. 재귀 검색에서만 생긴다.
    alternates: tuple[Path, ...] = ()


class EvidenceSource(Protocol):
    """아티팩트 이름을 바이트 스트림으로 바꿔 주는 것."""

    def open(self, artifact: str) -> BinaryIO: ...

    def available(self) -> list[str]: ...

    def locate(self, artifact: str) -> Located | None: ...

    def describe(self) -> str: ...


def _resolve(base: Path, relative: str) -> Path | None:
    """볼륨 루트 기준 경로를 실제 파일로 해석한다. 대소문자를 무시한다.

    NTFS는 대소문자를 구별하지 않지만, 추출 결과를 리눅스에서 분석하면
    파일시스템이 구별합니다. 정확한 철자를 먼저 시도하고(``stat`` 한 번),
    실패했을 때만 한 단계씩 훑습니다.
    """
    direct = base / relative
    try:
        if direct.is_file():
            return direct
    except OSError:
        return None

    current = base
    for part in relative.split("/"):
        if not current.is_dir():
            return None
        try:
            children = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            return None
        lowered = part.lower()
        match = next((child for child in children if child.name.lower() == lowered), None)
        if match is None:
            return None
        current = match
    return current if current.is_file() else None


class FileSource:
    """추출된 아티팩트가 담긴 **볼륨 루트 하나**.

    두 가지 모양을 모두 받습니다.

    - 볼륨 구조 보존형 — ``<root>/Windows/System32/config/SYSTEM``
    - 평탄형 — ``<root>/SYSTEM`` (필요한 파일만 모아 둔 폴더)
    """

    def __init__(self, root: str | os.PathLike[str], *, max_search: int = MAX_SEARCH_MATCHES) -> None:
        self.root = Path(root)
        if not self.root.is_dir():
            raise EvidenceError(f"증거 폴더 없음: {self.root}")
        self.max_search = max_search
        self._cache: dict[str, Located | None] = {}

    def describe(self) -> str:
        return f"파일 단위 볼륨 ({self.root})"

    def open(self, artifact: str) -> BinaryIO:
        found = self.locate(artifact)
        if found is None:
            location = FILE_LAYOUT.get(artifact)
            expected = ", ".join(location.relative_paths) if location else "등록 안 됨"
            raise ArtifactNotFound(
                f"{artifact}: {self.root} 에서 찾지 못함 (기대 위치: {expected})"
            )
        return found.path.open("rb")

    def available(self) -> list[str]:
        """제자리 또는 루트에서 바로 찾을 수 있는 아티팩트.

        재귀 검색은 하지 않습니다. 목록을 보려고 폴더 전체를 훑는 것은
        비쌉니다.
        """
        return [name for name in FILE_LAYOUT if self._probe(name) is not None]

    def locate(self, artifact: str) -> Located | None:
        """아티팩트를 찾는다. 결과는 캐시된다."""
        if artifact not in self._cache:
            self._cache[artifact] = self._probe(artifact) or self._search(artifact)
        return self._cache[artifact]

    def path_of(self, artifact: str) -> Path | None:
        found = self.locate(artifact)
        return found.path if found else None

    # ------------------------------------------------------------ 내부

    def _probe(self, artifact: str) -> Located | None:
        """``stat`` 몇 번으로 끝나는 빠른 경로.

        폴더 크기와 무관합니다. 10만 개 파일이 있어도 비용이 같습니다.
        """
        location = FILE_LAYOUT.get(artifact)
        if location is None:
            return None

        for relative in location.relative_paths:
            found = _resolve(self.root, relative)
            if found is not None:
                return Located(path=found, method="volume_path")

        for filename in location.filenames:
            found = _resolve(self.root, filename)
            if found is not None:
                return Located(path=found, method="root_file")
        return None

    def _search(self, artifact: str) -> Located | None:
        """마지막 수단. 폴더 전체를 훑되 정렬해 결정론적으로 고른다.

        ``os.walk``의 순서는 파일시스템에 의존합니다. 정렬하지 않으면
        같은 증거를 Windows와 Linux에서 돌렸을 때 다른 파일이 선택될 수
        있습니다. 포렌식 도구에서 재현성이 깨지는 것은 성능 문제와 급이
        다릅니다.

        얕은 것을 먼저 고릅니다. 깊이 묻힌 것보다 원본일 가능성이 높습니다.
        """
        location = FILE_LAYOUT.get(artifact)
        if location is None:
            return None
        wanted = {name.lower() for name in location.filenames}

        matches: list[tuple[int, str, Path]] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames.sort()
            here = Path(dirpath)
            depth = len(here.relative_to(self.root).parts)
            for filename in sorted(filenames):
                if filename.lower() in wanted:
                    matches.append((depth, filename.lower(), here / filename))
            if len(matches) >= self.max_search:
                break

        if not matches:
            return None
        matches.sort(key=lambda item: (item[0], str(item[2]).lower()))
        return Located(
            path=matches[0][2],
            method="search",
            alternates=tuple(item[2] for item in matches[1:]),
        )


class VolumeSource:
    """디스크 이미지 안의 NTFS 볼륨. **미구현.**

    raw dd와 E01이 여기로 모입니다. 생성자가 파일 같은 객체를 받으므로
    E01은 ``pyewf`` 핸들을 넘기면 되고 볼륨 해석 코드는 공유됩니다.

    구현할 때 할 일:

    1. 파티션 테이블(MBR 또는 GPT)에서 NTFS 파티션 시작 오프셋을 찾는다
    2. 부트섹터에서 클러스터 크기와 ``$MFT`` 시작 클러스터를 읽는다
    3. ``$MFT`` 레코드 0의 ``$DATA`` 런리스트로 전체 위치를 안다
    4. ``open()``이 그 런리스트를 따라 읽는 파일 같은 객체를 돌려준다

    4번을 통째로 메모리에 올리지 않는 것이 중요합니다. ``$MFT``는 수백
    MB가 되고, 다른 아티팩트를 꺼내려면 볼륨을 계속 들고 있어야 합니다.

    파티션이 여럿이면 **하나만 열도록** 하십시오. 한 실행은 한 볼륨입니다.
    """

    def __init__(self, stream: BinaryIO, *, description: str = "볼륨") -> None:
        self.stream = stream
        self.description = description

    def describe(self) -> str:
        return self.description

    def open(self, artifact: str) -> BinaryIO:
        raise NotImplementedError(
            "VolumeSource 미구현. 현재는 추출된 파일 단위(FileSource)만 지원합니다. "
            "구현 순서는 이 클래스의 docstring 참조."
        )

    def available(self) -> list[str]:
        raise NotImplementedError("VolumeSource 미구현")

    def locate(self, artifact: str) -> Located | None:
        raise NotImplementedError("VolumeSource 미구현")


def volume_candidates(root: Path) -> list[str]:
    """볼륨으로 보이는 하위 폴더 이름. 안내 메시지에 쓴다."""
    try:
        children = sorted(root.iterdir(), key=lambda p: p.name)[:_MAX_ROOT_ENTRIES]
    except OSError:
        return []
    return [child.name for child in children if child.is_dir() and _VOLUME_DIR.match(child.name)]


def open_source(root: str | os.PathLike[str]) -> EvidenceSource:
    """증거 경로를 보고 알맞은 소스를 만든다.

    볼륨들을 담은 폴더를 지정하면 어느 볼륨인지 안내하고 실패합니다.
    사용자가 가장 실수하기 쉬운 지점이라, 혼란스러운 결과 대신 행동 가능한
    메시지를 냅니다.
    """
    path = Path(root)
    if path.is_file():
        raise EvidenceError(
            f"{path}: 디스크 이미지 파싱은 아직 미구현입니다. "
            "추출된 아티팩트가 담긴 볼륨 폴더를 지정하십시오. "
            "(지원 계획은 src/stage04_parse/evidence.py 참조)"
        )
    if not path.is_dir():
        raise EvidenceError(f"증거 경로 없음: {path}")

    source = FileSource(path)
    if source.available():
        return source

    volumes = volume_candidates(path)
    if volumes:
        suggestions = "\n".join(f"    --evidence {path / name}" for name in volumes)
        raise NotAVolumeRoot(
            f"{path}: 볼륨 루트가 아닙니다.\n"
            f"  볼륨으로 보이는 하위 폴더: {', '.join(volumes)}\n"
            "  한 실행은 한 볼륨만 봅니다. 볼륨 하나를 지정하십시오:\n"
            f"{suggestions}\n"
            "  볼륨이 여럿이면 케이스를 나눕니다 (C-001-C, C-001-D)."
        )
    return source
