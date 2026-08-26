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

## 아티팩트가 파일 하나라고 가정하지 않는다

``prefetch``는 **폴더 하나에 든 .pf 전부가 아티팩트 하나**입니다. 그래서
접점이 하나 더 있습니다.

    아티팩트 이름  →  읽을 수 있는 바이트 스트림 **여러 개**

``open_all``이 그것이고, 파일 아티팩트에서는 하나만 나옵니다. 04단계는
항상 이 쪽을 쓰므로 두 종류를 구별하지 않아도 됩니다. 반대로 ``open``은
폴더 아티팩트를 **거부합니다** — 아무거나 하나를 골라 주면 나머지가
조용히 빠진 결과가 "프리패치 1건"으로 보고됩니다.

## 지원 계획

======================  ==========  ==========================================
형식                     상태        비고
======================  ==========  ==========================================
추출된 파일 단위          **구현**    볼륨 구조 보존형과 평탄형 모두
raw dd 이미지            **구현**    ``dissect.target`` 이 볼륨 계층을 맡는다
E01 / AFF4              미검증      같은 경로(``dissect.evidence``) — 실물 확인 전
======================  ==========  ==========================================

raw와 E01은 결국 같습니다. **E01은 raw로 펼쳐지는 컨테이너**이므로
``pyewf`` 핸들을 파일 같은 객체로 감싸면 ``VolumeSource``가 그대로 씁니다.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator, NoReturn, Protocol

__all__ = [
    "EvidenceError",
    "ArtifactNotFound",
    "EmptyArtifact",
    "NotAVolumeRoot",
    "ArtifactLocation",
    "Located",
    "Opened",
    "EvidenceSource",
    "FileSource",
    "VolumeSource",
    "open_source",
    "FILE_LAYOUT",
    "VOLUME_PATH_OVERRIDES",
    "MAX_SEARCH_MATCHES",
    "MAX_DIRECTORY_FILES",
]

_log = logging.getLogger(__name__)


class EvidenceError(RuntimeError):
    """증거를 열 수 없다."""


class ArtifactNotFound(EvidenceError):
    """요청한 아티팩트가 이 볼륨에 없다.

    실패가 아니라 **정보**다. 선별이 요청했는데 수집되지 않은 경우이며,
    보고서의 "분석 범위 한계"에 실려야 한다. 조용히 빈 결과를 내면
    "봤는데 없었다"와 "아예 못 봤다"가 구별되지 않는다.
    """


class EmptyArtifact(ArtifactNotFound):
    """아티팩트 파일이 있기는 한데 **0바이트**다.

    ``ArtifactNotFound``를 상속하는 이유는 04단계의 처리가 같아야 하기
    때문이다 — 읽지 못했으므로 건너뛰고 기록한다. 다만 **원인이 다르므로
    메시지를 나눈다.** "수집되지 않음"과 "수집됐는데 알맹이가 없음"은
    분석가가 취할 조치가 다르다. 후자는 추출을 다시 해야 한다.

    실제로 밟은 경우: ``$UsnJrnl:$J``는 콜론이 파일명에 못 들어가
    도구마다 다르게 저장되는데, 어떤 추출본은 **이름 없는 ``$DATA``
    스트림(0바이트)을 ``$Extend/$UsnJrnl``로 쓰고 실제 저널은 ``$J``라는
    별도 파일로** 내놓는다. 0바이트를 유효한 후보로 받아들이면 30만 건이
    든 진짜 저널을 옆에 두고 "레코드 0건"을 보고하게 된다.
    """


class NotAVolumeRoot(EvidenceError):
    """볼륨 루트가 아니라 볼륨들을 담은 폴더를 지정했다.

    사용자가 가장 실수하기 쉬운 지점이라 안내를 메시지에 담는다.
    """


#: 재귀 검색에서 모을 후보 수 상한. 넘으면 거기서 멈춘다.
MAX_SEARCH_MATCHES = 8

#: 디렉터리 아티팩트에서 열 파일 수 상한.
#:
#: 프리패치는 Windows가 128개로 제한하지만(Win8 이후 1024), 수집본에는
#: 여러 시점의 것이 섞여 더 많을 수 있습니다. 넉넉히 잡되 상한은 둡니다 —
#: 엉뚱한 폴더를 가리켰을 때 수만 개를 열고 앉아 있지 않게 합니다.
MAX_DIRECTORY_FILES = 4096

#: 볼륨으로 보이는 폴더 이름. ``C``, ``C:``, ``C%3A``, ``C_``.
_VOLUME_DIR = re.compile(r"^[A-Za-z](:|%3[Aa]|_)?$")

#: 볼륨 루트 여부를 판정할 때 훑을 하위 폴더 수 상한.
_MAX_ROOT_ENTRIES = 200


@dataclass(frozen=True)
class ArtifactLocation:
    """볼륨 안에서 아티팩트가 있어야 할 자리.

    대부분의 아티팩트는 **파일 하나**입니다(``$MFT``, 하이브, evtx). 그런
    것은 ``relative_paths``와 ``filenames``만 씁니다.

    프리패치는 다릅니다 — **폴더 하나에 든 .pf 파일 전부가 아티팩트
    하나**입니다. 그 경우 ``directory_paths``와 ``directory_suffix``를
    쓰고, 앞의 둘은 비웁니다.
    """

    #: 볼륨 루트 기준 경로. ``/`` 로 구분한다.
    relative_paths: tuple[str, ...] = ()
    #: 평탄한 폴더용 파일명 후보. 수집 도구마다 이름이 다르다.
    filenames: tuple[str, ...] = ()
    #: 디렉터리 아티팩트의 볼륨 기준 폴더 후보.
    directory_paths: tuple[str, ...] = ()
    #: 그 폴더에서 아티팩트로 볼 파일의 확장자(소문자).
    directory_suffix: str = ""

    @property
    def is_directory(self) -> bool:
        return bool(self.directory_suffix)


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
    # 채널 이름의 '/' 는 온디스크에서 %4 로 인코딩된다. 추출 도구가
    # 그대로 두는 경우와 풀어 쓰는 경우가 있어 후보를 둘 다 둔다.
    "evtx:Firewall": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/"
            "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
        ),
        filenames=(
            "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
            "Microsoft-Windows-Windows Firewall With Advanced Security-Firewall.evtx",
        ),
    ),
    "evtx:BITS": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/Microsoft-Windows-Bits-Client%4Operational.evtx",
        ),
        filenames=(
            "Microsoft-Windows-Bits-Client%4Operational.evtx",
            "Microsoft-Windows-Bits-Client-Operational.evtx",
        ),
    ),
    "evtx:NetworkProfile": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/Microsoft-Windows-NetworkProfile%4Operational.evtx",
        ),
        filenames=(
            "Microsoft-Windows-NetworkProfile%4Operational.evtx",
            "Microsoft-Windows-NetworkProfile-Operational.evtx",
        ),
    ),
    "evtx:Sysmon": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
        ),
        filenames=(
            "Microsoft-Windows-Sysmon%4Operational.evtx",
            "Microsoft-Windows-Sysmon-Operational.evtx",
        ),
    ),
    "evtx:DriverFrameworks": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
        ),
        filenames=(
            "Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
            "Microsoft-Windows-DriverFrameworks-UserMode-Operational.evtx",
        ),
    ),
    "evtx:KernelPnP": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/Microsoft-Windows-Kernel-PnP%4Configuration.evtx",
        ),
        filenames=(
            "Microsoft-Windows-Kernel-PnP%4Configuration.evtx",
            "Microsoft-Windows-Kernel-PnP-Configuration.evtx",
        ),
    ),
    "evtx:AssignedAccess": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/Microsoft-Windows-AssignedAccess%4Operational.evtx",
        ),
        filenames=(
            "Microsoft-Windows-AssignedAccess%4Operational.evtx",
            "Microsoft-Windows-AssignedAccess-Operational.evtx",
        ),
    ),
    "evtx:AssignedAccessAdmin": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/Microsoft-Windows-AssignedAccess%4Admin.evtx",
        ),
        filenames=(
            "Microsoft-Windows-AssignedAccess%4Admin.evtx",
            "Microsoft-Windows-AssignedAccess-Admin.evtx",
        ),
    ),
    "evtx:AssignedAccessBroker": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/Microsoft-Windows-AssignedAccessBroker%4Operational.evtx",
        ),
        filenames=(
            "Microsoft-Windows-AssignedAccessBroker%4Operational.evtx",
            "Microsoft-Windows-AssignedAccessBroker-Operational.evtx",
        ),
    ),
    "evtx:RDPConnection": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
        ),
        filenames=(
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager-Operational.evtx",
        ),
    ),
    "evtx:RDPSession": ArtifactLocation(
        relative_paths=(
            "Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
        ),
        filenames=(
            "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
            "Microsoft-Windows-TerminalServices-LocalSessionManager-Operational.evtx",
        ),
    ),
    # 채널 이름에 '/' 가 없어 %4 인코딩이 없다. Security·System 과 같은 모양이다.
    "evtx:Application": ArtifactLocation(
        relative_paths=("Windows/System32/winevt/Logs/Application.evtx",),
        filenames=("Application.evtx",),
    ),
    "registry:SYSTEM": ArtifactLocation(
        relative_paths=("Windows/System32/config/SYSTEM",),
        filenames=("SYSTEM", "SYSTEM.hiv"),
    ),
    "registry:SOFTWARE": ArtifactLocation(
        relative_paths=("Windows/System32/config/SOFTWARE",),
        filenames=("SOFTWARE", "SOFTWARE.hiv"),
    ),
    "registry:Amcache": ArtifactLocation(
        relative_paths=("Windows/AppCompat/Programs/Amcache.hve",),
        filenames=("Amcache.hve",),
    ),
    # Amcache 와 같은 폴더에 있다. Windows 7 에만 있고 Win8 부터는 없다 —
    # **어느 쪽을 찾아 나설지는 여기가 아니라 osinfo 가 정한다.** 이 표는
    # "있다면 어디에"만 안다.
    "recentfilecache": ArtifactLocation(
        relative_paths=("Windows/AppCompat/Programs/RecentFileCache.bcf",),
        filenames=("RecentFileCache.bcf",),
    ),
    # 유일한 디렉터리 아티팩트다. 폴더 안의 .pf 전부가 아티팩트 하나이며,
    # 파일마다 레코드가 하나씩 나온다.
    "prefetch": ArtifactLocation(
        directory_paths=("Windows/Prefetch", "Prefetch"),
        directory_suffix=".pf",
    ),
}

#: ``VolumeSource``에서만 쓰는 대체 경로. ``FILE_LAYOUT.relative_paths``는
#: 추출 도구가 콜론을 못 써서 벌어지는 이름 변형을 담는데, 원본 볼륨은
#: NTFS ADS 콜론 문법을 그대로 갖고 있다 — ``$Extend/$UsnJrnl:$J``처럼.
#: 여기 있는 경로를 ``relative_paths``보다 먼저 시도한다.
#: ``FileSource``는 이 테이블을 보지 않는다 — 추출 폴더의 동작을
#: 바꾸지 않기 위해서다.
VOLUME_PATH_OVERRIDES: dict[str, tuple[str, ...]] = {
    "$UsnJrnl": ("$Extend/$UsnJrnl:$J",),
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
    #: 있었지만 0바이트라 건너뛴 후보.
    #:
    #: 버리지 않고 남기는 이유는 **추출이 잘못됐다는 진단**이기 때문이다.
    #: 이 값이 비어 있지 않으면 같은 증거를 다시 뽑을 때 고쳐야 할 지점이
    #: 있다는 뜻이고, 매니페스트에 실려 나중에 되짚을 수 있어야 한다.
    empty_candidates: tuple[Path, ...] = ()


@dataclass(frozen=True)
class Opened:
    """열린 스트림과 그것이 온 파일.

    파서가 "지금 읽는 것이 어느 파일인가"를 알아야 할 때가 있습니다.
    프리패치 레코드는 ``fields.prefetch_file``에 원본 파일명을 담고,
    헤더 안의 해시를 그 이름과 대조합니다.
    """

    path: Path
    stream: BinaryIO


class EvidenceSource(Protocol):
    """아티팩트 이름을 바이트 스트림으로 바꿔 주는 것."""

    def open(self, artifact: str) -> BinaryIO: ...

    def open_all(self, artifact: str) -> "Iterator[Opened]": ...

    def available(self) -> list[str]: ...

    def locate(self, artifact: str) -> Located | None: ...

    def locate_all(self, artifact: str) -> "tuple[Located, ...]": ...

    def describe(self) -> str: ...


def _is_empty(path: Path) -> bool:
    """0바이트인가. 읽을 수 없으면 비었다고 보지 않는다.

    권한 문제로 ``stat``이 실패한 것을 "비었다"로 처리하면, 읽을 수 있었을
    파일을 조용히 건너뛰게 됩니다. 판단이 서지 않으면 후보로 남깁니다.
    """
    try:
        return path.stat().st_size == 0
    except OSError:
        return False


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


def _resolve_directory(base: Path, relative: str) -> Path | None:
    """``_resolve``의 폴더판. 마지막이 파일이 아니라 폴더여야 한다."""
    direct = base / relative
    try:
        if direct.is_dir():
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
    return current if current.is_dir() else None


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
        #: 아티팩트 → 매니페스트에 적을 출처. 파일 아티팩트는 그 파일,
        #: 디렉터리 아티팩트는 그 폴더다.
        self._cache: dict[str, Located | None] = {}
        #: 아티팩트 → **열 파일들.** 파일 아티팩트는 0개나 1개다.
        self._files: dict[str, tuple[Located, ...]] = {}
        #: 디렉터리 아티팩트를 찾아낸 폴더.
        self._directories: dict[str, Located] = {}
        #: 아티팩트별로 "있었지만 0바이트라 건너뛴" 후보.
        self._empties: dict[str, tuple[Path, ...]] = {}

    def describe(self) -> str:
        return f"파일 단위 볼륨 ({self.root})"

    def open(self, artifact: str) -> BinaryIO:
        """아티팩트 하나를 연다. **파일 아티팩트 전용이다.**

        디렉터리 아티팩트에는 "그 파일"이 없으므로 여기서 거부합니다.
        아무거나 하나를 골라 돌려주면 나머지가 조용히 빠진 결과가 나오고,
        그것이 "프리패치 1건"으로 보고됩니다.
        """
        location = FILE_LAYOUT.get(artifact)
        if location is not None and location.is_directory:
            raise EvidenceError(
                f"{artifact}: 파일 하나가 아니라 폴더 단위 아티팩트입니다. "
                "open_all() 로 여십시오."
            )

        found = self.locate(artifact)
        if found is None:
            self._raise_not_found(artifact)

        if found.empty_candidates:
            # 진짜 파일은 찾았지만 껍데기도 있었다. 추출본의 특성이므로
            # 알려 두면 다음 수집에서 고칠 수 있다.
            names = ", ".join(str(p.relative_to(self.root)) for p in found.empty_candidates)
            _log.warning(
                "%s: 0바이트 후보를 건너뛰고 %s 를 씁니다 (건너뛴 것: %s)",
                artifact,
                found.path.relative_to(self.root),
                names,
            )
        return found.path.open("rb")

    def open_all(self, artifact: str) -> Iterator[Opened]:
        """아티팩트를 이루는 **모든** 파일을 차례로 연다.

        파일 아티팩트면 하나, 디렉터리 아티팩트면 폴더 안의 파일 수만큼
        나옵니다. 04단계는 항상 이 쪽을 씁니다 — 두 종류를 한 경로로
        다루면 새 디렉터리 아티팩트가 생겨도 파이프라인은 그대로입니다.

        **찾지 못한 것은 여기서 바로 실패합니다.** 생성기 안에서 늦게
        터지면 이미 열린 출력 파일을 남긴 채 죽습니다.
        """
        found = self.locate_all(artifact)
        if not found:
            self._raise_not_found(artifact)
        return self._streams(found)

    @staticmethod
    def _streams(found: "tuple[Located, ...]") -> Iterator[Opened]:
        for item in found:
            with item.path.open("rb") as stream:
                yield Opened(path=item.path, stream=stream)

    def _raise_not_found(self, artifact: str) -> "NoReturn":
        """왜 못 읽었는지 나눠서 올린다. 조치가 다르기 때문이다."""
        empties = self._empties.get(artifact, ())
        if empties:
            # 파일은 있는데 전부 0바이트다. "수집 안 됨"과 원인이 다르고
            # 조치도 다르므로 메시지를 나눈다.
            names = ", ".join(str(p.relative_to(self.root)) for p in empties)
            raise EmptyArtifact(
                f"{artifact}: 파일은 있으나 0바이트입니다 ({names}). "
                "추출이 잘못됐을 가능성이 높습니다 — 내용이 이름 있는 "
                "스트림(예: $UsnJrnl:$J)에 있는데 이름 없는 $DATA 를 "
                "뽑았거나, 수집 중 잘렸습니다. 다시 추출하십시오."
            )
        location = FILE_LAYOUT.get(artifact)
        if location is None:
            expected = "등록 안 됨"
        elif location.is_directory:
            expected = ", ".join(f"{d}/*{location.directory_suffix}" for d in location.directory_paths)
        else:
            expected = ", ".join(location.relative_paths)
        raise ArtifactNotFound(f"{artifact}: {self.root} 에서 찾지 못함 (기대 위치: {expected})")

    def available(self) -> list[str]:
        """제자리 또는 루트에서 바로 찾을 수 있는 아티팩트.

        재귀 검색은 하지 않습니다. 목록을 보려고 폴더 전체를 훑는 것은
        비쌉니다.
        """
        return [name for name in FILE_LAYOUT if self._probe(name)]

    def locate(self, artifact: str) -> Located | None:
        """매니페스트에 적을 출처. 디렉터리 아티팩트면 **그 폴더**다."""
        self._resolve(artifact)
        return self._cache[artifact]

    def locate_all(self, artifact: str) -> "tuple[Located, ...]":
        """열어야 할 파일들. 파일 아티팩트면 0개나 1개."""
        self._resolve(artifact)
        return self._files[artifact]

    def _resolve(self, artifact: str) -> None:
        """찾아서 캐시에 넣는다. 두 캐시는 항상 같이 채워진다."""
        if artifact in self._cache:
            return
        found = self._probe(artifact) or self._search(artifact)
        self._files[artifact] = found
        location = FILE_LAYOUT.get(artifact)
        if location is not None and location.is_directory:
            self._cache[artifact] = self._directories.get(artifact)
        else:
            self._cache[artifact] = found[0] if found else None

    def path_of(self, artifact: str) -> Path | None:
        found = self.locate(artifact)
        return found.path if found else None

    # ------------------------------------------------------------ 내부

    def _probe(self, artifact: str) -> "tuple[Located, ...]":
        """``stat`` 몇 번으로 끝나는 빠른 경로.

        폴더 크기와 무관합니다. 10만 개 파일이 있어도 비용이 같습니다.

        **0바이트 후보는 건너뜁니다.** 이 아티팩트들에 빈 파일은 유효한
        값이 아니라 추출 실패의 흔적입니다. 여기서 멈추면 뒤에 있는 진짜
        파일에 도달하지 못합니다(``EmptyArtifact`` 참조).
        """
        location = FILE_LAYOUT.get(artifact)
        if location is None:
            return ()
        if location.is_directory:
            return self._probe_directory(artifact, location)

        empties: list[Path] = []

        for relative in location.relative_paths:
            found = _resolve(self.root, relative)
            if found is None:
                continue
            if _is_empty(found):
                empties.append(found)
                continue
            return (Located(path=found, method="volume_path", empty_candidates=tuple(empties)),)

        for filename in location.filenames:
            found = _resolve(self.root, filename)
            if found is None or found in empties:
                continue
            if _is_empty(found):
                empties.append(found)
                continue
            return (Located(path=found, method="root_file", empty_candidates=tuple(empties)),)

        # 후보를 찾긴 했으나 전부 비었다. _search 가 이어받을 수 있도록
        # 여기서는 빈 값을 내되, 무엇이 비었는지는 남긴다.
        self._empties[artifact] = tuple(empties)
        return ()

    def _probe_directory(
        self, artifact: str, location: ArtifactLocation
    ) -> "tuple[Located, ...]":
        """제자리 폴더에서 확장자가 맞는 파일을 전부 모은다.

        **파일 이름순으로 고정합니다.** ``iterdir``의 순서는 파일시스템에
        의존하므로, 정렬하지 않으면 같은 증거에서 ``prefetch.jsonl``의 줄
        순서가 기계마다 달라집니다. 산출물이 재현되지 않으면 대조가
        불가능해집니다.
        """
        for relative in location.directory_paths:
            folder = _resolve_directory(self.root, relative)
            if folder is None:
                continue
            found, empties = self._collect(folder, location.directory_suffix, "volume_path")
            self._empties[artifact] = empties
            if found:
                self._directories[artifact] = Located(
                    path=folder, method="volume_path", empty_candidates=empties
                )
                return found
        return ()

    def _collect(
        self, folder: Path, suffix: str, method: str
    ) -> "tuple[tuple[Located, ...], tuple[Path, ...]]":
        """폴더 하나에서 확장자가 맞는 파일을 모은다. 0바이트는 뺀다."""
        try:
            children = sorted(folder.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            return (), ()

        found: list[Located] = []
        empties: list[Path] = []
        for child in children:
            if not child.name.lower().endswith(suffix) or not child.is_file():
                continue
            if _is_empty(child):
                empties.append(child)
                continue
            if len(found) >= MAX_DIRECTORY_FILES:
                _log.warning(
                    "%s 에서 %d개까지만 읽습니다 (상한 MAX_DIRECTORY_FILES)",
                    folder,
                    MAX_DIRECTORY_FILES,
                )
                break
            found.append(Located(path=child, method=method))
        return tuple(found), tuple(empties)

    def _search(self, artifact: str) -> "tuple[Located, ...]":
        """마지막 수단. 폴더 전체를 훑되 정렬해 결정론적으로 고른다.

        ``os.walk``의 순서는 파일시스템에 의존합니다. 정렬하지 않으면
        같은 증거를 Windows와 Linux에서 돌렸을 때 다른 파일이 선택될 수
        있습니다. 포렌식 도구에서 재현성이 깨지는 것은 성능 문제와 급이
        다릅니다.

        얕은 것을 먼저 고릅니다. 깊이 묻힌 것보다 원본일 가능성이 높습니다.
        """
        location = FILE_LAYOUT.get(artifact)
        if location is None:
            return ()
        if location.is_directory:
            return self._search_directory(artifact, location)
        wanted = {name.lower() for name in location.filenames}

        matches: list[tuple[int, str, Path]] = []
        empties: list[Path] = list(self._empties.get(artifact, ()))
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames.sort()
            here = Path(dirpath)
            depth = len(here.relative_to(self.root).parts)
            for filename in sorted(filenames):
                if filename.lower() not in wanted:
                    continue
                candidate = here / filename
                # _probe 와 같은 이유로 0바이트는 후보가 아니다.
                if _is_empty(candidate):
                    if candidate not in empties:
                        empties.append(candidate)
                    continue
                matches.append((depth, filename.lower(), candidate))
            if len(matches) >= self.max_search:
                break

        self._empties[artifact] = tuple(empties)
        if not matches:
            return ()
        matches.sort(key=lambda item: (item[0], str(item[2]).lower()))
        return (
            Located(
                path=matches[0][2],
                method="search",
                alternates=tuple(item[2] for item in matches[1:]),
                empty_candidates=tuple(empties),
            ),
        )

    def _search_directory(
        self, artifact: str, location: ArtifactLocation
    ) -> "tuple[Located, ...]":
        """제자리에 없을 때. 확장자가 맞는 파일이 **가장 많은** 폴더를 고른다.

        파일 아티팩트의 검색과 기준이 다릅니다. 저쪽은 이름이 맞는 파일
        하나를 고르면 되지만, 여기서는 **어느 폴더가 프리패치 폴더인가**를
        골라야 합니다. ``.pf`` 하나가 다운로드 폴더에 굴러다닌다고 그것이
        아티팩트가 되면 안 됩니다.

        같은 수면 얕은 쪽, 그래도 같으면 경로 사전순입니다 — 재현성을
        위해 무승부를 남기지 않습니다.
        """
        best: tuple[int, int, str] | None = None
        best_found: tuple[Located, ...] = ()
        best_folder: Path | None = None
        best_empties: tuple[Path, ...] = ()

        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames.sort()
            if not any(name.lower().endswith(location.directory_suffix) for name in filenames):
                continue
            here = Path(dirpath)
            found, empties = self._collect(here, location.directory_suffix, "search")
            if not found:
                continue
            depth = len(here.relative_to(self.root).parts)
            key = (-len(found), depth, str(here).lower())
            if best is None or key < best:
                best, best_found, best_folder, best_empties = key, found, here, empties

        self._empties[artifact] = best_empties
        if best_folder is not None:
            self._directories[artifact] = Located(
                path=best_folder, method="search", empty_candidates=best_empties
            )
        return best_found


class VolumeSource:
    """디스크 이미지 안의 NTFS 볼륨. ``dissect.target`` 기반.

    raw dd와 E01이 여기로 모입니다. 파티션 테이블·부트섹터·``$MFT``
    런리스트 해석은 전부 ``dissect.target``에 맡깁니다 — 이 프로젝트가
    직접 구현하는 것은 파서(04단계)뿐이고, 볼륨 계층까지 직접 짜는 것은
    별개의 범위입니다. E01은 ``Target.open``이 ``dissect.evidence``로
    같은 경로를 태우므로 이 클래스 안에서는 형식을 구분하지 않습니다.

    **``target.filesystems[i]``에서 직접 찾습니다.**
    ``target.fs``(OS 레벨 병합 뷰)로는 ``$MFT`` 같은 메타파일이 나오지
    않는다는 것이 실측(``test_image.001``, 60GB raw NTFS 볼륨)으로
    확인됐습니다.

    ``dissect.util.stream.RunlistStream``이 ``open()``의 반환값입니다.
    ``seekable() == True``이고 ``seek(0)`` 후 재읽기 값이 원본과
    일치함을 같은 이미지로 확인했습니다 — ``mft.py``의 두 번 순회
    패턴과 호환됩니다. 런리스트를 따라가며 읽으므로 ``$MFT`` 수백MB를
    통째로 메모리에 올리지 않습니다.

    파티션이 여럿이면 **NTFS 파일시스템이 정확히 하나일 때만** 엽니다.
    한 실행은 한 볼륨입니다 — 여러 개면 어느 것인지 도구가 추측하지
    않고 실패합니다(``_open_volume_image`` 참조). 지금 확인된 이미지는
    파티션 테이블 없이 NTFS 볼륨 하나만 담은 형태라 이 경로만 검증했고,
    EFI/복구 파티션이 섞인 전체 디스크 이미지는 아직 대조하지
    못했습니다 — ``docs/limitations.md`` 참고.

    **추출된 폴더와 다른 점** — 볼륨은 표준 절대경로를 그대로 갖고
    있으므로 ``FileSource``처럼 파일명 후보나 재귀 검색이 필요 없습니다.
    ``FILE_LAYOUT``의 ``relative_paths``만 그대로 시도합니다.
    """

    def __init__(self, filesystem: Any, *, description: str) -> None:
        self.filesystem = filesystem
        self.description = description
        self._cache: dict[str, "Located | None"] = {}
        self._files: dict[str, "tuple[Located, ...]"] = {}

    def describe(self) -> str:
        return self.description

    def _resolve(self, artifact: str) -> Any:
        location = FILE_LAYOUT.get(artifact)
        if location is None:
            return None
        candidates = VOLUME_PATH_OVERRIDES.get(artifact, ()) + location.relative_paths
        for relative in candidates:
            try:
                entry = self.filesystem.path(relative)
                if entry.exists() and not entry.is_dir():
                    return entry
            except Exception:  # noqa: BLE001 - 손상 볼륨에서 무엇이 나올지 모른다
                continue
        return None

    def _resolve_directory(
        self, location: ArtifactLocation
    ) -> "tuple[Any | None, tuple[Located, ...]]":
        """폴더 아티팩트를 볼륨에서 찾는다.

        ``FileSource._collect``와 같은 규약입니다 — **이름순으로 고정하고**
        0바이트를 뺍니다. 정렬하지 않으면 같은 이미지에서 ``prefetch.jsonl``의
        줄 순서가 실행마다 달라져 대조가 불가능해집니다.
        """
        for relative in location.directory_paths:
            try:
                folder = self.filesystem.path(relative)
                if not folder.exists() or not folder.is_dir():
                    continue
                children = sorted(folder.iterdir(), key=lambda entry: entry.name.lower())
            except Exception:  # noqa: BLE001 - 손상 볼륨에서 무엇이 나올지 모른다
                continue

            found: list[Located] = []
            for child in children:
                if not child.name.lower().endswith(location.directory_suffix):
                    continue
                try:
                    if not child.is_file() or child.stat().st_size == 0:
                        continue
                except Exception:  # noqa: BLE001 - 같은 이유
                    continue
                if len(found) >= MAX_DIRECTORY_FILES:
                    _log.warning(
                        "%s 에서 %d개까지만 읽습니다 (상한 MAX_DIRECTORY_FILES)",
                        folder,
                        MAX_DIRECTORY_FILES,
                    )
                    break
                found.append(Located(path=child, method="volume_path"))
            if found:
                return folder, tuple(found)
        return None, ()

    def _populate(self, artifact: str) -> None:
        """두 캐시를 **항상 같이** 채운다. 한쪽만 차면 매니페스트와 산출물이 갈린다."""
        location = FILE_LAYOUT.get(artifact)
        if location is not None and location.is_directory:
            folder, files = self._resolve_directory(location)
            self._cache[artifact] = (
                Located(path=folder, method="volume_path") if folder is not None and files else None
            )
            self._files[artifact] = files
            return
        entry = self._resolve(artifact)
        located = Located(path=entry, method="volume_path") if entry is not None else None
        self._cache[artifact] = located
        self._files[artifact] = (located,) if located is not None else ()

    def locate(self, artifact: str) -> "Located | None":
        """매니페스트에 적을 출처. 디렉터리 아티팩트면 **그 폴더**다."""
        if artifact not in self._cache:
            self._populate(artifact)
        return self._cache[artifact]

    def locate_all(self, artifact: str) -> "tuple[Located, ...]":
        """열어야 할 파일들. 파일 아티팩트면 0개나 1개."""
        if artifact not in self._files:
            self._populate(artifact)
        return self._files[artifact]

    def _raise_not_found(self, artifact: str) -> "NoReturn":
        location = FILE_LAYOUT.get(artifact)
        if location is None:
            expected = "등록 안 됨"
        elif location.is_directory:
            expected = ", ".join(
                f"{d}/*{location.directory_suffix}" for d in location.directory_paths
            )
        else:
            expected = ", ".join(location.relative_paths)
        raise ArtifactNotFound(
            f"{artifact}: {self.description} 에서 찾지 못함 (기대 위치: {expected})"
        )

    def open(self, artifact: str) -> BinaryIO:
        """``FileSource.open``과 같은 이유로 폴더 아티팩트를 거부한다."""
        location = FILE_LAYOUT.get(artifact)
        if location is not None and location.is_directory:
            raise EvidenceError(
                f"{artifact}: 파일 하나가 아니라 폴더 단위 아티팩트입니다. "
                "open_all() 로 여십시오."
            )

        found = self.locate(artifact)
        if found is None:
            self._raise_not_found(artifact)
        # FileSource의 0바이트 판정과 같은 이유다 — 파일은 있는데
        # 알맹이가 없으면 "수집 안 됨"과 조치가 다르다.
        if found.path.stat().st_size == 0:
            raise EmptyArtifact(f"{artifact}: 볼륨 안 파일이 0바이트입니다 ({found.path}).")
        return found.path.open()

    def open_all(self, artifact: str) -> Iterator[Opened]:
        """``FileSource.open_all``과 같은 계약이다 — 못 찾으면 여기서 바로 실패한다."""
        found = self.locate_all(artifact)
        if not found:
            self._raise_not_found(artifact)
        return self._streams(found)

    @staticmethod
    def _streams(found: "tuple[Located, ...]") -> Iterator[Opened]:
        for item in found:
            with item.path.open() as stream:
                yield Opened(path=item.path, stream=stream)

    def available(self) -> list[str]:
        return [name for name in FILE_LAYOUT if self.locate(name) is not None]


def volume_letter(source: "EvidenceSource | str | os.PathLike[str]") -> str:
    """증거 경로에서 드라이브 문자를 유추한다.

    ``$MFT``에는 드라이브 문자가 없습니다. 한 실행은 한 볼륨이므로
    ``.../C`` 나 ``.../C%3A`` 같은 폴더 이름이 곧 볼륨입니다.

    유추할 수 없으면 ``C:``로 둡니다. 틀려도 경로 접두어 비교에서 결과가
    비어 나오므로 드러납니다 — 조용히 잘못된 값이 되지는 않습니다.
    """
    root = getattr(source, "root", source)
    name = os.path.basename(str(root).rstrip("/\\"))
    letter = name[:1].upper()
    return f"{letter}:" if letter.isalpha() and len(name) <= 4 else "C:"


def volume_candidates(root: Path) -> list[str]:
    """볼륨으로 보이는 하위 폴더 이름. 안내 메시지에 쓴다."""
    try:
        children = sorted(root.iterdir(), key=lambda p: p.name)[:_MAX_ROOT_ENTRIES]
    except OSError:
        return []
    return [child.name for child in children if child.is_dir() and _VOLUME_DIR.match(child.name)]


def _open_volume_image(path: Path, volume: int | None = None) -> VolumeSource:
    """raw dd/E01 이미지를 ``dissect.target``으로 연다.

    ``dissect``가 없으면 여기서만 실패합니다 — 추출된 파일 단위
    (``FileSource``)만 쓰는 실행에는 이 의존성이 필요 없습니다.

    NTFS가 여럿이면 ``volume``(``--volume``)로 **사람이 고릅니다.**
    도구가 크기나 순서로 추측하지 않습니다 — 복구 파티션과 시스템 볼륨
    둘 다 NTFS라 자동 판별이 그럴듯하게 틀릴 수 있고, 잘못 고르면
    "아티팩트가 없다"가 아니라 **다른 볼륨의 결과가 조용히 나옵니다.**
    """
    try:
        from dissect.target import Target
    except ImportError as e:
        raise EvidenceError(
            f"{path}: 디스크 이미지를 열려면 dissect.target 이 필요합니다 "
            "(pip install dissect.target). 추출된 아티팩트가 담긴 볼륨 폴더를 "
            "지정하는 방법도 있습니다."
        ) from e

    try:
        target = Target.open(str(path))
    except Exception as e:  # noqa: BLE001 - dissect가 던지는 예외 종류가 이미지마다 다르다
        raise EvidenceError(f"{path}: 이미지를 열지 못했습니다 — {e}") from e

    # target.fs(OS 레벨 병합 뷰)는 쓰지 않는다 — $MFT 같은 메타파일이
    # 나오지 않는다는 것이 실측으로 확인됐다(VolumeSource 클래스 docstring).
    ntfs = [fs for fs in target.filesystems if getattr(fs, "__type__", None) == "ntfs"]
    if not ntfs:
        raise EvidenceError(f"{path}: NTFS 파일시스템을 찾지 못했습니다.")
    if volume is not None:
        if not 0 <= volume < len(ntfs):
            raise EvidenceError(
                f"{path}: --volume {volume} 은 범위 밖입니다 "
                f"(NTFS {len(ntfs)}개, 0..{len(ntfs) - 1}).\n"
                f"{_volume_menu(ntfs)}"
            )
        chosen = volume
    elif len(ntfs) > 1:
        # 한 실행은 한 볼륨이다. 여러 파티션이 섞인 전체 디스크 이미지에서
        # 어느 것을 열지는 사람이 정한다.
        raise EvidenceError(
            f"{path}: NTFS 파일시스템이 {len(ntfs)}개 발견됐습니다. "
            "한 실행은 한 볼륨만 봅니다 — 어느 볼륨인지 지정하십시오.\n"
            f"{_volume_menu(ntfs)}\n"
            "  볼륨이 여럿이면 케이스를 나눕니다 (C-001-C, C-001-D)."
        )
    else:
        chosen = 0
    return VolumeSource(
        ntfs[chosen], description=f"디스크 이미지 ({path}, 볼륨 {chosen})"
    )


def _volume_menu(ntfs: list[Any]) -> str:
    """``--volume`` 후보를 크기와 함께 보여 준다.

    크기가 판별의 전부는 아니지만 복구 파티션(수백MB)과 시스템 볼륨(수십GB)을
    가르는 데는 대개 충분합니다. 그래도 **고르는 것은 사람입니다.**
    """
    lines = []
    for i, fs in enumerate(ntfs):
        vol = getattr(fs, "volume", None)
        size = getattr(vol, "size", None)
        gib = f"{size / 1024 ** 3:.1f}GiB" if isinstance(size, int) else "크기 불명"
        name = getattr(vol, "name", None) or "이름 없음"
        lines.append(f"    --volume {i}    {gib}  {name}")
    return "\n".join(lines)


def open_source(root: str | os.PathLike[str], *, volume: int | None = None) -> EvidenceSource:
    """증거 경로를 보고 알맞은 소스를 만든다.

    볼륨들을 담은 폴더를 지정하면 어느 볼륨인지 안내하고 실패합니다.
    사용자가 가장 실수하기 쉬운 지점이라, 혼란스러운 결과 대신 행동 가능한
    메시지를 냅니다.
    """
    path = Path(root)
    if path.is_file():
        return _open_volume_image(path, volume)
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
