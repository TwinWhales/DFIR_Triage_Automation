"""증거 접근 계층.

파서는 **증거가 어떤 형태로 왔는지 몰라야 합니다.** ``$MFT``를 파싱하는
코드가 "이게 추출된 파일인가, dd 이미지 속인가, E01 안인가"를 신경 쓰면
형식이 늘어날 때마다 모든 파서를 고쳐야 합니다.

그래서 접점을 하나로 좁힙니다.

    아티팩트 이름  →  읽을 수 있는 바이트 스트림

교육장에서 어떤 형식이 오든 이 계층만 갈아 끼우면 파서는 그대로입니다.

## 지원 계획

======================  ==========  =============================================
형식                     상태        비고
======================  ==========  =============================================
추출된 파일 단위          **구현**    ``$MFT``, ``Security.evtx`` 같은 파일이 담긴 폴더
raw dd 이미지            미구현      파티션 테이블 → NTFS 부트섹터 → ``$MFT`` 위치
E01 / AFF4              미구현      ``pyewf``로 열어 raw처럼 다룸
======================  ==========  =============================================

raw와 E01은 결국 같습니다. **E01은 raw로 펼쳐지는 컨테이너**이므로,
``pyewf`` 핸들을 파일 같은 객체로 감싸면 ``VolumeSource``가 그대로 씁니다.
그래서 볼륨을 해석하는 코드는 한 번만 쓰면 됩니다.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO, Protocol

__all__ = [
    "EvidenceError",
    "ArtifactNotFound",
    "EvidenceSource",
    "FileSource",
    "VolumeSource",
    "open_source",
    "FILE_LAYOUT",
]


class EvidenceError(RuntimeError):
    """증거를 열 수 없다."""


class ArtifactNotFound(EvidenceError):
    """요청한 아티팩트가 이 증거에 없다.

    실패가 아니라 **정보**다. 선별이 요청한 아티팩트가 수집되지 않은
    경우이며, 보고서의 "분석 범위 한계"에 실려야 한다. 조용히 빈 결과를
    내면 "봤는데 없었다"와 "아예 못 봤다"가 구별되지 않는다.
    """


class EvidenceSource(Protocol):
    """아티팩트 이름을 바이트 스트림으로 바꿔 주는 것."""

    def open(self, artifact: str) -> BinaryIO:
        """읽기용 스트림을 연다. 없으면 ``ArtifactNotFound``."""
        ...

    def available(self) -> list[str]:
        """이 증거에서 실제로 읽을 수 있는 아티팩트 목록."""
        ...

    def describe(self) -> str:
        """산출물에 기록할 한 줄 설명."""
        ...


#: 아티팩트 이름 → 파일명 후보. 앞에 있는 것부터 찾는다.
#:
#: 수집 도구마다 이름이 다르다. ``$UsnJrnl:$J``는 콜론이 파일명에 못 들어가
#: ``$J``나 ``$UsnJrnl$J``로 저장되는 것이 보통이다.
FILE_LAYOUT: dict[str, tuple[str, ...]] = {
    "$MFT": ("$MFT", "MFT", "$MFT.bin", "mft.raw"),
    "$UsnJrnl": ("$UsnJrnl$J", "$J", "$UsnJrnl", "UsnJrnl.bin"),
    "evtx:Security": ("Security.evtx", "Security.evtx.bin"),
    "evtx:System": ("System.evtx", "System.evtx.bin"),
    "registry:SYSTEM": ("SYSTEM", "SYSTEM.hiv"),
    "registry:SOFTWARE": ("SOFTWARE", "SOFTWARE.hiv"),
}


class FileSource:
    """추출된 아티팩트 파일이 담긴 폴더.

    가장 단순한 형태이고 세 형식 중 먼저 구현합니다. 수집 도구(KAPE,
    Velociraptor 등)가 뽑아 놓은 결과가 대개 이 모양입니다.

    파일을 **재귀로 찾습니다.** 수집 도구가 원본 경로 구조를 유지해
    ``C/Windows/System32/winevt/Logs/Security.evtx`` 처럼 깊이 넣어 두는
    경우가 흔하기 때문입니다.
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        if not self.root.is_dir():
            raise EvidenceError(f"증거 폴더 없음: {self.root}")
        self._index: dict[str, Path] | None = None

    def describe(self) -> str:
        return f"파일 단위 ({self.root})"

    def open(self, artifact: str) -> BinaryIO:
        path = self._locate(artifact)
        if path is None:
            candidates = ", ".join(FILE_LAYOUT.get(artifact, ()))
            raise ArtifactNotFound(
                f"{artifact}: {self.root} 에서 찾지 못함 (찾은 이름: {candidates or '등록 안 됨'})"
            )
        return path.open("rb")

    def available(self) -> list[str]:
        return [name for name in FILE_LAYOUT if self._locate(name) is not None]

    def path_of(self, artifact: str) -> Path | None:
        """실제 파일 경로. 매니페스트에 어디서 읽었는지 남길 때 쓴다."""
        return self._locate(artifact)

    def _locate(self, artifact: str) -> Path | None:
        if self._index is None:
            self._index = self._build_index()
        return self._index.get(artifact)

    def _build_index(self) -> dict[str, Path]:
        """폴더를 한 번만 훑어 파일명 → 경로 표를 만든다."""
        by_name: dict[str, Path] = {}
        for path in self.root.rglob("*"):
            if path.is_file():
                # 먼저 찾은 것을 남긴다. 얕은 곳이 원본에 가깝다.
                by_name.setdefault(path.name.lower(), path)

        index: dict[str, Path] = {}
        for artifact, candidates in FILE_LAYOUT.items():
            for candidate in candidates:
                found = by_name.get(candidate.lower())
                if found is not None:
                    index[artifact] = found
                    break
        return index


class VolumeSource:
    """디스크 이미지 안의 NTFS 볼륨. **미구현.**

    raw dd와 E01이 여기로 모입니다. 생성자가 파일 같은 객체를 받으므로,
    E01은 ``pyewf`` 핸들을 넘기면 되고 볼륨 해석 코드는 공유됩니다.

    구현할 때 할 일:

    1. 파티션 테이블(MBR 또는 GPT)을 읽어 NTFS 파티션의 시작 오프셋을 찾는다
    2. 부트섹터에서 클러스터 크기와 ``$MFT`` 시작 클러스터를 읽는다
    3. ``$MFT`` 레코드 0(``$MFT`` 자신)의 ``$DATA`` 런리스트로 전체 위치를 안다
    4. ``open()``이 그 런리스트를 따라 읽는 파일 같은 객체를 돌려준다

    4번을 통째로 메모리에 올리지 않는 것이 중요합니다. ``$MFT``는 수백 MB가
    되고, 다른 아티팩트를 꺼내려면 볼륨을 계속 들고 있어야 합니다.
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


def open_source(root: str | os.PathLike[str]) -> EvidenceSource:
    """증거 경로를 보고 알맞은 소스를 만든다.

    폴더면 ``FileSource``. 파일이면 이미지로 보고 ``VolumeSource``인데
    아직 미구현이라 안내와 함께 실패합니다.
    """
    path = Path(root)
    if path.is_dir():
        return FileSource(path)
    if path.is_file():
        raise EvidenceError(
            f"{path}: 디스크 이미지 파싱은 아직 미구현입니다. "
            "추출된 아티팩트 파일이 담긴 폴더를 지정하십시오. "
            "(지원 계획은 src/stage04_parse/evidence.py 참조)"
        )
    raise EvidenceError(f"증거 경로 없음: {path}")
