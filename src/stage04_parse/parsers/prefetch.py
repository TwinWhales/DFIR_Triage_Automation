"""프리패치 파서 — ``Windows/Prefetch/*.pf``.

온디스크 구조는 ``structs/prefetch_record.py``가, ``MAM`` 압축은
``structs/xpress_huffman.py``가 소유합니다. 여기에는 **판단이 필요한
것만** 있습니다 — 무엇을 레코드로 볼 것인가, 어떤 경로로 범위를 맞출
것인가, 장치 경로를 드라이브 문자로 바꿔도 되는가.

## 다른 파서와 다른 점 셋

**아티팩트가 파일 하나가 아니라 폴더 하나입니다.** ``parse()``는 .pf
파일 **하나**를 받고, 04단계가 폴더 안의 파일 수만큼 반복해 부릅니다
(``evidence.open_all``). 그래서 이 파서는 호출 사이에 상태를 들고
있어야 하고, 시작 지점을 ``begin_artifact()``로 받습니다.

**레코드 하나가 파일 하나입니다.** .pf 하나는 "실행 파일 하나가 어떻게
실행됐는가"를 통째로 말합니다. 적재된 파일 목록을 레코드로 쪼개면 실행
한 건이 수백 줄로 흩어지고, 그 수백 줄에는 저마다 고유 번호가 없어
``ref``를 만들 수 없습니다.

**``offset``이 항상 ``0x0``입니다.** 레코드가 곧 파일이므로 파일 안에서
되짚을 자리가 따로 없습니다. Win10 이후에는 온디스크 바이트가 압축돼
있어 **해제 후 오프셋은 파일 위치와 아무 관계가 없기도 합니다.** 어느
파일에서 나왔는지는 ``fields.prefetch_file``이 들고 있습니다.

## ref 는 실행 파일 경로 해시다

프리패치에는 MFT 레코드 번호 같은 일련번호가 없습니다. 아티팩트 안에서
유일한 값은 헤더 0x4C의 **경로 해시**이고, 그것을 10진수로 씁니다
(``src/common/refs.py`` 규약, 레지스트리가 nk 오프셋을 쓴 것과 같은 이유).

이 값은 파일명 뒤에 붙는 8자리 16진수와 같은 값입니다. **파일명이 아니라
헤더 쪽을 씁니다** — 파일명은 복사·이름 변경으로 바뀔 수 있지만 헤더는
원본이 만들어질 때 쓰인 값입니다. 둘이 다르면 경고를 남깁니다. 그 자체가
"이 .pf 는 제자리에 있던 것이 아니다"라는 정보입니다.

해시가 겹치면 **그 파일을 건너뜁니다.** 같은 ``ref``를 두 번 내면
``io.read_parsed_records``가 ``DuplicateRefError``로 05·06단계를 통째로
세웁니다. 한 건을 잃는 쪽이 파이프라인이 서는 쪽보다 낫고, 건너뛴 사실은
집계와 로그에 남습니다.

## 장치 경로를 드라이브 문자로 바꾸는 규칙

.pf 안의 경로는 ``\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\CMD.EXE``
형태입니다. 03단계의 ``path_prefix``는 ``C:\\...`` 형태라 그대로는 절대
매칭되지 않습니다.

**섀도 카피가 아닌 ``HARDDISKVOLUME<n>``이 정확히 하나일 때만** 그것을
증거 볼륨으로 보고 드라이브 문자로 바꿉니다. 한 실행은 한 볼륨이므로
그 하나가 곧 우리가 분석 중인 볼륨입니다. 둘 이상이면 어느 쪽인지 알
방법이 없어 **바꾸지 않습니다** — 틀린 드라이브 문자를 단 경로가
보고서에 실리는 것보다 매칭이 안 되는 편이 낫습니다.

``\\DEVICE\\HARDDISKVOLUMESHADOWCOPY3\\...``는 **바꾸지 않습니다.** 섀도
카피 안의 파일은 살아 있는 볼륨의 그 경로가 아닙니다. 실측
``evidence/[root]`` 73건 중 17건이 섀도 카피를 함께 참조합니다.

``path``와 ``fields.loaded_files``에 **같은 규칙을 겁니다.** 둘 다
파생값이고, 그것이 파생값임은 이 문서가 근거입니다.

한때는 ``path`` 하나만 바꾸고 목록은 원본 그대로 뒀습니다. 바꾼 이유는
**경로 기준 비교가 목록에서만 성립하지 않았기** 때문입니다. 03단계의
``path_prefix``도, 05단계가 프롬프트에 실을 항목을 고르는 기준도
(``allocation.for_prompt``) ``C:\\...`` 형태를 봅니다. 실측
(``win10_sysmon_testimage``, 적재 경로 10,109건)에서 "Windows 폴더 밖"이
**100%**로 나왔는데, 그건 사실이 아니라 접두어가 안 맞은 것이었습니다.
사이드로딩(T1574)의 가장 강한 신호 둘이 여기서 죽었습니다.

바뀐 항목 수는 ``stats["loaded_paths_converted"]``에 셉니다. 레코드는
나오는데 이 수가 0이면 **접두어를 못 알아본 것**입니다 — 위의 100%가
정확히 그 증상이었고, 조용히 지나가면 다시 못 찾습니다.

``loaded_file_count``는 원본 개수 그대로입니다. 개수는 변환과 무관합니다.

## 실행 파일 경로는 목록에서 찾는다

헤더에는 이름만 있고 경로가 없습니다(게다가 29자에서 잘립니다). 전체
경로는 적재 파일 목록 안에 있으므로 이름이 맞는 항목을 찾습니다. 후보가
정확히 하나일 때만 ``path``를 답니다. 여럿이면 어느 것인지 모르므로
달지 않습니다 — 모르는 것을 아는 척하면 06단계가 그것을 검증해 줍니다.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from ...common import refs
from ..structs import prefetch_record as pf
from .base import Scope

__all__ = ["PrefetchParser", "ARTIFACT", "DEVICE_VOLUME", "device_prefixes"]

_log = logging.getLogger(__name__)

#: 카탈로그(``mappings/_artifacts.yaml``)의 이름과 같아야 한다.
ARTIFACT = "prefetch"

#: 살아 있는 볼륨의 장치 경로. 두 형태를 받는다.
#:
#: 1. ``\DEVICE\HARDDISKVOLUME<n>`` — 장치 번호로 적힌 것
#: 2. ``\VOLUME{<생성시각>-<일련번호>}`` — 마운트 관리자의 영구 볼륨 이름
#:
#: 2번을 뒤늦게 넣었다. 2026-08-26 실물(win10_sysmon_testimage.001)의
#: 프리패치 **127건 전부**가 이 형태였고, 1번만 보던 탓에 경로가 하나도
#: 드라이브 문자로 안 바뀌었다. 그러면 06단계가 정상 문장을 환각으로
#: 센다 — 모델은 ``C:\WINDOWS\...``라고 쓰는데 레코드는
#: ``\VOLUME{...}\WINDOWS\...``라서 문자열이 안 맞는다.
#:
#: 뒤 8자리는 ``fields.volumes[].serial_number``와 같은 값이다(실측 확인).
#: 그래도 대조하지는 않는다 — 어긋날 때 변환을 포기하면 경로가 조용히
#: 안 바뀌고, 그건 지금 고치는 증상 그대로다.
#:
#: **``SHADOWCOPY``는 여전히 여기 걸리지 않는다.** 1번은 숫자만 받고
#: 2번은 16진수만 받으므로 ``HARDDISKVOLUMESHADOWCOPY1``은 양쪽 다
#: 어긋난다. 느슨하게 풀면 섀도 카피의 경로가 ``C:``로 둔갑한다.
DEVICE_VOLUME = re.compile(
    r"^(?:\\DEVICE\\HARDDISKVOLUME\d+|\\VOLUME\{[0-9a-f]{16}-[0-9a-f]{8}\})$",
    re.IGNORECASE,
)

#: 헤더의 실행 파일 이름 자리가 담을 수 있는 최대 글자 수. 이 길이면
#: 잘렸을 수 있으므로 목록에서 찾을 때 접두어로 맞춰 본다.
_EXECUTABLE_MAX_CHARS = 29

#: 잘린 이름을 접두어로 맞출 때 후보를 가르는 기준.
_EXE_SUFFIX = ".EXE"


def device_prefixes(volumes: "list[pf.Volume]") -> "str | None":
    """드라이브 문자로 바꿔도 되는 장치 경로. 정할 수 없으면 ``None``.

    섀도 카피를 뺀 살아 있는 볼륨(``DEVICE_VOLUME`` 참조)이 **정확히
    하나일 때만** 답합니다. 둘 이상이면 어느 것이 ``volume_letter``인지
    알 수 없고, 무르게 굴면 D: 의 실행 파일이 C: 로 보고됩니다.

    형태가 섞여도(``\\DEVICE\\HARDDISKVOLUME1`` 과 ``\\VOLUME{...}``)
    서로 다른 문자열이므로 둘로 세어 ``None``이 됩니다. 그 편이 맞습니다 —
    같은 볼륨인지 우리는 모릅니다.
    """
    live = {v.device_path.upper() for v in volumes if DEVICE_VOLUME.match(v.device_path)}
    return live.pop() if len(live) == 1 else None


class PrefetchParser:
    """.pf 파일 하나를 레코드 하나로.

    04단계가 파일마다 ``parse()``를 부르므로, 폴더 하나를 시작할 때
    ``begin_artifact()``로 상태를 비웁니다. 부르지 않아도 동작하지만
    (같은 프로세스에서 두 번 돌릴 때만 문제가 됩니다) 04단계는 부릅니다.
    """

    def __init__(self, artifact: str = ARTIFACT) -> None:
        self.artifact = artifact
        #: 04단계가 증거 경로에서 유추해 넣어 준다($MFT 파서와 같은 규약).
        self.volume_letter = "C:"
        #: 04단계가 파일마다 넣어 준다. 레코드에 원본 파일명을 남긴다.
        self.source_path: Path | None = None
        self.stats: dict[str, int] = self._new_stats()
        self._seen: dict[int, str] = {}

    @staticmethod
    def _new_stats() -> dict[str, int]:
        return {
            "files_read": 0,
            "records": 0,
            "parse_errors": 0,
            "compressed_files": 0,
            "skipped_entries": 0,
            "duplicate_refs": 0,
            "hash_mismatch": 0,
            "path_unresolved": 0,
            "loaded_paths_converted": 0,
            "out_of_scope": 0,
        }

    def begin_artifact(self) -> None:
        """폴더 하나를 시작한다. 집계와 ``ref`` 중복 감시를 비운다."""
        self.stats = self._new_stats()
        self._seen = {}

    # ------------------------------------------------------------ 진입점

    def parse(self, stream: BinaryIO, scope: Scope) -> Iterator[dict[str, Any]]:
        """.pf **하나**를 읽는다. 범위 밖이면 아무것도 내지 않는다.

        이 파일 하나를 못 읽어도 예외를 올리지 않습니다. 폴더 안의 다른
        파일은 여전히 읽어야 하고, 04단계는 아티팩트 단위로 실패를
        처리하기 때문입니다. 못 읽은 것은 집계와 로그에 남습니다.
        """
        name = self.source_path.name if self.source_path else "<이름 모름>"
        self.stats["files_read"] += 1

        try:
            record = self._build(stream.read(), name, scope)
        except pf.PrefetchError as e:
            self.stats["parse_errors"] += 1
            _log.warning("%s: %s 를 읽지 못했습니다 — %s", self.artifact, name, e)
            return
        if record is not None:
            self.stats["records"] += 1
            yield record

    # ------------------------------------------------------------ 레코드

    def _build(self, raw: bytes, name: str, scope: Scope) -> "dict[str, Any] | None":
        if pf.is_compressed(raw):
            self.stats["compressed_files"] += 1
            raw = pf.decompress_mam(raw)

        header = pf.read_header(raw)
        info, layout = pf.read_file_information(raw)

        if not pf.plausible_run_count(info.run_count):
            raise pf.PrefetchError(
                f"실행 횟수가 비정상입니다: {info.run_count} "
                f"(버전 {header.version}, 레이아웃 출처 {layout.source}). "
                "FILE_INFORMATION 의 자리가 이 빌드와 다를 수 있습니다."
            )
        if not pf.plausible_run_times(info.run_times):
            raise pf.PrefetchError(
                f"실행 시각이 비정상입니다: {info.run_times} "
                f"(버전 {header.version}, 레이아웃 출처 {layout.source})"
            )

        loaded, skipped_names = pf.read_filenames(raw, info, layout)
        volumes, skipped_volumes = pf.read_volumes(raw, info, layout)
        self.stats["skipped_entries"] += skipped_names + skipped_volumes
        if skipped_names or skipped_volumes:
            self.stats["parse_errors"] += 1
            _log.warning(
                "%s: %s 에서 항목 %d개를 읽지 못했습니다 (적재 파일 %d, 볼륨 %d)",
                self.artifact,
                name,
                skipped_names + skipped_volumes,
                skipped_names,
                skipped_volumes,
            )

        self._check_hash(header, name)

        live = device_prefixes(volumes)
        executable_path = self._executable_path(header.executable, loaded, live)
        loaded_paths = [self._to_drive(path, live) for path in loaded]
        self.stats["loaded_paths_converted"] += sum(
            1 for before, after in zip(loaded, loaded_paths) if before != after
        )

        if not self._in_scope(scope, executable_path, loaded, loaded_paths):
            self.stats["out_of_scope"] += 1
            return None

        if header.path_hash in self._seen:
            self.stats["duplicate_refs"] += 1
            _log.warning(
                "%s: %s 의 경로 해시 0x%08X 가 %s 와 겹칩니다. 같은 ref 를 두 번 내면 "
                "05·06단계가 서므로 이 파일을 건너뜁니다.",
                self.artifact,
                name,
                header.path_hash,
                self._seen[header.path_hash],
            )
            return None
        self._seen[header.path_hash] = name

        record: dict[str, Any] = {
            "ref": refs.make_ref(self.artifact, header.path_hash),
            "artifact": self.artifact,
            "record_num": header.path_hash,
            # 레코드가 곧 파일이라 되짚을 자리가 파일 시작뿐이다.
            # 어느 파일이었는지는 fields.prefetch_file 이 들고 있다.
            "offset": "0x0",
            "name": header.executable,
            "fields": {
                "prefetch_file": name,
                "format_version": header.version,
                "path_hash": f"{header.path_hash:08X}",
                "run_count": info.run_count,
                "run_times": [_iso(m) for m in info.run_times if m is not None],
                "loaded_file_count": len(loaded),
                "loaded_files": loaded_paths,
                "volumes": [_volume_field(volume) for volume in volumes],
            },
        }
        if executable_path is not None:
            record["path"] = executable_path

        latest = next((m for m in info.run_times if m is not None), None)
        if latest is not None:
            # null 은 스키마가 막는다. 읽지 못하면 키를 빼고 낸다
            # ($UsnJrnl·레지스트리와 같은 규약). 실행 시각이 없어도
            # "이 프로그램이 실행된 적 있다"는 사실 자체가 증거다.
            record["timestamp"] = _iso(latest)
        return record

    # ------------------------------------------------------------ 보조

    def _check_hash(self, header: pf.Header, name: str) -> None:
        """헤더의 해시와 파일명 뒤 8자리가 같은지 본다.

        다르면 이 .pf 가 제자리에서 만들어진 것이 아닙니다. 값을 고치지는
        않고 — 헤더 쪽이 원본입니다 — 사실만 남깁니다.
        """
        stem = name.rsplit("-", 1)
        if len(stem) != 2:
            return
        try:
            from_name = int(stem[1].split(".", 1)[0], 16)
        except ValueError:
            return
        if from_name != header.path_hash:
            self.stats["hash_mismatch"] += 1
            _log.warning(
                "%s: %s 의 파일명 해시(0x%08X)와 헤더 해시(0x%08X)가 다릅니다. "
                "헤더 쪽을 ref 로 씁니다.",
                self.artifact,
                name,
                from_name,
                header.path_hash,
            )

    def _executable_path(
        self, executable: str, loaded: list[str], live: "str | None"
    ) -> "str | None":
        """적재 파일 목록에서 실행 파일 자신의 전체 경로를 찾는다.

        **정확 일치를 먼저 보고, 없을 때만 접두어로 내려갑니다.** 둘을 한
        목록에 섞으면 이름이 29자인 실행 파일이 자기 ``.config``까지 후보로
        끌고 와 "후보가 둘이라 모르겠다"가 됩니다. 실측에서 그런 파일이
        둘 있었습니다(``SERVICEHUB.VSDETOUREDHOST.EXE``).

        접두어로 내려갔을 때는 ``.EXE``로 끝나는 것을 고릅니다. 잘린 이름의
        나머지를 우리가 알 수 없으므로 후보가 여럿인데, 프리패치가 가리키는
        것은 실행 파일이지 그 옆의 설정 파일이 아닙니다.

        그래도 하나로 좁혀지지 않으면 **달지 않습니다.** 32비트와 64비트에
        같은 이름이 있는 경우(``MSIEXEC.EXE``)가 실제로 있고, 그때 아무거나
        고르면 보고서가 틀린 경로를 말합니다.
        """
        wanted = executable.upper()

        exact = [path for path in loaded if _basename(path) == wanted]
        if len(exact) == 1:
            return self._to_drive(exact[0], live)

        if not exact and len(executable) >= _EXECUTABLE_MAX_CHARS:
            prefixed = [
                path
                for path in loaded
                if _basename(path).startswith(wanted) and _basename(path).endswith(_EXE_SUFFIX)
            ]
            if len(prefixed) == 1:
                return self._to_drive(prefixed[0], live)

        self.stats["path_unresolved"] += 1
        return None

    def _to_drive(self, path: str, live: "str | None") -> str:
        """장치 경로를 드라이브 문자로. 바꿀 수 없으면 그대로 둔다."""
        if live is None or not path.upper().startswith(live + "\\"):
            return path
        return self.volume_letter + path[len(live) :]

    def _in_scope(
        self,
        scope: Scope,
        executable_path: "str | None",
        loaded: list[str],
        loaded_paths: list[str],
    ) -> bool:
        """범위 안인가.

        **실행 파일 경로든 적재된 파일이든 하나라도 걸리면 통과입니다.**
        "웹루트 아래에서 무언가 실행됐다"와 "웹루트 아래 파일을 열었다"는
        둘 다 봐야 할 신호이고, 선별 실패로 증거를 놓치는 것이 이
        프로젝트의 최대 리스크입니다.

        **원본과 변환본을 둘 다 봅니다.** 레코드에 싣는 것은 변환본
        하나뿐이지만, 매핑이 장치 경로로 범위를 적었을 때 걸러지지 않게
        합니다 — 여기서 놓치면 아티팩트가 통째로 사라집니다.

        시간 범위는 여기서 보지 않습니다. ``flagging``이
        ``outside_time_range``를 붙입니다(``parsers/base.py``).
        """
        if not scope.path_prefix and not scope.extensions:
            return True

        candidates = loaded + loaded_paths
        if executable_path is not None:
            candidates.append(executable_path)
        return any(scope.matches_path(path) for path in candidates)


def _volume_field(volume: pf.Volume) -> dict[str, Any]:
    """볼륨 하나를 ``fields``에 넣을 형태로.

    생성 시각을 읽지 못하면 **키를 뺍니다.** ``null``을 넣으면 06단계가
    "생성 시각이 없음"이라는 값과 "읽지 못했음"을 구별하지 못합니다.
    """
    out: dict[str, Any] = {
        "device_path": volume.device_path,
        "serial_number": f"{volume.serial_number:08X}",
        "directory_count": volume.directory_count,
    }
    created = _iso(volume.created)
    if created is not None:
        out["created"] = created
    return out


def _basename(path: str) -> str:
    """장치 경로의 마지막 조각(대문자)."""
    return path.rsplit("\\", 1)[-1].upper()


def _iso(moment: Any) -> "str | None":
    """``datetime``을 이 프로젝트의 표기로. ``None``이면 ``None``.

    끝에 ``0``을 붙여 7자리를 만드는 것은 "100ns 자릿수는 버렸다"는
    뜻입니다. 다른 파서와 같은 규약입니다(``parsers/registry.py``).
    """
    return None if moment is None else moment.strftime("%Y-%m-%dT%H:%M:%S.%f0Z")
