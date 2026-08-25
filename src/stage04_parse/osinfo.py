"""이미지가 어느 Windows인가, 그리고 그 버전에 없는 아티팩트는 무엇인가.

## 왜 04단계가 이것을 하나

03단계는 증거를 열지 않습니다. 매핑과 시나리오만 보고 "무엇을 읽어야
하는가"를 정하므로 **디스크가 Windows 7인지 10인지 알 방법이 없습니다.**
증거를 처음 여는 것이 04단계이고, 그래서 판정도 여기서 합니다.

## 왜 판정이 필요한가

버전마다 **존재하지 않는 아티팩트**가 있습니다. `Amcache.hve`는 Win8부터
기본 탑재이고 Win7에는 없습니다(그 자리에 `RecentFileCache.bcf`가 있습니다).
버전을 모르면 Win7 이미지에서 Amcache가 안 나온 것이 ``artifact_not_found``
— 즉 **"수집 누락"** 으로 기록됩니다. 보고서의 "분석 범위 한계"에
"증거 없음"으로 실리고, 분석가는 있지도 않은 파일을 다시 뽑으러 갑니다.

"이 버전엔 원래 없다"와 "있어야 하는데 없다"는 조치가 다릅니다. 그래서
가릅니다.

## 모르면 거르지 않는다

버전 판정에 실패해도 04단계를 세우지 않습니다. SOFTWARE 하이브가 증거에
없을 수 있고(수집 범위를 좁힌 경우), 그것 자체는 파싱을 막을 이유가
아닙니다. 판정 불가는 매니페스트에 사유와 함께 남고, **가용성 판정은
아예 하지 않습니다.**

폴백 금지(`CLAUDE.md`)에 어긋나지 않습니다. 폴백은 실패를 감추고 그럴듯한
값을 지어내는 것인데, 여기서는 반대로 **모른다는 사실을 기록하고 판단을
보류**합니다. 틀린 방향도 명확합니다 — 안 거르면 최악이 "없는 파일을
찾다 못 찾음"(지금과 같음)이고, 잘못 거르면 **있는 증거를 안 읽습니다.**

## family는 제품명이 아니라 구조 세대다

`CurrentBuildNumber` 하나만 믿습니다. `ProductName`은 Win11 초기 빌드가
"Windows 10 Pro"라고 적혀 있는 것처럼 신뢰할 수 없고, `CurrentVersion`은
Win8.1 이후 전부 "6.3"으로 굳었습니다.

서버판은 클라이언트와 빌드를 공유합니다(2008 R2 = 7601, 2012 = 9200,
2012 R2 = 9600, 2016 = 14393). 그래서 ``family``가 ``win10``이라고 해서
클라이언트라는 뜻이 아닙니다 — **온디스크 구조가 그 세대**라는 뜻입니다.
아티팩트 구조를 가르는 데 필요한 것이 그것이고, 제품 구분이 필요하면
``installation_type``(Client/Server)이 따로 실립니다.

## 참고

* `docs/limitations.md` — 버전별로 확인한 것과 못 한 것
* `src/stage04_parse/evidence.py` `FILE_LAYOUT` — 아티팩트가 **어디에**
  있는지. 이 파일은 **언제부터** 있는지를 안다.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .parsers.registry import HiveBuffer, value_to_field

__all__ = [
    "WindowsVersion",
    "VersionUndetermined",
    "Availability",
    "AVAILABILITY",
    "FAMILIES",
    "CURRENT_VERSION_PATH",
    "detect",
    "family_of",
    "applicability",
]

_log = logging.getLogger(__name__)

#: 버전 정보가 있는 SOFTWARE 하이브 안의 키.
CURRENT_VERSION_PATH = "Microsoft\\Windows NT\\CurrentVersion"

#: 빌드 번호가 담긴 값 이름. **앞에서부터 찾아 처음 나오는 것**을 쓴다.
#:
#: 둘을 다 보는 것은 폴백이 아니라 `FILE_LAYOUT`이 수집 도구마다 다른
#: 파일명을 후보로 두는 것과 같다 — 같은 사실이 이름 둘로 저장돼 있다.
#: ``CurrentBuildNumber``를 먼저 보는 이유는 ``CurrentBuild``가 XP 시절
#: "1.511.1 () (Obsolete data - do not use)" 같은 문자열이었던 값이라
#: 이름 자체가 재활용된 자리이기 때문이다.
BUILD_VALUE_NAMES = ("CurrentBuildNumber", "CurrentBuild")

#: (하한, 상한, 이름). 상한 포함이다.
#:
#: 클라이언트 최종 빌드로 끊지 않고 다음 세대 시작 직전까지 넓힌 구간이
#: 있다 — ``win10``의 상한 21999가 그렇다. Server 2022(20348)처럼
#: **클라이언트에 대응물이 없는 빌드**가 그 사이에 들어오기 때문이다.
#: 구조 세대로는 Win10과 같은 자리라 그렇게 묶는다.
FAMILIES: tuple[tuple[int, int, str], ...] = (
    (7600, 7601, "win7"),      # Win7, Server 2008 R2
    (9200, 9200, "win8"),      # Win8, Server 2012
    (9600, 9600, "win81"),     # Win8.1, Server 2012 R2
    (10240, 21999, "win10"),   # Win10, Server 2016·2019·2022
    (22000, 999999, "win11"),  # Win11, Server 2025
)

#: 빌드가 어느 구간에도 없을 때 쓸 이름. Vista 이하이거나 미래 빌드다.
UNKNOWN_FAMILY = "unknown"


class VersionUndetermined(Exception):
    """버전을 판정하지 못했다.

    실패가 아니라 **정보**다(`evidence.ArtifactNotFound`와 같은 자리).
    메시지가 매니페스트에 그대로 실리므로 "왜 못 정했는지"까지 담는다.
    """


@dataclass(frozen=True)
class WindowsVersion:
    """판정 결과. 매니페스트에 그대로 실린다."""

    #: 이것만이 판정의 근거다. 나머지는 사람이 읽을 값이다.
    build: int
    #: ``FAMILIES``가 정한 구조 세대. 제품명이 아니다.
    family: str
    #: ``Windows 10 Pro`` 등. Win11 초기 빌드는 여기가 "Windows 10"이다.
    product_name: str = ""
    #: ``6.1``/``6.2``/``6.3``. Win8.1 이후로 굳어 변별력이 없다.
    current_version: str = ""
    #: ``Client`` 또는 ``Server``. 서버판이 빌드를 공유하므로 이것으로 가른다.
    installation_type: str = ""
    #: ``Professional``·``Enterprise`` 등.
    edition_id: str = ""
    #: ``21H2`` 등. Win10 2009(20H2) 이후에만 있다.
    display_version: str = ""
    #: ``ReleaseId``. Win10 1607~2009.
    release_id: str = ""
    #: Update Build Revision. Win10 이후에만 있다. 없으면 ``None``.
    revision: "int | None" = None

    @property
    def known(self) -> bool:
        return self.family != UNKNOWN_FAMILY

    def describe(self) -> str:
        """사람이 읽을 한 줄."""
        name = self.product_name or "이름 없음"
        parts = [f"{name} (빌드 {self.build}"]
        if self.revision is not None:
            parts.append(f".{self.revision}")
        parts.append(f", {self.family}")
        if self.installation_type:
            parts.append(f", {self.installation_type}")
        parts.append(")")
        return "".join(parts)

    def as_manifest(self) -> dict[str, Any]:
        """매니페스트에 실을 형태.

        빈 값은 뺀다 — 하이브에 없던 값과 "빈 문자열이 들어 있던 값"을
        구분할 이유가 없고, 없는 값을 실으면 07단계가 그것을 표에 그린다.
        """
        out: dict[str, Any] = {
            "determined": True,
            "build": self.build,
            "family": self.family,
        }
        for key, value in (
            ("product_name", self.product_name),
            ("current_version", self.current_version),
            ("installation_type", self.installation_type),
            ("edition_id", self.edition_id),
            ("display_version", self.display_version),
            ("release_id", self.release_id),
        ):
            if value:
                out[key] = value
        if self.revision is not None:
            out["revision"] = self.revision
        return out


def family_of(build: int) -> str:
    """빌드 번호 → 구조 세대. 아는 구간에 없으면 ``unknown``."""
    for low, high, name in FAMILIES:
        if low <= build <= high:
            return name
    return UNKNOWN_FAMILY


# ------------------------------------------------------------------ 판정


def _value(key: Any, name: str) -> Any:
    """값 하나를 읽는다. 없으면 ``None``.

    ``value_to_field``를 거치는 이유는 라이브러리의 UTF-16 잘림을 피하기
    위해서다(`parsers/registry.py` ``_decode_utf16le`` 참조). ``ProductName``에
    한글 에디션명이 들어오는 경우가 실제로 있다.
    """
    try:
        return value_to_field(key.value(name))
    except Exception:  # noqa: BLE001 - 없는 값과 깨진 값을 여기서 가르지 않는다
        return None


def _as_text(raw: Any) -> str:
    return raw.strip() if isinstance(raw, str) else ""


def detect_from_hive(data: bytes) -> WindowsVersion:
    """SOFTWARE 하이브 바이트에서 버전을 판정한다.

    빌드 번호를 못 읽으면 ``VersionUndetermined``다. 나머지 값은 없어도
    된다 — 판정의 근거가 아니라 사람이 읽을 값이다.
    """
    from Registry import Registry  # 지연 import: 하이브가 없으면 부를 일이 없다

    if data[:4] != b"regf":
        raise VersionUndetermined(
            "SOFTWARE 하이브가 아닙니다 (매직 불일치). 증거 경로를 확인하십시오."
        )
    try:
        hive = Registry.Registry(HiveBuffer(data))
        key = hive.open(CURRENT_VERSION_PATH)
    except Exception as e:  # noqa: BLE001 - 라이브러리가 무엇을 올릴지 모른다
        raise VersionUndetermined(
            f"SOFTWARE 하이브에서 {CURRENT_VERSION_PATH} 를 열지 못했습니다 — {e}"
        ) from e

    build_text = ""
    for name in BUILD_VALUE_NAMES:
        build_text = _as_text(_value(key, name))
        if build_text.isdigit():
            break
    if not build_text.isdigit():
        raise VersionUndetermined(
            f"{CURRENT_VERSION_PATH} 에서 빌드 번호를 읽지 못했습니다 "
            f"(본 값: {', '.join(BUILD_VALUE_NAMES)})"
        )

    build = int(build_text)
    revision = _value(key, "UBR")
    return WindowsVersion(
        build=build,
        family=family_of(build),
        product_name=_as_text(_value(key, "ProductName")),
        current_version=_as_text(_value(key, "CurrentVersion")),
        installation_type=_as_text(_value(key, "InstallationType")),
        edition_id=_as_text(_value(key, "EditionID")),
        display_version=_as_text(_value(key, "DisplayVersion")),
        release_id=_as_text(_value(key, "ReleaseId")),
        revision=revision if isinstance(revision, int) else None,
    )


def detect(source: Any) -> WindowsVersion:
    """증거에서 SOFTWARE 하이브를 열어 버전을 판정한다.

    ``source``는 `evidence.EvidenceSource`다. 하이브가 없거나 열리지
    않으면 ``VersionUndetermined``를 올린다 — 부르는 쪽이 기록하고
    **판단을 보류**한다.
    """
    from . import evidence

    try:
        stream = source.open("registry:SOFTWARE")
    except evidence.ArtifactNotFound as e:
        raise VersionUndetermined(f"SOFTWARE 하이브를 찾지 못했습니다 — {e}") from e
    except OSError as e:
        raise VersionUndetermined(f"SOFTWARE 하이브를 열지 못했습니다 — {e}") from e

    with stream:
        data = stream.read()
    if not data:
        raise VersionUndetermined("SOFTWARE 하이브가 0바이트입니다")
    return detect_from_hive(data)


# -------------------------------------------------------------- 가용성


@dataclass(frozen=True)
class Availability:
    """이 아티팩트가 존재할 수 있는 빌드 구간.

    ``mappings/_artifacts.yaml``이 아니라 여기 있는 이유는, 이것이
    "어디에 있는가"(`evidence.FILE_LAYOUT`)와 같은 종류의 **온디스크
    사실**이기 때문이다. 카탈로그는 "무엇을 왜 읽는가"를 정하는 곳이고
    03단계가 읽는데, 03단계는 버전을 모르므로 이 값을 쓸 데가 없다.
    """

    #: 이 빌드부터 존재한다. 0이면 하한 없음.
    min_build: int = 0
    #: 이 빌드까지 존재한다. 0이면 상한 없음.
    max_build: int = 0
    #: 왜 그런지. **보고서에 그대로 실리므로** 분석가가 읽을 문장으로 쓴다.
    note: str = ""


#: 아티팩트 → 존재 구간. **여기 없는 아티팩트는 모든 버전에 있다고 본다.**
#:
#: 넣기 전에 두 번 생각한다 — 잘못 넣으면 있는 증거를 안 읽는다. "이
#: 버전에서 흔히 비어 있다"는 여기 적을 것이 아니라 ``artifact_not_found``가
#: 이미 담당하는 일이다. **구조적으로 존재할 수 없는 것만** 적는다.
AVAILABILITY: dict[str, Availability] = {
    "registry:Amcache": Availability(
        min_build=9200,
        note=(
            "Amcache.hve는 Windows 8부터 기본 탑재입니다. Windows 7에는 "
            "KB2952664를 설치한 시스템에만 생기며, 기본 이미지에는 "
            "RecentFileCache.bcf가 그 자리를 대신합니다."
        ),
    ),
    "recentfilecache": Availability(
        min_build=7600,
        max_build=7601,
        note=(
            "RecentFileCache.bcf는 Windows 7 전용입니다. Windows 8부터 "
            "Amcache.hve가 대체했습니다."
        ),
    ),
}


def applicability(artifact: str, version: "WindowsVersion | None") -> "str | None":
    """이 버전에 이 아티팩트가 존재할 수 있는가.

    존재할 수 없으면 **사유 문장**을, 존재할 수 있거나 판단할 수 없으면
    ``None``을 돌려준다.

    ``version``이 ``None``(판정 실패)이거나 빌드가 아는 구간 밖이면
    거르지 않는다 — 모르면서 거르는 쪽이 증거를 없앤다.
    """
    if version is None or not version.known:
        return None
    rule = AVAILABILITY.get(artifact)
    if rule is None:
        return None

    # 문장은 **07단계의 사유 라벨 뒤에 붙는다**(``SKIP_REASONS``). 그쪽이
    # 이미 "이 Windows 버전에 없는 아티팩트"라고 말하므로 여기서는
    # 되풀이하지 않고 **근거만** 적는다.
    build = version.build
    if rule.min_build and build < rule.min_build:
        return f"빌드 {build} < {rule.min_build}. {rule.note}"
    if rule.max_build and build > rule.max_build:
        return f"빌드 {build} > {rule.max_build}. {rule.note}"
    return None
