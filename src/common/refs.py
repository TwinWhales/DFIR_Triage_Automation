"""ref 문자열 생성·파싱.

ref는 전 단계를 관통하는 유일한 증거 식별자다. 형식은 `<접두어>#<레코드번호>`.

문자열을 직접 조립하지 말고 반드시 이 모듈을 경유한다. 접두어를 손으로 쓰면
오타가 조용히 흘러가다가 06단계에서 "파싱 결과에 없는 레코드"로 둔갑해
환각률 통계를 오염시킨다. 실제로는 파서가 오타를 낸 것인데 LLM이 지어낸 것으로
집계된다.

레코드 번호는 아티팩트 내부의 고유 번호(MFT 레코드 번호, EVTX RecordId)를
그대로 쓴다. 자체 일련번호를 매기면 원본 대조가 불가능해진다.
"""

from __future__ import annotations

import re
from typing import NamedTuple

__all__ = [
    "RefError",
    "Ref",
    "ARTIFACT_PREFIX",
    "PREFIX_ARTIFACT",
    "REF_PATTERN",
    "make_ref",
    "parse_ref",
    "is_valid",
    "prefix_for",
    "artifact_of",
    "record_num_of",
]


class RefError(ValueError):
    """ref 형식 위반 또는 미등록 아티팩트."""


#: 아티팩트 이름 → ref 접두어. 새 아티팩트를 지원하면 여기에 먼저 추가한다.
ARTIFACT_PREFIX: dict[str, str] = {
    "$MFT": "MFT",
    "$UsnJrnl": "USN",
    "evtx:Security": "EVTX-SEC",
    "evtx:System": "EVTX-SYS",
    # 같은 evtx 파서가 맡는 다른 채널들. 접두어를 나누는 이유는 하나다 —
    # ref 만 보고 어느 로그에서 나온 레코드인지 되짚을 수 있어야 한다.
    "evtx:Firewall": "EVTX-FW",
    "evtx:BITS": "EVTX-BITS",
    "evtx:NetworkProfile": "EVTX-NET",
    # 레지스트리는 MFT 레코드 번호 같은 일련번호가 없다. 하이브 안에서
    # 유일한 값은 NK 레코드의 오프셋이므로 그것을 10진수로 쓴다.
    # `offset` 필드에는 같은 값이 16진수로 들어간다.
    "registry:SYSTEM": "REG-SYS",
    "registry:SOFTWARE": "REG-SW",
    # 프리패치도 일련번호가 없다. 아티팩트 안에서 유일한 값은 헤더 0x4C의
    # 실행 파일 경로 해시(파일명 뒤 8자리 16진수와 같은 값)이므로 그것을
    # 10진수로 쓴다. offset 은 0x0 이다 — 레코드가 곧 파일 하나다.
    "prefetch": "PF",
    # Amcache.hve도 regf 포맷이라 nk 오프셋을 쓴다 — SYSTEM/SOFTWARE와 같다.
    "registry:Amcache": "AMCACHE",
    # K-001 키오스크 시나리오가 요구하는 채널들. evtx 파서를 그대로 재사용하며
    # 채널만 다르다. 접두어를 하나로 묶지 않는 이유는 기존 채널과 같다 —
    # ref 만 보고 어느 로그에서 나온 레코드인지 되짚을 수 있어야 한다.
    #
    # Sysmon 만 EVTX- 접두어를 안 쓴다. Windows 기본 채널이 아니라 별도로
    # 설치하는 도구의 로그이고, EVTX-SYS 가 EVTX-SYSMON 의 접두어가 되는
    # 것을 피하려는 뜻도 있다 (REF_PATTERN 의 교대는 백트래킹으로 풀리지만,
    # 접두어가 겹치지 않는 편이 나중에 물리지 않는다).
    "evtx:Sysmon": "SYSMON",
    "evtx:DriverFrameworks": "EVTX-DRV",
    "evtx:KernelPnP": "EVTX-PNP",
    "evtx:AssignedAccess": "EVTX-AAOP",
    "evtx:AssignedAccessAdmin": "EVTX-AAADM",
    "evtx:AssignedAccessBroker": "EVTX-AABRK",
    "evtx:RDPConnection": "EVTX-RDPCM",
    "evtx:RDPSession": "EVTX-RDPLSM",
    "evtx:Application": "EVTX-APP",
    # HID/BadUSB 시나리오 채널(2026-08-31). Defender 는 방어 무력화
    # (T1562.001), PowerShell 은 스크립트 실행(T1059.001)의 근거다.
    "evtx:Defender": "EVTX-DEF",
    "evtx:PowerShell": "EVTX-PS",

    # RecentFileCache.bcf. Windows 7에서 Amcache 자리를 대신하는 아티팩트라
    # 접두어도 짝이 되게 지었다 — ref만 보고 "어느 세대의 실행 흔적인가"가
    # 드러난다. 레코드 번호는 항목의 파일 내 오프셋이다(레지스트리와 같다).
    "recentfilecache": "RFCACHE",

    # SRUM(SRUDB.dat). 공급자 테이블마다 아티팩트를 나눈다 — evtx 가 채널
    # 마다 나눈 것과 같은 이유이고, 여기서는 그것이 **필수**다. 레코드
    # 번호로 쓸 값은 AutoIncId 뿐인데 그것이 테이블 안에서만 유일해서,
    # 한 접두어로 묶으면 서로 다른 테이블의 1번이 같은 ref 가 된다.
    "srum:NetworkUsage": "SRUM-NET",
    "srum:AppResourceUsage": "SRUM-APP",
    "srum:NetworkConnectivity": "SRUM-CONN",
}

#: 역방향. ref만 보고 어느 파서가 만든 레코드인지 되짚을 때 쓴다.
PREFIX_ARTIFACT: dict[str, str] = {v: k for k, v in ARTIFACT_PREFIX.items()}

#: 앞자리 0을 허용하지 않는다. "MFT#012345"와 "MFT#12345"가 같은 레코드를
#: 가리키면서 문자열로는 달라지면, 06단계의 집합 대조가 통과해야 할 것을 기각한다.
REF_PATTERN = re.compile(
    r"^(?P<prefix>MFT|USN|EVTX-SEC|EVTX-SYS|EVTX-FW|EVTX-BITS|EVTX-NET"
    r"|REG-SYS|REG-SW|AMCACHE|RFCACHE|PF"
    r"|SYSMON|EVTX-DRV|EVTX-PNP|EVTX-AAOP|EVTX-AAADM|EVTX-AABRK|EVTX-RDPCM|EVTX-RDPLSM|EVTX-APP"
    r"|EVTX-DEF|EVTX-PS"
    r"|SRUM-NET|SRUM-APP|SRUM-CONN)#(?P<num>0|[1-9]\d*)$"
)


class Ref(NamedTuple):
    """파싱된 ref."""

    prefix: str
    record_num: int
    artifact: str

    def __str__(self) -> str:
        return f"{self.prefix}#{self.record_num}"


def prefix_for(artifact: str) -> str:
    """아티팩트 이름에 대응하는 ref 접두어를 돌려준다."""
    try:
        return ARTIFACT_PREFIX[artifact]
    except KeyError:
        known = ", ".join(sorted(ARTIFACT_PREFIX))
        raise RefError(f"미등록 아티팩트: {artifact!r} (등록된 값: {known})") from None


def make_ref(artifact: str, record_num: int) -> str:
    """`make_ref("$MFT", 12345)` → `"MFT#12345"`."""
    # bool은 int의 하위 타입이라 isinstance(True, int)가 참이다.
    # 플래그를 레코드 번호 자리에 잘못 넘기는 실수를 여기서 막는다.
    if isinstance(record_num, bool) or not isinstance(record_num, int):
        raise RefError(f"레코드 번호는 정수여야 함: {record_num!r}")
    if record_num < 0:
        raise RefError(f"레코드 번호는 음수일 수 없음: {record_num}")
    return f"{prefix_for(artifact)}#{record_num}"


def parse_ref(ref: str) -> Ref:
    """ref 문자열을 분해한다. 형식이 틀리면 `RefError`."""
    if not isinstance(ref, str):
        raise RefError(f"ref는 문자열이어야 함: {ref!r}")
    m = REF_PATTERN.match(ref)
    if not m:
        raise RefError(
            f"ref 형식 위반: {ref!r} "
            f"(형식은 <접두어>#<레코드번호>, 접두어는 {', '.join(sorted(PREFIX_ARTIFACT))})"
        )
    prefix = m.group("prefix")
    return Ref(prefix=prefix, record_num=int(m.group("num")), artifact=PREFIX_ARTIFACT[prefix])


def is_valid(ref: object) -> bool:
    """형식 검사만 한다. 해당 레코드가 실재하는지는 06단계가 본다."""
    return isinstance(ref, str) and REF_PATTERN.match(ref) is not None


def artifact_of(ref: str) -> str:
    """`"MFT#12345"` → `"$MFT"`."""
    return parse_ref(ref).artifact


def record_num_of(ref: str) -> int:
    """`"MFT#12345"` → `12345`."""
    return parse_ref(ref).record_num
