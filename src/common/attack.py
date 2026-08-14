"""ATT&CK ID 유효성 검사, 기법명 조회.

02단계 검증 규칙: ``techniques[].id``는 사전 정의된 ATT&CK ID 목록에
존재해야 한다.

검사를 두 층으로 나눈 이유가 있다.

- **형식 검사**(``is_valid_format``) — ``T1505.003`` 꼴인가. 스키마가 담당한다.
- **목록 검사**(``is_known``) — 실재하는 기법인가. 이 모듈이 담당한다.

sLLM이 만들어 내는 오류는 두 종류다. ``"웹셸"`` 같은 형식 위반과, ``T9999``
처럼 형식은 맞는데 존재하지 않는 ID다. 후자가 더 흔하고 더 위험하다.
형식만 보면 통과해 버리기 때문이다. 둘을 나눠 집계해야
``errors.jsonl``에서 "존재하지 않는 ATT&CK ID 생성" 비율이 따로 나온다.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

__all__ = [
    "TECHNIQUE_ID_PATTERN",
    "KNOWN_TECHNIQUES",
    "AttackIdError",
    "is_valid_format",
    "is_known",
    "name_of",
    "check_id",
    "mapped_techniques",
    "unmapped",
]


class AttackIdError(ValueError):
    """유효하지 않은 ATT&CK 기법 ID."""


#: ``T1505`` 또는 ``T1505.003``.
TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

#: 본 프로젝트가 다루는 범위의 기법 목록. **완전한 ATT&CK 카탈로그가 아니다.**
#:
#: 여기 없는 ID를 sLLM이 내면 스키마 위반으로 처리된다. 정상 기법인데
#: 목록에 없어서 기각된 사례가 나오면, 그것은 모델 문제가 아니라 이 목록의
#: 결손이다. ``errors.jsonl``의 ``detail.value`` 분포를 보고 채워 나간다.
KNOWN_TECHNIQUES: dict[str, str] = {
    # 매핑 테이블이 있는 기법 (mappings/windows/)
    "T1505.003": "Server Software Component: Web Shell",
    "T1136.001": "Create Account: Local Account",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1070.006": "Indicator Removal: Timestomp",
    # 매핑은 아직 없으나 시나리오에 자주 등장하는 기법
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1112": "Modify Registry",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
}


def is_valid_format(technique_id: object) -> bool:
    """``T1505.003`` 꼴인지만 본다. 실재 여부는 보지 않는다."""
    return isinstance(technique_id, str) and TECHNIQUE_ID_PATTERN.match(technique_id) is not None


def is_known(technique_id: object) -> bool:
    """``KNOWN_TECHNIQUES``에 있는 ID인가."""
    return isinstance(technique_id, str) and technique_id in KNOWN_TECHNIQUES


def name_of(technique_id: str) -> str | None:
    """기법명을 돌려준다. 모르는 ID면 ``None``."""
    return KNOWN_TECHNIQUES.get(technique_id)


def check_id(technique_id: object, *, require_known: bool = True) -> str:
    """검사를 통과하면 ID를 그대로 돌려주고, 아니면 ``AttackIdError``.

    ``require_known=False``는 카탈로그를 넓히는 실험용이다. 형식만 맞으면
    통과시켜 두고, 나중에 어떤 ID가 실제로 들어왔는지 훑어본다.
    """
    if not is_valid_format(technique_id):
        raise AttackIdError(
            f"ATT&CK ID 형식 위반: {technique_id!r} (형식은 T#### 또는 T####.###)"
        )
    assert isinstance(technique_id, str)
    if require_known and not is_known(technique_id):
        raise AttackIdError(f"유효하지 않은 ATT&CK ID: {technique_id}")
    return technique_id


def mapped_techniques(mappings_dir: str | Path) -> set[str]:
    """매핑 테이블 파일이 실제로 존재하는 기법 ID 집합.

    파일명이 곧 기법 ID다(``mappings/windows/T1505.003.yaml``).
    """
    root = Path(mappings_dir)
    return {
        p.stem
        for p in root.glob("*/*.yaml")
        if not p.name.startswith("_") and is_valid_format(p.stem)
    }


def unmapped(technique_ids: Iterable[str], mappings_dir: str | Path) -> list[str]:
    """매핑 테이블이 없어 선별에 쓰이지 못하는 기법을 골라낸다.

    02단계가 옳게 식별했는데 03단계가 아무것도 선별하지 못하는 경우를
    잡는다. 선별 재현율이 낮을 때 원인이 모델인지 매핑 결손인지
    구분하려면 이 목록이 필요하다.
    """
    have = mapped_techniques(mappings_dir)
    return [t for t in technique_ids if t not in have]
