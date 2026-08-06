"""EDR·SIEM 알럿 → 시나리오 본문. LLM을 쓰지 않는다.

알럿은 이미 구조화되어 있다. 기법 ID도 탐지 규칙이 이미 붙여 놓았다.
여기에 모델을 태우면 얻을 것 없이 환각 위험만 생긴다.

출력 형식은 자연어 경로와 **동일해야** 하므로 같은 단계 안에 둔다.
``normalize.py``가 ``source_type``을 보고 둘 중 하나로 분기한다.

이 구조 덕분에 LLM이 준비되지 않은 상태에서도 03단계 이후를 개발하고
테스트할 수 있다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ..common import attack

__all__ = ["AlertAdapterError", "convert", "SEVERITY_CONFIDENCE", "DEFAULT_WINDOW_DAYS"]


class AlertAdapterError(ValueError):
    """알럿에서 시나리오를 만들 수 없다."""


#: 탐지 규칙의 심각도를 신뢰도로 옮긴다. 알럿은 이미 룰이 확정한
#: 판단이므로 자연어 서술보다 높게 잡는다.
SEVERITY_CONFIDENCE: dict[str, float] = {
    "critical": 0.95,
    "high": 0.9,
    "medium": 0.7,
    "low": 0.5,
    "informational": 0.3,
}

DEFAULT_CONFIDENCE = 0.7

#: 탐지 시각 전후로 넓히는 기간. 탐지는 침해의 시작이 아니라 발각이므로
#: 앞쪽을 더 넓게 본다.
DEFAULT_WINDOW_DAYS = 2
LOOKBACK_DAYS = 3


def convert(raw: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """알럿 하나를 시나리오 본문으로 옮긴다."""
    if not isinstance(raw, dict):
        raise AlertAdapterError(f"알럿 본문이 객체가 아님: {type(raw).__name__}")

    techniques = _techniques(raw)
    if not techniques:
        # 기법이 없으면 선별할 것이 없다. 조용히 빈 배열을 내면
        # 03단계가 아무것도 못 하고 원인이 여기라는 것이 드러나지 않는다.
        raise AlertAdapterError(
            f"알럿에 ATT&CK 기법이 없다 (alert_id={raw.get('alert_id', '?')}). "
            "mitre 필드를 확인하거나 자연어 경로로 처리한다."
        )

    detected_at = _detected_at(raw)
    return {
        "target_os": _target_os(evidence),
        "techniques": techniques,
        "time_range": {
            "start": _iso(detected_at - timedelta(days=LOOKBACK_DAYS)),
            "end": _iso(detected_at + timedelta(days=DEFAULT_WINDOW_DAYS)),
            "basis": (
                f"알럿 탐지 시각({_iso(detected_at)}) 기준 "
                f"-{LOOKBACK_DAYS}일 ~ +{DEFAULT_WINDOW_DAYS}일. "
                "탐지는 침해의 시작이 아니라 발각이므로 앞쪽을 넓게 잡음"
            ),
        },
        "entities": _entities(raw),
        "overall_confidence": _confidence(raw),
        "unmapped_text": _unmapped(raw),
    }


def _techniques(raw: dict[str, Any]) -> list[dict[str, Any]]:
    confidence = _confidence(raw)
    rule_name = str(raw.get("rule_name", "")) or "탐지 규칙 이름 없음"

    techniques: list[dict[str, Any]] = []
    for technique_id in raw.get("mitre") or []:
        technique_id = str(technique_id)
        if not attack.is_valid_format(technique_id):
            # 알럿이 준 값이라도 형식이 틀리면 버린다. 여기서 통과시키면
            # 03단계가 매핑을 못 찾고 원인이 모델로 잘못 기록된다.
            continue
        techniques.append(
            {
                "id": technique_id,
                "name": attack.name_of(technique_id) or technique_id,
                "confidence": confidence,
                "evidence_text": rule_name,
            }
        )
    return techniques


def _confidence(raw: dict[str, Any]) -> float:
    severity = str(raw.get("severity", "")).strip().lower()
    return SEVERITY_CONFIDENCE.get(severity, DEFAULT_CONFIDENCE)


def _detected_at(raw: dict[str, Any]) -> datetime:
    value = raw.get("detected_at")
    if not value:
        raise AlertAdapterError("알럿에 detected_at이 없어 시간 범위를 정할 수 없다")
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise AlertAdapterError(f"detected_at 형식을 읽을 수 없음: {value!r}") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _target_os(evidence: dict[str, Any]) -> str:
    os_hint = str(evidence.get("os_hint", "")).lower()
    return "linux" if "linux" in os_hint or "ubuntu" in os_hint or "centos" in os_hint else "windows"


def _entities(raw: dict[str, Any]) -> dict[str, list[str]]:
    process = raw.get("process") or {}
    processes = [
        str(value)
        for value in (process.get("name"), process.get("parent"))
        if value
    ]

    paths = [str(p) for p in (raw.get("paths") or []) if p]
    for candidate in (process.get("path"), process.get("image")):
        if candidate:
            paths.append(str(candidate))

    accounts = [str(a) for a in (raw.get("accounts") or []) if a]
    if raw.get("user"):
        accounts.append(str(raw["user"]))

    ips = [str(i) for i in (raw.get("ips") or []) if i]
    for key in ("source_ip", "destination_ip", "remote_ip"):
        if raw.get(key):
            ips.append(str(raw[key]))

    hosts = [str(raw["host"])] if raw.get("host") else []
    return {
        "hosts": _dedupe(hosts),
        "paths": _dedupe(paths),
        "processes": _dedupe(processes),
        "accounts": _dedupe(accounts),
        "ips": _dedupe(ips),
    }


def _unmapped(raw: dict[str, Any]) -> list[str]:
    """기법으로 옮기지 못한 정보. 커맨드라인은 매핑 대상이 아니라 남긴다."""
    unmapped: list[str] = []
    cmdline = (raw.get("process") or {}).get("cmdline")
    if cmdline:
        unmapped.append(f"실행 명령: {cmdline}")
    return unmapped


def _dedupe(values: list[str]) -> list[str]:
    """순서를 유지하며 중복을 없앤다. paths의 첫 항목이 선별 기준이 된다."""
    return list(dict.fromkeys(values))
