"""노드 사이를 잇는다 — 지어낼 수 없는 값으로만.

**왜 파이썬이 하는가.** `ref` 에 노드를 넣어 05단계가 노드를 넘나들게 하면
"이 파일이 POS 로 갔다"를 **모델이 주장**하고, 06단계는 그 주장을 값 대조로만
봅니다. 노드를 잇는 판단이 검증되지 않은 채 보고서에 오릅니다. 그래서 노드
안은 지금 그대로 두고, 노드 사이는 결정론으로 잇습니다
(`docs/proposals/multi-node-campaign.md` 1장).

**새 어휘를 만들지 않습니다.** 값은 04단계의 `canonical` 오버레이에서 오고,
해시·경로 정규화는 `incident_packet`·`io.normalize_path` 의 것을 그대로
씁니다. 여기서 규칙을 다시 쓰면 같은 값이 노드 안에서는 이어지고 노드
사이에서는 안 이어지는 일이 생깁니다.

**링크는 "같은 값이 두 노드에 있었다"까지만 말합니다.** 인과도, 방향도
주장하지 않습니다. 시간 순서는 사람이 방향을 판단할 재료일 뿐입니다 —
시계가 노드마다 어긋날 수 있습니다.
"""

from __future__ import annotations

import re
from ipaddress import ip_address
from typing import Any, Iterable
from urllib.parse import urlsplit

from ..common.io import normalize_path, parse_timestamp
from ..stage04_parse import canonical
from ..stage05_interpret.incident_packet import _hash_keys

__all__ = ["AXES", "UBIQUITOUS_ACCOUNTS", "observations_of", "build_links"]

#: 상관 축. 순서가 곧 보고서에 실리는 순서다 — 지어내기 어려운 것부터.
AXES = ("hash", "network", "filename", "path", "account")

#: 계정 축에서 뺄 이름. 모든 윈도우 기계에 있으므로 노드를 이어도 뜻이 없다.
#: **이것은 베이스라인이 아니다** — 어느 기계에나 있는 내장 계정만 뺀다.
#: 배포 이미지가 같아서 공통인 사용자 계정은 못 거른다(설계서 6장).
UBIQUITOUS_ACCOUNTS = frozenset(
    {
        "system",
        "local service",
        "network service",
        "localsystem",
        "trustedinstaller",
        "-",
    }
)

#: 명령행에 박힌 IPv4. Sysmon EID 3 이 없는 채널에서도 다운로드 주소를 잡는다.
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

#: 명령행에 박힌 HTTP(S) URL. IP뿐 아니라 C2 도메인도 같은 축으로 잇는다.
_HTTP_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

#: 주소로 보아 어느 노드에나 나타날 수 있으므로 상관 키에서 제외한다.
_LOCAL_HOSTS = frozenset({"localhost", "localhost.localdomain"})


def _network_key(value: Any) -> "str | None":
    """호스트/IP를 정규화하고 로컬·루프백·미지정 주소를 제외한다."""
    if not isinstance(value, str) or not value.strip():
        return None
    key = value.strip().rstrip(".").casefold()
    if not key or key in _LOCAL_HOSTS:
        return None
    try:
        address = ip_address(key)
    except ValueError:
        # IPv4처럼 생겼지만 범위를 벗어난 값은 호스트명으로 되살리지 않는다.
        return None if _IPV4.fullmatch(key) else key
    if address.is_loopback or address.is_unspecified:
        return None
    return address.compressed.casefold()


def _account_key(value: Any) -> "str | None":
    """``DOMAIN\\user`` 에서 사용자 이름만. 내장 계정이면 ``None``."""
    if not isinstance(value, str) or not value.strip():
        return None
    name = value.strip().rsplit("\\", 1)[-1].casefold()
    if not name or name in UBIQUITOUS_ACCOUNTS or name.endswith("$"):
        # 끝의 ``$`` 는 컴퓨터 계정이다. 노드마다 다르므로 이을 것이 없다.
        return None
    return name


def _network_keys(canon: dict[str, Any]) -> set[str]:
    """원격 주소. 필드에 있는 것과 명령행에 박힌 것을 함께 본다.

    **사설 대역을 빼지 않는다.** 내부망 횡적 이동이 바로 그 대역이다.
    """
    keys: set[str] = set()
    remote = _network_key(canon.get("remote_ip"))
    if remote:
        keys.add(remote)
    command = canon.get("command_line")
    if isinstance(command, str):
        for match in _IPV4.finditer(command):
            key = _network_key(match.group(0))
            if key:
                keys.add(key)
        for match in _HTTP_URL.finditer(command):
            # 닫는 괄호·문장부호는 명령행 설명에서 URL 바로 뒤에 붙을 수 있다.
            candidate = match.group(0).rstrip(".,);]}")
            try:
                host = urlsplit(candidate).hostname
            except ValueError:
                continue
            key = _network_key(host)
            if key:
                keys.add(key)
    return keys


def _keys_of(record: dict[str, Any]) -> dict[str, set[str]]:
    """레코드 하나가 각 축에 내놓는 값."""
    canon = record.get("canonical")
    if not isinstance(canon, dict):
        canon = canonical.overlay(record).get("canonical") or {}

    keys: dict[str, set[str]] = {axis: set() for axis in AXES}
    keys["hash"] = set(_hash_keys({"canonical": canon}))
    keys["network"] = _network_keys(canon)

    path = canon.get("subject_path")
    if isinstance(path, str) and path.strip():
        normalized = normalize_path(path)
        keys["path"].add(normalized)
        base = normalized.rsplit("/", 1)[-1]
        if base:
            keys["filename"].add(base)

    account = _account_key(canon.get("user"))
    if account:
        keys["account"].add(account)
    return keys


#: 등급 순서. 노드 대표를 고를 때와 링크 등급을 정할 때 같은 표를 쓴다 —
#: 둘이 갈리면 "대표로 뽑힌 근거"와 "링크에 적힌 등급"이 어긋난다.
_GRADE_ORDER = {"passed": 0, "warning": 1, "uncited": 2}


def observations_of(node: str, records: Iterable[dict[str, Any]], verdicts: dict[str, str]) -> dict:
    """``(축, 값) → 이 노드의 대표 관측 하나``.

    **노드마다 하나로 줄이는 것이 여기다.** 같은 해시가 한 노드에서 수백 번
    나와도 링크는 하나여야 표가 반복으로 덮이지 않습니다.

    **판정이 좋은 쪽을 먼저 고르고, 같으면 이른 쪽을 고릅니다.** 순서가
    반대면 검증되지 않은 레코드가 검증된 것을 가립니다 — 합성 픽스처
    ``campaign-3node`` 에서 실제로 그랬습니다. ``s.ps1`` 이 kiosk 의 통과
    소견과 pos 의 주의 소견 양쪽에 있었는데, pos 쪽에 25초 더 이른 **인용되지
    않은** ``$MFT`` 레코드가 있어 링크 전체가 참고 항목으로 내려갔습니다.
    시각은 체인의 순서를 정할 뿐이고, 링크가 실릴 자리를 정하는 것은
    근거의 등급입니다.

    ``verdicts`` 는 ``ref → passed|warning|rejected`` 입니다. 없는 ref 는 어느
    소견도 인용하지 않은 것이라 ``uncited`` 가 됩니다.
    """
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        ref = record.get("ref")
        if not isinstance(ref, str) or not ref:
            continue
        verdict = verdicts.get(ref, "uncited")
        if verdict == "rejected":
            # 06단계가 기각한 소견만 이 레코드를 인용했다. 그것으로 노드를
            # 이으면 보고서가 검증을 우회한다 — 07이 기각된 문장의 타임라인
            # 항목을 지우는 것과 같은 자리다.
            continue
        moment = parse_timestamp(record.get("timestamp"))
        observation = {
            "node": node,
            "ref": ref,
            "artifact": str(record.get("artifact") or ""),
            "verdict": verdict,
        }
        if record.get("timestamp"):
            observation["at"] = record["timestamp"]

        for axis, values in _keys_of(record).items():
            for value in values:
                key = (axis, value)
                current = best.get(key)
                if current is None or _better(observation, moment, current):
                    best[key] = {**observation, "_moment": moment}
    return best


def _better(candidate: dict[str, Any], moment, incumbent: dict[str, Any]) -> bool:
    """판정이 좋은 쪽, 같으면 이른 쪽. 시각 없는 것은 있는 것에 밀린다."""
    rank = _GRADE_ORDER.get(candidate["verdict"], 2)
    held = _GRADE_ORDER.get(incumbent["verdict"], 2)
    if rank != held:
        return rank < held
    incumbent_moment = incumbent.get("_moment")
    if moment is None:
        return False
    if incumbent_moment is None:
        return True
    return moment < incumbent_moment



def build_links(per_node: dict[str, dict], node_count: int) -> dict[str, Any]:
    """노드별 관측을 모아 링크를 만든다.

    ``per_node`` 는 ``노드 이름 → observations_of() 결과`` 입니다.
    """
    merged: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for observations in per_node.values():
        for key, observation in observations.items():
            merged.setdefault(key, []).append(observation)

    links: list[dict[str, Any]] = []
    context: list[dict[str, Any]] = []
    ubiquitous = 0

    for (axis, value), observations in merged.items():
        if len({item["node"] for item in observations}) < 2:
            continue  # 한 노드 안의 값은 노드를 잇지 않는다
        if node_count >= 3 and len({item["node"] for item in observations}) == node_count:
            # 모든 노드에 있는 값은 대개 배경이다. 지우지 않고 세기만 한다 —
            # 진짜 해법은 베이스라인이고, 그것이 없다는 사실이 수치로 남아야
            # 한다(설계서 6장).
            ubiquitous += 1
            continue

        ordered = sorted(observations, key=lambda item: (item.get("at") is None, item.get("at") or ""))
        cleaned = [{k: v for k, v in item.items() if k != "_moment"} for item in ordered]
        entry: dict[str, Any] = {"axis": axis, "value": value, "observations": cleaned}

        span = _span_seconds(ordered)
        if span is not None:
            entry["span_seconds"] = span

        worst = max(_GRADE_ORDER.get(item["verdict"], 2) for item in cleaned)
        if worst >= _GRADE_ORDER["uncited"]:
            context.append(entry)
        else:
            entry["grade"] = "warning" if worst == _GRADE_ORDER["warning"] else "passed"
            links.append(entry)

    links.sort(key=_chain_order)
    context.sort(key=_chain_order)
    return {"links": links, "context_links": context, "ubiquitous_values": ubiquitous}


def _span_seconds(observations: list[dict[str, Any]]) -> "float | None":
    moments = [item.get("_moment") for item in observations if item.get("_moment") is not None]
    if len(moments) < 2:
        return None
    return round((max(moments) - min(moments)).total_seconds(), 3)


def _chain_order(entry: dict[str, Any]) -> tuple:
    """가장 이른 관측 순. 시각 없는 것은 뒤로, 그다음은 축 선언 순."""
    first = entry["observations"][0].get("at")
    return (first is None, first or "", AXES.index(entry["axis"]), entry["value"])
