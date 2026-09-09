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

__all__ = ["AXES", "OS_OWNED_PREFIXES", "UBIQUITOUS_ACCOUNTS", "observations_of", "build_links"]

#: 상관 축. 순서가 곧 보고서에 실리는 순서다 — 지어내기 어려운 것부터.
#:
#: ``peer`` 는 다른 축과 **조인 방식이 다르다.** 나머지는 "같은 값이 두 노드에
#: 있었다"인데, 이쪽은 **"A 가 기록한 원격 주소 == B 의 자기 주소"** 다.
#: 그래서 방향이 값에서 나온다 — 시각 순서가 아니라 A 의 레코드가 "나는 B 로
#: 붙었다"고 말한다. 횡적 이동의 유일한 직접 증거이고, 같은 외부 C2 를 공유한
#: 것(``network``)과는 뜻이 다르다.
AXES = ("hash", "peer", "network", "filename", "path", "account")

#: Sysmon 네트워크 연결(EID 3)에서 **자기 주소**를 읽을 때 쓰는 필드.
#: ``Initiated`` 가 참이면 이 기계가 건 연결이므로 ``SourceIp`` 가 자기 것이다.
#: 거짓(수신)이면 ``SourceIp`` 는 상대 주소이고, 실측에서 그쪽에는 멀티캐스트·
#: 브로드캐스트가 모인다(224.0.0.251·ff02::fb·x.x.x.255).
_NETWORK_EVENT_ID = 3

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


def _self_address(record: dict[str, Any]) -> "str | None":
    """이 레코드가 드러내는 **이 노드 자신의** 주소. 없으면 ``None``.

    질문에 IP 가 없어도 노드를 이으려면 각 노드의 주소를 알아야 하는데,
    ``02_scenario`` 의 ``entities.hosts`` 는 사람이 적어 준 것이라 두 줄짜리
    신고에는 없다(``키오스크`` 처럼 이름만 온다). 그래서 증거에서 읽는다.

    **아웃바운드만 본다.** ``Initiated`` 가 거짓인 수신 연결의 ``SourceIp`` 는
    상대 주소이고, 실측에서 그쪽에는 멀티캐스트·브로드캐스트가 모인다.
    """
    if record.get("event_id") != _NETWORK_EVENT_ID:
        return None
    fields = record.get("fields")
    if not isinstance(fields, dict):
        return None
    if str(fields.get("Initiated")).strip().lower() != "true":
        return None
    return _network_key(fields.get("SourceIp"))


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

    self_address = _self_address(record)
    if self_address:
        keys["peer"].add(self_address)
    return keys


#: 운영체제·설치 관리자가 놓은 자리. ``normalize_path`` 를 거친 꼴이라
#: 소문자에 슬래시다. 드라이브 문자는 뺀다 — 볼륨이 달라도 같은 자리다.
#:
#: **이 축들이 무엇을 말하는지가 여기서 갈린다.** 해시·파일명·경로가 두
#: 노드에서 같다는 것은 두 가지 중 하나다 — 공격자가 파일을 옮겼거나,
#: **두 기계가 같은 윈도우를 깔았거나**. 뒤쪽은 노드를 잇는 증거가 아니다.
#:
#: 실측(`K2L2-20260908`, 2026-09-10). 체인에 오른 🟢 5건 중 4건이
#: `c:/windows/system32/schtasks.exe` 와 `.../whoami.exe` 였다. 모든 윈도우
#: 기계에 같은 해시로 있는 파일이고, 이 사건과 무관하게 항상 일치한다.
#: 앞선 실행(`K2L-20260908`)에서는 같은 자리에 `dismhost.exe` 가 있었다.
#:
#: **모든 노드에 있는 값을 세는 규칙으로는 안 걸린다.** 그 규칙은 노드
#: 셋 전부에 있을 때만 도는데, 이 증거의 POS 에는 schtasks 실행 기록이
#: 없어 두 노드짜리 링크가 됐다. 값의 분포가 아니라 **자리**를 봐야 한다.
OS_OWNED_PREFIXES = (
    "windows/",
    "program files/",
    "program files (x86)/",
    "programdata/microsoft/",
    "winnt/",
)


def _os_owned(path: str) -> bool:
    """이 경로가 운영체제·설치 관리자의 자리인가.

    드라이브 문자를 떼고 본다. 못 떼면(상대 경로·UNC) **거짓**이다 —
    모르는 것을 배경으로 내리면 증거가 조용히 사라진다.
    """
    if not isinstance(path, str) or not path:
        return False
    body = path
    if len(body) > 2 and body[1] == ":":
        body = body[2:]
    body = body.lstrip("/")
    return body.startswith(OS_OWNED_PREFIXES)


#: ``_os_owned`` 로 걸러지는 축. ``peer``·``network``·``account`` 는 제외다 —
#: 주소와 계정에는 "자리"가 없고, ``peer`` 는 다른 노드가 자기 주소라고
#: 말한 것이라 배경일 수 없다(``_peer_links``).
_PATH_BEARING_AXES = frozenset({"hash", "filename", "path"})

#: 관측에 붙여 다니지만 문서에는 안 나가는 키. schemas/ 가 동결이고
#: ``observations`` 가 additionalProperties: false 라, 한 자리에서라도
#: 안 떼면 08 이 스키마 위반으로 멈춘다 — 실제로 그렇게 멈췄다.
_INTERNAL_KEYS = frozenset({"_moment", "_os_owned"})

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

        # 이 레코드의 대상 경로가 운영체제의 자리인가. 해시·파일명 축은
        # 값 자체에 경로가 없으므로 여기서 한 번 재어 붙인다 (``_os_owned``).
        canon = record.get("canonical")
        if not isinstance(canon, dict):
            canon = canonical.overlay(record).get("canonical") or {}
        subject = canon.get("subject_path")
        os_owned = _os_owned(normalize_path(subject)) if isinstance(subject, str) and subject else False

        for axis, values in _keys_of(record).items():
            for value in values:
                key = (axis, value)
                current = best.get(key)
                if current is None or _better(observation, moment, current):
                    best[key] = {**observation, "_moment": moment, "_os_owned": os_owned}
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
    os_background = 0

    for (axis, value), observations in merged.items():
        if len({item["node"] for item in observations}) < 2:
            continue  # 한 노드 안의 값은 노드를 잇지 않는다
        if node_count >= 3 and len({item["node"] for item in observations}) == node_count:
            # 모든 노드에 있는 값은 대개 배경이다. 지우지 않고 세기만 한다 —
            # 진짜 해법은 베이스라인이고, 그것이 없다는 사실이 수치로 남아야
            # 한다(설계서 6장).
            ubiquitous += 1
            continue

        if axis in _PATH_BEARING_AXES and all(item.get("_os_owned") for item in observations):
            # **두 기계가 같은 윈도우를 깔았다는 말이다.** 노드를 잇는 증거가
            # 아니므로 체인에서 내린다. 지우지는 않는다 — 참고 표에 남겨야
            # 무엇을 왜 뺐는지 되짚을 수 있다(모든 노드에 있는 값을 세기만
            # 하는 규칙과 같은 태도).
            os_background += 1
            observations = [{**item, "verdict": "uncited"} for item in observations]

        ordered = sorted(observations, key=lambda item: (item.get("at") is None, item.get("at") or ""))
        cleaned = [
            {k: v for k, v in item.items() if k not in _INTERNAL_KEYS}
            for item in ordered
        ]
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

    links.extend(_peer_links(per_node))

    links.sort(key=_chain_order)
    context.sort(key=_chain_order)
    return {
        "links": links,
        "context_links": context,
        "ubiquitous_values": ubiquitous,
        "os_background_values": os_background,
    }


def _peer_links(per_node: dict[str, dict]) -> list[dict[str, Any]]:
    """**A 가 기록한 원격 주소가 B 의 자기 주소인** 연결. 방향이 있다.

    다른 축과 조인이 다르다 — 같은 값을 두 노드가 **각자 다른 자격으로**
    내놓는다. B 는 ``peer``(내 주소가 이것이다), A 는 ``network``(나는 이
    주소로 붙었다). 그래서 화살표가 시각이 아니라 **레코드에서** 나온다.

    **인용 여부로 내리지 않는다.** 다른 축은 흔한 값이 배경일 수 있어
    소견이 인용한 것만 체인에 올리지만(``whoami.exe`` 가 그랬다), 이 축의
    값은 **이 캠페인의 다른 노드가 자기 주소라고 말한 것**이라 배경일 수
    없다. 판정은 ``observed`` 로 따로 둔다 — 파이썬이 레코드에서 읽은
    사실이지 모델의 주장이 아니므로, 06 을 통과한 소견과 같은 딱지를 달면
    보고서가 두 가지를 같은 말로 인쇄한다.

    한 노드가 주소를 여럿 갖는 것은 정상이다(사내망 + 오버레이). 주소마다
    링크를 따로 내되, 같은 (A, B) 쌍이 여러 주소로 이어지면 각각 남긴다 —
    어느 경로로 붙었는지가 조사에 쓸모 있다.
    """
    peer_links: list[dict[str, Any]] = []
    for destination, observations in per_node.items():
        for (axis, address), landing in observations.items():
            if axis != "peer":
                continue
            for source, other in per_node.items():
                if source == destination:
                    continue
                departure = other.get(("network", address))
                if departure is None:
                    continue
                # 순서가 곧 방향이다. 시각으로 다시 정렬하지 않는다 —
                # 시계가 어긋난 두 노드에서 화살표가 뒤집힌다.
                pair = [
                    {k: v for k, v in departure.items() if k not in _INTERNAL_KEYS},
                    {k: v for k, v in landing.items() if k not in _INTERNAL_KEYS},
                ]
                entry: dict[str, Any] = {
                    "axis": "peer",
                    "value": address,
                    "grade": "observed",
                    "observations": pair,
                }
                span = _span_seconds([departure, landing])
                if span is not None:
                    entry["span_seconds"] = span
                peer_links.append(entry)
    return peer_links


def _span_seconds(observations: list[dict[str, Any]]) -> "float | None":
    moments = [item.get("_moment") for item in observations if item.get("_moment") is not None]
    if len(moments) < 2:
        return None
    return round((max(moments) - min(moments)).total_seconds(), 3)


def _chain_order(entry: dict[str, Any]) -> tuple:
    """가장 이른 관측 순. 시각 없는 것은 뒤로, 그다음은 축 선언 순."""
    first = entry["observations"][0].get("at")
    return (first is None, first or "", AXES.index(entry["axis"]), entry["value"])
