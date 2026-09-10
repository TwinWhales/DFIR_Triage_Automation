"""Observable attention signals that guarantee sLLM review.

These signals do not classify a record as malicious.  They identify evidence
whose meaning must be dispositioned by the model so allocation cannot silently
discard it.

**어떤 실행 파일 이름도 이 파일에 적지 않는다.** 대표 레코드 선택 우선순위는
``mappings/_attention_signals.yaml`` 의 ``representative_images`` 가 원본이다.
파이썬에 적으면 그 표본에서만 맞는 값이 코드에 남는다.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from ..common import attention_policy

#: 사건 앵커를 찾을 창의 폭.
#:
#: **서로 다른 신호가 가장 많이 겹치는 창의 시작**을 그 실행의 사건 시각으로
#: 본다. 한 신호가 여러 번 나는 것은 흔하지만(설치 관리자가 임시 폴더에서
#: 여러 번 실행된다), **성격이 다른 신호 예닐곱이 한 시간 안에 겹치는 것**은
#: 배경에서 잘 일어나지 않는다.
#:
#: 실측(`K-2LINE-FIX`, 2026-09-09): 12일치 증거에서 이 창이 짚은 곳이
#: 2026-09-07 12:57 이고 거기 신호 7종이 겹쳤다 — 실제 공격 시각이다.
#: 같은 데이터에서 **신호 시각의 중앙값은 09-04 02:41 로 배경 한가운데**를
#: 짚었다. 중앙값이 아니라 밀집도를 보는 이유가 그것이다.
#:
#: ``allocation.DEFAULT_BURST_SECONDS``(120초)와 뜻이 다르다. 저쪽은 한
#: 프로세스 연쇄의 폭이고 이쪽은 사건 국면의 폭이다.
ANCHOR_WINDOW_SECONDS = 3600.0

#: 시각이 없는 레코드의 앵커 거리. 정렬에서 맨 뒤로 보내되 후보에서
#: 빼지는 않는다 — 레지스트리 키처럼 시각이 없어도 볼 것은 볼 것이다.
_NO_TIME_DISTANCE = float("inf")

#: 한 신호의 대표 자리에서 **똑같은 명령행**이 몇 번까지 갈 수 있나.
#:
#: ``max_representatives`` 는 "이 신호를 몇 건 보낼까"를 정하지만 **몇 가지를
#: 보낼까**는 정하지 않는다. 한 명령이 주기적으로 되풀이되면 그 자리를 전부
#: 같은 문자열이 먹는다. 실측(``K2L7``, 2026-09-10):
#:
#: .. code-block:: text
#:
#:     MGMT  execution_from_unusual_path         5자리 → 같은 명령행 1가지로 5건
#:     POS   execution_from_unusual_path         5자리 → 같은 명령행 1가지로 5건
#:     MGMT  execution_outside_known_volume_root 5자리 → 같은 명령행 2가지로 5건
#:
#: 세 경우 다 **모델이 보는 가짓수는 1~2인데 자리는 5를 썼다.** POS 는 그
#: 신호가 유일하게 "이름을 모르는 도구"를 잡는 레인인데, 그 레인 전체를
#: 수집 도구 자신이 가져가고 공격 표지는 보고서에 0건이었다.
#:
#: **2인 이유.** 1이면 "한 번 있었다"로 읽히고 주기가 안 보인다. 2면
#: **간격이 보인다** — 되풀이가 곧 사실인 신호(``database_dump_observed`` 의
#: YAML 주석)에서 그 사실이 살아 있으면서, 나머지 자리가 다른 가짓수로
#: 열린다. 3 이상은 위 실측에서 가짓수를 하나도 더 늘리지 못했다.
#:
#: **이름을 적지 않는다.** 무엇이 되풀이되는지는 데이터가 말하고, 여기 있는
#: 것은 "같은 문자열의 되풀이는 가짓수가 아니다"라는 셈법뿐이다.
MAX_IDENTICAL_COMMANDS = 2

#: 되풀이 판정에 쓸 필드. 이 값들이 다 같으면 같은 행위로 본다.
_REPEAT_KEY_FIELDS = ("Image", "CommandLine")


def _text(record: dict[str, Any]) -> str:
    fields = record.get("fields") if isinstance(record.get("fields"), dict) else {}
    values: list[str] = []
    for value in fields.values():
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(str(item) for item in value if isinstance(item, (str, int, float)))
    values.extend(str(record.get(key) or "") for key in ("path", "name", "timestamp"))
    return "\n".join(values).lower()


def _field(record: dict[str, Any], dotted: str) -> Any:
    """``fields.CommandLine`` 처럼 점 표기 하나를 따라간다."""
    current: Any = record
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _scoped_text(record: dict[str, Any], names: Iterable[str]) -> str:
    values: list[str] = []
    for name in names:
        value = _field(record, name)
        if isinstance(value, list):
            values.extend(str(item) for item in value)
        elif value is not None:
            values.append(str(value))
    return "\n".join(values).lower()


def _blob(record: dict[str, Any], rule: Any, full: str) -> str:
    """규칙이 볼 문자열. ``match_fields`` 를 적었으면 그 필드만 본다."""
    return _scoped_text(record, rule.match_fields) if rule.match_fields else full


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _string_values(child)]
    if isinstance(value, list):
        return [item for child in value for item in _string_values(child)]
    return []


def _group_tokens(signal: str, policy: Any) -> tuple[str, ...]:
    for group in policy.path_groups:
        if group.signal == signal:
            return group.contains
    return ()


def _representative_images(signal: str, policy: Any) -> tuple[str, ...]:
    for rule in policy.signals:
        if rule.name == signal and rule.representative_images:
            return rule.representative_images
    for group in policy.path_groups:
        if group.signal == signal and group.representative_images:
            return group.representative_images
    return ()


def _signal_context(record: dict[str, Any], signal: str, policy: Any) -> list[str]:
    """Keep exact matching source values so Reduce sees more than a flag name."""
    rules = [rule for rule in policy.signals if rule.name == signal]
    tokens = _group_tokens(signal, policy)
    matched: list[str] = []
    for value in _string_values(record):
        folded = value.casefold()
        if any(rule.matches(folded) for rule in rules) or any(token in folded for token in tokens):
            if value not in matched:
                matched.append(value)
    # 플래그 기반 신호는 이미 04단계가 관용구를 판정했다. Reduce가 플래그
    # 이름만 보고 처분하지 않도록, 선언된 필드의 원문도 함께 보낸다.
    if any(rule.flags for rule in rules):
        for rule in rules:
            for field in rule.match_fields:
                for value in _string_values(_field(record, field)):
                    if value not in matched:
                        matched.append(value)
    return matched[:4]


def _signal_requirement(record: dict[str, Any], signal: str, policy: Any) -> dict[str, list[str]]:
    full = _text(record)
    record_flags = tuple(str(flag).casefold() for flag in (record.get("flags") or []))
    for rule in policy.signals:
        if rule.name != signal:
            continue
        matched_flags = [flag for flag in rule.flags if flag in record_flags]
        if matched_flags:
            return {"flags": matched_flags}
        blob = _blob(record, rule, full)
        if rule.all_contains and all(token in blob for token in rule.all_contains):
            return {"all": list(rule.all_contains)}
        matched = [token for token in rule.any_contains if token in blob]
        if matched:
            return {"any": matched}
    matched = [token for token in _group_tokens(signal, policy) if token in full]
    return {"any": matched} if matched else {}


def signal_ids(record: dict[str, Any], *, mappings: str | None = None) -> list[str]:
    full = _text(record)
    record_flags = tuple(str(flag).casefold() for flag in (record.get("flags") or []))
    signals: list[str] = []
    policy = attention_policy.load(mappings)
    signals.extend(
        rule.name for rule in policy.signals
        if rule.must_review and rule.matches(_blob(record, rule, full), record_flags)
    )
    for group in policy.path_groups:
        if group.signal and group.must_review and any(token in full for token in group.contains):
            signals.append(group.signal)
    # Fan-out is retained in incident_context for contextual reasoning, but is
    # not globally promoted to must_review: browsers and service hosts routinely
    # exceed the threshold and would flood the mandatory disposition output.
    return signals


def _score(record: dict[str, Any], signal: str, policy: Any) -> int:
    """선언된 순서만으로 대표를 고른다 — 파이썬에 이름을 적지 않는다.

    경로 어휘의 적중 순위가 실행 파일 순위보다 앞선다. 구체적인 증거(브라우저
    자격증명 파일)가 실행 파일 이름보다 그 레코드를 잘 특정하기 때문이다.
    """
    ordered = _group_tokens(signal, policy)
    matches = (record.get("attention_evidence") or {}).get(signal, [])
    token_rank = max(
        (len(ordered) - ordered.index(token) for token in matches if token in ordered),
        default=0,
    )
    images = _representative_images(signal, policy)
    fields = record.get("fields") if isinstance(record.get("fields"), dict) else {}
    image = str(fields.get("Image") or record.get("name") or "").casefold()
    image_rank = next(
        (len(images) - index for index, name in enumerate(images) if image.endswith(name)),
        0,
    )
    return token_rank * 10 + image_rank


def _moment(record: dict[str, Any]) -> "datetime | None":
    value = record.get("timestamp")
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value.split(".")[0].rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def burst_anchor(
    observed: "list[tuple[datetime, frozenset[str]]]",
    exclude: "str | None" = None,
    reference: "datetime | None" = None,
) -> "datetime | None":
    """서로 다른 신호가 가장 많이 겹치는 창의 시작. 없으면 ``None``.

    ``exclude`` 는 지금 순위를 매기는 신호다. **자기 자신은 앵커 계산에서
    뺀다** — 안 빼면 그 신호가 많이 난 자리가 곧 앵커가 되어, 무엇을
    고르든 자기가 정당화된다.

    ``reference`` 는 **제외 없이 구한 앵커**다. 동점일 때만 본다 — 가까운
    창이 이긴다. 그다음 동점은 **신호가 조밀한 창**이 가른다. 셋 다 같으면
    예전처럼 이른 창이다.

    **밀도를 세 번째로 둔 이유**(2026-09-10, ``K2L3-MGMT``). ``reference`` 는
    전역 앵커 자신을 구할 때는 없다(그때는 기준이 없으니 당연하다). 그래서
    전역 앵커의 동점은 여전히 "이른 창"으로 갈렸고, 자격증명·RDP 신호를
    더하자 그 자리에서 뒤집혔다:

        환경 구축 창 08-27 10:11  종류 4 / 신호 레코드 10
        공격 창      09-08 07:36  종류 4 / 신호 레코드 17   ← 동점, 이른 창 승

    전역 앵커가 12일 전 환경 구축 시각으로 되돌아가자 그것을 ``reference``
    로 쓰는 신호별 앵커가 전부 따라 움직였고, 직전에 살려 낸 유출 도구 대표
    다섯 자리를 설치 관리자가 도로 가져갔다.

    밀도는 이 모듈이 처음부터 근거로 삼은 값이다 — ``ANCHOR_WINDOW_SECONDS``
    의 설명이 "중앙값이 아니라 밀집도를 보는 이유"를 적고 있다. 종류 수가
    같을 때 그 원칙으로 되돌아가는 것이라 새 기준을 만드는 것이 아니다.

    **동점 규칙을 왜 바꿨나**(2026-09-10, ``K2L2-MGMT``). 제외는 옳은
    가드지만, 그 신호가 **사건의 주된 증거일 때** 앵커를 무너뜨린다:

        공격 창 2026-09-08 07:36  신호 4종 → 자기 제외 3
        설치 창 2026-08-27 10:11  신호 3종 → 자기 제외 3   동점 → 이른 창 승

    ``execution_outside_known_volume_root`` 를 빼자 공격 창이 4종에서 3종이
    되어 12일 전 SQL Server 설치일과 동점이 됐고, "이른 창" 규칙이 설치일을
    골랐다. 그 앵커로 줄을 세우니 대표 다섯 자리를 설치 관리자가 가져가고
    **공격자가 볼륨 루트에 놓은 도구는 31등**이 됐다. 상한을 올려서 될 문제가
    아니었다.

    같은 데이터에서 **제외하지 않은 앵커는 공격 창을 정확히 짚었다.** 제외는
    자기정당화를 막으려는 것이지 답을 버리려는 것이 아니므로, 그 가드가
    동점을 만들었을 때는 제외 없는 답으로 되돌린다.

    **가드는 그대로 산다.** 제외한 뒤의 신호 종류 수가 여전히 순위를 정하고,
    한 신호만 난 창은 제외 후 종류가 0이라 후보에서 빠진다(아래 필터).
    ``reference`` 는 그 다음의 동점만 가른다.

    ## 제외가 사건을 다른 날로 옮기면 되돌린다 (2026-09-10, ``K2L7-MGMT``)

    동점 규칙만으로는 부족했다. **동점이 아니라 제외 후 실제로 역전되는**
    경우가 있다:

    .. code-block:: text

        전역 앵커                                   2026-09-08 06:50  ← 맞다
        execution_outside_known_volume_root 제외 후  2026-09-03 08:13  (118.6시간 밖)
        persistence_command 제외 후                  2026-09-03 08:13  (118.6시간 밖)

    그 앵커로 줄을 세운 결과 ``execution_outside_known_volume_root`` 대표
    다섯 자리를 **전부** 랩 제작일의 설치 후처리 도구가 가져갔고, 같은
    플래그를 든 **공격자의 유출 도구 21건은 05단계에 한 건도** 전달되지
    않았다. 04단계는 잡았는데 배분에서 사라진 것이다.

    같은 실행의 나머지 신호 8종은 전부 전역 앵커에서 0.8시간 안에 있었다 —
    **어긋난 것은 이 둘뿐**이라, 제외가 답을 옮긴 것이지 답이 원래 거기
    있었던 것이 아니다.

    **그래서 창 하나를 넘어가면 되돌린다.** 제외는 한 신호가 *자기 창 안에서*
    자기를 정당화하는 것을 막으려는 가드다. 사건을 **다른 날로 옮기는 것**은
    그 가드가 할 일이 아니고, 옮겨진 답은 신호 한 종이 빠진 약한 근거 위에
    서 있다. 전역 앵커는 아홉 종 전부가 받치고 있으므로 그쪽이 맞다.

    창(``ANCHOR_WINDOW_SECONDS``) 안의 어긋남은 그대로 둔다 — 위 표의
    0.0~0.8시간은 같은 국면 안에서 어느 순간이 더 조밀한가의 차이일 뿐이고,
    거리로 줄을 세울 때 결과가 거의 같다.
    """
    points = sorted(
        (moment, signals - {exclude} if exclude else signals) for moment, signals in observed
    )
    points = [(moment, signals) for moment, signals in points if signals]
    if not points:
        return None

    window = timedelta(seconds=ANCHOR_WINDOW_SECONDS)
    best_key: "tuple[int, float, int] | None" = None
    best_at = None
    for index, (start, _) in enumerate(points):
        kinds: set[str] = set()
        density = 0
        for moment, signals in points[index:]:
            if moment - start > window:
                break
            kinds |= signals
            density += 1
        # 종류가 많은 창 → reference 에 가까운 창 → **신호가 조밀한 창**.
        # 셋 다 같으면 앞의 것이 남으므로 이른 창이다 — 예전 규칙이 마지막에
        # 그대로 있다.
        key = (
            len(kinds),
            -abs((start - reference).total_seconds()) if reference is not None else 0.0,
            density,
        )
        if best_key is None or key > best_key:
            best_key, best_at = key, start
    # 제외가 사건을 창 밖으로 옮겼으면 제외 없는 답으로 되돌린다
    # (위 "제외가 사건을 다른 날로 옮기면 되돌린다").
    #
    # **되돌리기 전에 reference 가 혼자 서 있는지 본다.** reference 의 창에
    # 지금 순위를 매기는 신호밖에 없으면 그것은 자기정당화이므로 가드가
    # 이긴다. 다른 종류가 하나라도 받치고 있을 때만 되돌린다 — MGMT 의
    # 06:50 창은 여덟 종이 받치고 있었고, 그것이 이 규칙과 위 실측의 차이다.
    if (
        reference is not None
        and best_at is not None
        and abs((best_at - reference).total_seconds()) > ANCHOR_WINDOW_SECONDS
        and any(
            signals
            for moment, signals in points
            if reference <= moment <= reference + window
        )
    ):
        return reference
    return best_at


def _repeat_key(record: dict[str, Any]) -> str:
    """되풀이 판정의 열쇠. 값이 하나도 없으면 빈 문자열이다.

    빈 문자열은 **되풀이로 묶지 않는다** — 레지스트리 키나 evtx 레코드처럼
    명령행이 없는 아티팩트를 한 덩어리로 묶으면 서로 다른 관측이 같은
    행위로 취급된다.
    """
    fields = record.get("fields") if isinstance(record.get("fields"), dict) else {}
    parts = [str(fields.get(name) or "").strip().casefold() for name in _REPEAT_KEY_FIELDS]
    return chr(31).join(parts) if any(parts) else ""


def _distinct(ordered: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """앞에서부터 ``limit`` 건을 고르되 같은 명령행은 ``MAX_IDENTICAL_COMMANDS`` 까지.

    **두 번 훑는다.** 1차에서 상한에 걸려 건너뛴 것을 2차에서 되돌린다 —
    가짓수가 자릿수보다 적으면 자리를 비워 두는 것이 아니라 되풀이로 채운다.
    자리를 줄이는 것이 목적이 아니라 **같은 자릿수를 더 여러 가지로 채우는
    것**이 목적이기 때문이다.
    """
    chosen: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    deferred: list[dict[str, Any]] = []
    for record in ordered:
        if len(chosen) >= limit:
            break
        key = _repeat_key(record)
        if key and seen.get(key, 0) >= MAX_IDENTICAL_COMMANDS:
            deferred.append(record)
            continue
        chosen.append(record)
        if key:
            seen[key] = seen.get(key, 0) + 1
    for record in deferred:
        if len(chosen) >= limit:
            break
        chosen.append(record)
    return chosen


def apply(records: Iterable[dict[str, Any]], *, mappings: str | None = None) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = [dict(record) for record in records]
    policy = attention_policy.load(mappings)
    candidates: dict[str, list[dict[str, Any]]] = {}
    for record in enriched:
        for signal in signal_ids(record, mappings=mappings):
            candidates.setdefault(signal, []).append(record)
            tokens = _group_tokens(signal, policy)
            if not tokens:
                continue
            blob = _text(record)
            matches = [token for token in tokens if token in blob]
            if matches:
                record.setdefault("attention_evidence", {})[signal] = matches

    # 신호가 붙은 레코드의 (시각, 신호들). 앵커를 여기서 뽑는다.
    observed = [
        (moment, frozenset(signals))
        for record, signals in (
            (record, signal_ids(record, mappings=mappings)) for record in enriched
        )
        if signals and (moment := _moment(record)) is not None
    ]
    # 제외 없이 구한 앵커. 신호별 앵커가 동점일 때만 쓴다 (``burst_anchor``).
    incident_anchor = burst_anchor(observed)
    anchors = {
        signal: burst_anchor(observed, exclude=signal, reference=incident_anchor)
        for signal in candidates
    }

    def order(signal: str, record: dict[str, Any]) -> tuple[int, float, str, str]:
        # **사건 앵커에 가까운 것이 대표다.**
        #
        # 예전에는 동점이면 "먼저 관측된 것"이었다. 결정론적이지만 편향이
        # 있었다 — 배경 잡음은 하루 종일 쌓이고 공격은 한 번 늦게 일어나므로,
        # 이 규칙이 **체계적으로 잡음을 대표로 만든다.** 실측(`K-2LINE-FIX`):
        # execution_from_unusual_path 19건의 대표가 아침의 DismHost 였고,
        # 공격자가 돌린 `C:\Temp\nmap` 은 206시간 밖으로 밀렸다.
        #
        # 앵커가 없으면(시각이 없거나 신호가 하나뿐) 거리가 전부 같아져
        # 예전 순서 그대로다.
        anchor = anchors.get(signal)
        moment = _moment(record)
        distance = (
            abs((moment - anchor).total_seconds())
            if anchor is not None and moment is not None
            else _NO_TIME_DISTANCE if anchor is not None else 0.0
        )
        return (
            -_score(record, signal, policy),
            distance,
            str(record.get("timestamp") or ""),
            str(record.get("ref") or ""),
        )

    limits = {rule.name: rule.max_representatives for rule in policy.signals}
    limits.update(
        {group.signal: group.max_representatives for group in policy.path_groups if group.signal}
    )
    for signal, group in candidates.items():
        chosen = _distinct(
            sorted(group, key=lambda record: order(signal, record)),
            limits.get(signal, 1),
        )
        for record in chosen:
            record.setdefault("attention_signals", []).append(signal)
            record["must_review"] = True
            context = _signal_context(record, signal, policy)
            if context:
                record.setdefault("attention_context", {})[signal] = context
            requirement = _signal_requirement(record, signal, policy)
            if requirement:
                record.setdefault("attention_requirements", {})[signal] = requirement

    # Related duplicates remain ordinary context.  A single disposition covers
    # the observable signal family and keeps a 1,024-token local-model response
    # from being consumed by repeated cmd/conhost/netsh descendants.
    return enriched
