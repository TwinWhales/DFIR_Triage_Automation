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
    창이 이긴다. 없으면 예전처럼 이른 창이다.

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
    """
    points = sorted(
        (moment, signals - {exclude} if exclude else signals) for moment, signals in observed
    )
    points = [(moment, signals) for moment, signals in points if signals]
    if not points:
        return None

    window = timedelta(seconds=ANCHOR_WINDOW_SECONDS)
    best_key: "tuple[int, float] | None" = None
    best_at = None
    for index, (start, _) in enumerate(points):
        kinds: set[str] = set()
        for moment, signals in points[index:]:
            if moment - start > window:
                break
            kinds |= signals
        # 종류가 많은 창, 그다음 reference 에 가까운 창. 둘 다 같으면 앞의
        # 것이 남으므로 이른 창이다 — 예전 규칙이 마지막에 그대로 있다.
        key = (
            len(kinds),
            -abs((start - reference).total_seconds()) if reference is not None else 0.0,
        )
        if best_key is None or key > best_key:
            best_key, best_at = key, start
    return best_at


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
        chosen = sorted(group, key=lambda record: order(signal, record))[: limits.get(signal, 1)]
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
