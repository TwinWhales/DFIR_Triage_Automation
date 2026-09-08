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
from typing import Any

from ..common import attention_policy


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

    def order(signal: str, record: dict[str, Any]) -> tuple[int, str, str]:
        # 동점이면 먼저 관측된 것이 대표다. ref 문자열 비교로 가르면
        # SYSMON#99 가 SYSMON#1000 보다 커져 순서가 사실과 무관해진다.
        return (
            -_score(record, signal, policy),
            str(record.get("timestamp") or ""),
            str(record.get("ref") or ""),
        )

    representatives = {
        signal: min(group, key=lambda record: order(signal, record))
        for signal, group in candidates.items()
    }
    for signal, record in representatives.items():
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
