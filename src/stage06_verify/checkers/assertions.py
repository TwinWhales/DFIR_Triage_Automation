"""Evaluate typed semantic assertions against canonical/source fields."""

from __future__ import annotations

import ntpath
import re
from datetime import datetime
from typing import Any

from .. import comparators
from . import CheckContext, CheckResult, Rejection


def _value(endpoint: Any, ctx: CheckContext) -> Any:
    if not isinstance(endpoint, dict) or "ref" not in endpoint:
        return endpoint
    record = ctx.records.get(endpoint["ref"])
    if record is None:
        raise KeyError(endpoint["ref"])
    return comparators.get_field(record, endpoint["field"])


def _path(value: Any) -> str:
    return ntpath.normcase(ntpath.normpath(str(value).replace("/", "\\")))


def _under(subject: Any, base: Any) -> bool:
    child, root = _path(subject), _path(base).rstrip("\\")
    # Windows commonly treats both Program Files roots as one semantic family.
    if root.endswith(r"\program files"):
        return child == root or child.startswith(root + "\\") or child.startswith(root + " (x86)\\")
    return child == root or child.startswith(root + "\\")


def _time(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _number(value: Any) -> float:
    if isinstance(value, bool):
        raise TypeError("boolean is not a numeric assertion value")
    return float(value)


_HASH_RE = re.compile(r"^(?:md5|sha1|sha256)\s*[:=]\s*", re.IGNORECASE)
_DIGEST_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")


def _hashes(value: Any) -> set[str]:
    """Return normalized hash values without guessing algorithms."""
    if isinstance(value, dict):
        values = value.values()
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = (value,)
    normalized: set[str] = set()
    for item in values:
        if item is None:
            continue
        # Sysmon commonly stores several ALGORITHM=value pairs in one scalar.
        for token in re.split(r"[,;]", str(item)):
            digest = _HASH_RE.sub("", token.strip()).casefold()
            if _DIGEST_RE.fullmatch(digest):
                normalized.add(digest)
    return normalized


def _packet_join(assertion: dict[str, Any], subject: Any, other: Any, ctx: CheckContext) -> bool | None:
    """Recheck a compact packet ref join against the original records."""
    endpoint = assertion.get("subject")
    if not isinstance(endpoint, dict) or not isinstance(subject, list) or not isinstance(other, str):
        return None
    field = str(endpoint.get("field") or "")
    predicate = assertion.get("predicate")
    expected_field = f"incident_packet.{predicate}_refs"
    if field != expected_field:
        return None
    if other not in subject:
        return False
    anchor = ctx.records.get(str(endpoint.get("ref")))
    target = ctx.records.get(other)
    if anchor is None or target is None:
        return False
    left = anchor.get("canonical") if isinstance(anchor.get("canonical"), dict) else {}
    right = target.get("canonical") if isinstance(target.get("canonical"), dict) else {}
    if predicate == "same_path":
        return bool(left.get("subject_path") and right.get("subject_path")) and _path(left["subject_path"]) == _path(right["subject_path"])
    if predicate == "same_hash":
        return bool(_hashes(left.get("hashes")) & _hashes(right.get("hashes")))
    return None


def check(finding: dict[str, Any], ctx: CheckContext) -> CheckResult:
    assertions = finding.get("assertions") or []
    passed = 0
    for assertion in assertions:
        predicate = assertion["predicate"]
        try:
            subject = _value(assertion["subject"], ctx)
            other = _value(assertion.get("object"), ctx)
            if predicate == "equals":
                valid = comparators.compare("assertion", subject, other, tolerance_seconds=ctx.tolerance_seconds)
            elif predicate == "contains":
                valid = str(other).casefold() in str(subject).casefold()
            elif predicate == "list_contains":
                valid = isinstance(subject, list) and any(
                    str(other).casefold() in str(item).casefold() for item in subject
                )
            elif predicate == "under_path":
                valid = _under(subject, other)
            elif predicate == "outside_path":
                valid = not _under(subject, other)
            elif predicate == "same_path":
                packet_valid = _packet_join(assertion, subject, other, ctx)
                valid = packet_valid if packet_valid is not None else _path(subject) == _path(other)
            elif predicate == "same_hash":
                packet_valid = _packet_join(assertion, subject, other, ctx)
                valid = packet_valid if packet_valid is not None else bool(_hashes(subject) & _hashes(other))
            elif predicate == "spawned":
                # Normal prompt form: the deterministic incident packet lists
                # child refs, avoiding raw GUID token cost. Direct GUID endpoint
                # comparison remains supported for imported findings.
                if isinstance(subject, list):
                    needle = str(other).strip().casefold()
                    valid = any(str(item).strip().casefold() == needle for item in subject)
                else:
                    valid = str(subject).strip().casefold() == str(other).strip().casefold()
            elif predicate == "before":
                valid = _time(subject) < _time(other)
            elif predicate == "after":
                valid = _time(subject) > _time(other)
            elif predicate == "within":
                tolerance = float(assertion.get("tolerance_seconds", ctx.tolerance_seconds))
                valid = abs((_time(subject) - _time(other)).total_seconds()) <= tolerance
            elif predicate == "duration":
                # 초 단위 값이므로 시각 허용오차를 그대로 쓴다.
                tolerance = float(assertion.get("tolerance_seconds", ctx.tolerance_seconds))
                valid = abs(_number(subject) - _number(other)) <= tolerance
            elif predicate == "count":
                # **개수에 초 단위 허용오차를 쓰지 않는다.** 기본값 1.0 초를
                # 그대로 적용하면 자식이 7개인데 "6개"라 주장해도 통과한다
                # (2026-09-08 확인). 개수는 맞거나 틀리거나 둘 중 하나다.
                valid = _number(subject) == _number(other)
            else:
                valid = False
        except (KeyError, comparators.FieldMissing) as error:
            return CheckResult(
                rejection=Rejection("assertion_contradicted", {"assertion": assertion, "message": f"assertion endpoint unavailable: {error}"}),
                checks=len(assertions), checks_passed=passed,
            )
        except (TypeError, ValueError) as error:
            valid = False
        if not valid:
            return CheckResult(
                rejection=Rejection(
                    "assertion_contradicted",
                    {"assertion": assertion, "actual_subject": subject, "actual_object": other},
                ),
                checks=len(assertions), checks_passed=passed,
            )
        passed += 1
    return CheckResult(checks=len(assertions), checks_passed=passed)
