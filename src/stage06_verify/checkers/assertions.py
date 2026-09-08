"""Evaluate typed semantic assertions against canonical/source fields."""

from __future__ import annotations

import ntpath
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
                valid = _path(subject) == _path(other)
            elif predicate == "before":
                valid = _time(subject) < _time(other)
            elif predicate == "after":
                valid = _time(subject) > _time(other)
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
