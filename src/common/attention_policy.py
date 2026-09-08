"""Load the shared declarative attention and prompt-preservation policy."""

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class PathGroup:
    name: str
    contains: tuple[str, ...]
    signal: str | None = None
    must_review: bool = False
    attack: str | None = None


@dataclass(frozen=True)
class SignalRule:
    name: str
    all_contains: tuple[str, ...] = ()
    any_contains: tuple[str, ...] = ()
    must_review: bool = True

    def matches(self, text: str) -> bool:
        return bool(
            (self.all_contains and all(token in text for token in self.all_contains))
            or (self.any_contains and any(token in text for token in self.any_contains))
        )


@dataclass(frozen=True)
class AttentionPolicy:
    max_keep_items: int
    path_groups: tuple[PathGroup, ...]
    signals: tuple[SignalRule, ...]

    @property
    def keep_contains(self) -> tuple[str, ...]:
        return tuple(token for group in self.path_groups for token in group.contains)


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise PolicyError(f"{label} must be a list of non-empty strings")
    return tuple(item.casefold() for item in value)


@functools.lru_cache(maxsize=None)
def load(directory: str | None = None) -> AttentionPolicy:
    root = Path(directory) if directory else Path(__file__).resolve().parents[2] / "mappings"
    path = root / "_attention_signals.yaml"
    if not path.is_file():
        return AttentionPolicy(0, (), ())
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    keep = data.get("prompt_keep_path_groups") or {}
    if not isinstance(keep, dict):
        raise PolicyError(f"{path}: prompt_keep_path_groups must be a mapping")
    max_items = keep.get("max_items", 0)
    if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 0:
        raise PolicyError(f"{path}: max_items must be a non-negative integer")
    groups_raw = keep.get("groups") or {}
    if not isinstance(groups_raw, dict):
        raise PolicyError(f"{path}: groups must be a mapping")
    groups: list[PathGroup] = []
    for name, spec in groups_raw.items():
        if not isinstance(spec, dict):
            raise PolicyError(f"{path}: group {name} must be a mapping")
        signal = spec.get("signal")
        if signal is not None and (not isinstance(signal, str) or not signal):
            raise PolicyError(f"{path}: group {name}.signal must be a string")
        groups.append(PathGroup(str(name), _strings(spec.get("contains"), f"{name}.contains"), signal,
                                bool(spec.get("must_review", False)), spec.get("attack")))
    rules_raw = data.get("attention_signals") or {}
    if not isinstance(rules_raw, dict):
        raise PolicyError(f"{path}: attention_signals must be a mapping")
    rules = tuple(
        SignalRule(str(name), _strings(spec.get("all_contains"), f"{name}.all_contains"),
                   _strings(spec.get("any_contains"), f"{name}.any_contains"),
                   bool(spec.get("must_review", True)))
        for name, spec in rules_raw.items()
        if isinstance(spec, dict)
    )
    return AttentionPolicy(max_items, tuple(groups), rules)

