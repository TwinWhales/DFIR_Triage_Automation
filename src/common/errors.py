"""``errors.jsonl`` 기록 인터페이스.

폴백은 초기에 구현하지 않는다(work-guide 3.4). 대신 실패 지점을 기록하는
자리는 처음부터 만들어 둔다. 3주차에 누적된 실패 유형을 보고 폴백 필요
여부를 판단하기 위해서다.

``type``과 ``action``을 고정 어휘로 강제하는 이유는 발표 자료의 통계가 이
파일에서 직접 산출되기 때문이다. 누가 ``"parse_err"``라고 한 번 쓰면
파싱 실패율이 조용히 낮게 집계된다. 그래서 쓰는 시점에 막는다.
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, NoReturn

from . import io

__all__ = ["ERROR_TYPES", "ACTIONS", "ErrorLog", "tally"]

#: 고정 어휘. 새 유형이 필요하면 여기에 추가하고 전체 공지한다.
ERROR_TYPES = frozenset(
    {"schema_violation", "parse_error", "malformed_output", "empty_result", "timeout"}
)

ACTIONS = frozenset({"retry", "skip", "abort"})


class ErrorLog:
    """한 케이스의 ``errors.jsonl``에 append 한다.

    단계 구분 없이 한 파일에 누적한다. 파이프라인 한 번 실행의 실패를
    시간순으로 이어 보려면 파일이 나뉘어 있으면 안 된다.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    @classmethod
    def for_case(cls, case_dir: str | os.PathLike[str]) -> "ErrorLog":
        """``cases/C-001/`` → ``cases/C-001/errors.jsonl``."""
        return cls(Path(case_dir) / "errors.jsonl")

    def record(
        self,
        stage: str,
        type: str,
        detail: dict[str, Any],
        action: str,
        attempt: int | None = None,
    ) -> dict[str, Any]:
        """실패 한 건을 기록하고, 기록한 항목을 돌려준다."""
        if type not in ERROR_TYPES:
            raise ValueError(
                f"미등록 오류 유형: {type!r} (등록된 값: {', '.join(sorted(ERROR_TYPES))})"
            )
        if action not in ACTIONS:
            raise ValueError(
                f"미등록 조치: {action!r} (등록된 값: {', '.join(sorted(ACTIONS))})"
            )

        entry: dict[str, Any] = {
            "ts": io.utc_now(),
            "stage": stage,
            "type": type,
            "detail": detail,
            "action": action,
        }
        if attempt is not None:
            entry["attempt"] = attempt
        io.append_jsonl(self.path, entry)
        return entry

    def abort(self, stage: str, type: str, detail: dict[str, Any]) -> NoReturn:
        """기록하고 즉시 중단한다.

        조용히 넘어가지 않는 것이 방침이다. 폴백이 없는 상태에서 실패를
        삼키면, 뒤 단계가 빈 입력을 정상으로 받아 원인 파악이 불가능해진다.
        """
        self.record(stage, type, detail, action="abort")
        message = detail.get("message") or detail.get("msg") or ""
        print(f"[{stage}] {type}: {message}", file=sys.stderr)
        print(f"  detail: {detail}", file=sys.stderr)
        print(f"  기록됨: {self.path}", file=sys.stderr)
        raise SystemExit(1)


def tally(path: str | os.PathLike[str]) -> dict[str, Any]:
    """``errors.jsonl``을 집계한다.

    발표 자료의 "스키마 검증 실패율 8%, 그중 6%는 존재하지 않는 ATT&CK ID"
    같은 수치가 여기서 나온다. ``detail.field`` 분포를 보면 sLLM이 어떤
    필드에서 자주 틀리는지 드러난다.
    """
    by_type: Counter[str] = Counter()
    by_action: Counter[str] = Counter()
    by_stage: Counter[str] = Counter()
    by_stage_type: Counter[tuple[str, str]] = Counter()
    by_field: Counter[str] = Counter()

    total = 0
    for entry in io.read_jsonl(path):
        total += 1
        stage, etype = entry.get("stage", "?"), entry.get("type", "?")
        by_type[etype] += 1
        by_action[entry.get("action", "?")] += 1
        by_stage[stage] += 1
        by_stage_type[(stage, etype)] += 1
        field = (entry.get("detail") or {}).get("field")
        if field:
            by_field[field] += 1

    return {
        "total": total,
        "by_type": dict(by_type),
        "by_action": dict(by_action),
        "by_stage": dict(by_stage),
        "by_stage_type": {f"{s}/{t}": n for (s, t), n in by_stage_type.items()},
        "by_field": dict(by_field),
    }
