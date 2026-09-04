"""기각을 실행에 걸쳐 누적하는 대장(臺帳).

**왜 06단계가 이것을 쓰나.** 기각 상세는 ``06_verified.json`` 에 있는데 그
파일은 같은 case-id 를 다시 돌리면 덮인다(``--force``). 매핑을 넓힐 근거는
여러 실행에 걸쳐 쌓여야 하므로(``work.md`` 10번) 덮이지 않는 자리가 따로
있어야 한다.

**입구마다 붙이지 않는다.** 처음에는 ``tools/live_check.py`` 만 기록했는데,
``run_pipeline.sh`` 나 웹 UI 로 돌린 실행은 어디에도 남지 않았다. 정작 사람이
자주 쓰는 두 경로에서 근거가 새고 있었고, 그것이 드러나지도 않았다. 기록하는
쪽을 **기각을 만드는 단계 자신**으로 내리면 입구가 몇 개든 상관없어진다.

**append 만 한다.** 실행 하나가 앞 실행의 줄을 고치지 않는다. 같은 케이스를
다시 돌리면 줄이 하나 더 붙고, ``(case_id, verified_at, id)`` 로 서로
구별된다 — 그래서 대장을 두 번 읽어도 두 번 세지 않는다.

**실패시키지 않는다.** 대장을 못 쓰는 것은 검증 결과와 무관하다. 여기서
멈추면 기록하려다 파이프라인을 죽이는 셈이 된다.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

__all__ = ["DEFAULT_LEDGER", "append_rejections"]

#: 대장의 기본 자리. ``benchmark/results/`` 는 실행 기록이 쌓이는 곳이고
#: ``benchmark/collect.py`` 가 읽는 곳이다(gitignore 대상 — 산출물이지
#: 지식이 아니다. 사람이 가른 판단은 ``benchmark/rejections.yaml`` 이다).
DEFAULT_LEDGER = Path(__file__).resolve().parents[2] / "benchmark/results/rejections.jsonl"


def append_rejections(
    verified: dict[str, Any], path: "str | os.PathLike[str] | None" = None
) -> int:
    """이 실행의 기각을 대장에 덧붙인다. 쓴 줄 수를 낸다.

    기각이 없으면 아무것도 쓰지 않는다 — 빈 줄이 쌓이면 "기각이 없었다"와
    "이 실행이 기록되지 않았다"가 구별되지 않는다.
    """
    rejected = verified.get("rejected") or []
    if not rejected:
        return 0

    ledger = Path(path) if path is not None else DEFAULT_LEDGER
    header = {
        "case_id": verified.get("case_id"),
        "verified_at": verified.get("generated_at"),
        "generator": verified.get("generator"),
    }
    try:
        ledger.parent.mkdir(parents=True, exist_ok=True)
        with ledger.open("a", encoding="utf-8", newline="\n") as handle:
            for entry in rejected:
                handle.write(json.dumps({**header, **entry}, ensure_ascii=False) + "\n")
    except OSError:
        # 기록하려다 파이프라인을 죽이지 않는다 — 위 설명 참조.
        return 0
    return len(rejected)
