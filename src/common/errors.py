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

__all__ = [
    "ERROR_TYPES",
    "ACTIONS",
    "ErrorLog",
    "tally",
]


#: 고정 어휘. 새 유형이 필요하면 여기에 추가하고 전체 공지한다.
#:
#: ``llm_error`` 는 2026-08-30 에 추가됐다(전체 공지 대상). 모델 호출이
#: 타임아웃이 **아닌** 이유로 실패한 것이다 — 모델명 오타, 서버 미기동,
#: 잘못된 호스트. 그전에는 이 예외를 아무도 잡지 않아 파이썬 트레이스백이
#: 그대로 올라왔고 ``errors.jsonl`` 에 남지 않았다.
#:
#: ``claim_validation`` 은 2026-09-03 에 추가됐다.
#: 05단계에서 모델이 만든 ``(ref, field, value)`` claim이 실제로 모델에게
#: 전달된 레코드와 일치하지 않을 때 기록한다.
#:
#: ``assembly_error`` 는 2026-09-03 에 추가됐다(전체 공지 대상).
#: 05단계가 모델이 고른 ``ref`` 로 findings 를 조립하다 자기 일을 못 한
#: 것이다. **``claim_validation`` 과 갈라 둔 이유가 처리에 있다** — 저쪽은
#: 모델 잘못이라 피드백을 주고 다시 물어보면 고쳐질 수 있지만, 이쪽은 같은
#: 코드가 같은 입력으로 같은 답을 낸다. 재시도하면 모델을 세 번 더 부르고
#: 똑같이 죽으므로 **한 번에 중단한다.** 두 유형을 한 이름으로 세면 "모델이
#: 틀렸다"와 "우리가 틀렸다"가 같은 통계에 섞인다.
#:
#: 예:
#:
#: - ref는 실제 전달된 레코드지만 해당 field가 존재하지 않음
#: - field는 존재하지만 모델이 실제와 다른 value를 주장함
#: - 다른 레코드의 값을 현재 ref에 잘못 붙임
#:
#: 이것을 ``schema_violation`` 으로 합치지 않는다.
#: JSON 구조 자체는 올바르지만 **근거 내용이 잘못된 경우**이므로,
#: 출력 형식 오류와 LLM 근거 오류를 통계에서 구분해야 한다.
#:
#: **``timeout`` 과 ``llm_error`` 도 합치지 않는다.**
#: 둘은 조치가 다르고(기다릴 것인가 / 설정을 고칠 것인가),
#: 07단계 통계가 이 어휘로 직접 산출된다.
#: ``uncovered_input`` · ``nonverbatim_evidence`` 는 2026-09-04 에 추가됐다
#: (전체 공지 대상). 둘 다 02단계가 **입력 서술을 얼마나 옮겼는가**를 센다.
#:
#: 다른 유형과 성격이 다르다 — **실패가 아니라 측정이다.** 그래서 조치가
#: ``retry`` 가 아니라 ``record`` 다. 실측에서 이 검사는 8/8 걸렸고,
#: 재시도를 붙이면 02단계가 13.8초에서 41.4초가 되면서도 통과하지 못했다
#: (소형 모델이 매번 같은 방식으로 인용을 다듬는다). 그래서 고치려 들지
#: 않고 세기만 한다.
#:
#: 세는 이유는 **프롬프트를 고쳤을 때 나아졌는지 알기 위해서**다. 같은 날
#: few-shot 예시를 고쳐 계정 기법 검출이 0/8 에서 8/8 이 됐는데, 그 차이를
#: 볼 자리가 이 통계다.
#:
#: - ``uncovered_input`` — 입력의 어느 구간이 어떤 기법으로도 옮겨지지
#:   않았다. 그 축은 03단계가 아티팩트를 요청하지 않으므로 조사에서 통째로
#:   빠지는데, 07단계 보고서는 그것을 "증거가 없었다"와 같은 말로 인쇄한다.
#: - ``nonverbatim_evidence`` — ``evidence_text`` 가 원문의 부분문자열이
#:   아니다. 다듬는 과정에서 절이 사라지는 것이 실제 실패 방식이라
#:   (``자동 실행 등록과 계정 관련 변경이`` → ``자동 실행 등록이``)
#:   위 항목의 선행 지표다.
#: ``ungrounded_entity`` 는 2026-09-05 에 추가됐다(전체 공지 대상).
#: 위의 둘과 같은 성격이다 — **실패가 아니라 측정**이라 조치가 ``record`` 다.
#:
#: 02단계가 ``entities`` 에 입력 원문에 없는 값을 넣은 것이다. 실측에서
#: ``paths`` 는 **16/16 전부** 그랬다(2026-09-05, 두 입력 8회씩). 그냥 남는
#: 것이 아니라 **사람이 기법별로 써 둔 ``defaults`` 를 덮으므로**
#: (``scope_resolver.build_context``) 03단계가 엉뚱한 폴더를 훑게 된다.
#: 02단계가 그 값을 떨구고 여기 적는다.
#:
#: 세는 이유는 ``uncovered_input`` 과 같다 — **프롬프트를 고쳤을 때
#: 나아졌는지 알기 위해서**다. 같은 자리의 ``hosts`` 환각은 2026-09-04 의
#: few-shot 수정으로 0/16 이 됐는데, 그 차이를 볼 자리가 이 통계다.
ERROR_TYPES = frozenset(
    {
        "schema_violation",
        "claim_validation",
        "parse_error",
        "malformed_output",
        "empty_result",
        "timeout",
        "llm_error",
        "assembly_error",
        "uncovered_input",
        "nonverbatim_evidence",
        "ungrounded_entity",
    }
)


#: ``record`` 는 2026-09-04 에 추가됐다(전체 공지 대상). **고치지 않고
#: 세기만 한 것**이다. 나머지 셋은 파이프라인의 흐름을 바꾸지만 이것은
#: 바꾸지 않는다 — 다시 부르지도, 건너뛰지도, 멈추지도 않는다.
#:
#: 통계에서 분모를 오염시키지 않으려고 따로 둔다. ``skip`` 으로 적으면
#: "읽지 못해 건너뛴 아티팩트" 수에 섞이고, ``retry`` 로 적으면 실제로
#: 부르지 않은 호출이 재시도 횟수에 잡힌다.
ACTIONS = frozenset(
    {
        "retry",
        "skip",
        "abort",
        "record",
    }
)


class ErrorLog:
    """한 케이스의 ``errors.jsonl``에 append 한다.

    단계 구분 없이 한 파일에 누적한다. 파이프라인 한 번 실행의 실패를
    시간순으로 이어 보려면 파일이 나뉘어 있으면 안 된다.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
    ) -> None:
        self.path = Path(path)

    @classmethod
    def for_case(
        cls,
        case_dir: str | os.PathLike[str],
    ) -> "ErrorLog":
        """``cases/C-001/`` → ``cases/C-001/errors.jsonl``."""

        return cls(
            Path(case_dir) / "errors.jsonl"
        )

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
                (
                    f"미등록 오류 유형: {type!r} "
                    f"(등록된 값: "
                    f"{', '.join(sorted(ERROR_TYPES))})"
                )
            )

        if action not in ACTIONS:
            raise ValueError(
                (
                    f"미등록 조치: {action!r} "
                    f"(등록된 값: "
                    f"{', '.join(sorted(ACTIONS))})"
                )
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

        io.append_jsonl(
            self.path,
            entry,
        )

        return entry

    def abort(
        self,
        stage: str,
        type: str,
        detail: dict[str, Any],
    ) -> NoReturn:
        """기록하고 즉시 중단한다.

        조용히 넘어가지 않는 것이 방침이다. 폴백이 없는 상태에서 실패를
        삼키면, 뒤 단계가 빈 입력을 정상으로 받아 원인 파악이 불가능해진다.
        """

        self.record(
            stage,
            type,
            detail,
            action="abort",
        )

        message = (
            detail.get("message")
            or detail.get("msg")
            or ""
        )

        print(
            f"[{stage}] {type}: {message}",
            file=sys.stderr,
        )

        print(
            f"  detail: {detail}",
            file=sys.stderr,
        )

        print(
            f"  기록됨: {self.path}",
            file=sys.stderr,
        )

        raise SystemExit(1)


def tally(
    path: str | os.PathLike[str],
) -> dict[str, Any]:
    """``errors.jsonl``을 집계한다.

    발표 자료의 "스키마 검증 실패율 8%, 그중 6%는 존재하지 않는 ATT&CK ID"
    같은 수치가 여기서 나온다. ``detail.field`` 분포를 보면 sLLM이 어떤
    필드에서 자주 틀리는지 드러난다.

    ``claim_validation``도 일반 오류 유형과 동일하게 집계되므로,
    Stage 05에서 모델이 실제 근거 삼중항을 얼마나 자주 잘못 만드는지도
    별도의 수치로 확인할 수 있다.
    """

    by_type: Counter[str] = Counter()
    by_action: Counter[str] = Counter()
    by_stage: Counter[str] = Counter()
    by_stage_type: Counter[tuple[str, str]] = Counter()
    by_field: Counter[str] = Counter()

    total = 0

    for entry in io.read_jsonl(path):
        total += 1

        stage = entry.get(
            "stage",
            "?",
        )

        etype = entry.get(
            "type",
            "?",
        )

        by_type[etype] += 1
        by_action[
            entry.get("action", "?")
        ] += 1

        by_stage[stage] += 1
        by_stage_type[
            (stage, etype)
        ] += 1

        field = (
            entry.get("detail")
            or {}
        ).get("field")

        if field:
            by_field[field] += 1

    return {
        "total": total,
        "by_type": dict(by_type),
        "by_action": dict(by_action),
        "by_stage": dict(by_stage),
        "by_stage_type": {
            f"{stage}/{etype}": count
            for (
                stage,
                etype,
            ), count in by_stage_type.items()
        },
        "by_field": dict(by_field),
    }