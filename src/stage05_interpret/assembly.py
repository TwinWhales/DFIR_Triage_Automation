"""모델이 고른 것으로 findings 문서를 **결정론적으로** 조립한다.

모델에게 문장·`claims`·타임라인을 다 쓰게 하는 대신, **어느 레코드가
의심스러운가**만 고르게 하고 나머지는 파이썬이 원본에서 옮긴다.

.. code-block:: text

    모델이 내는 것    {ref, technique, reason, severity}
    파이썬이 만드는 것 claims (원본에서 1:1 복사), timeline (시각순 정렬)

**무엇이 좋아지고 무엇이 사라지는가.** 좋아지는 것은 출력이 짧아 빠르고,
모델이 긴 값을 옮겨 적다 틀릴 자리가 없어진다는 것이다. 사라지는 것은
**측정**이다 — 06단계의 ``value_match`` 가 우리가 복사한 값을 우리가 원본과
대조하는 항등식이 된다. 그래서 06단계에 ``technique_supported`` 를 함께
넣었다(`docs/limitations.md` 의 환각 유형 표).

**모델의 문장은 `statement` 하나로 남는다.** `reason` 이 그대로 간다. 그
줄은 여전히 아무도 검증하지 않는다 — 이것은 이 구조가 만든 문제가 아니라
원래 있던 한계이고, 표의 마지막 행이다.

## claims 를 어디서 꺼내나

``mappings/_flags.yaml`` 의 ``claim_fields`` 가 순서와 상한을 정한다.
코드에 박지 않은 이유는 ``prompt_drop_fields`` 와 같다 — 아티팩트마다
값이 사는 층이 다르고(``$UsnJrnl`` 은 ``fields`` 가 없다), 새 파서가 붙을
때 함께 늘어야 하기 때문이다.

**하나도 없으면 claims 를 비운다.** 그 소견은 06단계에서 ``unverifiable``
이 되고, 그것이 정직한 결과다. 없는 필드를 지어내 채우면 그 순간 06단계가
우리가 만든 값을 검증하게 된다.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..common.io import parse_timestamp
from ..stage04_parse.flagging import ClaimFields, claim_fields
from .record_filter import NO_TIME, activity_times

__all__ = [
    "AssemblyError",
    "SelectionError",
    "assemble_body",
    "claim_for",
    "walk_field",
]


class SelectionError(ValueError):
    """모델이 고른 것이 레코드와 맞지 않는다. **모델 잘못이다.**

    지금 하나뿐이다 — 그 레코드에 **없는 필드**를 근거로 지목한 경우.
    문법이 막지 못하는 자리다. ``evidence_fields`` 의 enum 은 배치 전체가
    가진 이름의 합집합이라, 옆 레코드의 필드 이름을 이 레코드에 붙이는 것은
    문법상 합법이다.

    **이것이 조립 경로에서 유일하게 살아남은 모델 오류 채널이다.** 값은
    파이썬이 옮기므로 옮겨 적기 오류가 없고, ``ref``·기법은 enum 이 막는다.
    남는 자유도 중 기계적으로 잡히는 것이 이 하나라, 재시도할 값이 있다.
    """


class AssemblyError(ValueError):
    """조립기가 자기 일을 못 했다. **모델 잘못이 아니라 우리 잘못이다.**

    ``ClaimValidationError`` 와 갈라 두는 이유가 여기 있다. 저쪽은 모델이
    레코드에 없는 값을 말한 것이라 다시 물어보면 고쳐질 수 있지만, 이쪽은
    같은 코드가 같은 입력으로 같은 답을 낸다. 재시도하면 모델을 세 번 더
    부르고 똑같이 죽는다.
    """


def walk_field(record: dict[str, Any], name: str) -> "tuple[bool, Any]":
    """점 표기로 필드 하나를 찾는다. ``(있는가, 값)``.

    ``06단계 comparators.get_field`` 와 **같은 규약**이어야 한다. 조립이
    꺼낸 자리와 검증이 보는 자리가 다르면, 우리가 넣은 claim 을 우리가
    기각한다. 다만 그쪽은 표기 대안까지 보는 반면 여기는 정확히 그 자리만
    본다 — 넣을 때는 원본에 있는 이름을 그대로 쓰는 것이 맞다.

    값이 ``None`` 인 것은 **없는 것으로 본다.** 스키마가 claim 의 ``value``
    를 스칼라로 못 박아 ``None`` 은 실을 수 없고, 실을 수 없는 것을 골라
    두면 조립이 뒤에서 터진다.
    """
    node: Any = record
    for part in name.split("."):
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    if node is None:
        return False, None
    return True, node


def claim_for(
    record: dict[str, Any],
    fields: "ClaimFields | None" = None,
    chosen: "list[str] | None" = None,
) -> list[dict[str, Any]]:
    """레코드 하나에서 claims 를 뽑는다. **원본을 그대로 옮긴다.**

    어휘에 적힌 순서대로 보고, 레코드에 있는 것만 상한까지 담는다.
    요약하거나 단위를 바꾸지 않는다 — 06단계가 이 값을 원본과 대조하므로,
    손대는 순간 우리가 만든 불일치가 환각률에 잡힌다.

    **목록·객체는 싣지 않는다.** 동결 스키마가 ``value`` 를 문자열·숫자·
    불리언으로 못 박았다(`schemas/findings.schema.json`). ``flags`` 처럼
    배열인 값을 실으면 스키마 위반이고, 그 위반은 모델이 아니라 우리가
    만든 것이다.
    """
    fields = claim_fields() if fields is None else fields
    if fields.max_items <= 0:
        return []

    # 모델이 근거 필드를 지목했으면 **그것을 쓴다.** 어휘 순서는 지목이
    # 없을 때만 쓰인다. 이 갈림이 "껍데기 claims" 를 막는 자리다 — 어휘
    # 순서로만 뽑으면 claims 가 문장이 기대는 필드가 아니라 그 아티팩트에
    # 흔한 필드가 된다. 실측(2026-09-03)에서 프리패치 소견의 claims 가
    # path·name·timestamp 였고, 그 아티팩트 판단의 핵심인 run_count·
    # loaded_files 는 하나도 들어가지 않았다.
    order = list(chosen) if chosen else list(fields.names)

    claims: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in order:
        if name in seen:
            continue
        seen.add(name)
        if len(claims) >= fields.max_items:
            break
        found, value = walk_field(record, name)
        if not found or not isinstance(value, (str, int, float, bool)):
            continue
        claims.append({"ref": record["ref"], "field": name, "value": value})
    return claims


def _sort_time(record: dict[str, Any]) -> datetime:
    """타임라인 정렬에 쓸 시각. 못 읽으면 맨 뒤로.

    ``record_filter.activity_times`` 를 쓰는 것은 ``$MFT`` 때문이다 — 거기엔
    ``timestamp`` 가 없고 ``si_*`` 넷이 있다. 그 갈래를 여기서 다시 쓰면
    두 곳이 갈라진다.
    """
    times = activity_times(record)
    return min(times) if times else NO_TIME


def _timeline_ts(record: dict[str, Any]) -> "str | None":
    """타임라인에 적을 시각 문자열. 원본 표기를 그대로 쓴다.

    동결 스키마의 ``timestamp`` 패턴을 만족해야 하므로, 만족하지 못하는
    값이면 그 레코드는 타임라인에 오르지 않는다. **소견에서 빠지지는
    않는다** — 시각을 못 읽는 것과 증거가 아닌 것은 다르다.
    """
    for name in ("timestamp", "si_btime", "si_ctime", "si_mtime"):
        value = record.get(name)
        if isinstance(value, str) and parse_timestamp(value) is not None:
            return value
    return None


def assemble_body(
    selections: list[dict[str, Any]],
    records: dict[str, dict[str, Any]],
    fields: "ClaimFields | None" = None,
) -> dict[str, Any]:
    """모델이 고른 목록 → findings 본문(``findings`` + ``timeline``).

    ``selections`` 는 모델이 낸
    ``{ref, technique, reason, severity, evidence_fields}`` 이고,
    ``records`` 는 **이번에 실제로 전달한** 레코드의 ``ref`` → 레코드다.

    **``evidence_fields`` 가 claims 를 정한다.** 모델이 "이 문장은 이 필드에
    기댄다"고 지목한 것이고, 값은 파이썬이 원본에서 옮긴다. 지목이 없으면
    어휘 순서로 떨어지지만, 그때 claims 는 문장이 기대는 필드가 아니라 그
    아티팩트에 흔한 필드가 된다(``claim_for`` 참조).

    **같은 ref 가 두 번 오면 앞의 것만 쓴다.** 모델이 같은 레코드를 두 번
    고르는 일이 있고, 그대로 두면 소견과 타임라인이 중복된다. 뒤엣것을
    버리는 것은 앞이 대개 더 강한 판단이기 때문이 아니라 **재현되기**
    때문이다 — 기준이 있어야 같은 입력에 같은 문서가 나온다.

    **타임라인은 시각순이다.** 소견 순서가 아니라 사건 순서여야 보고서에서
    읽힌다. 시각을 못 읽는 레코드는 맨 뒤로 가고, 스키마를 만족하는 시각
    문자열이 없으면 타임라인에는 오르지 않는다.
    """
    fields = claim_fields() if fields is None else fields

    findings: list[dict[str, Any]] = []
    used: set[str] = set()

    for selection in selections:
        ref = selection.get("ref")
        if not ref or ref in used:
            continue
        record = records.get(ref)
        if record is None:
            # 문법 enum 이 이번에 보낸 ref 만 허용하므로 여기 오면 우리가
            # 잘못 짝지은 것이다. 조용히 건너뛰면 모델이 고른 증거가 소리
            # 없이 사라진다.
            raise AssemblyError(
                f"모델이 고른 {ref} 가 전달 레코드에 없다. "
                "조립기에 넘긴 레코드 목록과 질의에 실은 목록이 어긋났다."
            )
        used.add(ref)

        statement = str(selection.get("reason") or "").strip()
        if not statement:
            raise SelectionError(f"{ref} 의 reason 이 비었다.")

        # 모델이 지목한 근거 필드가 **그 레코드에** 있어야 한다. enum 은
        # 배치 전체가 가진 이름의 합집합이라, 옆 레코드의 필드를 이 레코드에
        # 붙이는 것은 문법상 합법이다. 조립 경로에서 살아남은 유일한 모델
        # 오류 채널이라, 조용히 버리지 않고 다시 물어본다.
        chosen = [name for name in (selection.get("evidence_fields") or []) if name]
        missing = [name for name in chosen if not walk_field(record, name)[0]]
        if missing:
            raise SelectionError(
                f"{ref} 에 없는 필드를 근거로 지목했다: {', '.join(missing)}"
            )

        findings.append(
            {
                "id": f"F{len(findings) + 1}",
                "statement": statement,
                "refs": [ref],
                "claims": claim_for(record, fields, chosen),
                "technique": selection.get("technique") or None,
                "severity": selection.get("severity") or "info",
            }
        )

    timeline = []
    for finding in sorted(findings, key=lambda f: _sort_time(records[f["refs"][0]])):
        record = records[finding["refs"][0]]
        ts = _timeline_ts(record)
        if ts is not None:
            timeline.append(
                {"ts": ts, "event": finding["statement"], "refs": list(finding["refs"])}
            )

    return {"findings": findings, "timeline": timeline}
