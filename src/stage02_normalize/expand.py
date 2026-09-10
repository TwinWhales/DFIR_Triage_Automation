"""02단계 확장 — 05단계가 낸 추가 조사 요청을 시나리오에 반영한다.

**LLM을 부르지 않는다.** "02단계 재트리거"를 곧이곧대로 읽으면 모델에게
시나리오를 다시 쓰게 하는 것이 되는데, 02단계의 실패 방식이 **축을 통째로
빠뜨리는 것**이다(2026-09-04 실측, ``docs/limitations.md`` 3-6). 2차에서
그것이 재현되면 루프백이 증거를 넓히는 것이 아니라 1차 결과를 파괴한다.
넓히러 갔다가 좁혀 오는 경로를 만들 이유가 없다.

그래서 여기서 하는 일은 전부 결정론이고, 결과는 **1차의 상위집합임이
보장된다** — 기법은 추가만, 시간 범위는 합집합만, ``entities``는 손대지
않는다. 그 불변식을 ``tests/test_loopback.py``가 지킨다.

요청 셋을 받는다.

- ``expand_time_range`` — ``pivot_time`` 앞뒤 ``window_hours``만큼 넓힌다
- ``request_technique`` — 기법을 ``techniques``에 더한다
- ``request_artifact`` — 03단계에 ``--force-artifacts``로 넘길 이름을 모은다.
  시나리오에는 아티팩트를 담을 자리가 없으므로(동결 스키마) ``applied``에 남고,
  실제로 넘기는 것은 오케스트레이터다

**받아들이지 않은 요청은 사유와 함께 남긴다.** ``05_requests.json``의
``disposition``과 ``errors.jsonl``의 ``investigation_rejected`` 두 곳이다.
앞은 사람이 그 요청을 되짚는 자리이고, 뒤는 "열거형이 새고 있는가"를 세는
자리다 — 요청 가능한 ``ref``·기법·아티팩트가 전부 enum이므로 제약을 건
실행에서 이 수는 0에 가까워야 한다.

**수용된 요청이 하나도 없으면 2차 시나리오를 쓰지 않고 종료 코드 3으로
끝난다.** 헛도는 2차를 만들지 않기 위해서다(가드레일 G3). 오케스트레이터가
그 코드를 보고 1차로 마무리한다.

사용법::

    python -m src.stage02_normalize.expand \\
        --scenario cases/C-001/02_scenario.round1.json \\
        --requests cases/C-001/05_requests.json \\
        --findings cases/C-001/05_findings.round1.json \\
        --selection cases/C-001/03_selection.round1.json \\
        --input cases/C-001/01_input.json \\
        --out cases/C-001/02_scenario.json

``--requests``는 **제자리에서 고쳐 쓴다** — 요청과 판정이 한 파일에 있어야
"무엇을 물었고 무엇이 받아들여졌나"를 한 번에 본다. 05단계가 적은 헤더는
건드리지 않는다. 그 문서의 주인은 여전히 05단계다.

설계는 ``docs/proposals/stage05-investigation-loopback.md``.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..common import attack
from ..common import errors as errlog
from ..common import io, schema
from ..stage03_select import mapping_loader
from . import timeband

__all__ = [
    "STAGE",
    "REQUEST_STAGE",
    "EXIT_NOTHING_TO_DO",
    "Outcome",
    "expand",
    "main",
]

#: 이 모듈이 내는 문서는 02단계 산출물이다. 동결 스키마의 ``stage`` const 다.
STAGE = "02_normalize"

#: ``errors.jsonl``에 적을 단계. **발견하는 코드는 여기 있지만 틀린 것은
#: 05단계의 산출물**이고, 고칠 자리도 05의 조사 요청 프롬프트다.
#: ``by_stage_type``을 읽는 사람이 어디를 봐야 하는지가 이 값으로 정해진다.
REQUEST_STAGE = "05_interpret"

#: 수용된 요청이 없다. 실패가 아니라 "2차를 돌릴 이유가 없다"이므로 0도 1도
#: 아닌 값으로 낸다 — 오케스트레이터가 이 셋을 갈라 다르게 처리한다.
EXIT_NOTHING_TO_DO = 3

#: 2차 요청으로 들어온 기법의 ``confidence``.
#:
#: **낮은 값인 것이 두 가지를 동시에 한다.** 의미상 이것은 모델이 "확인해
#: 보자"고 낸 가설이지 1차 분류의 결론이 아니다. 그리고 03단계의
#: ``_leading_technique``가 confidence 최대값으로 대표 기법을 고르므로
#: (``select.py``), 높게 주면 **강제 선별의 사유 딱지가 2차 가설로 바뀐다.**
REQUEST_CONFIDENCE = 0.3


@dataclass
class Outcome:
    """확장 결과. 파일을 쓰기 전의 값이라 시험이 이것만 보면 된다."""

    scenario: dict[str, Any]
    requests: list[dict[str, Any]]
    techniques: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    time_range_widened: bool = False
    behavior_applied: bool = False

    @property
    def accepted(self) -> bool:
        """2차를 돌릴 이유가 있는가."""
        return bool(
            self.techniques
            or self.artifacts
            or self.time_range_widened
            or self.behavior_applied
        )

    def applied(self) -> dict[str, Any]:
        """``05_requests.json``의 ``applied`` 블록."""
        return {
            "time_range": {
                "start": self.scenario["time_range"]["start"],
                "end": self.scenario["time_range"]["end"],
            },
            "techniques": list(self.techniques),
            "artifacts": list(self.artifacts),
        }


def _parse_utc(value: str) -> datetime:
    """``2026-09-07T13:37:00Z`` → aware datetime. 소수부는 버린다."""
    return datetime.strptime(value.split(".")[0].rstrip("Z"), "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=timezone.utc
    )


def _to_utc(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _one_line(text: str) -> str:
    """``evidence_text``·``basis``에 실을 모델 문장을 한 줄로 만든다.

    07단계 보고서가 ``evidence_text``를 **마크다운 표의 칸에 그대로 넣는다**
    (``templates/report.md.j2``). 줄바꿈이나 ``|``가 들어 있으면 표가 깨져
    그 아래 행이 통째로 안 보인다. 모델이 쓴 문장이 그대로 오는 자리라
    여기서 막는다.
    """
    return " ".join(str(text).replace("|", "/").split())


def _reject(request: dict[str, Any], reason: str, detail: str) -> None:
    request["disposition"] = {"verdict": "rejected", "reason": reason, "detail": detail}


def _accept(request: dict[str, Any], detail: str) -> None:
    request["disposition"] = {"verdict": "accepted", "reason": "applied", "detail": detail}


def _widen_time_range(
    request: dict[str, Any],
    time_range: dict[str, str],
    collected_at: "datetime | None",
) -> bool:
    """시간 범위를 넓힌다. 실제로 넓어졌으면 ``True``.

    **좁히지 않는다.** 1차 범위를 항상 포함하도록 합집합만 취하므로,
    수집 시각으로 상한을 당기더라도 1차의 끝보다 앞으로는 가지 않는다.
    """
    pivot = _parse_utc(request["pivot_time"])
    window = timedelta(hours=int(request["window_hours"]))
    current = (_parse_utc(time_range["start"]), _parse_utc(time_range["end"]))

    # **축이 증거 밖이면 넓힐 것이 없다.** 아래 클램프만으로는 못 막는다 —
    # 수집 시각 한참 뒤를 축으로 잡아도 상한까지는 넓어지므로, 1차의 끝과
    # 수집 시각 사이의 몇 초를 얻자고 2차 재파싱을 통째로 돌리게 된다.
    # 실제 실행에서는 ``pivot_time`` 이 전달한 레코드의 시각 중에서만
    # 나오므로(열거형) 걸릴 일이 드물지만, 걸리면 그 요청은 근거가 없다.
    if collected_at is not None and pivot > collected_at:
        _reject(
            request,
            "out_of_evidence",
            f"축으로 삼은 시각({request['pivot_time']})이 "
            f"수집 시각({_to_utc(collected_at)}) 뒤라 증거가 없습니다.",
        )
        return False

    start = min(current[0], pivot - window)
    end = max(current[1], pivot + window)

    # **수집 시각이 상한이다.** 그 뒤로는 증거 자체가 없다
    # (``timeband.clamp_to_collection``과 같은 근거). 다만 1차보다 좁히지는
    # 않는다 — 1차 범위는 이미 그 판단을 지나온 값이다.
    clamped = end
    if collected_at is not None and end > collected_at:
        clamped = max(current[1], collected_at)

    if (start, clamped) == current:
        _reject(
            request,
            "out_of_evidence" if clamped != end else "no_widening",
            (
                f"넓히자는 구간({_to_utc(pivot - window)}~{_to_utc(pivot + window)})이 "
                + (
                    f"수집 시각({_to_utc(collected_at)}) 뒤라 증거가 없습니다."
                    if clamped != end and collected_at is not None
                    else f"이미 1차 범위({time_range['start']}~{time_range['end']}) 안입니다."
                )
            ),
        )
        return False

    before = (time_range["start"], time_range["end"])
    time_range["start"], time_range["end"] = _to_utc(start), _to_utc(clamped)
    _accept(
        request,
        f"분석 기간을 {before[0]}~{before[1]} 에서 "
        f"{time_range['start']}~{time_range['end']} 로 넓혔습니다.",
    )
    return True


def _add_technique(
    request: dict[str, Any],
    scenario: dict[str, Any],
    mapped: "set[str]",
) -> "str | None":
    """기법을 더한다. 더했으면 그 ID.

    **두 기각을 나눈다.** 존재하지 않는 ID를 지어낸 것과, 실재하지만 매핑
    YAML이 아직 없는 것은 조치가 다르다 — 앞은 프롬프트를 고칠 일이고
    뒤는 매핑을 넓힐 일이다(``benchmark/rejections.yaml``).
    """
    technique_id = request["technique_id"]

    if not attack.is_known(technique_id):
        _reject(
            request,
            "unknown_technique",
            f"{technique_id} 는 실재하지 않는 ATT&CK ID 입니다.",
        )
        return None

    if technique_id not in mapped:
        _reject(
            request,
            "unmapped_technique",
            f"{technique_id} 는 매핑 YAML이 없어 03단계가 아무 아티팩트도 고르지 못합니다.",
        )
        return None

    if any(t.get("id") == technique_id for t in scenario["techniques"]):
        _reject(
            request,
            "already_selected",
            f"{technique_id} 는 1차 시나리오에 이미 있습니다.",
        )
        return None

    scenario["techniques"].append(
        {
            "id": technique_id,
            "name": attack.name_of(technique_id) or technique_id,
            "confidence": REQUEST_CONFIDENCE,
            # **입력 원문에서 온 값이 아니라는 사실을 문장이 말한다.**
            # 이 필드는 07단계 보고서의 "식별된 기법" 표에 그대로 실리므로,
            # 여기서 출처를 감추면 보고서가 1차 분류와 2차 가설을 같은
            # 말로 인쇄한다. ``--force-artifacts``가 ``reason.rationale``에
            # 같은 방식으로 적어 두는 것과 같은 규약이다.
            "evidence_text": (
                f"2차 조사 요청({request['based_on_ref']}): "
                f"{_one_line(request['rationale'])}"
            ),
        }
    )
    _accept(request, f"{technique_id} 를 시나리오에 추가했습니다 (2차 조사 요청).")
    return technique_id


def _add_artifact(
    request: dict[str, Any],
    *,
    catalog: mapping_loader.Catalog,
    target_os: str,
    already_selected: "set[str]",
    claimed: "set[str]",
) -> "str | None":
    """03단계에 강제 선별로 넘길 아티팩트를 고른다. 골랐으면 그 이름.

    **파서가 없는 것은 여기서 막는다.** ``psreadline_history``처럼
    ``supported: false``인 아티팩트는 요청해도 03단계 ``_force_select``가
    ``unusable_reason``을 보고 올리지 않는다. 그대로 통과시키면 2차가
    아무것도 못 가져오면서 재파싱 시간만 쓴다.

    ``claimed``는 **이 요청 묶음에서 이미 수용한 이름**이다. 같은 아티팩트를
    두 번 요청하면 둘 다 수용돼 ``applied.artifacts``에 중복이 생기는데,
    스키마가 그 배열에 ``uniqueItems``를 걸어 두었으므로 문서가 무효가 된다.
    기법 쪽은 이 문제가 없다 — ``_add_technique``가 시나리오의
    ``techniques``를 직접 보고, 그 목록은 수용할 때마다 자란다.
    """
    name = request["artifact"]

    if name not in catalog:
        _reject(request, "unsupported_artifact", f"카탈로그에 없는 아티팩트: {name}")
        return None

    unusable = catalog[name].unusable_reason(target_os)
    if unusable is not None:
        _reject(request, "unsupported_artifact", f"{name}: {unusable}")
        return None

    if name in already_selected:
        _reject(request, "already_selected", f"{name} 은 1차에서 이미 읽었습니다.")
        return None

    # **어휘는 같고 문장이 다르다.** 스키마의 기각 사유에 "중복 요청"을
    # 새로 만들지 않는다 — 두 경우 모두 "이미 볼 예정"이라는 같은 사실이고,
    # 무엇 때문에 그런지는 detail 이 말한다.
    if name in claimed:
        _reject(
            request,
            "already_selected",
            f"{name} 은 이 요청 묶음에서 이미 수용했습니다.",
        )
        return None

    claimed.add(name)
    _accept(request, f"{name} 을 2차에 Tier 1 로 강제 선별합니다.")
    return name


def expand(
    scenario: dict[str, Any],
    requests: list[dict[str, Any]],
    *,
    input_refs: "set[str]",
    already_selected: "set[str]",
    catalog: mapping_loader.Catalog,
    mapped: "set[str]",
    collected_at: "datetime | None" = None,
    generator: "str | None" = None,
) -> Outcome:
    """요청을 반영한 2차 시나리오를 만든다. **1차를 고치지 않는다.**

    돌려주는 ``Outcome.scenario``는 새 문서이고, 넘겨받은 ``scenario``는
    그대로다. ``requests``의 각 항목에는 ``disposition``이 채워진다.
    """
    working = copy.deepcopy(scenario)
    outcome = Outcome(scenario=working, requests=requests)
    #: 이 묶음에서 이미 수용한 아티팩트. 요청을 훑으며 자란다.
    claimed: set[str] = set()

    for request in requests:
        kind = request.get("type")
        if kind == "request_behavior":
            # 이미 파싱된 04 데이터가 필요한 요청이라 react_loop의
            # behavior_search가 먼저 처리한다. 여기서는 그 결과가 2차
            # Stage05를 열 만큼 있었는지만 받아들인다.
            disposition = request.get("disposition") or {}
            if disposition.get("verdict") == "accepted":
                if disposition.get("reason") == "applied":
                    outcome.behavior_applied = True
                continue
            if disposition:
                continue
            _reject(
                request,
                "behavior_not_processed",
                "request_behavior는 tools/react_loop.py의 행위 재검색을 먼저 거쳐야 합니다.",
            )
            continue

        # **근거가 먼저다.** 요청의 내용이 아무리 그럴듯해도 근거로 든
        # 레코드를 모델이 실제로 받지 않았다면 그 요청은 근거가 없다.
        # 열거형으로 막아 두었으므로 여기 걸리는 것은 제약이 새고 있다는 뜻이다.
        ref = request.get("based_on_ref")
        if ref not in input_refs:
            _reject(
                request,
                "ungrounded_ref",
                f"{ref} 는 05단계에 전달한 레코드가 아닙니다.",
            )
            continue

        if kind == "expand_time_range":
            if _widen_time_range(request, working["time_range"], collected_at):
                outcome.time_range_widened = True
        elif kind == "request_technique":
            added = _add_technique(request, working, mapped)
            if added:
                outcome.techniques.append(added)
        elif kind == "request_artifact":
            added = _add_artifact(
                request,
                catalog=catalog,
                target_os=working["target_os"],
                already_selected=already_selected,
                claimed=claimed,
            )
            if added:
                outcome.artifacts.append(added)

    if not outcome.accepted:
        return outcome

    # ``basis``는 "범위가 틀렸을 때 원인이 드러난다"는 자리다(스키마).
    # 우리가 넓힌 것도 그 원인의 일부이므로 1차의 근거를 지우지 않고 잇는다
    # (``timeband``가 같은 자리에 같은 방식으로 적는다).
    if outcome.time_range_widened:
        pivots = ", ".join(
            f"{r['based_on_ref']} {r['pivot_time']}±{r['window_hours']}h"
            for r in requests
            if r.get("type") == "expand_time_range"
            and (r.get("disposition") or {}).get("verdict") == "accepted"
        )
        working["time_range"]["basis"] = _one_line(
            f"{working['time_range'].get('basis') or ''} "
            f"05단계의 2차 조사 요청으로 넓혔다 ({pivots})."
        )

    # **1차의 generator를 지우지 않는다.** 어느 모델이 1차를 썼는가는
    # 2차 문서에서도 복원할 수 있어야 한다 — ``tools/live_check.py``의
    # 결산이 이 값에서 "목업이 섞이지 않았는가"를 본다.
    working["generator"] = generator or f"{scenario['generator']} → expand.py"

    outcome.scenario = io.new_document(
        working["case_id"],
        STAGE,
        working["generator"],
        **{
            key: working[key]
            for key in (
                "target_os",
                "techniques",
                "time_range",
                "entities",
                "overall_confidence",
                "unmapped_text",
            )
        },
    )
    return outcome


def _log_rejections(requests: list[dict[str, Any]], log: errlog.ErrorLog) -> int:
    """기각을 ``errors.jsonl``에도 남긴다. 남긴 건수를 돌려준다.

    **실패가 아니라 측정이라 ``action="record"``다.** 흐름을 바꾸지
    않는다 — 다시 묻지도, 건너뛰지도, 멈추지도 않는다.
    """
    count = 0
    for index, request in enumerate(requests):
        disposition = request.get("disposition") or {}
        if disposition.get("verdict") != "rejected":
            continue
        count += 1
        log.record(
            REQUEST_STAGE,
            "investigation_rejected",
            {
                "field": f"requests[{index}].{request.get('type', '?')}",
                "value": disposition.get("reason"),
                "message": disposition.get("detail", ""),
                "based_on_ref": request.get("based_on_ref"),
            },
            action="record",
        )
    return count


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage02_normalize.expand",
        description=(
            "05단계의 추가 조사 요청을 시나리오에 반영해 2차 시나리오를 만든다. "
            "LLM을 부르지 않는다. 수용된 요청이 없으면 아무것도 쓰지 않고 "
            f"종료 코드 {EXIT_NOTHING_TO_DO} 으로 끝난다"
        ),
    )
    parser.add_argument("--scenario", required=True, help="1차 02_scenario.json 경로")
    parser.add_argument("--requests", required=True, help="05_requests.json 경로. 제자리에서 고쳐 쓴다")
    parser.add_argument("--findings", required=True, help="1차 05_findings.json 경로. input_refs 를 읽는다")
    parser.add_argument("--selection", required=True, help="1차 03_selection.json 경로. 이미 읽은 아티팩트를 안다")
    parser.add_argument(
        "--input",
        dest="input_path",
        default=None,
        help=(
            "01_input.json 경로. evidence.root 에서 수집 시각을 찾아 시간 범위의 "
            "상한으로 쓴다. 없으면 상한을 걸지 않는다 — **못 찾으면 지어내지 "
            "않는다**(timeband.collection_time)"
        ),
    )
    parser.add_argument("--out", required=True, help="2차 시나리오 출력 경로")
    parser.add_argument("--mappings", default="mappings", help="매핑 디렉터리. 기본 %(default)s")
    parser.add_argument("--errors", default=None, help="errors.jsonl 경로. 생략하면 --out 과 같은 디렉터리")
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    out_path = Path(args.out)
    log = errlog.ErrorLog(Path(args.errors) if args.errors else out_path.parent / "errors.jsonl")

    scenario = io.read_json(args.scenario)
    requests_doc = io.read_json(args.requests)
    findings = io.read_json(args.findings)
    selection = io.read_json(args.selection)

    for document, stage, name in (
        (scenario, "02_normalize", "scenario"),
        (requests_doc, "05_investigate", "investigation"),
        (findings, "05_interpret", "findings"),
        (selection, "03_select", "selection"),
    ):
        try:
            io.check_header(document, expected_stage=stage)
            schema.validate(document, name)
        except schema.SchemaViolation as violation:
            log.abort(STAGE, "schema_violation", violation.as_detail())
        except io.HeaderError as e:
            log.abort(STAGE, "schema_violation", {"field": "<header>", "message": str(e)})

    try:
        catalog = mapping_loader.load_catalog(args.mappings)
    except mapping_loader.MappingError as e:
        log.abort(STAGE, "schema_violation", {"field": "<mappings>", "message": str(e)})

    collected_at = None
    if args.input_path:
        evidence = io.read_json(args.input_path).get("evidence") or {}
        collected_at = timeband.collection_time(evidence.get("root"))

    outcome = expand(
        scenario,
        requests_doc.get("requests", []),
        input_refs=set(findings.get("input_refs", [])),
        already_selected={entry["artifact"] for entry in selection.get("selected", [])},
        catalog=catalog,
        mapped=attack.mapped_techniques(args.mappings),
        collected_at=collected_at,
    )

    rejected = _log_rejections(outcome.requests, log)

    # 판정은 수용 여부와 무관하게 남긴다. 2차를 안 돌리기로 했다면 **왜
    # 안 돌렸는지**가 남아야 하고, 그것이 이 파일이다.
    requests_doc["requests"] = outcome.requests
    if outcome.accepted:
        requests_doc["applied"] = outcome.applied()
    else:
        # 다시 돌린 실행이 이전의 applied 를 물려받으면, 아무것도 반영하지
        # 않은 파일이 반영했다고 말한다.
        requests_doc.pop("applied", None)
    # **쓰기 전에 본다.** 들어올 때 이미 검증한 문서지만 그 뒤에 우리가
    # disposition 과 applied 를 얹었다. 그 손질이 스키마를 깨면 무효한 파일이
    # 조용히 남고, 07 보고서와 관문이 한참 뒤에 그것을 발견한다 — 원인에서
    # 멀어질수록 되짚기 어려워지는 자리다.
    #
    # 실제로 그런 적이 있다: 같은 아티팩트를 두 번 요청하면 둘 다 수용되어
    # applied.artifacts 에 중복이 생겼는데, 스키마가 그 배열에 uniqueItems 를
    # 걸어 두었는데도 검증이 없어 그대로 쓰였다(`_add_artifact` 의 claimed).
    #
    # **우리 결함이므로 즉시 멈춘다.** 재시도해도 같은 결과다 — 아래 2차
    # 시나리오를 검증하는 자리와 같은 판단이고, log.abort 가 errors.jsonl 에
    # 남기고 사유를 출력한 뒤 끝낸다.
    try:
        schema.validate(requests_doc, "investigation")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())

    io.write_json(args.requests, requests_doc)

    accepted = sum(
        1
        for request in outcome.requests
        if (request.get("disposition") or {}).get("verdict") == "accepted"
    )
    if not outcome.accepted:
        print(
            f"{args.requests}: 요청 {len(outcome.requests)}건 중 수용 0건 "
            f"(기각 {rejected}건) — 2차를 돌리지 않는다"
        )
        return EXIT_NOTHING_TO_DO

    try:
        schema.validate(outcome.scenario, "scenario")
    except schema.SchemaViolation as violation:
        # 우리가 만든 문서가 스키마를 못 맞추면 우리 결함이다. 재시도해도
        # 같은 결과라 즉시 멈춘다(``alert_adapter``와 같은 판단).
        log.abort(STAGE, "schema_violation", violation.as_detail())

    io.write_json(out_path, outcome.scenario)
    widened = outcome.scenario["time_range"]
    print(
        f"{out_path}: 요청 {len(outcome.requests)}건 중 수용 {accepted}건 "
        f"/ 기법 +{len(outcome.techniques)}"
        f"{' (' + ', '.join(outcome.techniques) + ')' if outcome.techniques else ''}"
        f" / 아티팩트 +{len(outcome.artifacts)}"
        f"{' (' + ', '.join(outcome.artifacts) + ')' if outcome.artifacts else ''}"
        f" / 기간 {widened['start']}~{widened['end']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
