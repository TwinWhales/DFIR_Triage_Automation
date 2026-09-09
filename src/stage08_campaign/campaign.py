"""08단계 — 노드 여럿을 한 사건으로 읽는다.

``campaign.json`` 이 적은 노드마다 이미 끝난 01~07 산출물을 열고, 노드
**사이**를 결정론으로 잇는다. 설계는 `docs/proposals/multi-node-campaign.md`.

**LLM을 부르지 않는다.** 07과 같은 이유다 — 마지막에 모델이 문장을 다시
쓰면 앞의 모든 검증이 무의미해진다. 08은 Jinja2 템플릿이다.

**노드 하나가 없거나 덜 끝났어도 멈추지 않는다.** 대신 그 노드가 왜 빠졌는지
결과와 보고서 첫 화면에 싣는다. 조용히 적은 노드짜리 캠페인이 되면, 읽는
사람은 "그 단말에는 흔적이 없었다"로 읽는다.

사용법::

    python -m src.stage08_campaign.campaign \\
        --in campaigns/KIOSK-0910/campaign.json \\
        --cases cases/ \\
        --out campaigns/KIOSK-0910/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ..common import errors as errlog
from ..common import io, schema
from . import correlate

__all__ = ["STAGE", "load_campaign", "read_node", "build", "render", "main"]

STAGE = "08_campaign"
TEMPLATE_DIR = Path(__file__).parent / "templates"


class CampaignError(ValueError):
    """``campaign.json`` 자체가 쓸 수 없는 경우. 노드 결측과는 다르다."""


def load_campaign(path: str | Path) -> dict[str, Any]:
    """``campaign.json`` 을 읽고 최소 형태만 본다.

    스키마를 따로 두지 않는 이유는 이것이 **사람이 쓰는 입력**이기 때문이다.
    01단계 입력과 같은 자리이고, 틀렸을 때 스키마 위반 메시지보다 무엇을
    고쳐야 하는지 말해 주는 편이 낫다.
    """
    document = io.read_json(path)
    campaign_id = document.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id:
        raise CampaignError("campaign_id 가 없습니다")

    nodes = document.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise CampaignError("nodes 가 비었습니다 — 노드를 하나 이상 적습니다")

    seen: set[str] = set()
    for entry in nodes:
        if not isinstance(entry, dict):
            raise CampaignError(f"nodes 항목이 객체가 아닙니다: {entry!r}")
        name, case_id = entry.get("node"), entry.get("case_id")
        if not isinstance(name, str) or not name:
            raise CampaignError(f"node 이름이 없습니다: {entry!r}")
        if not isinstance(case_id, str) or not case_id:
            raise CampaignError(f"{name}: case_id 가 없습니다")
        if name in seen:
            # 이름이 겹치면 관측이 어느 노드 것인지 알 수 없다. ref 가 노드
            # 안에서만 유일한 것과 같은 이유로 여기서 막는다.
            raise CampaignError(f"node 이름이 겹칩니다: {name}")
        seen.add(name)
    return document


def _verdicts(case_dir: Path) -> "tuple[dict[str, str], str | None]":
    """``ref → passed|warning|rejected``. 읽지 못하면 사유를 함께 낸다.

    06단계는 소견 단위로 판정하고 08단계는 레코드 단위로 이으므로, 소견의
    판정을 그 소견이 인용한 ``ref`` 로 내린다. 한 ref 가 여러 소견에 인용됐고
    판정이 갈리면 **좋은 쪽**을 남긴다 — 통과한 소견이 그 레코드를 근거로
    삼았다는 사실이 기각된 소견 때문에 사라지면 안 된다.
    """
    verified_path = case_dir / "06_verified.json"
    findings_path = case_dir / "05_findings.json"
    if not verified_path.is_file():
        return {}, "06_verified.json 없음"
    if not findings_path.is_file():
        return {}, "05_findings.json 없음"

    try:
        verified = io.read_json(verified_path)
    except Exception as exc:  # noqa: BLE001 — 노드만 제외하고 캠페인은 계속 간다
        return {}, f"06_verified.json 을 읽지 못했습니다: {exc}"
    if not isinstance(verified, dict):
        return {}, "06_verified.json 의 최상위 값이 JSON 객체가 아닙니다"
    try:
        findings = io.read_json(findings_path)
    except Exception as exc:  # noqa: BLE001 — 노드만 제외하고 캠페인은 계속 간다
        return {}, f"05_findings.json 을 읽지 못했습니다: {exc}"
    if not isinstance(findings, dict):
        return {}, "05_findings.json 의 최상위 값이 JSON 객체가 아닙니다"
    refs_by_id = {
        item["id"]: item.get("refs") or []
        for item in findings.get("findings", [])
        if isinstance(item, dict) and item.get("id")
    }

    rank = {"passed": 0, "warning": 1, "rejected": 2}
    result: dict[str, str] = {}
    for key, verdict in (("passed", "passed"), ("unverifiable", "warning"), ("rejected", "rejected")):
        for item in verified.get(key, []):
            if not isinstance(item, dict):
                continue
            for ref in refs_by_id.get(item.get("id"), []):
                current = result.get(ref)
                if current is None or rank[verdict] < rank[current]:
                    result[ref] = verdict
    return result, None


def read_node(entry: dict[str, Any], cases_dir: Path) -> dict[str, Any]:
    """노드 하나를 연다. 못 열어도 예외를 던지지 않고 사유를 담아 돌려준다."""
    node = {
        "node": entry["node"],
        "case_id": entry["case_id"],
        "status": "ok",
        "_records": [],
        "_verdicts": {},
    }
    if entry.get("role"):
        node["role"] = str(entry["role"])

    case_dir = cases_dir / entry["case_id"]
    if not case_dir.is_dir():
        node["status"] = "missing"
        node["reason"] = f"케이스 디렉터리가 없습니다: {case_dir}"
        return node

    parsed_dir = case_dir / "04_parsed"
    if not parsed_dir.is_dir():
        node["status"] = "incomplete"
        node["reason"] = "04_parsed 없음 — 04단계를 먼저 실행합니다"
        return node

    try:
        records = io.read_parsed_records(parsed_dir)
    except Exception as exc:  # noqa: BLE001 — 사유를 싣고 계속 간다
        node["status"] = "incomplete"
        node["reason"] = f"04_parsed 를 읽지 못했습니다: {exc}"
        return node

    verdicts, problem = _verdicts(case_dir)
    if problem is not None:
        node["status"] = "incomplete"
        node["reason"] = problem
        return node

    scenario_path = case_dir / "02_scenario.json"
    if scenario_path.is_file():
        try:
            scenario = io.read_json(scenario_path)
            hosts = (scenario.get("entities") or {}).get("hosts") or []
        except Exception as exc:  # noqa: BLE001 — 노드만 제외하고 캠페인은 계속 간다
            node["status"] = "incomplete"
            node["reason"] = f"02_scenario.json 을 읽지 못했습니다: {exc}"
            return node
        if hosts:
            node["host"] = str(hosts[0])

    node["_records"] = list(records.values())
    node["_verdicts"] = verdicts
    node["records"] = len(records)
    return node


def drop_ambiguous_hosts(nodes: list[dict[str, Any]]) -> None:
    """두 노드가 같은 호스트 이름을 집었으면 그 이름은 어느 쪽도 특정하지 못한다.

    ``read_node`` 가 채우는 ``host`` 의 출처는 **02단계 시나리오의
    ``entities.hosts[0]``** 이고, 그것은 신고자가 문장에서 처음 언급한
    기계다. 노드마다 다른 신고문을 받으면 대개 자기 자신이 맨 앞에 오지만,
    **한 사건을 한 질문으로 조사하면 세 노드가 같은 이름을 집는다.**

    실측(`K2L-20260908`, 2026-09-10). 세 노드에 같은 두 줄
    ("키오스크에 USB가 꽂힌 뒤 포스기를 지나 관리서버까지...")을 주자
    ``entities.hosts`` 가 이렇게 나왔다:

        kiosk  ['키오스크', '관리서버']    → 키오스크
        pos    ['키오스크', '관리서버']    → 키오스크   ← POS 를 키오스크라고 적었다
        mgmt   []                          → 미상

    표에 틀린 이름을 적는 것은 비워 두는 것보다 나쁘다. 겹치면 셋 다 지운다.

    **이것은 신원을 알아내는 코드가 아니라 없는 신원을 주장하지 않게 하는
    코드다.** 노드의 진짜 신원은 증거에 있다(SYSTEM 하이브의 ComputerName).
    지금은 그 키가 선별 범위에 없어 04단계가 읽지 않는다 — 읽게 되면 이
    함수가 아니라 ``read_node`` 가 거기서 값을 가져와야 한다.
    """
    seen: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        if node.get("host"):
            seen.setdefault(str(node["host"]), []).append(node)
    for owners in seen.values():
        if len(owners) > 1:
            for node in owners:
                node.pop("host", None)


def build(campaign: dict[str, Any], nodes: list[dict[str, Any]], *, generator: str = "campaign.py") -> dict[str, Any]:
    """08 문서를 만든다. 파일을 읽지도 쓰지도 않는다."""
    drop_ambiguous_hosts(nodes)
    usable = [node for node in nodes if node["status"] == "ok"]
    per_node = {
        node["node"]: correlate.observations_of(node["node"], node["_records"], node["_verdicts"])
        for node in usable
    }
    result = correlate.build_links(per_node, len(usable))

    links = result["links"]
    public_nodes = [
        {key: value for key, value in node.items() if not key.startswith("_")} for node in nodes
    ]
    document = io.new_document(
        campaign["campaign_id"],
        STAGE,
        generator,
        nodes=public_nodes,
        links=links,
        context_links=result["context_links"],
        stats={
            "nodes_total": len(nodes),
            "nodes_ok": len(usable),
            "links": len(links),
            "links_passed": sum(1 for link in links if link["grade"] == "passed"),
            "links_warning": sum(1 for link in links if link["grade"] == "warning"),
            "links_observed": sum(1 for link in links if link["grade"] == "observed"),
            "context_links": len(result["context_links"]),
            "ubiquitous_values": result["ubiquitous_values"],
        },
    )
    # ``result["os_background_values"]`` 는 문서에 싣지 않는다. schemas/ 는
    # 동결이고 stats·links·context_links 가 모두 additionalProperties: false
    # 라 키를 하나 더하려면 스키마를 고쳐야 하는데, 그 판단은 전체 공지
    # 대상이다. 지금은 correlate 의 반환값과 테스트에만 남는다.
    return document


#: 등급 → 보고서 딱지. observed 는 소견 인용과 무관한 관측이다.
_BADGES = {"passed": "🟢", "warning": "🟡", "observed": "🔵"}

AXIS_LABELS = {
    "hash": "해시",
    "peer": "노드 간 접속",
    "network": "네트워크",
    "filename": "파일명",
    "path": "경로",
    "account": "계정",
}


#: 참고 표에 실을 최대 줄 수.
#:
#: **문서가 아니라 표를 자른다.** ``08_campaign.json`` 에는 전부 남는다 —
#: 자르는 것은 사람이 여는 마크다운뿐이고, 몇 건 중 몇 건인지 표 위에 적는다.
#:
#: 실측(2026-09-10): ``K2L-20260908`` 의 참고 연결이 44,471건이라 보고서가
#: **44,538줄**이었다. 본문은 55줄이고 나머지가 전부 이 표였다 — 경로 29,236 ·
#: 파일명 14,681 로, ``registry:SOFTWARE`` 를 통째로 연 실행에서 CBS 컴포넌트
#: 이름이 두 노드에 같이 있다는 것을 한 줄씩 적은 것이다. 같은 사건을 다시
#: 돌린 ``K2L2-20260908`` 은 2,505건이었다. **실행마다 자릿수가 흔들리므로**
#: 상한이 없으면 보고서를 열 수 있는지가 운에 달린다.
#:
#: 60인 것은 한 화면에서 훑을 수 있는 분량이고, 그 이상은 어차피 표가 아니라
#: 질의로 봐야 하기 때문이다.
MAX_CONTEXT_ROWS = 60


def _context_priority(link: dict[str, Any]) -> tuple[int, str]:
    """참고 표에서 먼저 보여 줄 순서. **지어내기 어려운 축이 앞이다.**

    ``AXES`` 의 선언 순서를 그대로 쓴다(그 상수의 주석). 시간순으로 앞에서
    60개를 자르면 **가장 오래된 배경 잡음**이 실리는데, 그것은 이 표를 읽는
    이유가 아니다 — 인용되지 않았지만 볼 만한 것이 있는지 훑는 자리다.
    """
    order = correlate.AXES
    axis = str(link.get("axis") or "")
    rank = order.index(axis) if axis in order else len(order)
    return (rank, str(link.get("observations", [{}])[0].get("at") or ""))


def build_context(document: dict[str, Any]) -> dict[str, Any]:
    """템플릿에 넘길 값. 판정에 쓰이는 값은 여기서 만들지 않는다."""
    def decorate(link: dict[str, Any]) -> dict[str, Any]:
        observations = link["observations"]
        return {
            **link,
            "axis_label": AXIS_LABELS.get(link["axis"], link["axis"]),
            # peer 축은 모델이 아니라 파이썬이 레코드에서 읽은 사실이라
            # 딱지를 따로 둔다. 같은 딱지를 달면 06 을 통과한 소견과
            # 구별되지 않는다.
            "badge": _BADGES.get(str(link.get("grade")), _BADGES["warning"]),
            "hops": " → ".join(item["node"] for item in observations),
            "at": observations[0].get("at", "미상"),
        }

    skipped = [node for node in document["nodes"] if node["status"] != "ok"]
    # **문서가 아니라 표를 자른다** (``MAX_CONTEXT_ROWS``). 고른 뒤 다시
    # 시각순으로 세워야 표가 읽히므로, 우선순위는 고르는 데에만 쓴다.
    context_links = document["context_links"]
    shown = sorted(context_links, key=_context_priority)[:MAX_CONTEXT_ROWS]
    shown.sort(key=lambda link: str(link.get("observations", [{}])[0].get("at") or ""))
    return {
        "campaign_id": document["case_id"],
        "generated_at": document["generated_at"],
        "nodes": document["nodes"],
        "skipped": skipped,
        "links": [decorate(link) for link in document["links"]],
        "context_links": [decorate(link) for link in shown],
        "context_total": len(context_links),
        "context_shown": len(shown),
        "stats": document["stats"],
        "mermaid": _mermaid(document["links"]),
    }


def _mermaid(links: list[dict[str, Any]]) -> list[str]:
    """노드 사이의 이동을 간선으로. **링크가 말하는 것 이상을 그리지 않는다.**

    화살표는 시간 순서일 뿐 인과가 아니다. 같은 노드 쌍을 여러 축이 이으면
    간선 하나에 축 이름을 모아 붙인다 — 간선을 겹쳐 그리면 그림이 사실보다
    촘촘해 보인다.
    """
    edges: dict[tuple[str, str], set[str]] = {}
    for link in links:
        observations = link["observations"]
        for left, right in zip(observations, observations[1:]):
            if left["node"] == right["node"]:
                continue
            if io.parse_timestamp(left.get("at")) is None or io.parse_timestamp(right.get("at")) is None:
                # 시각이 없는 쪽을 뒤로 정렬했다는 이유만으로 이동 방향을
                # 주장하지 않는다. 표에는 링크를 남기되 다이어그램에서 뺀다.
                continue
            edges.setdefault((left["node"], right["node"]), set()).add(
                AXIS_LABELS.get(link["axis"], link["axis"])
            )
    lines = ["graph LR"]
    for (left, right), axes in sorted(edges.items()):
        lines.append(f"  {left}[{left}] -->|{'·'.join(sorted(axes))}| {right}[{right}]")
    return lines


def render(context: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template("campaign.md.j2").render(**context)


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage08_campaign.campaign",
        description="노드 여럿의 01~07 산출물을 한 사건으로 잇는다.",
    )
    parser.add_argument("--in", dest="in_path", required=True, help="campaign.json 경로")
    parser.add_argument("--cases", default="cases", help="노드 케이스가 있는 디렉터리. 기본 %(default)s")
    parser.add_argument("--out", required=True, help="산출물을 쓸 디렉터리")
    parser.add_argument("--errors", help="errors.jsonl 경로. 기본은 --out 아래")
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    log = errlog.ErrorLog(Path(args.errors) if args.errors else out_dir / "errors.jsonl")

    try:
        campaign = load_campaign(args.in_path)
    except (CampaignError, FileNotFoundError, ValueError) as exc:
        print(f"[{STAGE}] {exc}", file=sys.stderr)
        return 2  # 사람이 쓴 입력의 오류다. errors.jsonl 은 파이프라인 실패만 담는다.

    nodes = [read_node(entry, Path(args.cases)) for entry in campaign["nodes"]]
    document = build(campaign, nodes)

    try:
        schema.validate(document, "campaign")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())

    json_path = io.write_json(out_dir / "08_campaign.json", document)
    md_path = out_dir / "08_campaign.md"
    md_path.write_text(render(build_context(document)), encoding="utf-8")

    stats = document["stats"]
    print(
        f"{json_path}: 노드 {stats['nodes_ok']}/{stats['nodes_total']} / "
        f"링크 {stats['links']}건 (통과 {stats['links_passed']} / 주의 {stats['links_warning']}"
        f" / 노드 간 접속 {stats['links_observed']}) / "
        f"참고 {stats['context_links']}건"
    )
    skipped = [node for node in document["nodes"] if node["status"] != "ok"]
    for node in skipped:
        print(f"  빠진 노드 {node['node']}: {node.get('reason', '사유 미상')}", file=sys.stderr)
    print(f"{md_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
