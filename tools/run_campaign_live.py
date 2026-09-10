"""여러 노드의 01→07과 08 캠페인 상관분석을 한 번에 실행한다.

사용 예::

    .venv/Scripts/python.exe tools/run_campaign_live.py \
        --campaign-id K2L3-20260908 \
        --evidence-dir evidence \
        --raw "키오스크에 USB가 꽂힌 뒤 포스기를 지나 관리서버까지 공격이 진행되었습니다. 분석해주세요." \
        --model qwen2.5:latest --loop

``--campaign-id``를 주면 증거 디렉터리에서 노드를 찾아 ``campaign.json``과
case_id를 자동 생성한다. 기존 ``--campaign`` 방식도 그대로 지원한다.
``campaign.json`` 순서대로 노드를 실행한다. 같은 case_id가 이미 있으면 실전
재실행을 위해 ``live_check.py --force``를 사용한다. 기존 결과를 보존해 08만
다시 만들려면 ``--skip-existing``을 지정한다.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import io  # noqa: E402

DEFAULT_CAMPAIGN = "campaigns/K2L3-20260908/campaign.json"
CASES_DIR = REPO_ROOT / "cases"
CAMPAIGNS_DIR = REPO_ROOT / "campaigns"

CAMPAIGN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
AUTO_NODE_ORDER = {"kiosk": 0, "pos": 1, "mgmt": 2}
NODE_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("kiosk", ("kiosk",)),
    ("pos", ("pos",)),
    ("mgmt", ("mgmt", "management")),
)


class OrchestratorError(RuntimeError):
    """입력이나 실행 환경 때문에 캠페인을 시작할 수 없다."""


def load_campaign_config(path: Path) -> dict[str, Any]:
    """08단계 입력의 최소 계약을 독립적으로 검사한다.

    도움말과 노드 실행 준비는 08단계 구현을 import하지 않는다. 따라서 08
    모듈에 작업 중 문법 오류가 있어도 ``--help``는 사용할 수 있고, 오류는
    실제 Stage 08 subprocess의 종료 코드로 격리된다.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise OrchestratorError(f"campaign.json을 읽지 못했습니다: {exc}") from exc
    if not isinstance(document, dict):
        raise OrchestratorError("campaign.json의 최상위 값이 객체가 아닙니다")
    campaign_id = document.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id:
        raise OrchestratorError("campaign_id가 없습니다")
    nodes = document.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise OrchestratorError("nodes가 비었습니다")
    seen: set[str] = set()
    for entry in nodes:
        if not isinstance(entry, dict):
            raise OrchestratorError(f"nodes 항목이 객체가 아닙니다: {entry!r}")
        node, case_id = entry.get("node"), entry.get("case_id")
        if not isinstance(node, str) or not node:
            raise OrchestratorError(f"node 이름이 없습니다: {entry!r}")
        if not isinstance(case_id, str) or not case_id:
            raise OrchestratorError(f"{node}: case_id가 없습니다")
        if node in seen:
            raise OrchestratorError(f"node 이름이 겹칩니다: {node}")
        seen.add(node)
    return document


@dataclass(frozen=True)
class ReportSummary:
    node: str
    case_id: str
    path: Path
    passed: int
    warning: int
    rejected: int
    behaviors: tuple[str, ...]

    @property
    def total(self) -> int:
        return self.passed + self.warning + self.rejected

    @property
    def pass_rate(self) -> float:
        return 100.0 * self.passed / self.total if self.total else 0.0

    @property
    def reject_rate(self) -> float:
        return 100.0 * self.rejected / self.total if self.total else 0.0


BEHAVIOR_PATTERNS: tuple[tuple[str, str], ...] = (
    ("초기 침투", r"\busb\b|removable|certutil|다운로드"),
    ("실행", r"powershell|cmd\.exe|wscript|cscript|rundll32"),
    ("지속성", r"schtasks|scheduled task|예약 작업|작업 스케줄|autorun|windowstelemetry"),
    ("방어 회피", r"set-mppreference|defender|fodhelper|enablelua|\buac\b|wazuh.{0,20}stop"),
    ("정찰", r"\bnmap|\bwhoami|systeminfo|ipconfig|arp(?:\.exe|\s+-a)|netstat|\bwmic"),
    ("횡적 이동", r"smbghost|cve-2020-0796|psexec|\brdp\b|remote desktop|원격 데스크톱|:445|:3389"),
    ("자격 증명", r"credentials?|password|passwd|자격 증명|암호|login data"),
    ("수집", r"sqlcmd|settlements|select\s+\*|\.csv\b|데이터.{0,12}덤프|테이블.{0,12}백업"),
    ("C2", r"reverse shell|리버스 셸|:4444"),
    ("유출", r"rclone|gdrive|google drive|exfil|유출|반출"),
)

DISK_IMAGE_SUFFIXES = frozenset({".001", ".e01", ".raw", ".dd", ".vhd", ".vhdx"})


def _default_evidence_dir() -> str:
    sibling = REPO_ROOT.parent / "DFIR_Triage_Automation" / "evidence"
    if sibling.is_dir():
        return str(sibling)
    return str(REPO_ROOT / "evidence")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python tools/run_campaign_live.py",
        description="캠페인의 각 노드 01→07 실행, 08 상관분석, 최종 요약을 순서대로 수행한다.",
    )
    campaign_source = parser.add_mutually_exclusive_group()
    campaign_source.add_argument(
        "--campaign",
        default=None,
        help=f"기존 campaign.json 경로 (생성 모드를 쓰지 않을 때 기본: {DEFAULT_CAMPAIGN})",
    )
    campaign_source.add_argument(
        "--campaign-id",
        help="증거 폴더에서 노드·case_id를 찾아 campaigns/<ID>/campaign.json을 자동 생성",
    )
    parser.add_argument(
        "--evidence-dir",
        default=_default_evidence_dir(),
        help="노드별 KAPE 결과나 디스크 이미지가 있는 상위 디렉터리 (기본: 형제 프로젝트/evidence, 없으면 ./evidence)",
    )
    parser.add_argument("--raw", required=True, help="모든 노드에 공통으로 전달할 자연어 사고 설명")
    parser.add_argument("--model", default="qwen2.5:latest", help="02·05단계 Ollama 모델 (기본: qwen2.5:latest)")
    parser.add_argument(
        "--mode",
        choices=("assemble", "model"),
        default="assemble",
        help="05단계 findings 생성 방식 (기본: assemble)",
    )
    parser.add_argument("--max-chunks", type=int, default=8, help="assemble 모드의 최대 질의 조각 수 (기본: 8)")
    parser.add_argument("--num-ctx", type=int, default=16384, help="Ollama 컨텍스트 창 (기본: 16384)")
    loop = parser.add_mutually_exclusive_group()
    loop.add_argument(
        "--loop",
        dest="loop",
        action="store_true",
        default=True,
        help="05단계 자율 루프백을 실행한다 (기본)",
    )
    loop.add_argument(
        "--no-loop",
        dest="loop",
        action="store_false",
        help="05단계 자율 루프백을 생략한다",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="07_report.md가 이미 있는 노드는 재실행하지 않고 08에서 재사용한다",
    )
    parser.add_argument(
        "--overwrite-campaign",
        action="store_true",
        help="--campaign-id 자동 생성 대상이 이미 있으면 새 탐색 결과로 덮어쓴다",
    )
    args = parser.parse_args(argv)
    if args.max_chunks < 1:
        parser.error("--max-chunks는 1 이상이어야 합니다")
    if args.num_ctx < 1:
        parser.error("--num-ctx는 1 이상이어야 합니다")
    if args.overwrite_campaign and not args.campaign_id:
        parser.error("--overwrite-campaign은 --campaign-id와 함께 사용해야 합니다")
    return args


def _absolute(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return candidate.resolve()


def _name_matches(name: str, terms: Sequence[str]) -> bool:
    lowered = name.casefold()
    return any(
        re.search(rf"(?:^|[^a-z0-9]){re.escape(term)}(?:[^a-z0-9]|$)", lowered)
        for term in terms
    )


def _node_terms(entry: dict[str, Any]) -> tuple[str, ...]:
    raw = str(entry["node"]).casefold()
    aliases: dict[str, tuple[str, ...]] = {
        "kiosk": ("kiosk",),
        "pos": ("pos",),
        "mgmt": ("mgmt", "management"),
        "management": ("management", "mgmt"),
        "server": ("server", "mgmt", "management"),
    }
    terms = list(aliases.get(raw, (raw,)))
    ignored = {"case", "camp", "campaign", "node", "endpoint", "server"}
    for token in re.findall(r"[a-z]{3,}", str(entry.get("case_id", "")).casefold()):
        if token not in ignored and token not in terms:
            terms.append(token)
    return tuple(terms)


def _enter_volume_root(candidate: Path) -> Path:
    """KAPE의 ``snapshot/C`` 구조면 실제 볼륨 루트인 ``C``를 반환한다."""
    if candidate.is_file() or (candidate / "Windows").is_dir():
        return candidate.resolve()

    preferred = ("C", "C_", "C%3A", "C:", "[root]")
    for name in preferred:
        child = candidate / name
        if child.is_dir() and (child / "Windows").is_dir():
            return child.resolve()

    volume_children = [
        child
        for child in candidate.iterdir()
        if child.is_dir() and (child / "Windows").is_dir()
    ]
    if len(volume_children) == 1:
        return volume_children[0].resolve()
    return candidate.resolve()


def _is_evidence_candidate(path: Path) -> bool:
    """압축 원본은 제외하고 추출 디렉터리와 지원 가능한 이미지형 파일만 고른다."""
    return path.is_dir() or (path.is_file() and path.suffix.casefold() in DISK_IMAGE_SUFFIXES)


def _is_auto_discoverable_evidence(path: Path) -> bool:
    """자동 생성 시 일반 폴더를 KAPE 증거로 오인하지 않는다."""
    if path.is_file():
        return path.suffix.casefold() in DISK_IMAGE_SUFFIXES
    if not path.is_dir():
        return False
    if (path / "Windows").is_dir():
        return True
    try:
        return any(
            child.is_dir() and (child / "Windows").is_dir()
            for child in path.iterdir()
        )
    except OSError:
        return False


def _infer_node_name(path: Path) -> str:
    """증거 항목 이름에서 안정적인 소문자 노드 ID를 만든다."""
    name = path.stem if path.is_file() else path.name
    for canonical, aliases in NODE_ALIASES:
        if _name_matches(name, aliases):
            return canonical

    prefix = re.split(
        r"(?i)[_-](?:snapshot|kape|triage|evidence)(?:[_-]|$)",
        name,
        maxsplit=1,
    )[0]
    slug = re.sub(r"[^a-z0-9]+", "-", prefix.casefold()).strip("-")
    if not slug:
        raise OrchestratorError(f"증거 이름에서 node를 만들 수 없습니다: {path.name}")
    return slug


def _auto_case_prefix(campaign_id: str) -> str:
    """K2L8-20260908은 K2L8-KIOSK처럼 읽기 쉬운 case_id를 만든다."""
    return re.sub(r"-\d{8}$", "", campaign_id, flags=re.IGNORECASE)


def build_auto_campaign_config(campaign_id: str, evidence_dir: Path) -> dict[str, Any]:
    """증거 루트의 KAPE 스냅샷·이미지를 노드와 case_id로 변환한다."""
    if not CAMPAIGN_ID_RE.fullmatch(campaign_id):
        raise OrchestratorError(
            "--campaign-id는 영문자·숫자로 시작하고 영문자, 숫자, 점, 밑줄, 하이픈만 사용할 수 있습니다"
        )
    if not evidence_dir.is_dir():
        raise OrchestratorError(f"증거 상위 디렉터리가 없습니다: {evidence_dir}")

    try:
        candidates = sorted(
            (item for item in evidence_dir.iterdir() if _is_auto_discoverable_evidence(item)),
            key=lambda item: item.name.casefold(),
        )
    except OSError as exc:
        raise OrchestratorError(f"증거 디렉터리를 읽지 못했습니다: {evidence_dir}: {exc}") from exc
    if not candidates:
        raise OrchestratorError(
            "자동 생성할 KAPE 스냅샷이나 디스크 이미지를 찾지 못했습니다: "
            f"{evidence_dir}"
        )

    grouped: dict[str, list[Path]] = {}
    for candidate in candidates:
        grouped.setdefault(_infer_node_name(candidate), []).append(candidate)
    duplicates = {node: paths for node, paths in grouped.items() if len(paths) > 1}
    if duplicates:
        node = sorted(duplicates)[0]
        shown = ", ".join(path.name for path in duplicates[node])
        raise OrchestratorError(f"{node}: 자동 탐색된 증거가 둘 이상입니다: {shown}")

    case_prefix = _auto_case_prefix(campaign_id)
    ordered = sorted(grouped, key=lambda node: (AUTO_NODE_ORDER.get(node, 100), node))
    nodes = []
    for node in ordered:
        evidence = grouped[node][0]
        nodes.append(
            {
                "node": node,
                "case_id": f"{case_prefix}-{node.upper()}",
                "role": "server" if node == "mgmt" else "endpoint",
                "evidence": evidence.name,
            }
        )
    return {"campaign_id": campaign_id, "nodes": nodes}


def create_auto_campaign(
    campaign_id: str,
    evidence_dir: Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, dict[str, Any]]:
    """자동 캠페인을 원자적으로 기록하고 생성 경로와 문서를 반환한다."""
    path = CAMPAIGNS_DIR / campaign_id / "campaign.json"
    if path.exists() and not overwrite:
        raise OrchestratorError(
            f"자동 생성 대상이 이미 있습니다: {path} "
            "(재생성하려면 --overwrite-campaign을 지정하십시오)"
        )
    document = build_auto_campaign_config(campaign_id, evidence_dir)
    io.write_json(path, document)
    return path, document


def find_evidence_for_node(entry: dict[str, Any], evidence_dir: Path) -> Path:
    """노드 이름을 포함한 증거 항목을 찾고 KAPE 볼륨 루트까지 내려간다."""
    explicit = entry.get("evidence")
    if explicit:
        candidate = Path(str(explicit)).expanduser()
        if not candidate.is_absolute():
            candidate = evidence_dir / candidate
        if not candidate.exists():
            raise OrchestratorError(f"{entry['node']}: 지정된 증거 경로가 없습니다: {candidate}")
        return _enter_volume_root(candidate)

    terms = _node_terms(entry)
    try:
        direct = [
            item
            for item in evidence_dir.iterdir()
            if _is_evidence_candidate(item) and _name_matches(item.name, terms)
        ]
    except OSError as exc:
        raise OrchestratorError(f"증거 디렉터리를 읽지 못했습니다: {evidence_dir}: {exc}") from exc
    candidates = direct
    if not candidates:
        candidates = [
            item
            for item in evidence_dir.glob("*/*")
            if _is_evidence_candidate(item) and _name_matches(item.name, terms)
        ]

    candidates = sorted({item.resolve() for item in candidates}, key=lambda item: str(item).casefold())
    if not candidates:
        raise OrchestratorError(
            f"{entry['node']}: {evidence_dir} 아래에서 노드 이름 "
            f"({', '.join(terms)})과 일치하는 증거를 찾지 못했습니다"
        )
    if len(candidates) > 1:
        shown = "\n    ".join(str(item) for item in candidates)
        raise OrchestratorError(
            f"{entry['node']}: 일치하는 증거가 둘 이상입니다. campaign.json의 노드에 "
            f"evidence 경로를 지정하십시오:\n    {shown}"
        )
    return _enter_volume_root(candidates[0])


def build_live_command(
    args: argparse.Namespace,
    entry: dict[str, Any],
    evidence: Path,
    cases_dir: Path,
    *,
    replace_existing: bool,
) -> list[str]:
    command = [
        sys.executable,
        "tools/live_check.py",
        "--case-id",
        str(entry["case_id"]),
        "--cases-dir",
        str(cases_dir),
        "--evidence",
        str(evidence),
        "--raw",
        args.raw,
        "--model",
        args.model,
        "--mode",
        args.mode,
        "--max-chunks",
        str(args.max_chunks),
        "--num-ctx",
        str(args.num_ctx),
    ]
    if args.loop:
        command.append("--loop")
    if entry.get("volume") is not None:
        command += ["--volume", str(entry["volume"])]
    if replace_existing:
        command.append("--force")
    return command


def _shown_command(command: Sequence[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(list(command))
    return shlex.join(command)


def run_command(command: list[str]) -> int:
    print(f"$ {_shown_command(command)}", flush=True)
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
            check=False,
        )
    except OSError as exc:
        raise OrchestratorError(f"명령을 시작하지 못했습니다: {_shown_command(command)}: {exc}") from exc
    return int(completed.returncode)


def _reviewed_text(report: str) -> str:
    start = report.find("## 확인된 사실")
    if start < 0:
        start = 0
    end = report.find("## 미확인 사항", start)
    return report[start:] if end < 0 else report[start:end]


def _behavior_text(report: str) -> str:
    """ATT&CK 제목이 아니라 실제 소견 문장과 근거에서 행위를 찾는다.

    잘못 붙은 ``T1048 Exfiltration`` 제목 때문에 단순 nmap 실행을 유출로
    요약하는 식의 2차 오해를 만들지 않는다.
    """
    return "\n".join(
        line for line in _reviewed_text(report).splitlines() if not line.lstrip().startswith("#")
    )


def read_report_summary(node: str, case_id: str, path: Path) -> ReportSummary:
    if not path.is_file():
        raise OrchestratorError(f"{node}: 최종 보고서가 없습니다: {path}")
    try:
        report = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise OrchestratorError(f"{node}: 최종 보고서를 읽지 못했습니다: {path}: {exc}") from exc
    match = re.search(
        r"검증 결과:\s*통과\s*(\d+)\s*/\s*주의\s*(\d+)\s*/\s*기각\s*(\d+)",
        report,
    )
    if not match:
        raise OrchestratorError(f"{node}: 07_report.md에서 검증 결과를 읽지 못했습니다")
    reviewed = _behavior_text(report)
    behaviors = tuple(
        label
        for label, pattern in BEHAVIOR_PATTERNS
        if re.search(pattern, reviewed, flags=re.IGNORECASE | re.DOTALL)
    )
    return ReportSummary(
        node=node,
        case_id=case_id,
        path=path,
        passed=int(match.group(1)),
        warning=int(match.group(2)),
        rejected=int(match.group(3)),
        behaviors=behaviors,
    )


def _display_width(value: str) -> int:
    return sum(2 if unicodedata.east_asian_width(char) in "WF" else 1 for char in value)


def _pad(value: object, width: int) -> str:
    text = str(value)
    return text + " " * max(0, width - _display_width(text))


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> None:
    rendered = [[str(cell) for cell in row] for row in rows]
    widths = [
        max(_display_width(headers[index]), *(_display_width(row[index]) for row in rendered))
        for index in range(len(headers))
    ]
    print("| " + " | ".join(_pad(header, widths[index]) for index, header in enumerate(headers)) + " |")
    print("|-" + "-|-".join("-" * width for width in widths) + "-|")
    for row in rendered:
        print("| " + " | ".join(_pad(cell, widths[index]) for index, cell in enumerate(row)) + " |")


def print_dashboard(
    campaign_doc: dict[str, Any],
    campaign_out: Path,
    cases_dir: Path,
) -> None:
    summaries = [
        read_report_summary(
            str(entry["node"]),
            str(entry["case_id"]),
            cases_dir / str(entry["case_id"]) / "07_report.md",
        )
        for entry in campaign_doc["nodes"]
    ]
    campaign_json = campaign_out / "08_campaign.json"
    campaign_report = campaign_out / "08_campaign.md"
    if not campaign_json.is_file() or not campaign_report.is_file():
        raise OrchestratorError(f"08단계 최종 산출물이 없습니다: {campaign_out}")
    try:
        campaign_result = json.loads(campaign_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OrchestratorError(f"08_campaign.json을 읽지 못했습니다: {exc}") from exc
    if not isinstance(campaign_result, dict):
        raise OrchestratorError("08_campaign.json의 최상위 값이 객체가 아닙니다")

    print("\n" + "=" * 88)
    print(f"캠페인 최종 요약 — {campaign_doc['campaign_id']}")
    print("=" * 88)
    rows = [
        (
            item.node,
            item.case_id,
            item.total,
            item.passed,
            item.warning,
            item.rejected,
            f"{item.pass_rate:.1f}%",
            f"{item.reject_rate:.1f}%",
            ", ".join(item.behaviors) or "탐지 행위 없음",
        )
        for item in summaries
    ]
    _print_table(
        ("노드", "케이스", "소견", "통과", "주의", "기각", "통과율", "기각률", "주요 탐지 행위"),
        rows,
    )

    peer_links = [link for link in campaign_result.get("links", []) if link.get("axis") == "peer"]
    print("\n복원된 노드 간 피어 링크")
    if not peer_links:
        print("- 없음")
    else:
        for link in peer_links[:20]:
            hops = " → ".join(
                str(observation.get("node", "?"))
                for observation in link.get("observations", [])
            )
            print(f"- {hops} / {link.get('value', '-')} / {link.get('grade', '-')}")
        if len(peer_links) > 20:
            print(f"- 그 밖의 링크 {len(peer_links) - 20}건은 08_campaign.md를 확인하십시오")

    ordered_nodes = [str(entry["node"]) for entry in campaign_doc["nodes"]]
    expected_edges = set(zip(ordered_nodes, ordered_nodes[1:]))
    observed_edges = {
        (str(left.get("node")), str(right.get("node")))
        for link in peer_links
        for left, right in zip(link.get("observations", []), link.get("observations", [])[1:])
    }
    if expected_edges:
        restored = expected_edges & observed_edges
        if restored == expected_edges:
            chain_status = "확인"
        elif restored:
            chain_status = f"부분 확인 ({len(restored)}/{len(expected_edges)} hop)"
        else:
            chain_status = "미복원"
        print(f"- campaign 순서 피어 체인 ({' → '.join(ordered_nodes)}): {chain_status}")

    reviewed = "\n".join(
        _reviewed_text(item.path.read_text(encoding="utf-8")) for item in summaries
    )
    settlements = bool(
        re.search(r"settlements", reviewed, re.IGNORECASE)
        and re.search(r"sqlcmd|select\s+\*|\.csv\b", reviewed, re.IGNORECASE)
    )
    gdrive = bool(
        re.search(r"rclone", reviewed, re.IGNORECASE)
        and re.search(r"gdrive|google drive", reviewed, re.IGNORECASE)
    )
    print("\n최종 임팩트")
    print(f"- DB settlements 테이블 덤프: {'확인' if settlements else '미확인'}")
    print(
        "- gdrive 클라우드 유출: "
        + ("반출 명령 확인 (실제 전송 성공 여부는 별도 검증 필요)" if gdrive else "미확인")
    )
    print(f"\n08 보고서: {campaign_report}")


def main(argv: Sequence[str] | None = None) -> int:
    io.configure_console()
    args = parse_args(argv)
    try:
        evidence_dir = _absolute(args.evidence_dir)
        if not evidence_dir.is_dir():
            raise OrchestratorError(f"증거 상위 디렉터리가 없습니다: {evidence_dir}")
        if args.campaign_id:
            campaign_path, campaign_doc = create_auto_campaign(
                args.campaign_id,
                evidence_dir,
                overwrite=args.overwrite_campaign,
            )
            print(f"[CAMPAIGN] 자동 생성: {campaign_path}")
            for entry in campaign_doc["nodes"]:
                print(
                    f"  {entry['node']} → {entry['case_id']} "
                    f"({entry['role']}, {entry['evidence']})"
                )
        else:
            campaign_path = _absolute(args.campaign or DEFAULT_CAMPAIGN)
            if not campaign_path.is_file():
                raise OrchestratorError(f"campaign.json이 없습니다: {campaign_path}")
            campaign_doc = load_campaign_config(campaign_path)

        total_steps = len(campaign_doc["nodes"]) + 1
        CASES_DIR.mkdir(parents=True, exist_ok=True)
        for index, entry in enumerate(campaign_doc["nodes"], start=1):
            node = str(entry["node"])
            case_id = str(entry["case_id"])
            case_dir = CASES_DIR / case_id
            report = case_dir / "07_report.md"
            print("\n" + "=" * 88)
            print(f"[{index}/{total_steps}] [Stage 01-07] Node {node.upper()} ({case_id})")
            print("=" * 88)
            if args.skip_existing and report.is_file():
                print(f"[SKIP] 기존 최종 보고서 재사용: {report}")
                continue

            evidence = find_evidence_for_node(entry, evidence_dir)
            replace_existing = case_dir.exists()
            if replace_existing:
                print(f"[REPLACE] 기존 케이스를 live_check.py --force로 다시 생성합니다: {case_dir}")
            print(f"[EVIDENCE] {evidence}")
            command = build_live_command(
                args,
                entry,
                evidence,
                CASES_DIR,
                replace_existing=replace_existing,
            )
            code = run_command(command)
            if code != 0:
                print(f"[FAIL] {node} 분석 실패 (종료 코드 {code}). Stage 08은 실행하지 않습니다.", file=sys.stderr)
                return code or 1
            if not report.is_file():
                raise OrchestratorError(f"{node}: 성공 종료했지만 07_report.md가 생성되지 않았습니다")

        campaign_out = campaign_path.parent
        campaign_out.mkdir(parents=True, exist_ok=True)
        print("\n" + "=" * 88)
        print(f"[{total_steps}/{total_steps}] [Stage 08] Campaign {campaign_doc['campaign_id']}")
        print("=" * 88)
        stage08 = [
            sys.executable,
            "-m",
            "src.stage08_campaign.campaign",
            "--in",
            str(campaign_path),
            "--cases",
            str(CASES_DIR),
            "--out",
            str(campaign_out),
        ]
        code = run_command(stage08)
        if code != 0:
            print(f"[FAIL] Stage 08 실패 (종료 코드 {code})", file=sys.stderr)
            return code or 1

        print_dashboard(campaign_doc, campaign_out, CASES_DIR)
        return 0
    except OrchestratorError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[ERROR] 파일시스템 작업 실패: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] 사용자가 실행을 중단했습니다.", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
