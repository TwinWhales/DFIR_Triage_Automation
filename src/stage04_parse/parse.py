"""04단계 — 결정론적 파싱.

선별 결과를 받아 해당 아티팩트의 지정된 범위만 읽는다. LLM은 관여하지
않는다. 소형 모델에 파싱까지 맡기면 환각이 데이터 계층에서 발생해
검증 자체가 불가능해진다.

**현재 상태: 카탈로그(``mappings/_artifacts.yaml``)의 아티팩트에는 전부
파서가 있다** — ``$MFT``, ``$UsnJrnl``, evtx 2종, registry 2종, ``prefetch``.
등록된 파서 목록은 ``parsers/__init__.py``가 들고 있다.

**아티팩트가 파일 하나라고 가정하지 않는다.** ``prefetch``는 폴더 안의
.pf 전부가 아티팩트 하나이며, ``_records``가 ``evidence.open_all``로
파일마다 파서를 부른다. 파서는 자기가 몇 번째로 불렸는지 몰라도 된다.

파서가 없거나 증거 파일이 없는 아티팩트가 선별되면 ``errors.jsonl``에
남기고 건너뛴다 — 조용히 빈 결과를 내지 않는다. 같은 내용이
``_manifest.json``의 ``skipped``에도 들어가고, 07단계가 그것을 읽어
보고서의 "분석 범위 한계"에 사유와 함께 싣는다(``docs/limitations.md``
4-1). ``note_skip`` 참조.

**증거가 어느 Windows인지 먼저 판정한다**(``osinfo``). 그 버전에 존재할
수 없는 아티팩트는 찾아 보지도 않고 ``version_not_applicable``로 적는다 —
Win7 이미지의 ``Amcache.hve``가 그렇다. 판정에 실패하면 아무것도 거르지
않는다. 근거는 ``osinfo`` 모듈 docstring에 있다.

증거 없이 배선만 확인하려면 목업 ``04_parsed/``를 미리 넣어 두고
``--skip-existing``으로 건너뛴다.

**시간 범위는 기본적으로 소프트 필터다** — ``outside_time_range``만 붙이고
전부 내보낸다(``flagging.py``). 다만 파일이 ``--large-artifact-mb``(기본
100MB)를 넘으면 그 판정을 하드 컷으로 바꿔 아예 뺀다(``_should_prune_outside_range``).
크기와 무관하게 소프트 방식만 쓰려면 ``--no-time-range-prune``.

사용법::

    python -m src.stage04_parse.parse \\
        --in cases/C-001/03_selection.json --out cases/C-001/04_parsed/ \\
        --evidence /mnt/evidence/WEB01 --skip-existing
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from ..common import errors as errlog
from ..common import io, schema
from . import evidence, flagging, osinfo, parsers
from .parsers.base import Scope

__all__ = [
    "STAGE",
    "group_by_artifact",
    "merge_scopes",
    "write_manifest",
    "parse_artifact",
    "main",
]

STAGE = "04_parse"

#: 파일 크기가 이보다 크면(바이트) 시간 범위 밖 레코드를 아예 뺀다.
#:
#: 소형 아티팩트는 그대로 둔다 — ``outside_time_range``만 붙이고 전부
#: 내보낸다(``flagging.py`` 참조). 시간 추론이 틀렸을 때 원인을 되짚으려면
#: 레코드가 남아 있어야 하기 때문이다. 이 트레이드오프를 무제한 유지하면
#: 대형 ``$MFT``·``$UsnJrnl``에서 05단계로 넘어가기도 전에 디스크와 메모리
#: 비용이 커지므로, 임계치를 넘는 것만 하드 컷으로 바꾼다.
#:
#: **임의로 잡은 값이다.** 실제 대형 증거로 대조한 적이 없다 —
#: ``docs/limitations.md`` 참고.
DEFAULT_LARGE_ARTIFACT_BYTES = 100 * 1024 * 1024  # 100MB

#: 아티팩트 이름 → ``04_parsed/`` 안의 파일명.
OUTPUT_FILENAMES: dict[str, str] = {
    "$MFT": "mft.jsonl",
    "$UsnJrnl": "usnjrnl.jsonl",
    "evtx:Security": "evtx_security.jsonl",
    "evtx:System": "evtx_system.jsonl",
    "evtx:Firewall": "evtx_firewall.jsonl",
    "evtx:BITS": "evtx_bits.jsonl",
    "evtx:NetworkProfile": "evtx_networkprofile.jsonl",
    "evtx:Sysmon": "evtx_sysmon.jsonl",
    "evtx:DriverFrameworks": "evtx_driverframeworks.jsonl",
    "evtx:KernelPnP": "evtx_kernelpnp.jsonl",
    "evtx:AssignedAccess": "evtx_assignedaccess.jsonl",
    "evtx:AssignedAccessAdmin": "evtx_assignedaccess_admin.jsonl",
    "evtx:AssignedAccessBroker": "evtx_assignedaccessbroker.jsonl",
    "evtx:RDPConnection": "evtx_rdp_connection.jsonl",
    "evtx:RDPSession": "evtx_rdp_session.jsonl",
    "evtx:Application": "evtx_application.jsonl",
    "registry:SYSTEM": "registry_system.jsonl",
    "registry:SOFTWARE": "registry_software.jsonl",
    "registry:Amcache": "registry_amcache.jsonl",
    "recentfilecache": "recentfilecache.jsonl",
    "prefetch": "prefetch.jsonl",
    # SRUM 은 공급자 테이블마다 아티팩트가 하나다. 셋이 같은 SRUDB.dat 를
    # 읽지만 파일은 따로 낸다 — ref 접두어가 다르고, 06단계가 파일별로
    # 대조하기 때문이다.
    "srum:NetworkUsage": "srum_networkusage.jsonl",
    "srum:AppResourceUsage": "srum_appresourceusage.jsonl",
    "srum:NetworkConnectivity": "srum_networkconnectivity.jsonl",
}

#: 합집합으로 넓히는 범위 키. 여기 없는 키는 첫 값을 쓴다.
UNION_KEYS = ("path_prefix", "extensions", "event_ids")


def merge_scopes(scopes: list[dict[str, Any]]) -> dict[str, Any]:
    """같은 아티팩트에 대한 여러 scope를 하나로 합친다.

    **좁히지 않고 넓힌다.** 두 기법이 각각 다른 경로를 요구하면 둘 다
    읽어야 한다. 교집합을 취하면 한 기법의 증거를 놓치는데, 그것이
    선별 방식의 가장 큰 리스크다.

    ``time_range``는 가장 이른 시작과 가장 늦은 끝으로 넓힌다.
    """
    merged: dict[str, Any] = {}

    for key in UNION_KEYS:
        values: list[Any] = []
        for scope in scopes:
            values.extend(scope.get(key, []))
        if values:
            merged[key] = list(dict.fromkeys(values))

    starts = [s["time_range"]["start"] for s in scopes if s.get("time_range")]
    ends = [s["time_range"]["end"] for s in scopes if s.get("time_range")]
    if starts and ends:
        # ISO 8601 UTC Z 표기는 문자열 정렬이 곧 시간 정렬이다.
        merged["time_range"] = {"start": min(starts), "end": max(ends)}

    return merged


def group_by_artifact(selection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """``selected``를 아티팩트별로 묶는다.

    같은 아티팩트가 여러 번 나올 수 있다. 03단계가 기법마다 "왜 필요한지"를
    보존하려고 합치지 않기 때문이다. 같은 파일을 두 번 파싱하지 않도록
    여기서 묶는다. ``docs/mapping-guide.md``에 적힌 04단계 계약이다.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in selection.get("selected", []):
        grouped.setdefault(entry["artifact"], []).append(entry.get("scope") or {})
    return {artifact: merge_scopes(scopes) for artifact, scopes in grouped.items()}


def write_manifest(
    out_dir: Path,
    case_id: str,
    files: list[dict[str, Any]],
    implementation: str = "native",
    skipped: "list[dict[str, Any]] | None" = None,
    windows: "dict[str, Any] | None" = None,
) -> Path:
    """``_manifest.json``을 쓴다.

    ``record_count``는 실제 줄 수와 반드시 같아야 한다. 이 값으로
    "몇 건을 읽었는가"를 보고하고, 테스트가 파일과 대조한다.

    ``generator``에 어느 파서 구현으로 돌렸는지 남긴다. 참조 구현은
    임시이므로, 산출물만 보고 구분할 수 있어야 한다.

    **``skipped``는 읽지 못한 아티팩트다.** 매니페스트는 이 단계가 자기가
    한 일을 적는 곳이므로 "안 한 일"도 여기 적는다. 예전에는 이것이
    ``errors.jsonl``에만 남아 07단계가 볼 수 없었고, 그 결과 보고서가
    **읽지 못한 아티팩트를 언급조차 하지 않았다**(docs/limitations.md 4-1).

    ``windows``는 증거가 어느 Windows인가다(``osinfo``). 판정에 실패해도
    키는 남는다 — ``{"determined": false, "reason": ...}``. "키가 없다"와
    "못 정했다"는 다르고, 07단계가 그 차이를 보고서에 적는다.
    """
    manifest = io.new_document(
        case_id,
        STAGE,
        io.make_generator("parse.py", implementation),
        files=files,
        skipped=list(skipped or []),
        windows=dict(
            windows or {"determined": False, "reason": "판정을 시도하지 않았습니다"}
        ),
        total_records=sum(entry["record_count"] for entry in files),
        flagged_records=sum(entry["flagged_count"] for entry in files),
    )
    return io.write_json(out_dir / "_manifest.json", manifest)


def _already_parsed(out_dir: Path) -> bool:
    """건너뛸 수 있을 만큼 산출물이 갖춰져 있는가."""
    return (out_dir / "_manifest.json").is_file() and any(out_dir.glob("*.jsonl"))


class _Counter:
    """레코드를 흘려보내며 개수를 센다.

    스트리밍을 유지하려고 이렇게 합니다. 리스트로 모아서 세면 ``$MFT``
    수십만 건이 전부 메모리에 올라갑니다.
    """

    def __init__(self) -> None:
        self.total = 0
        self.flagged = 0
        self.pruned = 0

    def __call__(self, records: "Any") -> "Any":
        for record in records:
            self.total += 1
            if record.get("flags"):
                self.flagged += 1
            yield record


def _should_prune_outside_range(
    scope: Scope, size_bytes: int, *, threshold_bytes: int, enabled: bool
) -> bool:
    """이 아티팩트를 시간 범위로 하드 컷할지 정한다.

    시간 범위 자체가 없으면 컷할 기준이 없으므로 항상 ``False``다.
    """
    if not enabled or threshold_bytes < 0:
        return False
    if scope.start is None and scope.end is None:
        return False
    return size_bytes > threshold_bytes


def _drop_outside_range(records: "Any", counter: "_Counter") -> "Any":
    """``outside_time_range`` 가 붙은 레코드를 빼고 흘려보낸다.

    ``flagging.py``가 이미 판정을 끝낸 결과를 재사용한다 — 시간 범위의
    의미는 거기 한 곳에만 있어야 한다. 여기서는 "이번 실행에서 그 판정을
    내보낼지 뺄지"만 결정한다.
    """
    for record in records:
        if "outside_time_range" in (record.get("flags") or []):
            counter.pruned += 1
            continue
        yield record


def _records(
    parser: Any,
    source: evidence.EvidenceSource,
    artifact: str,
    scope: Scope,
) -> "Any":
    """아티팩트를 이루는 파일들을 차례로 열어 레코드를 흘려보낸다.

    대부분의 아티팩트는 파일이 하나라 이 반복이 한 번 돌고 끝납니다.
    프리패치만 폴더 안의 .pf 수만큼 돕니다. **두 경우를 한 경로로 다루는
    것이 요점입니다** — 파서는 자기가 몇 번째로 불렸는지 몰라도 되고,
    04단계는 아티팩트가 파일인지 폴더인지 몰라도 됩니다.

    파서가 ``source_path``를 들고 있으면 파일마다 채워 줍니다. 프리패치
    레코드가 원본 .pf 파일명을 남기는 데 씁니다.
    """
    wants_path = hasattr(parser, "source_path")
    for opened in source.open_all(artifact):
        if wants_path:
            parser.source_path = opened.path
        yield from parser.parse(opened.stream, scope)


def parse_artifact(
    artifact: str,
    scope_dict: dict[str, Any],
    source: evidence.EvidenceSource,
    out_dir: Path,
    *,
    implementation: str = "native",
    large_artifact_bytes: int = DEFAULT_LARGE_ARTIFACT_BYTES,
    prune_large_artifacts: bool = True,
) -> dict[str, Any]:
    """아티팩트 하나를 파싱해 JSONL로 쓰고 매니페스트 항목을 돌려준다.

    파서가 만든 레코드에 ``flagging``이 플래그를 붙인 뒤 기록됩니다.
    파서는 플래그를 신경 쓰지 않아도 됩니다.

    파일이 ``large_artifact_bytes``보다 크고 시간 범위가 지정돼 있으면,
    ``outside_time_range`` 로 판정된 레코드를 아예 빼고 기록합니다(하드
    컷). 그 밖에는 기존과 같이 전부 내보내고 플래그만 붙입니다(소프트).
    ``prune_large_artifacts=False``로 끄면 크기와 무관하게 항상 소프트
    방식입니다.
    """
    parser = parsers.get(artifact, implementation)
    if parser is None:
        other = "reference" if implementation == "native" else "native"
        hint = (
            f" (참조 구현으로는 가능: --parser {other})"
            if parsers.get(artifact, other) is not None
            else ""
        )
        raise LookupError(
            f"{artifact}: {implementation} 파서가 등록되지 않았습니다"
            f"{hint}. src/stage04_parse/parsers/__init__.py 참조."
        )

    # $MFT에는 드라이브 문자가 없다. 한 실행은 한 볼륨이므로 증거 경로에서
    # 유추해 넘긴다. 경로 접두어 비교가 이 값에 의존한다. 프리패치도
    # 같은 값을 쓴다 — 장치 경로를 드라이브 문자로 바꿀 때다.
    if hasattr(parser, "volume_letter"):
        parser.volume_letter = evidence.volume_letter(source)

    # 폴더 단위 아티팩트는 parse() 가 파일마다 불린다. 파서가 호출 사이에
    # 들고 있는 집계와 ref 중복 감시를 여기서 비운다.
    begin = getattr(parser, "begin_artifact", None)
    if begin is not None:
        begin()

    located = source.locate(artifact)
    files_read = len(source.locate_all(artifact))
    scope = Scope.from_selection(scope_dict)
    filename = OUTPUT_FILENAMES[artifact]
    counter = _Counter()

    # 폴더 단위 아티팩트는 located.path 가 폴더라 st_size 가 디렉터리
    # 엔트리 크기다. 즉 하드 컷이 사실상 걸리지 않는데, 이 임계치가 겨냥한
    # 것이 $MFT·$J 처럼 파일 하나가 수십~수백 MB 인 경우라 그대로 둔다.
    size_bytes = located.path.stat().st_size if located is not None else 0
    prune = _should_prune_outside_range(
        scope, size_bytes, threshold_bytes=large_artifact_bytes, enabled=prune_large_artifacts
    )

    records = flagging.apply_all(_records(parser, source, artifact, scope), scope)
    if prune:
        records = _drop_outside_range(records, counter)
    written = io.write_jsonl(out_dir / filename, counter(records))

    # 파서가 집계를 내놓으면 받는다. 읽지 못하고 건너뛴 구간이 있는데
    # 매니페스트에 0으로 남으면, 저널의 빈 구간을 "아무 일도 없었다"로
    # 읽게 된다. 집계를 내놓지 않는 파서는 0이다.
    stats = getattr(parser, "stats", None) or {}
    entry: dict[str, Any] = {
        "artifact": artifact,
        "path": filename,
        "record_count": written,
        "flagged_count": counter.flagged,
        "parse_errors": int(stats.get("parse_errors", 0)),
    }
    if stats.get("unreadable_bytes"):
        # 구간 수(parse_errors)만으로는 규모를 알 수 없다. 구간 1곳이
        # 8바이트인 것과 500KB인 것은 판단이 다르다.
        entry["unreadable_bytes"] = int(stats["unreadable_bytes"])
    if prune:
        # 대형 아티팩트라 시간 범위 밖 레코드를 하드 컷했다는 사실 자체를
        # 남긴다. 0건을 뺐어도 "이번 실행은 하드 컷 모드였다"는 정보다 —
        # 조용히 넘어가면 나중에 소프트 방식과 결과를 비교할 수 없다.
        entry["time_range_pruned_count"] = counter.pruned
    if files_read > 1:
        # 폴더 단위 아티팩트다. source_path 는 폴더를 가리키므로 그 안에서
        # 몇 개를 열었는지가 따로 있어야 한다 — "프리패치 3건"이 파일이
        # 세 개뿐이었다는 뜻인지 73개 중 3개만 범위에 들었다는 뜻인지
        # 산출물만 보고 갈릴 수 있어야 한다.
        entry["source_file_count"] = files_read
    if located is not None:
        # 어느 파일에서 읽었는지 남긴다. 나중에 "이 결과가 어디서 나왔나"를
        # 되짚을 수 있어야 하고, method가 search면 제자리에 없던 것이므로
        # 한 번 확인해 볼 값이다.
        entry["source_path"] = str(located.path)
        entry["source_method"] = located.method
        if located.alternates:
            entry["source_alternates"] = [str(p) for p in located.alternates]
        if located.empty_candidates:
            # 0바이트라 건너뛴 후보. 추출이 잘못됐다는 진단이므로 산출물에
            # 남긴다 — 같은 증거를 다시 뽑을 때 고쳐야 할 지점이다.
            entry["source_empty_skipped"] = [str(p) for p in located.empty_candidates]
    return entry


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.stage04_parse.parse",
        description="선별된 아티팩트의 지정 범위만 파싱한다.",
    )
    parser.add_argument("--in", dest="in_path", required=True, help="03_selection.json 경로")
    parser.add_argument("--out", required=True, help="04_parsed/ 출력 디렉터리")
    parser.add_argument("--evidence", required=True, help="증거 루트 경로(볼륨 폴더 또는 디스크 이미지 파일)")
    parser.add_argument(
        "--volume",
        type=int,
        default=None,
        help=(
            "디스크 이미지에 NTFS가 여럿일 때 열 볼륨 번호. 지정하지 않으면 "
            "후보를 보여 주고 멈춘다 — 도구가 추측하지 않는다"
        ),
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="산출물이 이미 있으면 건너뛴다. 파싱이 가장 오래 걸리므로 실험 반복에 필수",
    )
    parser.add_argument(
        "--parser",
        choices=parsers.IMPLEMENTATIONS,
        default="native",
        help=(
            "파서 구현. 기본 %(default)s. $MFT 메인 파서는 parsers/mft.py"
            "(analyzeMFT 기반)이며 native/reference 양쪽에서 동일하게 쓰인다"
        ),
    )
    parser.add_argument("--errors", default=None)
    parser.add_argument(
        "--large-artifact-mb",
        type=float,
        default=DEFAULT_LARGE_ARTIFACT_BYTES / (1024 * 1024),
        help=(
            "이 크기(MB)를 넘는 아티팩트는 시간 범위 밖 레코드를 하드 컷한다. "
            "기본 %(default)s MB. 임의로 잡은 값이니 실측 후 조정할 것 "
            "(docs/limitations.md)"
        ),
    )
    parser.add_argument(
        "--no-time-range-prune",
        action="store_true",
        help="크기와 무관하게 항상 소프트 방식(outside_time_range 플래그만)을 쓴다",
    )
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    io.configure_console()
    args = _parse_args(argv)
    out_dir = Path(args.out)
    log = errlog.ErrorLog(Path(args.errors) if args.errors else out_dir.parent / "errors.jsonl")

    selection = io.read_json(args.in_path)
    try:
        io.check_header(selection, expected_stage="03_select")
        schema.validate(selection, "selection")
    except schema.SchemaViolation as violation:
        log.abort(STAGE, "schema_violation", violation.as_detail())
    except io.HeaderError as e:
        log.abort(STAGE, "schema_violation", {"field": "<header>", "message": str(e)})

    targets = group_by_artifact(selection)

    if args.skip_existing and _already_parsed(out_dir):
        print(
            f"{out_dir}: 이미 산출물이 있어 건너뜀 "
            f"({', '.join(sorted(targets))} 요청됨, --skip-existing)"
        )
        return 0

    unsupported = sorted(set(targets) - set(OUTPUT_FILENAMES))
    if unsupported:
        log.abort(
            STAGE,
            "parse_error",
            {
                "message": (
                    f"출력 파일명이 정의되지 않은 아티팩트: {', '.join(unsupported)}. "
                    "OUTPUT_FILENAMES에 추가한다."
                )
            },
        )

    try:
        source = evidence.open_source(args.evidence, volume=args.volume)
    except evidence.NotAVolumeRoot as e:
        # 사용자 입력 문제다. 안내를 그대로 보여 주고 errors.jsonl은
        # 건드리지 않는다 — 파이프라인 실패 통계에 섞을 일이 아니다.
        print(f"[{STAGE}] {e}", file=sys.stderr)
        return 2
    except evidence.EvidenceError as e:
        log.abort(STAGE, "parse_error", {"message": str(e)})

    # 증거가 어느 Windows인가. **실패해도 계속 간다** — 판정은 파싱의
    # 전제가 아니라 "이 버전엔 원래 없다"를 가리기 위한 보조 정보다.
    # 사유는 매니페스트에 남고, 못 정하면 가용성 판정을 아예 하지 않는다
    # (osinfo 모듈 docstring "모르면 거르지 않는다").
    try:
        version: "osinfo.WindowsVersion | None" = osinfo.detect(source)
        windows_note = version.as_manifest()
        # flush 하는 이유는 바로 뒤에 stderr 로 나가는 "버전 미해당"이
        # 있기 때문이다. 버퍼에 남으면 사유가 판정보다 먼저 찍혀, 무엇을
        # 근거로 뺐는지가 콘솔에서 거꾸로 보인다.
        print(f"[{STAGE}] Windows 판정 — {version.describe()}", flush=True)
        if not version.known:
            print(
                f"[{STAGE}] 아는 빌드 구간에 없습니다 (빌드 {version.build}). "
                "버전별 가용성 판정을 건너뜁니다.",
                file=sys.stderr,
            )
    except osinfo.VersionUndetermined as e:
        # ``errors.jsonl``에는 남기지 않는다. 저 로그는 **아티팩트 단위**
        # 실패의 집계이고 발표 통계의 출처인데(``common/errors.py``),
        # 버전 판정은 아티팩트가 아니다. 섞으면 "못 읽은 아티팩트 수"가
        # 부풀고 어느 쪽이 진짜인지 모르게 된다. ``NotAVolumeRoot``가 같은
        # 이유로 이미 그 로그를 건드리지 않는다.
        #
        # 조용히 넘어가는 것도 아니다 — 사유가 stderr와 매니페스트
        # ``windows.reason`` 양쪽에 남고, 07단계가 그것을 보고서에 싣는다.
        version = None
        windows_note = {"determined": False, "reason": str(e)}
        print(f"[{STAGE}] Windows 버전 판정 불가 — {e}", file=sys.stderr)

    files: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    def note_skip(artifact: str, reason: str, message: str, label: str) -> None:
        """읽지 못한 아티팩트를 **두 곳에** 남긴다.

        ``errors.jsonl``은 전 단계가 공유하는 집계용 로그이고,
        ``_manifest.json``은 07단계가 읽는 이 단계의 산출물이다. 예전에는
        앞엣것만 있어서 보고서가 스킵을 알지 못했다.
        """
        log.record(
            STAGE,
            "empty_result",
            {"field": "selected[].artifact", "value": artifact, "message": message},
            action="skip",
        )
        skipped.append({"artifact": artifact, "reason": reason, "message": message})
        print(f"[{STAGE}] {label} — {message}", file=sys.stderr)

    large_artifact_bytes = int(args.large_artifact_mb * 1024 * 1024)
    for artifact, scope_dict in sorted(targets.items()):
        # **증거를 열기 전에** 판정한다. 이 버전에 존재할 수 없는
        # 아티팩트를 찾아 헤매다 artifact_not_found 로 적으면, 보고서가
        # "수집 누락"이라고 말하게 된다 — 분석가는 있지도 않은 파일을
        # 다시 뽑으러 간다.
        not_applicable = osinfo.applicability(artifact, version)
        if not_applicable:
            note_skip(artifact, "version_not_applicable", not_applicable, "버전 미해당")
            continue
        try:
            entry = parse_artifact(
                artifact,
                scope_dict,
                source,
                out_dir,
                implementation=args.parser,
                large_artifact_bytes=large_artifact_bytes,
                prune_large_artifacts=not args.no_time_range_prune,
            )
        except LookupError as e:
            # 파서 미구현. 실패가 아니라 지원 범위 밖이며, 보고서의
            # "분석 범위 한계"로 이어져야 할 정보다.
            note_skip(artifact, "parser_missing", str(e), "건너뜀")
            continue
        except evidence.EmptyArtifact as e:
            # 파일은 있는데 0바이트다. "수집 안 됨"과 조치가 다르므로 나눈다.
            note_skip(artifact, "empty_artifact", str(e), "빈 파일")
            continue
        except evidence.ArtifactNotFound as e:
            # 선별은 요청했는데 증거에 없다. 수집 누락이다.
            note_skip(artifact, "artifact_not_found", str(e), "증거 없음")
            continue
        except io.JsonlEncodeError as e:
            # 산출물을 UTF-8 로 쓸 수 없다. 아래 ValueError 절이 삼키면
            # "어느 레코드인가"가 사라지므로 **앞에** 둔다.
            #
            # 파서가 이런 값을 내보내지 않는 것이 1차이고(예:
            # parsers/usnjrnl.py 의 _encodable_name), 여기까지 왔다는 것은
            # 아직 안 걸러진 경로가 있다는 뜻이다. 조용히 넘기면 아티팩트가
            # 통째로 사라진 채 이유가 안 남는다.
            log.abort(STAGE, "malformed_output", {"artifact": artifact, **e.as_detail()})
        except (OSError, ValueError) as e:
            log.abort(STAGE, "parse_error", {"value": artifact, "message": str(e)})

        files.append(entry)
        pruned_note = (
            f", 시간범위 하드컷 {entry['time_range_pruned_count']}건 제외"
            if "time_range_pruned_count" in entry
            else ""
        )
        print(
            f"  {artifact}: {entry['record_count']}건 "
            f"(플래그 {entry['flagged_count']}건{pruned_note}) → {entry['path']}"
        )

    if not files:
        log.abort(
            STAGE,
            "empty_result",
            {
                "message": (
                    f"파싱된 아티팩트가 없습니다 (요청: {', '.join(sorted(targets))}). "
                    f"등록된 {args.parser} 파서: "
                    f"{', '.join(parsers.registered(args.parser)) or '없음'}. "
                    f"참조 구현: {', '.join(parsers.registered('reference')) or '없음'}. "
                    f"목업으로 관통 실행하려면 {out_dir} 에 산출물을 넣고 "
                    "--skip-existing 을 붙이십시오."
                )
            },
        )

    write_manifest(
        out_dir,
        selection["case_id"],
        files,
        implementation=args.parser,
        skipped=skipped,
        windows=windows_note,
    )
    # native/reference 는 $MFT 에 한해 같은 인스턴스를 가리킨다. 산출물만
    # 보고 어느 쪽으로 돌렸는지 구분할 수 있게 매니페스트에는 남기되,
    # 콘솔에서 다른 파서인 것처럼 보이게 하지는 않는다.
    note = " — native와 동일" if args.parser == "reference" else ""
    print(
        f"{out_dir}: {len(files)}개 아티팩트, "
        f"총 {sum(f['record_count'] for f in files)}건 "
        f"(증거: {source.describe()}, 파서: {args.parser}{note})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
