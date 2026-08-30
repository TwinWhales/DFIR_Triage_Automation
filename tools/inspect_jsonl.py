"""04단계 산출물을 빠르게 들여다본다 — 요약과 조회, 그리고 대조.

``04_parsed/``는 파일이 스무 개가 넘고 `$MFT`·`$UsnJrnl`은 수십 MB다.
"뭐가 몇 건 나왔나", "이 경로가 걸린 레코드가 있나"를 보려고 매번 파이썬을
한 줄씩 짜게 되는데, 팀 기계는 Windows라 ``jq``가 있다고 가정할 수도 없다.

## 요약은 매니페스트를 믿지 않는다

``_manifest.json``이 "몇 건을 읽었다"고 적고, 07단계 보고서가 그 값을
싣는다. **그런데 실물 실행에서 그 값이 파일과 같은지 아무도 보지 않는다.**
벤치마크 데이터셋은 테스트가 대조하지만(``test_benchmark``), 60GB 이미지를
돌린 결과는 대조 상대가 없다.

그래서 이 도구는 매니페스트를 요약에 그대로 옮기지 않고 **파일을 세어
맞춰 본다.** 넷을 본다.

1. 매니페스트의 ``record_count`` = 실제 줄 수
2. ``ref``가 파일들 사이에서 유일한가 — 겹치면 05·06단계가 선다
   (``io.read_parsed_records``의 ``DuplicateRefError``). **05단계에 가서
   터지는 것과 04 직후에 아는 것은 다르다**
3. ``record_num``이 ``ref``의 숫자 부분과 같은가 — 스키마가 보지 않는
   불변식이다(``parsed_record.schema.json``의 ``record_num`` 설명)
4. 레코드의 ``artifact``가 그 파일이 맡은 아티팩트인가 — 파서가 남의
   파일에 쓰면 06단계가 그것을 환각으로 집계한다

**하나라도 어긋나면 종료 코드가 1이다.**

## 조회는 읽기만 한다

거르고 보여 줄 뿐 고치거나 다시 계산하지 않는다. 원본 바이트가 필요하면
``tools/hexdump_record.py``로 넘긴다 — 여기서 흉내 내면 진실이 둘이 된다.

메모리도 05·06단계처럼 쓰지 않는다. ``io.read_parsed_records``는 전부
``ref``로 색인해 들고 있는데, 그건 두 단계가 대조를 해야 해서다. 여기서는
줄을 흘려보내며 ``ref`` 문자열만 모은다.

## 사용법

::

    # 요약 + 대조 (기본)
    .venv/Scripts/python.exe tools/inspect_jsonl.py --parsed cases/K-ALERT/04_parsed

    # 레코드 하나를 펼쳐 본다
    .venv/Scripts/python.exe tools/inspect_jsonl.py --parsed <04_parsed> --ref MFT#12345

    # 걸러 보기 — 조건은 AND 로 묶인다
    .venv/Scripts/python.exe tools/inspect_jsonl.py --parsed <04_parsed> \\
        --flag deleted --path "\\\\Users\\\\Public" --limit 5

    # 파이프로 넘길 때는 레코드 원문 그대로
    .venv/Scripts/python.exe tools/inspect_jsonl.py --parsed <04_parsed> \\
        --artifact '$UsnJrnl' --flag file_created --json
"""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common import io as _io  # noqa: E402
from src.common import refs  # noqa: E402
from src.stage04_parse.parse import OUTPUT_FILENAMES  # noqa: E402

__all__ = [
    "InspectError",
    "display_width",
    "Summary",
    "Filters",
    "summarize",
    "select",
    "artifact_of_file",
    "main",
]

#: 어긋난 것을 몇 건까지 보여 줄 것인가. 나머지는 수로 남긴다 —
#: 수만 건이면 콘솔을 덮는다(``parsers/mft.py``의 fixup 경고와 같은 규약).
MAX_VIOLATIONS_SHOWN = 5

#: 조회 기본 표시 건수.
DEFAULT_LIMIT = 20

#: 요약의 플래그 분포에서 보여 줄 개수.
TOP_FLAGS = 12

#: 출력 파일명 → 아티팩트. ``OUTPUT_FILENAMES``의 역방향이다.
FILE_ARTIFACT: dict[str, str] = {v: k for k, v in OUTPUT_FILENAMES.items()}


class InspectError(RuntimeError):
    """들여다볼 수 없다. 사유를 그대로 사람에게 보인다."""


@dataclass
class ArtifactSummary:
    """파일 하나에서 실제로 센 것."""

    artifact: str
    filename: str
    records: int = 0
    flagged: int = 0
    flags: Counter = field(default_factory=Counter)
    earliest: "str | None" = None
    latest: "str | None" = None
    #: ``timestamp`` 키가 없던 레코드. `$MFT`는 전부 여기 들어간다 —
    #: 시각이 ``si_*``/``fn_*``에 있어서지 시각이 없어서가 아니다.
    without_timestamp: int = 0
    #: 매니페스트가 적은 값. 없으면 ``None``.
    manifest_count: "int | None" = None


@dataclass
class Summary:
    """요약 한 판."""

    directory: Path
    artifacts: "list[ArtifactSummary]" = field(default_factory=list)
    header: "dict[str, Any]" = field(default_factory=dict)
    skipped: "list[dict[str, Any]]" = field(default_factory=list)
    violations: "list[str]" = field(default_factory=list)
    violation_count: int = 0
    manifest_found: bool = False

    @property
    def records(self) -> int:
        return sum(a.records for a in self.artifacts)

    @property
    def flagged(self) -> int:
        return sum(a.flagged for a in self.artifacts)

    def note(self, message: str) -> None:
        """어긋난 것을 하나 적는다. 앞의 몇 건만 보이고 나머지는 센다."""
        self.violation_count += 1
        if len(self.violations) < MAX_VIOLATIONS_SHOWN:
            self.violations.append(message)


@dataclass(frozen=True)
class Filters:
    """조회 조건. **AND로 묶인다.**

    OR를 만들지 않는 이유는 하나다 — "왜 이 레코드가 나왔나"를 조건만 보고
    말할 수 있어야 한다. 여러 조건을 섞어 봐야 하면 두 번 돌린다.
    """

    ref: "str | None" = None
    artifact: "str | None" = None
    flags: tuple[str, ...] = ()
    path: "str | None" = None
    name: "str | None" = None
    event_ids: tuple[int, ...] = ()

    def matches(self, record: "dict[str, Any]") -> bool:
        if self.ref is not None and record.get("ref") != self.ref:
            return False
        if self.artifact is not None and record.get("artifact") != self.artifact:
            return False
        if self.flags:
            present = set(record.get("flags") or ())
            if not present.issuperset(self.flags):
                return False
        if self.path is not None and self.path.lower() not in str(record.get("path") or "").lower():
            return False
        if self.name is not None and self.name.lower() not in str(record.get("name") or "").lower():
            return False
        if self.event_ids and record.get("event_id") not in self.event_ids:
            return False
        return True

    @property
    def empty(self) -> bool:
        return not any(
            (self.ref, self.artifact, self.flags, self.path, self.name, self.event_ids)
        )


# =============================================================== 읽기


def artifact_of_file(path: Path) -> "str | None":
    """``mft.jsonl`` → ``$MFT``. 04단계가 낸 파일이 아니면 ``None``."""
    return FILE_ARTIFACT.get(path.name)


def _jsonl_files(directory: Path) -> "list[Path]":
    if not directory.is_dir():
        raise InspectError(f"04_parsed 디렉터리가 아니다: {directory}")
    files = sorted(directory.glob("*.jsonl"))
    if not files:
        raise InspectError(f"{directory} 에 .jsonl 이 없다 (04단계를 돌린 적이 없다)")
    return files


def _read_manifest(directory: Path) -> "dict[str, Any] | None":
    path = directory / "_manifest.json"
    if not path.is_file():
        return None
    try:
        return _io.read_json(path)
    except Exception as e:  # noqa: BLE001 - 손상된 매니페스트가 요약을 막지 않게 한다
        raise InspectError(f"{path} 를 읽지 못했다 — {e}") from None


def summarize(directory: Path) -> Summary:
    """파일을 실제로 세고 매니페스트와 맞춰 본다."""
    summary = Summary(directory=directory)
    manifest = _read_manifest(directory)
    counts: dict[str, int] = {}

    if manifest is not None:
        summary.manifest_found = True
        summary.header = {
            key: manifest.get(key)
            for key in ("case_id", "stage", "generated_at", "generator")
            if manifest.get(key)
        }
        summary.header["windows"] = manifest.get("windows") or {}
        summary.skipped = list(manifest.get("skipped") or [])
        counts = {
            str(entry.get("path")): int(entry.get("record_count", 0))
            for entry in manifest.get("files") or []
        }

    seen: dict[str, str] = {}
    for path in _jsonl_files(directory):
        artifact = artifact_of_file(path)
        if artifact is None:
            # 04단계가 내지 않는 파일이다. 조용히 세면 합계가 오염된다.
            summary.note(f"{path.name}: 04단계가 내는 파일 이름이 아니다")
            continue
        entry = ArtifactSummary(
            artifact=artifact, filename=path.name, manifest_count=counts.get(path.name)
        )
        _count_file(path, entry, summary, seen)
        summary.artifacts.append(entry)

    _check_manifest_totals(manifest, summary)
    return summary


def _count_file(
    path: Path, entry: ArtifactSummary, summary: Summary, seen: "dict[str, str]"
) -> None:
    for record in _io.read_jsonl(path):
        entry.records += 1
        flags = record.get("flags") or []
        if flags:
            entry.flagged += 1
            entry.flags.update(flags)

        moment = record.get("timestamp")
        if isinstance(moment, str) and moment:
            # ISO 8601 UTC Z 표기는 문자열 정렬이 곧 시간 정렬이다
            # (``parse.py``의 ``merge_scopes``와 같은 근거).
            if entry.earliest is None or moment < entry.earliest:
                entry.earliest = moment
            if entry.latest is None or moment > entry.latest:
                entry.latest = moment
        else:
            entry.without_timestamp += 1

        ref = record.get("ref")
        if not isinstance(ref, str):
            summary.note(f"{path.name}: ref 없는 레코드가 있다")
            continue
        if ref in seen:
            summary.note(f"{ref} 가 {seen[ref]} 와 {path.name} 양쪽에 있다")
        else:
            seen[ref] = path.name

        if record.get("artifact") != entry.artifact:
            summary.note(
                f"{ref}: artifact 가 {record.get('artifact')!r} 인데 "
                f"{path.name} 은 {entry.artifact} 의 파일이다"
            )
        try:
            if refs.record_num_of(ref) != record.get("record_num"):
                summary.note(
                    f"{ref}: record_num 이 {record.get('record_num')!r} 로 ref 와 다르다"
                )
        except refs.RefError as e:
            summary.note(f"{path.name}: {e}")

    if entry.manifest_count is not None and entry.manifest_count != entry.records:
        summary.note(
            f"{entry.filename}: 매니페스트는 {entry.manifest_count:,}건인데 "
            f"실제 줄 수는 {entry.records:,}건이다"
        )


def _check_manifest_totals(manifest: "dict[str, Any] | None", summary: Summary) -> None:
    """매니페스트의 합계도 본다. 07단계 보고서가 싣는 값이다."""
    if manifest is None:
        return
    total = manifest.get("total_records")
    if isinstance(total, int) and total != summary.records:
        summary.note(
            f"매니페스트 total_records 가 {total:,} 인데 실제 합계는 {summary.records:,} 다"
        )
    flagged = manifest.get("flagged_records")
    if isinstance(flagged, int) and flagged != summary.flagged:
        summary.note(
            f"매니페스트 flagged_records 가 {flagged:,} 인데 실제 합계는 {summary.flagged:,} 다"
        )

    # 매니페스트에는 있는데 파일이 없는 경우. 반대는 위에서 걸린다.
    on_disk = {a.filename for a in summary.artifacts}
    for record in manifest.get("files") or []:
        name = str(record.get("path"))
        if name not in on_disk:
            summary.note(f"매니페스트가 {name} 을 적었는데 파일이 없다")


def select(directory: Path, filters: Filters, limit: int) -> "Iterator[dict[str, Any]]":
    """조건에 맞는 레코드를 흘려보낸다. ``limit``에서 멈추지 않는다.

    센 김에 끊지 않는 이유는 **"5건 표시 (총 128건 일치)"** 를 말하기
    위해서다. 몇 건인지 모르면 표본을 봤는지 전부를 봤는지 갈리지 않는다.
    """
    files = _jsonl_files(directory)
    if filters.ref is not None:
        # ref 의 접두어가 어느 파일인지 이미 말해 준다(``refs.py``).
        wanted = OUTPUT_FILENAMES.get(refs.artifact_of(filters.ref))
        files = [p for p in files if p.name == wanted] or files
    if filters.artifact is not None:
        wanted = OUTPUT_FILENAMES.get(filters.artifact)
        files = [p for p in files if p.name == wanted] or files

    for path in files:
        for record in _io.read_jsonl(path):
            if filters.matches(record):
                yield record


# =============================================================== 출력


def display_width(text: str) -> int:
    """터미널에서 차지하는 칸 수. 한글·한자는 두 칸이다.

    ``str.ljust``는 코드 포인트를 세므로 한글이 섞인 표가 어긋납니다.
    아티팩트 이름은 ASCII 인데 머리글이 한글이라 이 표에서는 항상 섞입니다.
    """
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def pad(text: str, width: int) -> str:
    """``display_width`` 기준으로 오른쪽을 채운다."""
    return text + " " * max(0, width - display_width(text))


def _print_summary(summary: Summary) -> None:
    print(f"04_parsed 요약 — {summary.directory}")
    header = summary.header
    if header:
        line = " · ".join(
            str(header[key]) for key in ("case_id", "stage", "generated_at", "generator") if key in header
        )
        print(f"  {line}")
        windows = header.get("windows") or {}
        if windows.get("determined"):
            print(f"  {windows.get('name') or windows.get('family')} (빌드 {windows.get('build')})")
        elif windows:
            print(f"  Windows 판정 실패 — {windows.get('reason')}")
    elif not summary.manifest_found:
        print("  _manifest.json 이 없다 — 파일만 세고 매니페스트 대조는 건너뛴다")
    print()

    width = max([display_width(a.artifact) for a in summary.artifacts] + [display_width("아티팩트")])
    print(f"  {pad('아티팩트', width)}  {'레코드':>8}  {'플래그':>8}  시간 범위")
    for entry in sorted(summary.artifacts, key=lambda a: a.artifact):
        if entry.earliest and entry.latest:
            span = f"{entry.earliest[:10]} … {entry.latest[:10]}"
            if entry.without_timestamp:
                span += f"  (시각 없는 레코드 {entry.without_timestamp:,}건)"
        else:
            span = "timestamp 필드 없음"
        print(
            f"  {pad(entry.artifact, width)}  {entry.records:>10,}  {entry.flagged:>10,}  {span}"
        )
    print(f"  {pad('합계', width)}  {summary.records:>10,}  {summary.flagged:>10,}")

    flags: Counter = Counter()
    for entry in summary.artifacts:
        flags.update(entry.flags)
    if flags:
        print(f"\n  플래그 분포 (전체 {len(flags)}종)")
        for name, count in flags.most_common(TOP_FLAGS):
            print(f"    {name:<32} {count:>10,}")
        if len(flags) > TOP_FLAGS:
            print(f"    … 나머지 {len(flags) - TOP_FLAGS}종")

    if summary.skipped:
        print(f"\n  읽지 못한 아티팩트 {len(summary.skipped)}종")
        for item in summary.skipped:
            print(f"    {item.get('artifact')} — {item.get('reason')}: {item.get('message', '')}")


def _print_violations(summary: Summary) -> bool:
    """대조 결과. 통과했으면 참."""
    print("\n  대조")
    if not summary.violation_count:
        checks = [
            "매니페스트 record_count = 실제 줄 수" if summary.manifest_found else None,
            f"ref 유일 ({summary.records:,}건)",
            "record_num = ref 의 숫자",
            "레코드의 artifact = 그 파일의 아티팩트",
        ]
        for check in [c for c in checks if c]:
            print(f"    ✓ {check}")
        return True

    for message in summary.violations:
        print(f"    ✗ {message}")
    if summary.violation_count > len(summary.violations):
        print(f"    … 어긋난 것 {summary.violation_count - len(summary.violations)}건 더")
    return False


def _one_line(record: "dict[str, Any]") -> str:
    """레코드 하나를 한 줄로. 무엇을 보여 줄지는 아티팩트마다 다르다."""
    parts = [f"{record.get('ref')}", f"{record.get('artifact')}"]
    label = record.get("path") or record.get("name") or ""
    if label:
        parts.append(str(label))
    if record.get("event_id") is not None:
        parts.append(f"EID {record['event_id']}")
    moment = record.get("timestamp") or record.get("si_mtime")
    if moment:
        parts.append(str(moment))
    flags = record.get("flags") or []
    if flags:
        parts.append(f"[{','.join(flags)}]")
    return "  ".join(parts)


def _print_record(record: "dict[str, Any]") -> None:
    """``--ref`` 하나를 펼친다. 원본 바이트는 다른 도구로 넘긴다."""
    print(json.dumps(record, ensure_ascii=False, indent=2))
    print(
        f"\n원본 바이트: .venv/Scripts/python.exe tools/hexdump_record.py {record.get('ref')} "
        "--parsed <04_parsed> --evidence <증거> [--volume N]"
    )


# =============================================================== CLI


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python tools/inspect_jsonl.py",
        description="04단계 산출물을 요약하고 조회한다. 요약은 매니페스트를 파일과 맞춰 본다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "예:\n"
            "  inspect_jsonl.py --parsed cases/K-ALERT/04_parsed\n"
            "  inspect_jsonl.py --parsed <04_parsed> --ref MFT#12345\n"
            "  inspect_jsonl.py --parsed <04_parsed> --flag deleted --path Users\\\\Public\n"
        ),
    )
    parser.add_argument("--parsed", required=True, help="04_parsed 디렉터리")
    parser.add_argument("--ref", default=None, help="이 ref 하나를 펼쳐 본다")
    parser.add_argument("--artifact", default=None, help="이 아티팩트만 (예: '$MFT')")
    parser.add_argument(
        "--flag", action="append", default=[], metavar="FLAG", help="이 플래그가 붙은 것만 (반복 가능, AND)"
    )
    parser.add_argument("--path", default=None, help="path 에 이 문자열이 든 것만 (대소문자 무시)")
    parser.add_argument("--name", default=None, help="name 에 이 문자열이 든 것만 (대소문자 무시)")
    parser.add_argument(
        "--event-id", action="append", type=int, default=[], metavar="N", help="이 event_id 만 (반복 가능, OR)"
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"표시 건수 (기본 {DEFAULT_LIMIT})")
    parser.add_argument("--json", action="store_true", help="한 줄 요약 대신 레코드 원문을 줄마다 낸다")
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    _io.configure_console()
    args = _parse_args(argv)
    directory = Path(args.parsed)

    filters = Filters(
        ref=args.ref,
        artifact=args.artifact,
        flags=tuple(args.flag),
        path=args.path,
        name=args.name,
        event_ids=tuple(args.event_id),
    )

    try:
        if filters.empty:
            summary = summarize(directory)
            _print_summary(summary)
            return 0 if _print_violations(summary) else 1

        if args.artifact is not None and args.artifact not in OUTPUT_FILENAMES:
            # 이름 오타와 "그 아티팩트가 안 나왔다"는 조치가 다르다.
            print(
                f"--artifact {args.artifact!r} 는 04단계가 아는 이름이 아니다 "
                f"(예: {', '.join(sorted(OUTPUT_FILENAMES)[:3])} …)",
                file=sys.stderr,
            )
            return 1

        shown = 0
        matched = 0
        for record in select(directory, filters, args.limit):
            matched += 1
            if shown >= args.limit:
                continue
            shown += 1
            if args.ref is not None and not args.json:
                _print_record(record)
            elif args.json:
                print(json.dumps(record, ensure_ascii=False))
            else:
                print(_one_line(record))
    except (InspectError, refs.RefError, ValueError) as e:
        print(f"{e}", file=sys.stderr)
        return 1

    if matched == 0:
        # 없는 것은 정상 결과다. 종료 코드로 실패를 뜻하지 않는다.
        print("일치하는 레코드가 없다")
    elif matched > shown:
        print(f"\n{shown}건 표시 (총 {matched:,}건 일치)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
