"""우리 프리패치 파서 출력을 PECmd 결과와 대조한다.

프리패치는 이 저장소에서 **온디스크 구조까지 우리가 직접 구현한** 몇 안 되는
아티팩트입니다(``structs/prefetch_record.py``). 오프셋 하나가 어긋나도 형식은
멀쩡해서 스키마를 통과하고 06단계 검증도 통과합니다 — 레코드에 적힌 값과
문장이 일치하니까요. **파이프라인 안에서는 아무도 못 잡습니다.**

지금까지의 채점은 ``tools/scan_prefetch.py``, 즉 **같은 파일을 다른 경로로
읽는 우리 코드**였습니다. 그것은 메트릭 배열을 걷는 해석과 문자열 블록을
쪼개는 해석이 서로를 지지하는지만 봅니다. 실행 횟수·실행 시각처럼 **값 자체가
맞는지는 모릅니다.** ``(30, 212)`` 레이아웃을 정한 방법("1~7회 실행된 파일의
유효 시각 개수 == 실행 횟수")도 우리 코드 안에서 닫혀 있어, 우리 구현과
공통 오해를 공유합니다.

이 도구가 그 자리를 밖에서 채웁니다.

## 쓰는 법

PECmd 는 저장소에 넣지 않습니다. 바이너리라 ``third_party/`` 대상도 아닙니다::

    PECmd.exe -d "<수집본>\\C\\Windows\\Prefetch" --csv C:\\temp\\pecmd_out

    .venv/Scripts/python.exe -m src.stage04_parse.parse \\
        --in <범위를 비운 03_selection.json> --out cases/K-ALERT/04_parsed/ \\
        --evidence <수집본>/C

    .venv/Scripts/python.exe tools/compare_prefetch.py \\
        --ours cases/K-ALERT/04_parsed/prefetch.jsonl \\
        --pecmd C:\\temp\\pecmd_out --full

**``--in`` 의 범위를 비우십시오.** 우리 파서는 선별된 범위만 냅니다. 건수까지
대조하려면(``--full``) 폴더 전체를 내야 합니다. 범위를 준 출력에 ``--full`` 을
붙이면 "저쪽에만 있음"이 잔뜩 나오는데 그것은 파서의 오류가 아닙니다.

``--pecmd`` 는 디렉터리(``--csv`` 출력)도 파일도 받습니다. 디렉터리면
``*_PECmd_Output.csv`` 중 가장 최근 것을 씁니다 — ``_Timeline.csv`` 는 실행
시각을 한 줄씩 편 것이라 레코드 단위 대조에 쓰지 않습니다.

## 무엇으로 짝짓고 무엇을 채점하나

**짝은 .pf 파일 이름으로 짓습니다.** 경로 해시가 아닙니다 — 헤더 해시와
파일명 뒤 8자리가 **다른 경우가 이 파서의 관심사**이고(그 자체가 "제자리에서
만들어진 .pf 가 아니다"라는 정보), 해시로 짝을 지으면 바로 그 경우에 짝이
안 지어져 불일치가 아니라 "저쪽에만 있음"으로 둔갑합니다.

채점하는 것은 ``GRADED`` 가 들고 있습니다. 핵심은 셋입니다.

* **실행 횟수** — ``FILE_INFORMATION`` 안에서 자리가 버전마다 달라지는 값.
  빌드가 바뀌었을 때 가장 먼저 어긋나는 자리입니다.
* **실행 시각** — PECmd 는 ``LastRun`` + ``PreviousRun0..6`` 으로, 우리는
  ``fields.run_times`` 배열로 냅니다. **개수와 순서까지** 봅니다. 자리를
  잘못 잡으면 값보다 개수가 먼저 어긋납니다.
* **경로 해시** — 헤더 ``0x4C``. ``ref`` 의 근거라 여기가 틀리면 원본 대조가
  통째로 무너집니다.

**버전은 채점하지 않고 교차표로 보여 줍니다.** PECmd 의 ``Version`` 은
``Win10OrWin11`` 같은 문자열이고 도구 버전마다 표기가 바뀝니다. 그것을 우리
정수(23·26·30·31)에 매핑해 채점하면 **PECmd 의 표기가 바뀐 것을 우리 파서의
오류로 셉니다.** 대신 어떤 조합이 몇 건인지 인쇄합니다 — Win10 빌드 축에서
읽고 싶은 것이 사실 그 표입니다.

**적재 파일 목록은 경로가 아니라 개수만 봅니다.** 우리는 장치 경로를 드라이브
문자로 바꿔 싣고(``parsers/prefetch.py``) PECmd 는 원본 그대로 냅니다. 경로
문자열을 그대로 비교하면 **변환 규칙의 차이**를 파싱 오류로 셉니다. 경로 내용
자체는 ``tools/scan_prefetch.py`` 가 이미 다른 길로 채점합니다.

## 열 이름이 다르면

PECmd 버전마다 열 이름이 조금씩 다릅니다. 짝을 짓는 데 필요한 열이 없으면
실제 열 목록을 보여 주고 **멈춥니다.** 선택적인 열(해시·볼륨·적재 파일 수)이
없으면 그 항목만 "채점 안 함"으로 인쇄합니다 — 조용히 건너뛰지 않습니다.
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common import io  # noqa: E402

__all__ = [
    "Record",
    "Mismatch",
    "Report",
    "load_ours",
    "load_pecmd",
    "find_csv",
    "compare",
    "main",
]

#: 짝을 짓고 핵심 값을 채점하는 데 반드시 있어야 하는 열.
REQUIRED_COLUMNS = ("SourceFilename", "ExecutableName", "RunCount", "LastRun")

#: 있으면 채점하고, 없으면 "채점 안 함"으로 인쇄하는 열.
#:
#: PECmd 버전에 따라 이 열들의 이름이 다르거나 아예 없습니다. 없는 것을
#: 오류로 세면 **도구 버전의 차이가 파서의 오류로 둔갑합니다.**
OPTIONAL_COLUMNS = ("Hash", "Volume0Serial", "Volume0Created", "FilesLoaded")

#: PECmd 의 이전 실행 시각 열. ``LastRun`` 다음에 이 순서로 붙는다.
PREVIOUS_RUN_COLUMNS = tuple(f"PreviousRun{n}" for n in range(7))

DEFAULT_TOLERANCE_SECONDS = 1.0


@dataclass(frozen=True)
class Record:
    """양쪽을 같은 모양으로 맞춘 레코드."""

    source_file: str
    executable: str
    path_hash: "int | None"
    run_count: "int | None"
    run_times: "tuple[datetime, ...]"
    volume_serial: "int | None"
    volume_created: "datetime | None"
    loaded_count: "int | None"
    #: 채점하지 않고 교차표에만 쓴다.
    version: str = ""


@dataclass(frozen=True)
class Mismatch:
    source_file: str
    field: str
    ours: object
    theirs: object


@dataclass
class Report:
    ours_count: int = 0
    theirs_count: int = 0
    #: 저쪽 CSV 에 열이 없어 채점하지 못한 항목. 요약에 그대로 인쇄한다.
    ungraded: "tuple[str, ...]" = ()
    #: PECmd 에는 있는데 우리에게 없는 .pf. ``--full`` 에서만 오류.
    missing_from_ours: list[str] = field(default_factory=list)
    #: 우리에게만 있는 .pf. **항상 오류** — 없는 것을 지어낸 것이다.
    extra_in_ours: list[str] = field(default_factory=list)
    mismatches: list[Mismatch] = field(default_factory=list)
    #: (우리 format_version, PECmd Version) → 건수.
    versions: dict[tuple[str, str], int] = field(default_factory=dict)
    full: bool = False

    def passed(self) -> bool:
        if self.extra_in_ours or self.mismatches:
            return False
        return not (self.full and self.missing_from_ours)

    def summary(self) -> str:
        """``docs/artifact-notes.md`` 에 그대로 붙일 수 있는 형태."""
        matched = self.theirs_count - len(self.missing_from_ours)
        lines = [
            f"- 우리 레코드 {self.ours_count}건 / PECmd {self.theirs_count}건"
            f" / 짝지음 {matched}건",
            f"- 값 불일치 {len(self.mismatches)}건",
            f"- 우리에만 있는 .pf {len(self.extra_in_ours)}건",
            f"- PECmd 에만 있는 .pf {len(self.missing_from_ours)}건"
            + ("" if self.full else " (선별 범위 밖이면 정상)"),
        ]
        by_field: dict[str, int] = {}
        for mismatch in self.mismatches:
            by_field[mismatch.field] = by_field.get(mismatch.field, 0) + 1
        if by_field:
            lines.append("- 필드별 불일치:")
            lines.extend(
                f"    - `{name}` {count}건"
                for name, count in sorted(by_field.items(), key=lambda kv: -kv[1])
            )
        if self.ungraded:
            lines.append("- 채점 안 함 (PECmd CSV 에 열이 없음): " + ", ".join(self.ungraded))
        lines.append(f"- 판정: {'통과' if self.passed() else '실패'}")
        return "\n".join(lines)


# ------------------------------------------------------------------ 읽기


def _int(value: Any, *, base: int = 10) -> "int | None":
    """숫자를 표기 차이 없이. 빈 값과 못 읽는 값은 ``None``.

    ``None`` 은 "없다"이지 0 이 아닙니다. 0 으로 뭉개면 저쪽이 안 낸 값과
    우리가 0 을 읽은 것을 구별할 수 없습니다.
    """
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16 if base == 16 or text.lower().startswith("0x") else base)
    except ValueError:
        return None


def _basename(value: str) -> str:
    """경로에서 파일 이름만. PECmd 는 ``SourceFilename`` 을 전체 경로로 낸다."""
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()


def load_ours(path: "str | Path") -> dict[str, Record]:
    """우리 ``prefetch.jsonl`` 을 읽는다. 열쇠는 .pf 파일 이름."""
    records: dict[str, Record] = {}
    for row in io.read_jsonl(path):
        if row.get("artifact") != "prefetch":
            continue
        fields = row.get("fields") or {}
        name = _basename(fields.get("prefetch_file", ""))
        if not name:
            # prefetch_file 은 파서가 항상 넣는다. 없다면 이 JSONL 이
            # 프리패치 파서의 출력이 아니다. 조용히 건너뛰면 "짝지은 0건
            # 전부 일치"라는 무의미한 통과가 나온다.
            raise ValueError(
                f"{path}: fields.prefetch_file 이 없는 레코드가 있습니다"
                f" (ref={row.get('ref')}). 프리패치 파서의 출력이 맞습니까?"
            )
        volumes = fields.get("volumes") or []
        first = volumes[0] if volumes else {}
        records[name] = Record(
            source_file=name,
            executable=str(row.get("name") or "").strip().upper(),
            path_hash=_int(fields.get("path_hash"), base=16),
            run_count=_int(fields.get("run_count")),
            run_times=tuple(
                t
                for t in (io.parse_timestamp(v) for v in fields.get("run_times") or [])
                if t is not None
            ),
            volume_serial=_int(first.get("serial_number"), base=16),
            volume_created=io.parse_timestamp(first.get("created")),
            loaded_count=_int(fields.get("loaded_file_count")),
            version=str(fields.get("format_version", "")),
        )
    return records


def find_csv(target: "str | Path") -> Path:
    """``--pecmd`` 가 가리키는 CSV 파일 하나를 정한다.

    디렉터리면 ``*_PECmd_Output.csv`` 중 가장 최근 것. ``_Timeline.csv`` 는
    실행 시각을 한 줄씩 편 것이라 레코드 단위 대조에 쓰지 않습니다.
    """
    source = Path(target)
    if source.is_file():
        return source
    if not source.is_dir():
        raise FileNotFoundError(f"{source}: 파일도 디렉터리도 아닙니다")
    matches = [
        p
        for p in source.glob("*_PECmd_Output.csv")
        if not p.name.lower().endswith("_timeline.csv")
    ]
    if not matches:
        listing = ", ".join(p.name for p in sorted(source.iterdir())) or "(비어 있음)"
        raise FileNotFoundError(
            f"{source}: *_PECmd_Output.csv 가 없습니다.\n"
            f"  이 디렉터리의 파일: {listing}\n"
            "  PECmd.exe -d <Prefetch 폴더> --csv <이 디렉터리> 로 뽑으십시오."
        )
    return max(matches, key=lambda p: p.stat().st_mtime)


def load_pecmd(path: "str | Path") -> "tuple[dict[str, Record], tuple[str, ...]]":
    """PECmd CSV 를 읽는다. (레코드, 열이 없어 채점 못 하는 항목)."""
    source = Path(path)
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames or []
        _require_columns(columns, source)
        absent = tuple(name for name in OPTIONAL_COLUMNS if name not in columns)

        records: dict[str, Record] = {}
        for row in reader:
            name = _basename(row.get("SourceFilename", ""))
            if not name:
                continue
            times = [
                io.parse_timestamp(row.get(column))
                for column in ("LastRun", *PREVIOUS_RUN_COLUMNS)
                if column in columns
            ]
            records[name] = Record(
                source_file=name,
                executable=str(row.get("ExecutableName") or "").strip().upper(),
                path_hash=_int(row.get("Hash"), base=16),
                run_count=_int(row.get("RunCount")),
                # 빈 칸은 "그 자리에 시각이 없다"이므로 버린다. 우리
                # run_times 도 읽지 못한 자리를 빼고 낸다 (파서 참조).
                run_times=tuple(t for t in times if t is not None),
                volume_serial=_int(row.get("Volume0Serial"), base=16),
                volume_created=io.parse_timestamp(row.get("Volume0Created")),
                loaded_count=(
                    _loaded_count(row.get("FilesLoaded")) if "FilesLoaded" in columns else None
                ),
                version=str(row.get("Version") or "").strip(),
            )
    return records, absent


def _loaded_count(value: Any) -> "int | None":
    """``FilesLoaded`` 열에서 항목 수를. 비어 있으면 ``None``.

    PECmd 는 이 열을 도구 버전에 따라 개수(정수)로도, 경로를 이어 붙인
    문자열로도 냅니다. 둘 다 받되 **개수만** 씁니다 — 경로 내용은 변환
    규칙이 서로 달라 여기서 채점할 수 없습니다(모듈 docstring 참조).
    """
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    return len([part for part in text.replace("|", ",").split(",") if part.strip()])


def _require_columns(columns: list[str], source: Path) -> None:
    missing = [name for name in REQUIRED_COLUMNS if name not in columns]
    if missing:
        raise ValueError(
            f"{source}: 필요한 열이 없습니다 — {', '.join(missing)}\n"
            f"  실제 열: {', '.join(columns)}\n"
            "  PECmd 버전에 따라 이름이 다릅니다. "
            "tools/compare_prefetch.py 의 REQUIRED_COLUMNS 를 고치십시오."
        )


# ------------------------------------------------------------------ 대조

#: 채점할 항목. (필드 이름, 저쪽에 이 열이 없으면 통째로 건너뛸 열 이름).
#:
#: 시각은 ``tolerance_seconds`` 안이면 같은 것으로 봅니다 — PECmd 는 기본
#: 표기가 초 단위이고 우리는 100ns 자리까지 냅니다.
GRADED: "tuple[tuple[str, str | None], ...]" = (
    ("executable", None),
    ("run_count", None),
    ("run_times", None),
    ("path_hash", "Hash"),
    ("volume_serial", "Volume0Serial"),
    ("volume_created", "Volume0Created"),
    ("loaded_count", "FilesLoaded"),
)


def _times_differ(
    ours: "tuple[datetime, ...]", theirs: "tuple[datetime, ...]", tolerance: float
) -> bool:
    if len(ours) != len(theirs):
        return True
    return any(abs((a - b).total_seconds()) > tolerance for a, b in zip(ours, theirs))


def compare(
    ours: dict[str, Record],
    theirs: dict[str, Record],
    *,
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    full: bool = False,
    ungraded: "tuple[str, ...]" = (),
) -> Report:
    """두 결과를 대조한다. .pf 파일 이름으로 짝을 맞춘다."""
    report = Report(
        ours_count=len(ours),
        theirs_count=len(theirs),
        full=full,
        ungraded=ungraded,
    )
    report.extra_in_ours = sorted(set(ours) - set(theirs))
    report.missing_from_ours = sorted(set(theirs) - set(ours))
    skip = {name for name, column in GRADED if column and column in ungraded}

    for name in sorted(set(ours) & set(theirs)):
        mine, yours = ours[name], theirs[name]
        pair = (mine.version, yours.version)
        report.versions[pair] = report.versions.get(pair, 0) + 1

        for field_name, _column in GRADED:
            if field_name in skip:
                continue
            a, b = getattr(mine, field_name), getattr(yours, field_name)

            if field_name == "run_times":
                if _times_differ(a, b, tolerance_seconds):
                    report.mismatches.append(
                        Mismatch(name, field_name, _show_times(a), _show_times(b))
                    )
                continue

            # 저쪽이 안 낸 값은 채점하지 않는다. CSV 는 없는 값을 빈 칸으로
            # 내는데, 그것과 "우리가 못 읽었다"를 구별할 수 없다.
            if b is None:
                continue
            if isinstance(a, datetime) and isinstance(b, datetime):
                if abs((a - b).total_seconds()) > tolerance_seconds:
                    report.mismatches.append(Mismatch(name, field_name, a, b))
                continue
            if a != b:
                report.mismatches.append(Mismatch(name, field_name, a, b))

    return report


def _show_times(times: "tuple[datetime, ...]") -> str:
    if not times:
        return "(없음)"
    shown = ", ".join(t.strftime("%Y-%m-%d %H:%M:%S") for t in times[:3])
    return f"{len(times)}개 " + shown + (" …" if len(times) > 3 else "")


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/compare_prefetch.py",
        description="우리 프리패치 파서 출력을 PECmd 결과와 대조한다.",
    )
    parser.add_argument("--ours", required=True, help="04_parsed/prefetch.jsonl 경로")
    parser.add_argument(
        "--pecmd",
        required=True,
        help="PECmd --csv 출력 디렉터리 또는 *_PECmd_Output.csv 파일",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="우리 결과가 전수여야 한다고 본다. 범위 없이 돌린 출력에 쓴다",
    )
    parser.add_argument("--tolerance-seconds", type=float, default=DEFAULT_TOLERANCE_SECONDS)
    parser.add_argument("--show", type=int, default=10, help="불일치 예시 출력 수")
    args = parser.parse_args(argv)

    io.configure_console()

    csv_path = find_csv(args.pecmd)
    theirs, absent = load_pecmd(csv_path)
    report = compare(
        load_ours(args.ours),
        theirs,
        tolerance_seconds=args.tolerance_seconds,
        full=args.full,
        ungraded=absent,
    )

    print(f"대조 상대: {csv_path}")
    print(report.summary())

    if report.versions:
        print("\n버전 교차표 (채점하지 않는다 — 표기를 그대로 보여 준다)")
        print("  우리 format_version".ljust(24) + "PECmd Version".ljust(24) + "건수")
        for (mine, yours), count in sorted(report.versions.items(), key=lambda kv: -kv[1]):
            print(
                "  "
                + (mine or "(없음)").ljust(24)
                + (yours or "(없음)").ljust(24)
                + str(count)
            )

    if report.mismatches:
        print(f"\n불일치 예시 (최대 {args.show}건):")
        for mismatch in report.mismatches[: args.show]:
            print(
                f"  {mismatch.source_file} · {mismatch.field}\n"
                f"    우리  : {mismatch.ours}\n"
                f"    PECmd : {mismatch.theirs}"
            )
    if report.extra_in_ours:
        print(f"\n우리에만 있는 .pf: {report.extra_in_ours[: args.show]}")
    if report.missing_from_ours:
        print(f"\nPECmd 에만 있는 .pf: {report.missing_from_ours[: args.show]}")

    print("\n원인을 파악하면 docs/artifact-notes.md 에 기록하십시오.")
    return 0 if report.passed() else 1


if __name__ == "__main__":
    raise SystemExit(main())
