"""우리 $MFT 파서 출력을 MFTECmd 결과와 대조한다.

직접 구현의 리스크는 **조용히 틀리는 것**입니다. 오프셋 하나가 어긋나도
형식은 멀쩡해서 스키마를 통과하고, 06단계 검증도 통과합니다 — 레코드에
적힌 값과 문장이 일치하니까요. **파이프라인 안에서는 아무도 못 잡습니다.**

그래서 바깥에서 채점합니다. 기존 도구를 **쓰지 않는 것**과 **대조군으로
삼는 것**은 별개입니다. "우리 파서가 MFTECmd와 1,842건 전부 일치했다"는
발표에서 신뢰도를 크게 올립니다.

사용법::

    MFTECmd.exe -f "C:\\evidence\\$MFT" --csv out --csvf mft.csv

    python tools/compare_mft.py --ours cases/C-001/04_parsed/mft.jsonl \\
                               --mftecmd out/mft.csv

**우리 파서는 선별된 범위만 냅니다.** 레코드 수까지 대조하려면 범위를
비우고(``scope`` 없이) 돌린 결과를 쓰고 ``--full``을 붙이십시오.
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.common import io  # noqa: E402

__all__ = ["Record", "Mismatch", "Report", "load_ours", "load_mftecmd", "compare", "main"]

#: 우리 필드 → MFTECmd CSV 열 이름.
#:
#: MFTECmd 버전마다 열 이름이 조금씩 다릅니다. 열을 못 찾으면 에러
#: 메시지에 실제 열 목록이 나오니 그것을 보고 여기를 고치십시오.
#: ``0x10``이 ``$STANDARD_INFORMATION``, ``0x30``이 ``$FILE_NAME``입니다.
TIMESTAMP_COLUMNS: dict[str, str] = {
    "si_btime": "Created0x10",
    "si_mtime": "LastModified0x10",
    "si_ctime": "LastRecordChange0x10",
    "si_atime": "LastAccess0x10",
    "fn_btime": "Created0x30",
    "fn_mtime": "LastModified0x30",
    "fn_ctime": "LastRecordChange0x30",
}

#: 대조할 타임스탬프. work-guide 3.2가 "타임스탬프 4종"을 요구합니다.
COMPARED_TIMESTAMPS = ("si_btime", "si_mtime", "si_ctime", "si_atime")

DEFAULT_TOLERANCE_SECONDS = 1.0


@dataclass(frozen=True)
class Record:
    """양쪽을 같은 모양으로 맞춘 레코드."""

    record_num: int
    path: str
    timestamps: dict[str, datetime | None]


@dataclass(frozen=True)
class Mismatch:
    record_num: int
    field: str
    ours: object
    theirs: object


@dataclass
class Report:
    ours_count: int = 0
    theirs_count: int = 0
    #: MFTECmd에는 있는데 우리에게 없는 레코드. ``--full``에서만 오류.
    missing_from_ours: list[int] = field(default_factory=list)
    #: 우리에게만 있는 레코드. **항상 오류** — 없는 것을 지어낸 것이다.
    extra_in_ours: list[int] = field(default_factory=list)
    mismatches: list[Mismatch] = field(default_factory=list)
    full: bool = False

    def passed(self) -> bool:
        if self.extra_in_ours or self.mismatches:
            return False
        return not (self.full and self.missing_from_ours)

    def summary(self) -> str:
        """``docs/artifact-notes.md``에 그대로 붙일 수 있는 형태."""
        lines = [
            f"- 우리 레코드 {self.ours_count}건 / MFTECmd {self.theirs_count}건",
            f"- 값 불일치 {len(self.mismatches)}건",
            f"- 우리에만 있는 레코드 {len(self.extra_in_ours)}건",
            f"- MFTECmd에만 있는 레코드 {len(self.missing_from_ours)}건"
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
        lines.append(f"- 판정: {'통과' if self.passed() else '실패'}")
        return "\n".join(lines)


def normalize_path(value: str) -> str:
    """드라이브 문자와 선행 ``.``을 떼고 비교 가능한 형태로.

    MFTECmd는 ``$MFT``만 읽으므로 드라이브 문자를 모릅니다. ``.\\Users\\x``
    처럼 볼륨 루트 기준으로 냅니다. 우리는 ``C:\\Users\\x``라 그대로
    비교하면 전부 불일치합니다.
    """
    text = io.normalize_path(value)
    if len(text) > 1 and text[1] == ":":  # "c:/users/x"
        text = text[2:]
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/") or "/"


def load_ours(path: str | Path) -> dict[int, Record]:
    """우리 ``mft.jsonl``을 읽는다."""
    records: dict[int, Record] = {}
    for row in io.read_jsonl(path):
        if row.get("artifact") != "$MFT":
            continue
        number = int(row["record_num"])
        records[number] = Record(
            record_num=number,
            path=normalize_path(row.get("path", "")),
            timestamps={
                name: io.parse_timestamp(row.get(name)) for name in TIMESTAMP_COLUMNS
            },
        )
    return records


def load_mftecmd(path: str | Path) -> dict[int, Record]:
    """MFTECmd CSV를 읽는다."""
    source = Path(path)
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames or []
        _require_columns(columns, source)

        records: dict[int, Record] = {}
        for row in reader:
            number = int(row["EntryNumber"])
            parent = (row.get("ParentPath") or "").strip()
            name = (row.get("FileName") or "").strip()
            records[number] = Record(
                record_num=number,
                path=normalize_path(f"{parent}\\{name}" if parent else name),
                timestamps={
                    field_name: io.parse_timestamp(row.get(column))
                    for field_name, column in TIMESTAMP_COLUMNS.items()
                },
            )
    return records


def _require_columns(columns: list[str], source: Path) -> None:
    needed = {"EntryNumber", "FileName", "ParentPath"} | set(
        TIMESTAMP_COLUMNS[name] for name in COMPARED_TIMESTAMPS
    )
    missing = sorted(needed - set(columns))
    if missing:
        raise ValueError(
            f"{source}: 필요한 열이 없습니다 — {', '.join(missing)}\n"
            f"  실제 열: {', '.join(columns)}\n"
            "  MFTECmd 버전에 따라 이름이 다릅니다. "
            "tools/compare_mft.py 의 TIMESTAMP_COLUMNS 를 고치십시오."
        )


def compare(
    ours: dict[int, Record],
    theirs: dict[int, Record],
    *,
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    full: bool = False,
) -> Report:
    """두 결과를 대조한다. 레코드 번호로 짝을 맞춘다."""
    report = Report(ours_count=len(ours), theirs_count=len(theirs), full=full)
    report.extra_in_ours = sorted(set(ours) - set(theirs))
    report.missing_from_ours = sorted(set(theirs) - set(ours))

    for number in sorted(set(ours) & set(theirs)):
        mine, yours = ours[number], theirs[number]

        if mine.path != yours.path:
            report.mismatches.append(Mismatch(number, "path", mine.path, yours.path))

        for name in COMPARED_TIMESTAMPS:
            a, b = mine.timestamps.get(name), yours.timestamps.get(name)
            if a is None and b is None:
                continue
            if a is None or b is None or abs((a - b).total_seconds()) > tolerance_seconds:
                report.mismatches.append(Mismatch(number, name, a, b))

    return report


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/compare_mft.py",
        description="우리 $MFT 파서 출력을 MFTECmd 결과와 대조한다.",
    )
    parser.add_argument("--ours", required=True, help="04_parsed/mft.jsonl 경로")
    parser.add_argument("--mftecmd", required=True, help="MFTECmd --csv 출력 파일")
    parser.add_argument(
        "--full",
        action="store_true",
        help="우리 결과가 전수여야 한다고 본다. 범위 없이 돌린 출력에 쓴다",
    )
    parser.add_argument("--tolerance-seconds", type=float, default=DEFAULT_TOLERANCE_SECONDS)
    parser.add_argument("--show", type=int, default=10, help="불일치 예시 출력 수")
    args = parser.parse_args(argv)

    io.configure_console()

    report = compare(
        load_ours(args.ours),
        load_mftecmd(args.mftecmd),
        tolerance_seconds=args.tolerance_seconds,
        full=args.full,
    )

    print(report.summary())
    if report.mismatches:
        print(f"\n불일치 예시 (최대 {args.show}건):")
        for mismatch in report.mismatches[: args.show]:
            print(
                f"  MFT#{mismatch.record_num} {mismatch.field}\n"
                f"    우리      : {mismatch.ours}\n"
                f"    MFTECmd  : {mismatch.theirs}"
            )
    if report.extra_in_ours:
        print(f"\n우리에만 있는 레코드: {report.extra_in_ours[: args.show]}")

    print("\n원인을 파악하면 docs/artifact-notes.md 에 기록하십시오.")
    return 0 if report.passed() else 1


if __name__ == "__main__":
    raise SystemExit(main())
