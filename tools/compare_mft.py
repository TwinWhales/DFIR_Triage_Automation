"""우리 $MFT 파서 출력을 MFTECmd 결과와 대조한다.

직접 구현의 리스크는 **조용히 틀리는 것**입니다. 오프셋 하나가 어긋나도
형식은 멀쩡해서 스키마를 통과하고, 06단계 검증도 통과합니다 — 레코드에
적힌 값과 문장이 일치하니까요. **파이프라인 안에서는 아무도 못 잡습니다.**

그래서 바깥에서 채점합니다. 기존 도구를 **쓰지 않는 것**과 **대조군으로
삼는 것**은 별개입니다. "우리 파서가 MFTECmd와 1,842건 전부 일치했다"는
발표에서 신뢰도를 크게 올립니다.

대조 상대는 둘 중 하나입니다.

**MFTECmd** — 외부 도구. 최종 검증용::

    MFTECmd.exe -f "C:\\evidence\\$MFT" --csv out --csvf mft.csv
    python tools/compare_mft.py --ours cases/C-001/04_parsed/mft.jsonl \\
                               --mftecmd out/mft.csv

**참조 구현** — ``--parser reference`` 로 뽑은 우리 형식 JSONL.
MFTECmd를 설치하지 않아도 되고 ``pytest`` 안에서 돌아가므로, 자체 파서를
만드는 동안 **매번 즉시 채점**할 수 있습니다::

    python -m src.stage04_parse.parse ... --parser reference --out /tmp/ref
    python -m src.stage04_parse.parse ... --parser native    --out /tmp/native
    python tools/compare_mft.py --ours /tmp/native/mft.jsonl --reference /tmp/ref/mft.jsonl

**우리 파서는 선별된 범위만 냅니다.** 레코드 수까지 대조하려면 범위를
비우고(``scope`` 없이) 돌린 결과를 쓰고 ``--full``을 붙이십시오.

**MFTECmd 쪽 ADS 행은 제외하고 대조합니다**(``ADS_COLUMN`` 참조). 요약에
제외 건수가 나오므로, 기록을 남길 때 그 줄을 함께 붙이십시오 — 조건이
빠지면 같은 CSV 로 다른 숫자가 나옵니다.
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

__all__ = [
    "Record",
    "Mismatch",
    "Report",
    "Loaded",
    "load_ours",
    "load_mftecmd",
    "compare",
    "main",
]

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

#: ADS(대체 데이터 스트림) 행을 가려내는 열.
#:
#: **MFTECmd 는 스트림마다 한 행을 냅니다.** ``Sysmon.exe`` 와
#: ``Sysmon.exe:Zone.Identifier`` 가 **같은 EntryNumber 의 두 행**입니다.
#: 우리 파서는 이름 없는 ``$DATA`` 만 보므로(``parsers/mft.py`` 의
#: ``_data_size``) 레코드당 한 건입니다. ADS 는 범위 밖입니다
#: (``work-guide.md`` 3.3).
#:
#: 걸러 내지 않으면 **레코드 수로는 아무것도 드러나지 않습니다** — 두 행이
#: 같은 키를 쓰므로 나중 행이 앞 행을 덮어쓸 뿐입니다. 그러면 경로가
#: ``Sysmon.exe:Zone.Identifier`` 로 바뀌어 ADS 를 가진 파일 수만큼 경로
#: 불일치가 쏟아지고, 타임스탬프도 본체가 아닌 행과 대조하게 됩니다.
ADS_COLUMN = "IsAds"

#: ``IsAds`` 가 가질 수 있는 값. 모르는 값은 조용히 넘기지 않습니다 —
#: MFTECmd 가 표기를 바꿨다는 뜻이고, 그것을 False 로 읽으면 ADS 행이
#: 대조에 섞여 들어옵니다.
BOOLEAN_VALUES: dict[str, bool] = {"true": True, "false": False, "1": True, "0": False}

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


@dataclass(frozen=True)
class Loaded:
    """대조 상대를 읽은 결과. 레코드와 **대조 조건**을 함께 들고 있다.

    제외한 행 수를 레코드와 나눠 둔 것은 그 수를 요약에 적기 위해서입니다.
    조건이 빠진 기록은 재현되지 않습니다 — 같은 CSV 로 다른 숫자가 나옵니다.
    """

    records: dict[int, Record]
    #: 제외한 ADS 행 수. ADS 개념이 없는 상대(참조 구현)는 ``None``.
    ads_rows: int | None = None


@dataclass
class Report:
    ours_count: int = 0
    theirs_count: int = 0
    #: 대조 상대의 이름. 요약에 그대로 쓴다.
    against: str = "대조군"
    #: 제외한 ADS 행 수. ``None`` 이면 해당 없음이라 요약에 적지 않는다.
    ads_rows: int | None = None
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
            f"- 우리 레코드 {self.ours_count}건 / {self.against} {self.theirs_count}건",
            f"- 값 불일치 {len(self.mismatches)}건",
            f"- 우리에만 있는 레코드 {len(self.extra_in_ours)}건",
            f"- {self.against}에만 있는 레코드 {len(self.missing_from_ours)}건"
            + ("" if self.full else " (선별 범위 밖이면 정상)"),
        ]
        # 조건을 요약 안에 넣는다. 붙여 넣은 기록만 보고도 무엇을 뺀
        # 대조인지 알 수 있어야 한다.
        if self.ads_rows is not None:
            lines.append(
                f"- 대조 조건: {self.against}의 ADS 행 {self.ads_rows}건 제외"
                f" (`{ADS_COLUMN}` = True). 우리 파서는 이름 없는 `$DATA`만 낸다"
            )
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


def load_mftecmd(path: str | Path) -> Loaded:
    """MFTECmd CSV를 읽는다. **ADS 행은 제외한다** (``ADS_COLUMN`` 참조).

    레코드 번호로 짝을 맞추므로 같은 번호가 두 번 나오면 하나가 조용히
    사라집니다. ADS 를 걸러 낸 뒤에도 중복이 남으면 **중단합니다** —
    덮어쓰면 어느 행과 대조했는지 알 수 없고, 그것이 이 도구가 막으려는
    "조용히 틀리는 것"입니다.
    """
    source = Path(path)
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames or []
        _require_columns(columns, source)

        records: dict[int, Record] = {}
        duplicates: list[int] = []
        ads_rows = 0
        for row in reader:
            number = int(row["EntryNumber"])
            if _is_ads(row, source, number):
                ads_rows += 1
                continue
            if number in records:
                duplicates.append(number)  # 먼저 읽은 것을 남긴다
                continue
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

    if duplicates:
        shown = ", ".join(str(number) for number in sorted(set(duplicates))[:10])
        raise ValueError(
            f"{source}: EntryNumber 가 중복입니다 — {len(duplicates)}건 ({shown})\n"
            f"  ADS 행({ADS_COLUMN})은 이미 제외했으므로 다른 이유입니다. "
            "하드링크나 MFTECmd 의 출력 단위 변경을 의심하십시오.\n"
            "  덮어쓰면 어느 행과 대조했는지 알 수 없으므로 중단합니다."
        )

    return Loaded(records=records, ads_rows=ads_rows)


def _is_ads(row: dict[str, str], source: Path, number: int) -> bool:
    """이 행이 대체 데이터 스트림인가.

    ``FileName`` 의 콜론으로도 가려낼 수 있지만(NTFS 파일 이름에는 콜론이
    못 들어간다) 그것은 표기에 기대는 판정입니다. 열이 있으면 열을 봅니다.
    """
    raw = (row.get(ADS_COLUMN) or "").strip().lower()
    if raw not in BOOLEAN_VALUES:
        raise ValueError(
            f"{source}: EntryNumber {number} 의 {ADS_COLUMN} 값을 읽을 수 없습니다"
            f" — {raw!r}\n"
            f"  아는 값: {', '.join(sorted(BOOLEAN_VALUES))}\n"
            "  MFTECmd 가 표기를 바꿨다면 tools/compare_mft.py 의 BOOLEAN_VALUES 를 "
            "고치십시오. 모르는 값을 False 로 넘기면 ADS 행이 대조에 섞입니다."
        )
    return BOOLEAN_VALUES[raw]


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
    # ADS 판정에 쓰는 열은 따로 본다. 없으면 폴백하지 않고 멈춘다 —
    # 콜론으로 대신 가려내면 그 판정이 맞았는지 아무도 확인하지 않는다.
    if ADS_COLUMN not in columns:
        raise ValueError(
            f"{source}: {ADS_COLUMN} 열이 없어 ADS 행을 가려낼 수 없습니다.\n"
            f"  실제 열: {', '.join(columns)}\n"
            "  MFTECmd 가 오래된 버전이면 올리십시오. 이 열 없이 대조하면 ADS 행이 "
            "같은 EntryNumber 의 본체 행을 덮어써, ADS 를 가진 파일 수만큼 경로 "
            "불일치가 나옵니다."
        )


def compare(
    ours: dict[int, Record],
    theirs: dict[int, Record],
    *,
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    full: bool = False,
    against: str = "대조군",
    ads_rows: int | None = None,
) -> Report:
    """두 결과를 대조한다. 레코드 번호로 짝을 맞춘다.

    ``ads_rows`` 는 ``load_mftecmd`` 가 제외한 행 수입니다. 대조 조건이라
    요약에 들어가야 합니다 — 그것 없이는 같은 CSV 로 다른 숫자가 나옵니다.
    """
    report = Report(
        ours_count=len(ours),
        theirs_count=len(theirs),
        full=full,
        against=against,
        ads_rows=ads_rows,
    )
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
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--mftecmd", help="MFTECmd --csv 출력 파일")
    source.add_argument(
        "--reference",
        help="참조 구현으로 뽑은 mft.jsonl. MFTECmd 없이 즉시 대조할 때",
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

    # 참조 구현은 우리 형식이라 ADS 개념이 없다. ads_rows 를 None 으로 둬야
    # 요약에 "ADS 0건 제외"라는 없는 조건이 적히지 않는다.
    if args.mftecmd:
        loaded = load_mftecmd(args.mftecmd)
    else:
        loaded = Loaded(records=load_ours(args.reference))

    report = compare(
        load_ours(args.ours),
        loaded.records,
        tolerance_seconds=args.tolerance_seconds,
        full=args.full,
        against="MFTECmd" if args.mftecmd else "참조 구현",
        ads_rows=loaded.ads_rows,
    )

    print(f"대조 상대: {args.mftecmd or args.reference}")
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
