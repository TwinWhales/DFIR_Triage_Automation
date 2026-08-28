"""우리 ``$MFT`` 파서 출력을 ``dissect.ntfs`` 의 순회와 대조한다.

``compare_mft.py`` 와 목적은 같고 **대조 상대가 다릅니다.** 저쪽은
MFTECmd(외부 도구)나 우리 참조 구현을 씁니다. 이쪽은 이미 설치돼 있는
``dissect.ntfs`` 를 씁니다.

**왜 하나 더 만드나** — MFTECmd 는 따로 받아야 해서 오래 미실시로
남아 있었고(``docs/limitations.md`` "외부 도구 대조가 부분적이다"), 그
사이 ``$MFT`` 는 **산출량이 두 번째로 많은데 검증이 가장 약한** 파서로
남았습니다. ``dissect.ntfs`` 는 ``dissect.target`` 을 깔면 함께 오므로
(``requirements.txt`` 에 이미 있습니다) **받을 것이 없습니다.**

우리 파서는 ``third_party/analyzeMFT`` 계열이고 ``dissect.ntfs`` 는
전혀 다른 계보입니다. 같은 사람이 짠 두 구현이 아니므로 **공통 오해가
생기지 않습니다** — 독립 순회 정답지(``$UsnJrnl``)로는 못 잡던 종류가
여기서 잡힙니다. 다만 MFTECmd 를 대신하지는 못합니다. 저쪽은 DFIR
현장의 사실상 표준이라 발표에서 값이 다릅니다.

**두 도구는 원래 다른 집합을 냅니다.** 그것이 불일치가 아니라는 것을
아는 것이 이 스크립트의 일입니다.

- **dissect 에만 있는 것** — ``$FILE_NAME`` 이 없는 레코드입니다.
  ``#12``~``#15`` 같은 NTFS 예약 슬롯과 속성 목록 확장 레코드가 여기
  해당합니다. 이름도 경로도 없어 우리가 거르는 것이 맞습니다.
- **우리에게만 있는 것** — ``deleted`` 플래그가 붙은 삭제 레코드입니다.
  dissect 의 ``IN_USE`` 판정이 **정의상** 제외하는 것이고, 삭제 파일을
  보는 것이 DFIR 의 요점이므로 우리가 더 보는 것이 맞습니다.

그래서 **위 둘로 설명되지 않는 차이만 불일치로 셉니다.** 하나라도
있으면 종료 코드 1 입니다.

덤으로 **부모 슬롯 재사용으로 경로가 어긋난 레코드**를 셉니다
(``docs/limitations.md`` "``$MFT`` 만으로는 알 수 없는 것"). 삭제
레코드의 부모 참조가 가리키는 슬롯이 그 사이 다른 파일에 재할당되면
경로 중간에 **파일이 디렉터리 자리로** 들어갑니다. 불일치가 아니라
알려진 한계라 종료 코드에 영향을 주지 않지만, 이미지마다 비율이 다르고
그 경로가 05단계 프롬프트에 그대로 실리므로 세어 둘 값이 있습니다.

**범위 없이 뽑은 출력에 쓰십시오.** 우리 파서는 선별된 범위만 냅니다.
``scope`` 를 비우고 돌린 ``mft.jsonl`` 이 아니면 "우리에게만 있는 것"이
아니라 "안 뽑은 것"이 섞여 판정이 무의미해집니다::

    python -m src.stage04_parse.parse --in <범위 없는 selection> \\
        --out cases/X/04_parsed/ --evidence evidence/img.001 --volume 1
    python tools/compare_mft_dissect.py --image evidence/img.001 --volume 1 \\
        --ours cases/X/04_parsed/mft.jsonl

대조 기록은 ``docs/artifact-notes.md`` 에 남깁니다.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.stage04_parse import evidence  # noqa: E402

__all__ = ["Report", "load_ours", "scan_dissect", "compare", "main"]

#: ``$MFT`` 레코드 헤더의 IN_USE 비트.
FLAG_IN_USE = 0x01

#: 경로 중간에 낀 성분이 **파일로 보이는가**. 부모 슬롯 재사용의 흔적이다.
#:
#: 완벽한 판별이 아닙니다 — GAC 처럼 디렉터리 이름에 점이 들어가는 자리가
#: 실제로 있습니다(``\\assembly\\GAC_MSIL\\System.Xml\\2.0.0.0__...``).
#: 그래서 **확장자를 이 목록으로 한정하고**, 삭제 레코드에만 셉니다.
#: 넓히면 오탐이 늘어 수치의 뜻이 흐려집니다.
_B = "\\"
STALE_PARENT = re.compile(
    "[" + _B + _B + "][^" + _B + _B + "]+[.]"
    "(?:edb|log|ini|tmp|dat|db|etl|evtx|bak|sys|dll|exe)"
    "[" + _B + _B + "]",
    re.IGNORECASE,
)


@dataclass
class Report:
    """대조 결과. ``ok`` 가 아니면 종료 코드 1."""

    ours: set[int] = field(default_factory=set)
    in_use: set[int] = field(default_factory=set)
    scanned: int = 0

    #: dissect 만 가진 것 중 ``$FILE_NAME`` 이 없어 설명되는 것.
    explained_nameless: list[int] = field(default_factory=list)
    #: 우리만 가진 것 중 ``deleted`` 로 설명되는 것.
    explained_deleted: list[int] = field(default_factory=list)
    #: 설명되지 않는 것. **이것만이 불일치다.**
    unexplained_dissect_only: list[int] = field(default_factory=list)
    unexplained_ours_only: list[int] = field(default_factory=list)

    #: 부모 슬롯 재사용으로 경로가 어긋난 삭제 레코드.
    stale_parent: list[str] = field(default_factory=list)
    deleted_total: int = 0

    @property
    def ok(self) -> bool:
        return not (self.unexplained_dissect_only or self.unexplained_ours_only)


def load_ours(path: Path) -> dict[int, dict]:
    """``mft.jsonl`` 을 ``레코드번호 → 레코드`` 로 읽는다."""
    out: dict[int, dict] = {}
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            out[record["record_num"]] = record
    return out


def scan_dissect(image: str, volume: int | None) -> tuple[dict[int, object], set[int]]:
    """``dissect.ntfs`` 로 ``$MFT`` 를 순회한다.

    04단계와 **같은 증거 계층**을 통해 엽니다. 이미지를 따로 마운트하지
    않으므로 볼륨 선택도 같은 규칙을 따릅니다 — 볼륨이 여럿인데 지정하지
    않으면 04단계와 똑같이 거부됩니다.
    """
    source = evidence.open_source(image, volume=volume) if volume is not None else evidence.open_source(image)
    filesystem = getattr(source, "filesystem", None)
    if filesystem is None:
        raise SystemExit(
            "이 증거는 디스크 이미지가 아닙니다 — 추출된 폴더에는 $MFT 를 순회할 "
            "파일시스템이 없습니다. 이미지 파일을 주십시오."
        )
    segments: dict[int, object] = {}
    for record in filesystem.ntfs.mft.segments():
        segments[record.segment] = record
    in_use = {n for n, r in segments.items() if r.header.Flags & FLAG_IN_USE}
    return segments, in_use


def _has_filename(record: object) -> bool:
    """``$FILE_NAME`` 이 있는가.

    python 쪽에서 이름을 물어 예외가 나면 없는 것으로 봅니다. dissect 는
    ``$FN`` 이 없을 때 ``TypeError`` 를 냅니다.
    """
    try:
        record.filename()  # type: ignore[attr-defined]
    except Exception:
        return False
    return True


def compare(ours: dict[int, dict], segments: dict[int, object], in_use: set[int]) -> Report:
    """두 집합의 차이를 **설명되는 것과 아닌 것**으로 가른다."""
    report = Report(ours=set(ours), in_use=in_use, scanned=len(segments))

    for number in sorted(in_use - set(ours)):
        if not _has_filename(segments[number]):
            report.explained_nameless.append(number)
        else:
            report.unexplained_dissect_only.append(number)

    for number in sorted(set(ours) - in_use):
        if "deleted" in (ours[number].get("flags") or []):
            report.explained_deleted.append(number)
        else:
            report.unexplained_ours_only.append(number)

    for record in ours.values():
        if "deleted" not in (record.get("flags") or []):
            continue
        report.deleted_total += 1
        path = record.get("path")
        if path and STALE_PARENT.search(path):
            report.stale_parent.append(path)

    return report


def _render(report: Report, show: int) -> None:
    print(f"dissect.ntfs: 순회 {report.scanned:,} / IN_USE {len(report.in_use):,}")
    print(f"우리 파서    : {len(report.ours):,}건")
    print(f"교집합       : {len(report.ours & report.in_use):,}건")
    print()

    print(f"dissect 에만 있음 {len(report.explained_nameless) + len(report.unexplained_dissect_only):,}건")
    print(f"  $FILE_NAME 없음 (설명됨)      {len(report.explained_nameless):,}건")
    if report.unexplained_dissect_only:
        print(f"  **설명 안 됨**                {len(report.unexplained_dissect_only):,}건")
        for number in report.unexplained_dissect_only[:show]:
            print(f"      #{number}")

    print(f"우리에게만 있음 {len(report.explained_deleted) + len(report.unexplained_ours_only):,}건")
    print(f"  deleted 플래그 (설명됨)        {len(report.explained_deleted):,}건")
    if report.unexplained_ours_only:
        print(f"  **설명 안 됨**                {len(report.unexplained_ours_only):,}건")
        for number in report.unexplained_ours_only[:show]:
            print(f"      #{number}")
    print()

    if report.deleted_total:
        ratio = len(report.stale_parent) / report.deleted_total * 100
        print(
            f"부모 슬롯 재사용으로 경로가 어긋난 것: "
            f"{len(report.stale_parent):,} / {report.deleted_total:,}건 ({ratio:.0f}%)"
        )
        print("  알려진 한계입니다 (limitations.md \"$MFT만으로는 알 수 없는 것\"). 판정에 넣지 않습니다.")
        for path in report.stale_parent[:show]:
            print(f"      {path}")
        print()

    if report.ok:
        print("일치. 두 구현의 차이가 전부 설명됩니다.")
    else:
        print("불일치. 위 '설명 안 됨' 항목을 보십시오.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/compare_mft_dissect.py",
        description="우리 $MFT 파서 출력을 dissect.ntfs 순회와 대조한다.",
    )
    parser.add_argument("--image", required=True, help="디스크 이미지 경로 (04단계의 --evidence 와 같은 값)")
    parser.add_argument("--volume", type=int, default=None, help="NTFS 가 여럿일 때 볼륨 번호")
    parser.add_argument("--ours", required=True, help="04_parsed/mft.jsonl 경로. 범위 없이 뽑은 것이어야 한다")
    parser.add_argument("--show", type=int, default=5, help="예시 출력 수")
    args = parser.parse_args(argv)

    ours = load_ours(Path(args.ours))
    segments, in_use = scan_dissect(args.image, args.volume)
    report = compare(ours, segments, in_use)
    _render(report, args.show)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
