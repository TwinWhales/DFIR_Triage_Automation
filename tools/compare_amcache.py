"""우리 Amcache 파서 출력을 AmcacheParser 결과와 대조한다.

직접 구현이 아니라 python-registry 어댑터지만, **조용히 틀리는 위험은
같습니다.** 값 이름을 잘못 옮기거나 타임스탬프를 다르게 해석해도 형식은
멀쩡해서 스키마를 통과하고, 06단계 검증도 통과합니다 — 레코드에 적힌
값과 문장이 일치하니까요. 파이프라인 안에서는 아무도 못 잡습니다.

그래서 바깥에서 채점합니다. `docs/limitations.md` 가 "외부 도구
(AmcacheParser 등) 대조는 하지 않았습니다"를 **아는 구멍**으로 적어 둔
자리가 여기입니다.

## 쓰는 법

AmcacheParser 는 저장소에 넣지 않습니다. 바이너리라 `third_party/` 대상도
아닙니다. 받아서 아무 데나 두고 하이브를 직접 가리킵니다::

    AmcacheParser.exe -f Amcache.hve -i --nl --csv out

    .venv/Scripts/python.exe -m src.stage04_parse.parse \\
        --in <범위를 비운 03_selection.json> --out /tmp/am \\
        --evidence evidence/0824test.001 --volume 1

    .venv/Scripts/python.exe tools/compare_amcache.py \\
        --ours /tmp/am/registry_amcache.jsonl --amcache out

**`--nl` 을 붙이십시오.** 없으면 AmcacheParser 가 트랜잭션 로그(.LOG1/
.LOG2)를 재생합니다. 우리 파서는 재생하지 않으므로 그대로 대조하면 우리가
없는 레코드를 저쪽이 갖게 되어, 파서의 정확성이 아니라 **로그 재생 여부의
차이**를 재게 됩니다.

**`--in` 의 범위를 비우십시오.** 우리 파서는 선별된 범위만 냅니다.
레코드 수까지 대조하려면 하이브 전체를 내야 합니다.

## 무엇을 대조하나

AmcacheParser 는 하이브를 **범주별 CSV** 로 내고, 우리는 키 하나를 레코드
하나로 냅니다. 그래서 범주마다 짝을 짓는 열쇠와 비교할 필드를 아래
`CATEGORIES` 가 들고 있습니다.

**`Root\\File` 은 대조하지 않습니다.** AmcacheParser 는 이 하이브를 "new
format" 으로 보고 `Root\\InventoryApplicationFile` 만 읽습니다. 우리는
둘 다 읽습니다(360건이 저쪽에 없음). 그것은 불일치가 아니라 **범위 결정의
차이**라 여기서 채점하지 않고 보고서에 "저쪽에 없는 것" 으로 셉니다.
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import sys
from typing import Any, Callable

BACKSLASH = chr(92)


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _int(value: Any) -> str:
    """숫자를 표기 차이 없이. 16진 문자열도 받는다."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(int(text, 16) if text.lower().startswith("0x") else int(text))
    except ValueError:
        return text.lower()


def _date(value: Any) -> str:
    """날짜를 ``YYYY-MM-DD HH:MM:SS`` 까지만.

    AmcacheParser 는 기본 표기가 초 단위이고 우리는 100ns 자리까지 냅니다.
    **더 정밀한 쪽을 깎아 맞춥니다** — 여기서 재려는 것은 "같은 시각을
    가리키는가"이지 표기가 같은가가 아닙니다. 초 미만의 정확성은
    ``--mp`` 를 붙인 별도 실행으로 봐야 합니다.

    **``MM/dd/yyyy`` 도 같은 시각으로 봅니다.** ``InventoryApplication`` 의
    ``InstallDate`` 는 FILETIME 이 아니라 **하이브에 그렇게 적힌 문자열**
    (``RegSZ``, 예: ``'03/20/2017 03:53:52'``)입니다. AmcacheParser 는
    그것을 파싱해 ISO 로 다시 쓰고, 우리는 원본 그대로 냅니다 —
    ``registry.py`` 가 문자열 값을 생김새로 재해석하지 않기 때문이고,
    그것은 의도된 설계입니다(`comparators.py` 의 "값의 생김새로 판단하지
    않는다"와 같은 자리).

    그래서 이 차이는 **파서의 오류가 아니라 표기의 차이**이고, 여기서
    양쪽을 같은 것으로 봅니다. 다만 하류에 남는 위험이 있습니다 —
    `docs/limitations.md` 참조.
    """
    text = str(value or "").strip().replace("T", " ").rstrip("Z")
    if len(text) >= 19 and text[2] == "/" and text[5] == "/":
        month, day, rest = text[:2], text[3:5], text[6:]
        year, clock = rest[:4], rest[4:].strip()
        text = f"{year}-{month}-{day} {clock}"
    return text[:19] if len(text) >= 19 else text


#: 범주별 대조 규칙.
#:
#: ``subkey``   — 우리 레코드의 ``path`` 에서 ``Amcache\\Root\\`` 다음 조각
#: ``csv``      — AmcacheParser CSV 파일명의 꼬리
#: ``key``      — 짝을 지을 열쇠. (CSV 열 이름, 우리 필드 이름)
#: ``compare``  — 비교할 필드들. (CSV 열, 우리 필드, 정규화 함수)
CATEGORIES: dict[str, dict[str, Any]] = {
    "InventoryApplicationFile": {
        "csv": "AssociatedFileEntries",
        "key": ("LongPathHash", "LongPathHash"),
        "compare": [
            ("FullPath", "LowerCaseLongPath", _lower),
            ("ProgramId", "ProgramId", _lower),
            ("Size", "Size", _int),
            ("BinaryType", "BinaryType", _lower),
            ("BinFileVersion", "BinFileVersion", _lower),
            ("FileKeyLastWriteTimestamp", "__timestamp__", _date),
        ],
    },
    "InventoryDriverBinary": {
        "csv": "DriveBinaries",
        "key": ("KeyName", "__name__"),
        "compare": [
            ("DriverName", "DriverName", _lower),
            ("DriverCompany", "DriverCompany", _lower),
            ("DriverVersion", "DriverVersion", _lower),
            ("ImageSize", "ImageSize", _int),
            ("Service", "Service", _lower),
            ("Inf", "Inf", _lower),
            ("KeyLastWriteTimestamp", "__timestamp__", _date),
        ],
    },
    "InventoryDeviceContainer": {
        "csv": "DeviceContainers",
        "key": ("KeyName", "__name__"),
        "compare": [
            ("Categories", "Categories", _lower),
            ("Manufacturer", "Manufacturer", _lower),
            ("ModelName", "ModelName", _lower),
            ("KeyLastWriteTimestamp", "__timestamp__", _date),
        ],
    },
    "InventoryApplication": {
        "csv": "ProgramEntries",
        "key": ("ProgramId", "__name__"),
        "compare": [
            ("Name", "Name", _lower),
            ("Publisher", "Publisher", _lower),
            ("Version", "Version", _lower),
            ("InstallDate", "InstallDate", _date),
            ("KeyLastWriteTimestamp", "__timestamp__", _date),
        ],
    },
    "InventoryDriverPackage": {
        "csv": "DriverPackages",
        "key": ("KeyName", "__name__"),
        "compare": [
            ("Class", "Class", _lower),
            ("Provider", "Provider", _lower),
            ("Version", "Version", _lower),
            ("KeyLastWriteTimestamp", "__timestamp__", _date),
        ],
    },
}

#: AmcacheParser 가 이 하이브에서 읽지 않는 서브키. 불일치가 아니라
#: **범위 결정의 차이**다 — 모듈 docstring 참조.
NOT_READ_BY_AMCACHEPARSER = ("File",)


def our_records(path: str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def subkey_of(record: dict[str, Any]) -> str:
    parts = [p for p in (record.get("path") or "").split(BACKSLASH) if p]
    return parts[2] if len(parts) > 2 else ""


def is_leaf(record: dict[str, Any]) -> bool:
    """컨테이너 키(``Amcache\\Root\\X``) 자체는 항목이 아니다."""
    return len([p for p in (record.get("path") or "").split(BACKSLASH) if p]) >= 4


def our_field(record: dict[str, Any], name: str) -> Any:
    if name == "__name__":
        return record.get("name")
    if name == "__timestamp__":
        return record.get("timestamp")
    return (record.get("fields") or {}).get(name)


def load_csv(directory: str, suffix: str) -> "list[dict[str, str]] | None":
    matches = glob.glob(os.path.join(directory, f"*_Amcache_{suffix}.csv"))
    if not matches:
        return None
    with open(max(matches, key=os.path.getmtime), encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def compare_category(
    subkey: str,
    rule: dict[str, Any],
    ours: list[dict[str, Any]],
    theirs: list[dict[str, str]],
    show: int,
) -> tuple[int, int, list[str]]:
    """(불일치 수, 짝지은 수, 사람이 읽을 줄들)."""
    csv_key, our_key = rule["key"]
    ours_by: dict[str, dict[str, Any]] = {}
    for record in ours:
        value = _lower(our_field(record, our_key))
        if value:
            ours_by[value] = record

    lines: list[str] = []
    matched = mismatches = missing = 0
    for row in theirs:
        key = _lower(row.get(csv_key))
        record = ours_by.pop(key, None)
        if record is None:
            missing += 1
            if missing <= show:
                lines.append(f"    우리에게 없음: {csv_key}={key[:60]}")
            continue
        matched += 1
        for csv_col, our_name, normalize in rule["compare"]:
            want = normalize(row.get(csv_col))
            got = normalize(our_field(record, our_name))
            # 저쪽이 빈 값이면 채점하지 않는다. CSV 는 없는 값을 빈 칸으로
            # 내는데, 그것과 "우리가 못 읽었다"를 구별할 수 없다.
            if not want:
                continue
            if want != got:
                mismatches += 1
                if mismatches <= show:
                    lines.append(
                        f"    값 불일치 [{csv_col}] {record.get('ref')}: "
                        f"저쪽={want[:50]!r} 우리={got[:50]!r}"
                    )

    for leftover in list(ours_by)[:show]:
        lines.append(f"    저쪽에 없음: {ours_by[leftover].get('ref')} ({leftover[:50]})")
    return mismatches + missing + len(ours_by), matched, lines


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ours", required=True, help="registry_amcache.jsonl (범위를 비우고 뽑은 것)")
    parser.add_argument("--amcache", required=True, help="AmcacheParser --csv 출력 디렉터리")
    parser.add_argument("--show", type=int, default=5, help="범주마다 보여 줄 불일치 예시 수")
    args = parser.parse_args(argv)

    records = our_records(args.ours)
    leaves = [r for r in records if is_leaf(r)]
    print(f"우리 레코드 {len(records)}건 (컨테이너 키 제외 항목 {len(leaves)}건)")
    print()

    total_bad = total_matched = 0
    header = "  범주".ljust(30) + "저쪽".rjust(7) + "우리".rjust(7) + "짝지음".rjust(8) + "불일치".rjust(8)
    print(header)
    print("  " + "-" * (len(header) - 2))

    details: list[str] = []
    for subkey, rule in CATEGORIES.items():
        theirs = load_csv(args.amcache, rule["csv"])
        ours = [r for r in leaves if subkey_of(r) == subkey]
        if theirs is None:
            print("  " + subkey.ljust(28) + "CSV 없음".rjust(7) + str(len(ours)).rjust(7))
            continue
        bad, matched, lines = compare_category(subkey, rule, ours, theirs, args.show)
        total_bad += bad
        total_matched += matched
        print(
            "  "
            + subkey.ljust(28)
            + str(len(theirs)).rjust(7)
            + str(len(ours)).rjust(7)
            + str(matched).rjust(8)
            + str(bad).rjust(8)
        )
        if lines:
            details.append("  == " + subkey)
            details.extend(lines)

    skipped = [r for r in leaves if subkey_of(r) in NOT_READ_BY_AMCACHEPARSER]
    if skipped:
        print()
        print(f"  AmcacheParser 가 안 읽는 서브키: {len(skipped)}건 "
              f"({', '.join(NOT_READ_BY_AMCACHEPARSER)})")
        print("    → 불일치가 아니라 범위 결정의 차이다. 채점하지 않는다.")

    if details:
        print()
        print("불일치 상세")
        print("\n".join(details))

    print()
    if total_bad == 0:
        print(f"판정: 통과 — 짝지은 {total_matched}건 전부 일치")
        return 0
    print(f"판정: 불일치 {total_bad}건 (짝지은 {total_matched}건 중)")
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
