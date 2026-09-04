"""``tools/compare_prefetch.py`` — 우리 프리패치 출력과 PECmd 결과의 대조.

이 도구의 존재 이유는 우리 파서를 **밖에서** 채점하는 것입니다. 그래서 이
테스트가 지키는 성질도 둘뿐입니다.

**하나 — 도구 차이를 파서의 오류로 세지 않는가.** 2026-09-05 의 첫 실물
대조(192건)에서 유일한 "불일치"가 그 부류였습니다. PECmd 는 ``FilesLoaded``
를 쉼표로 이어 붙여 내는데 .NET 어셈블리 경로는 **이름 안에 쉼표를 품습니다**.
한 항목이 넷으로 세어져 우리 198 / 저쪽 201 이 됐고, 파서는 옳았습니다.
이런 오탐은 조용히 틀리는 쪽보다 나쁩니다 — 멀쩡한 파서를 고치러 가게 만듭니다.

**둘 — 진짜 어긋난 것은 잡는가.** 통과만 시키는 대조는 대조가 아닙니다.
채점하는 셋(실행 횟수·실행 시각·경로 해시) 각각을 일부러 틀려서 봅니다.
실행 시각은 **개수·순서·값** 셋이 따로 어긋날 수 있어 셋 다 겨눕니다.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from tools.compare_prefetch import (
    compare,
    load_ours,
    load_pecmd,
    _loaded_count,
)


# =============================================================== 합성

#: 실물에서 나온 모양 그대로. ``ASSEMBLY`` 경로가 이름 안에 쉼표를 품는다.
ASSEMBLY_PATH = (
    r"\VOLUME{01dd34881fccb9be-501fdb3f}\WINDOWS\ASSEMBLY\GIT-CREDENTIAL-MANAGER,"
    r" VERSION=2.9.0.0, CULTURE=NEUTRAL, PUBLICKEYTOKEN=NULL\GCM.DLL"
)

PECMD_COLUMNS = [
    "SourceFilename",
    "ExecutableName",
    "Hash",
    "Version",
    "RunCount",
    "LastRun",
    "PreviousRun0",
    "PreviousRun1",
    "Volume0Serial",
    "Volume0Created",
    "FilesLoaded",
]


def ours_row(
    *,
    prefetch_file: str = "GCM.EXE-017B887C.pf",
    run_count: int = 5,
    run_times: "list[str] | None" = None,
    path_hash: str = "17B887C",
    loaded_file_count: int = 2,
) -> dict:
    return {
        "ref": f"prefetch#{prefetch_file}",
        "artifact": "prefetch",
        "name": "GCM.EXE",
        "fields": {
            "prefetch_file": prefetch_file,
            "path_hash": path_hash,
            "run_count": run_count,
            "run_times": run_times
            if run_times is not None
            else ["2026-08-31T09:36:39Z", "2026-08-31T08:52:12Z"],
            "loaded_file_count": loaded_file_count,
            "format_version": "30",
            "volumes": [],
        },
    }


def write_ours(tmp_path: Path, rows: "list[dict]") -> Path:
    import json

    path = tmp_path / "prefetch.jsonl"
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    return path


def write_pecmd(
    tmp_path: Path,
    *,
    files_loaded: str,
    run_count: int = 5,
    last_run: str = "2026-08-31 09:36:39",
    previous: "tuple[str, str]" = ("2026-08-31 08:52:12", ""),
    path_hash: str = "17B887C",
    source_file: str = "GCM.EXE-017B887C.pf",
) -> Path:
    """``--csv`` 출력 모양으로. 디렉터리를 돌려준다 (도구가 받는 형태)."""
    out = tmp_path / "pecmd_out"
    out.mkdir(exist_ok=True)
    path = out / "20260905000000_PECmd_Output.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PECMD_COLUMNS)
        writer.writeheader()
        writer.writerow(
            {
                "SourceFilename": rf"C:\Windows\Prefetch\{source_file}",
                "ExecutableName": "GCM.EXE",
                "Hash": path_hash,
                "Version": "Windows 10 or Windows 11",
                "RunCount": str(run_count),
                "LastRun": last_run,
                "PreviousRun0": previous[0],
                "PreviousRun1": previous[1],
                "Volume0Serial": "",
                "Volume0Created": "",
                "FilesLoaded": files_loaded,
            }
        )
    return out


# =============================== 하나 — 도구 차이를 오류로 세지 않는다


@pytest.mark.parametrize(
    "text, expected",
    [
        # 실물에서 터진 자리. 항목 둘인데 쉼표가 넷이다.
        (rf"\VOLUME{{a}}\NTDLL.DLL, {ASSEMBLY_PATH}", 2),
        # 평범한 경우.
        (r"\VOLUME{a}\A.DLL, \VOLUME{a}\B.DLL", 2),
        # 드라이브 문자로 내는 판.
        (r"C:\A.DLL, C:\B.DLL", 2),
        # 파이프로 잇는 판.
        (r"\VOLUME{a}\A.DLL|\VOLUME{a}\B.DLL|\VOLUME{a}\C.DLL", 3),
        # 개수(정수)로 내는 판.
        ("42", 42),
        # 경로처럼 안 생긴 표기 하나 — 0 으로 뭉개지 않는다.
        # 0 은 "적재 파일이 없다"라는 다른 뜻이다.
        ("SOMETHING", 1),
    ],
)
def test_loaded_count_는_경로_안의_쉼표에_속지_않는다(text: str, expected: int) -> None:
    assert _loaded_count(text) == expected


def test_loaded_count_는_빈_값을_None_으로_낸다() -> None:
    """빈 칸은 0 이 아니라 "저쪽이 안 냈다"이다. 0 으로 뭉개면 채점된다."""
    assert _loaded_count("") is None
    assert _loaded_count(None) is None


def test_쉼표를_품은_경로가_불일치를_만들지_않는다(tmp_path: Path) -> None:
    """실물 재현. 이 경로 하나가 192건 대조의 유일한 오탐이었다."""
    ours = load_ours(write_ours(tmp_path, [ours_row(loaded_file_count=2)]))
    theirs, absent = load_pecmd(
        _csv_in(write_pecmd(tmp_path, files_loaded=rf"\VOLUME{{a}}\NTDLL.DLL, {ASSEMBLY_PATH}"))
    )

    report = compare(ours, theirs, full=True, ungraded=absent)

    # 채점을 건너뛰어서 통과한 것이 아님을 못박는다. ``FilesLoaded`` 가
    # 채점 대상에서 빠져 있으면 이 테스트는 무엇도 지키지 않는다.
    assert absent == ()
    assert report.mismatches == []
    assert report.passed()


def test_적재_파일_수가_다르면_잡는다(tmp_path: Path) -> None:
    """위 테스트가 공허하지 않다는 증거. 이 자리는 실제로 채점된다."""
    ours = load_ours(write_ours(tmp_path, [ours_row(loaded_file_count=3)]))
    theirs, absent = load_pecmd(
        _csv_in(write_pecmd(tmp_path, files_loaded=rf"\VOLUME{{a}}\NTDLL.DLL, {ASSEMBLY_PATH}"))
    )

    report = compare(ours, theirs, full=True, ungraded=absent)

    assert [m.field for m in report.mismatches] == ["loaded_count"]


# =============================== 둘 — 진짜 어긋난 것은 잡는다


def test_실행_횟수가_다르면_잡는다(tmp_path: Path) -> None:
    ours = load_ours(write_ours(tmp_path, [ours_row(run_count=5)]))
    theirs, absent = load_pecmd(
        _csv_in(write_pecmd(tmp_path, files_loaded="2", run_count=6))
    )

    report = compare(ours, theirs, full=True, ungraded=absent)

    assert [m.field for m in report.mismatches] == ["run_count"]
    assert not report.passed()


def test_경로_해시가_다르면_잡는다(tmp_path: Path) -> None:
    """``ref`` 의 근거다. 여기가 틀리면 원본 대조가 통째로 무너진다."""
    ours = load_ours(write_ours(tmp_path, [ours_row(path_hash="DEADBEEF")]))
    theirs, absent = load_pecmd(_csv_in(write_pecmd(tmp_path, files_loaded="2")))

    report = compare(ours, theirs, full=True, ungraded=absent)

    assert [m.field for m in report.mismatches] == ["path_hash"]


@pytest.mark.parametrize(
    "run_times, 왜",
    [
        (["2026-08-31T09:36:39Z"], "개수가 하나 적다"),
        (["2026-08-31T08:52:12Z", "2026-08-31T09:36:39Z"], "순서가 뒤집혔다"),
        (["2001-01-01T00:00:00Z", "2026-08-31T08:52:12Z"], "값 하나가 틀렸다"),
    ],
)
def test_실행_시각은_개수_순서_값_셋_다_잡는다(
    tmp_path: Path, run_times: "list[str]", 왜: str
) -> None:
    """자리를 잘못 잡으면 값보다 개수가 먼저 어긋난다 — 셋을 따로 본다."""
    ours = load_ours(write_ours(tmp_path, [ours_row(run_times=run_times)]))
    theirs, absent = load_pecmd(_csv_in(write_pecmd(tmp_path, files_loaded="2")))

    report = compare(ours, theirs, full=True, ungraded=absent)

    assert [m.field for m in report.mismatches] == ["run_times"], 왜


def test_우리에만_있는_pf_는_full_이_아니어도_실패다(tmp_path: Path) -> None:
    """없는 것을 지어낸 것이다. 선별 범위와 무관하게 오류다."""
    ours = load_ours(
        write_ours(
            tmp_path,
            [ours_row(), ours_row(prefetch_file="GHOST.EXE-00000000.pf")],
        )
    )
    theirs, absent = load_pecmd(_csv_in(write_pecmd(tmp_path, files_loaded="2")))

    report = compare(ours, theirs, full=False, ungraded=absent)

    assert report.extra_in_ours == ["ghost.exe-00000000.pf"]
    assert not report.passed()


def test_prefetch_파서의_출력이_아니면_멈춘다(tmp_path: Path) -> None:
    """조용히 건너뛰면 "짝지은 0건 전부 일치"라는 무의미한 통과가 나온다."""
    row = ours_row()
    del row["fields"]["prefetch_file"]

    with pytest.raises(ValueError, match="prefetch_file"):
        load_ours(write_ours(tmp_path, [row]))


def _csv_in(directory: Path) -> Path:
    from tools.compare_prefetch import find_csv

    return find_csv(directory)
