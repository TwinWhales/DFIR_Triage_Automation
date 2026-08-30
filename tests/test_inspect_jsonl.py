"""``tools/inspect_jsonl.py`` — 04단계 산출물의 요약과 조회.

요약 쪽 테스트는 전부 **어긋난 것을 잡는가**입니다. 이 도구가 세는 값은
`_manifest.json`이 이미 적어 둔 값과 같아야 하는데, 같은지 아무도 보지
않던 자리라 도구를 만든 것이고, 그렇다면 도구가 다름을 실제로 알아채는지가
전부입니다. 통과만 시키는 대조는 대조가 아닙니다.

조회 쪽은 **조건이 조건대로 걸리는가**입니다. `--flag` 둘을 주면 AND 이고,
`--path`는 부분 일치에 대소문자를 무시합니다. 이것이 어긋나면 "안 나왔다"와
"없다"가 구별되지 않습니다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.inspect_jsonl import (
    InspectError,
    display_width,
    main,
    summarize,
)


# =============================================================== 합성


def mft(ref: str, number: int, path: str, flags: "list[str] | None" = None) -> dict:
    return {
        "ref": ref,
        "artifact": "$MFT",
        "record_num": number,
        "offset": f"0x{number * 1024:X}",
        "path": path,
        "name": path.rsplit("\\", 1)[-1],
        "flags": flags or [],
    }


def evtx(ref: str, number: int, event_id: int, when: str, flags: "list[str] | None" = None) -> dict:
    return {
        "ref": ref,
        "artifact": "evtx:System",
        "record_num": number,
        "offset": f"0x{number * 512:X}",
        "event_id": event_id,
        "timestamp": when,
        "channel": "System",
        "computer": "WIN-TEST",
        "flags": flags or [],
    }


def write_parsed(
    tmp_path: Path,
    files: "dict[str, list[dict]]",
    *,
    manifest: bool = True,
    counts: "dict[str, int] | None" = None,
    totals: "tuple[int, int] | None" = None,
    extra_files: "list[str] | None" = None,
) -> Path:
    """``04_parsed/`` 하나를 만든다.

    ``counts``·``totals``로 매니페스트에 **일부러 다른 값**을 적을 수
    있습니다. 그것이 이 테스트들의 절반입니다.
    """
    parsed = tmp_path / "04_parsed"
    parsed.mkdir(exist_ok=True)

    for filename, records in files.items():
        with (parsed / filename).open("w", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    if manifest:
        entries = [
            {
                "artifact": records[0]["artifact"] if records else "$MFT",
                "path": filename,
                "record_count": (counts or {}).get(filename, len(records)),
                "flagged_count": sum(1 for r in records if r["flags"]),
                "parse_errors": 0,
            }
            for filename, records in files.items()
        ]
        entries.extend(
            {"artifact": "$UsnJrnl", "path": name, "record_count": 1, "flagged_count": 0}
            for name in (extra_files or [])
        )
        total, flagged = totals or (
            sum(len(r) for r in files.values()),
            sum(1 for records in files.values() for r in records if r["flags"]),
        )
        (parsed / "_manifest.json").write_text(
            json.dumps(
                {
                    "case_id": "T-001",
                    "stage": "04_parse",
                    "schema_version": "1.0",
                    "generated_at": "2026-08-30T00:00:00Z",
                    "generator": "parse.py / native",
                    "files": entries,
                    "skipped": [],
                    "windows": {"determined": True, "family": "win10", "build": "15063"},
                    "total_records": total,
                    "flagged_records": flagged,
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
    return parsed


SAMPLE = {
    "mft.jsonl": [
        mft("MFT#1", 1, "C:\\Windows\\System32\\cmd.exe"),
        mft("MFT#2", 2, "C:\\Users\\Public\\banker.exe", ["deleted"]),
        mft("MFT#3", 3, "C:\\Users\\public\\dropper.dll", ["deleted", "timestamp_mismatch"]),
    ],
    "evtx_system.jsonl": [
        evtx("EVTX-SYS#10", 10, 7045, "2026-08-01T10:00:00.0000000Z", ["service_installed"]),
        evtx("EVTX-SYS#11", 11, 7040, "2026-08-02T10:00:00.0000000Z"),
    ],
}


# =============================================================== 요약


def test_summary_counts_the_files_not_the_manifest(tmp_path, capsys):
    parsed = write_parsed(tmp_path, SAMPLE)

    code = main(["--parsed", str(parsed)])
    out = capsys.readouterr().out

    assert code == 0
    assert "$MFT" in out and "evtx:System" in out

    total = next(line for line in out.splitlines() if line.strip().startswith("합계"))
    # 레코드 5건, 그중 **플래그가 붙은 레코드** 3건. 플래그 개수(4)가 아니다 —
    # 둘을 섞으면 05단계 쿼터 이야기가 어긋난다.
    assert total.split()[1:] == ["5", "3"]

    # 분포는 플래그마다 센다. 이쪽이 4건이다.
    assert "deleted" in out and "timestamp_mismatch" in out
    assert "✓ 매니페스트 record_count = 실제 줄 수" in out


def test_summary_catches_a_manifest_that_overcounts(tmp_path, capsys):
    """07단계 보고서가 싣는 값이다. 파일과 다르면 보고서가 틀린 수를 싣는다."""
    parsed = write_parsed(tmp_path, SAMPLE, counts={"mft.jsonl": 9})

    code = main(["--parsed", str(parsed)])
    out = capsys.readouterr().out

    assert code == 1
    assert "매니페스트는 9건인데" in out


def test_summary_catches_wrong_totals(tmp_path, capsys):
    parsed = write_parsed(tmp_path, SAMPLE, totals=(999, 0))

    code = main(["--parsed", str(parsed)])
    out = capsys.readouterr().out

    assert code == 1
    assert "total_records" in out
    assert "flagged_records" in out


def test_summary_catches_a_duplicate_ref(tmp_path, capsys):
    """겹치면 05·06단계가 선다. **04 직후에 알아야 한다.**"""
    files = {
        "mft.jsonl": [mft("MFT#1", 1, "C:\\a.exe")],
        "evtx_system.jsonl": [evtx("EVTX-SYS#10", 10, 7045, "2026-08-01T10:00:00.0000000Z")],
    }
    files["evtx_system.jsonl"][0]["ref"] = "MFT#1"
    files["evtx_system.jsonl"][0]["record_num"] = 1
    parsed = write_parsed(tmp_path, files)

    code = main(["--parsed", str(parsed)])
    out = capsys.readouterr().out

    assert code == 1
    assert "양쪽에 있다" in out


def test_summary_catches_record_num_that_disagrees_with_the_ref(tmp_path, capsys):
    """스키마가 보지 않는 불변식이다 — 여기서 안 보면 아무도 안 본다."""
    records = [mft("MFT#1", 1, "C:\\a.exe")]
    records[0]["record_num"] = 77
    parsed = write_parsed(tmp_path, {"mft.jsonl": records})

    code = main(["--parsed", str(parsed)])
    assert code == 1
    assert "ref 와 다르다" in capsys.readouterr().out


def test_summary_catches_a_record_in_the_wrong_file(tmp_path, capsys):
    """파서가 남의 파일에 쓰면 06단계가 그것을 환각으로 집계한다."""
    records = [mft("MFT#1", 1, "C:\\a.exe")]
    records[0]["artifact"] = "evtx:System"
    parsed = write_parsed(tmp_path, {"mft.jsonl": records})

    code = main(["--parsed", str(parsed)])
    assert code == 1
    assert "의 파일이다" in capsys.readouterr().out


def test_summary_catches_a_file_the_manifest_promised(tmp_path, capsys):
    parsed = write_parsed(tmp_path, SAMPLE, extra_files=["usnjrnl.jsonl"])

    code = main(["--parsed", str(parsed)])
    assert code == 1
    assert "파일이 없다" in capsys.readouterr().out


def test_summary_does_not_silently_count_a_foreign_file(tmp_path, capsys):
    """04단계가 내지 않는 이름은 합계에 넣지 않는다. 조용히 넣으면 수가 오염된다."""
    parsed = write_parsed(tmp_path, SAMPLE)
    (parsed / "notes.jsonl").write_text('{"ref": "X#1"}\n', encoding="utf-8")

    code = main(["--parsed", str(parsed)])
    out = capsys.readouterr().out

    assert code == 1
    assert "04단계가 내는 파일 이름이 아니다" in out


def test_summary_without_a_manifest_says_so_and_still_checks_the_rest(tmp_path, capsys):
    """중단된 실행에는 매니페스트가 없다. 산출물은 있는데 완료는 아니다."""
    parsed = write_parsed(tmp_path, SAMPLE, manifest=False)

    code = main(["--parsed", str(parsed)])
    out = capsys.readouterr().out

    assert code == 0
    assert "_manifest.json 이 없다" in out
    assert "✓ ref 유일" in out


def test_summary_reports_the_time_span_and_the_records_without_one(tmp_path, capsys):
    """`$MFT`는 시각이 ``si_*``에 있어 ``timestamp``가 없다. 없다고 말한다."""
    parsed = write_parsed(tmp_path, SAMPLE)

    main(["--parsed", str(parsed)])
    out = capsys.readouterr().out

    assert "2026-08-01 … 2026-08-02" in out
    assert "timestamp 필드 없음" in out


def test_summary_needs_a_directory_with_output(tmp_path):
    empty = tmp_path / "04_parsed"
    empty.mkdir()
    with pytest.raises(InspectError) as e:
        summarize(empty)
    assert ".jsonl 이 없다" in str(e.value)


# =============================================================== 조회


def test_flags_are_and_not_or(tmp_path, capsys):
    """둘을 주면 둘 다 붙은 것만. OR 면 "왜 이게 나왔나"를 말할 수 없다."""
    parsed = write_parsed(tmp_path, SAMPLE)

    main(["--parsed", str(parsed), "--flag", "deleted", "--flag", "timestamp_mismatch"])
    out = capsys.readouterr().out

    assert "MFT#3" in out
    assert "MFT#2" not in out


def test_path_match_is_a_case_insensitive_substring(tmp_path, capsys):
    """`Public`과 `public`이 갈리면 실물에서 놓친다."""
    parsed = write_parsed(tmp_path, SAMPLE)

    main(["--parsed", str(parsed), "--path", "users\\public"])
    out = capsys.readouterr().out

    assert "MFT#2" in out and "MFT#3" in out
    assert "MFT#1" not in out


def test_event_id_filter(tmp_path, capsys):
    parsed = write_parsed(tmp_path, SAMPLE)

    main(["--parsed", str(parsed), "--event-id", "7045"])
    out = capsys.readouterr().out

    assert "EVTX-SYS#10" in out
    assert "EVTX-SYS#11" not in out


def test_ref_prints_the_whole_record_and_points_at_the_bytes(tmp_path, capsys):
    """펼쳐 보고 나면 다음 질문은 "원본은?"이다. 그 도구로 넘긴다."""
    parsed = write_parsed(tmp_path, SAMPLE)

    main(["--parsed", str(parsed), "--ref", "MFT#2"])
    out = capsys.readouterr().out

    assert '"offset": "0x800"' in out
    assert "hexdump_record.py MFT#2" in out


def test_json_output_is_the_record_itself(tmp_path, capsys):
    """파이프로 넘길 때 우리 표기를 끼얹지 않는다."""
    parsed = write_parsed(tmp_path, SAMPLE)

    main(["--parsed", str(parsed), "--flag", "deleted", "--json"])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]

    assert [r["ref"] for r in lines] == ["MFT#2", "MFT#3"]


def test_limit_still_reports_the_true_total(tmp_path, capsys):
    """표본을 봤는지 전부를 봤는지 갈려야 한다."""
    parsed = write_parsed(tmp_path, SAMPLE)

    main(["--parsed", str(parsed), "--flag", "deleted", "--limit", "1"])
    out = capsys.readouterr().out

    assert "1건 표시 (총 2건 일치)" in out


def test_no_match_is_not_a_failure(tmp_path, capsys):
    """없는 것은 정상 결과다. 종료 코드로 실패를 뜻하지 않는다."""
    parsed = write_parsed(tmp_path, SAMPLE)

    code = main(["--parsed", str(parsed), "--path", "없는경로"])
    assert code == 0
    assert "일치하는 레코드가 없다" in capsys.readouterr().out


def test_unknown_artifact_name_is_refused(tmp_path, capsys):
    parsed = write_parsed(tmp_path, SAMPLE)

    code = main(["--parsed", str(parsed), "--artifact", "evtx:없는채널"])
    assert code == 1
    assert "아는 이름이 아니다" in capsys.readouterr().err


def test_artifact_filter_narrows_to_one_file(tmp_path, capsys):
    parsed = write_parsed(tmp_path, SAMPLE)

    main(["--parsed", str(parsed), "--artifact", "$MFT"])
    out = capsys.readouterr().out

    assert "MFT#1" in out
    assert "EVTX-SYS" not in out


# =============================================================== 부속


def test_korean_counts_as_two_columns():
    """한글이 한 칸으로 세지면 표가 어긋난다."""
    assert display_width("아티팩트") == 8
    assert display_width("$MFT") == 4
