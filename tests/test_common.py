"""src/common/ 단위 테스트."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.common import attack, errors, io, refs
from casepaths import FIXTURES

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------- refs


def test_make_ref_round_trips():
    ref = refs.make_ref("$MFT", 12345)
    assert ref == "MFT#12345"
    parsed = refs.parse_ref(ref)
    assert (parsed.prefix, parsed.record_num, parsed.artifact) == ("MFT", 12345, "$MFT")


@pytest.mark.parametrize(
    "artifact,expected",
    [
        ("$MFT", "MFT#7"),
        ("$UsnJrnl", "USN#7"),
        ("evtx:Security", "EVTX-SEC#7"),
        ("evtx:System", "EVTX-SYS#7"),
        ("registry:SYSTEM", "REG-SYS#7"),
        ("registry:SOFTWARE", "REG-SW#7"),
        ("registry:Amcache", "AMCACHE#7"),
        ("evtx:Firewall", "EVTX-FW#7"),
        ("evtx:BITS", "EVTX-BITS#7"),
        ("evtx:NetworkProfile", "EVTX-NET#7"),
        ("prefetch", "PF#7"),
    ],
)
def test_every_registered_artifact_has_a_prefix(artifact, expected):
    assert refs.make_ref(artifact, 7) == expected


@pytest.mark.parametrize("artifact", sorted(refs.ARTIFACT_PREFIX))
def test_every_prefix_survives_a_round_trip(artifact):
    """``ARTIFACT_PREFIX`` 만 고치고 ``REF_PATTERN`` 을 잊는 실수를 잡는다.

    ``make_ref`` 는 딕셔너리만 보므로 통과하고, ``parse_ref`` 에서 터진다.
    접두어가 서로의 접두사인 경우(``EVTX-BITS`` 와 ``EVTX-B...``)도 여기서
    갈린다 — 정규식 대안의 순서가 틀리면 왕복이 깨진다.
    """
    parsed = refs.parse_ref(refs.make_ref(artifact, 7))
    assert (parsed.record_num, parsed.artifact) == (7, artifact)


def test_no_prefix_is_a_prefix_of_another():
    """접두어끼리 앞부분이 겹치지 않아야 한다.

    겹쳐도 ``REF_PATTERN`` 은 백트래킹으로 풀린다 — 그래서 왕복 테스트는
    통과한다. 그런데도 막아 두는 이유는, 정규식 말고 다른 방법으로
    접두어를 가르는 코드(``split("#")`` 후 사전 조회, 문자열 ``startswith``)
    가 나중에 붙으면 그쪽은 조용히 틀리기 때문이다.

    실제로 걸렸다: ``evtx:Sysmon`` 에 ``EVTX-SYSMON`` 을 주려다
    ``EVTX-SYS``(evtx:System)의 확장이 되는 것을 보고 ``SYSMON`` 으로
    바꿨다(2026-08-25).
    """
    prefixes = sorted(refs.ARTIFACT_PREFIX.values())
    overlaps = [
        (a, b) for a in prefixes for b in prefixes if a != b and b.startswith(a)
    ]
    assert overlaps == [], f"접두어가 서로의 앞부분이다: {overlaps}"


def test_amcache_ref_round_trips_through_parse_ref():
    # ARTIFACT_PREFIX 만 고치고 REF_PATTERN 을 잊는 실수를
    # make_ref 만으로는 못 잡는다 — parse_ref 까지 왕복시켜야 잡힌다.
    ref = refs.make_ref("registry:Amcache", 0x1A2B3C)
    assert ref == "AMCACHE#1715004"
    parsed = refs.parse_ref(ref)
    assert (parsed.prefix, parsed.record_num, parsed.artifact) == (
        "AMCACHE",
        0x1A2B3C,
        "registry:Amcache",
    )


def test_unknown_artifact_is_rejected_with_the_list_of_known_ones():
    with pytest.raises(refs.RefError) as e:
        refs.make_ref("$LogFile", 1)
    assert "$MFT" in str(e.value)


def test_bool_is_not_accepted_as_a_record_number():
    # isinstance(True, int)가 참이라 방심하면 MFT#1 이 만들어진다.
    with pytest.raises(refs.RefError):
        refs.make_ref("$MFT", True)


def test_negative_record_number_is_rejected():
    with pytest.raises(refs.RefError):
        refs.make_ref("$MFT", -1)


@pytest.mark.parametrize(
    "bad",
    ["MFT12345", "MFT#", "#12345", "mft#12345", "MFT#12a", "LOG#1", "MFT#012345", "MFT#1 ", ""],
)
def test_malformed_refs_are_rejected(bad):
    assert not refs.is_valid(bad)
    with pytest.raises(refs.RefError):
        refs.parse_ref(bad)


def test_leading_zero_is_rejected_so_refs_compare_as_strings():
    # 06단계는 refs를 집합으로 대조한다. 같은 레코드가 두 표기를 가지면
    # 통과해야 할 문장이 ref_not_in_input 으로 기각된다.
    assert refs.is_valid("MFT#12345")
    assert not refs.is_valid("MFT#012345")


def test_zero_is_a_valid_record_number():
    assert refs.is_valid("MFT#0")
    assert refs.record_num_of("MFT#0") == 0


def test_prefix_map_is_bijective():
    assert len(refs.ARTIFACT_PREFIX) == len(refs.PREFIX_ARTIFACT)


# ------------------------------------------------------------------ io


def test_json_round_trip_preserves_korean_and_backslashes(tmp_path):
    doc = io.new_document(
        "C-001", "02_normalize", "test", paths=["C:\\inetpub\\wwwroot"], note="한글 주석"
    )
    p = tmp_path / "out.json"
    io.write_json(p, doc)
    back = io.read_json(p)
    assert back == doc
    # ensure_ascii=False 라야 사람이 파일을 열어 읽을 수 있다.
    assert "한글 주석" in p.read_text(encoding="utf-8")


def test_written_files_use_lf_even_on_windows(tmp_path):
    # JSONL에 CR이 섞이면 리눅스 쪽에서 마지막 필드에 \r 이 달려 들어가
    # 값 비교가 조용히 틀어진다.
    j = tmp_path / "a.json"
    io.write_json(j, {"a": 1, "b": 2})
    assert b"\r\n" not in j.read_bytes()

    jl = tmp_path / "a.jsonl"
    io.write_jsonl(jl, [{"a": 1}, {"a": 2}])
    assert b"\r\n" not in jl.read_bytes()

    io.append_jsonl(jl, {"a": 3})
    assert b"\r\n" not in jl.read_bytes()


def test_header_is_first_in_the_file(tmp_path):
    doc = io.new_document("C-001", "03_select", "select.py", selected=[])
    p = tmp_path / "out.json"
    io.write_json(p, doc)
    keys = list(json.loads(p.read_text(encoding="utf-8")).keys())
    assert keys[:5] == list(io.HEADER_FIELDS)


def test_schema_version_mismatch_is_an_immediate_error():
    doc = io.new_document("C-001", "02_normalize", "x")
    doc["schema_version"] = "0.9"
    with pytest.raises(io.HeaderError, match="schema_version"):
        io.check_header(doc)


def test_stage_mismatch_is_caught():
    doc = io.new_document("C-001", "02_normalize", "x")
    with pytest.raises(io.HeaderError, match="stage"):
        io.check_header(doc, expected_stage="03_select")


def test_generator_is_optional_only_when_asked():
    doc = io.new_document("C-001", "01_input", "x")
    del doc["generator"]
    with pytest.raises(io.HeaderError, match="generator"):
        io.check_header(doc)
    io.check_header(doc, require_generator=False)  # 01_input 경로


def test_make_generator_records_the_model():
    assert io.make_generator("normalize.py", "qwen2.5-7b-q4") == "normalize.py / qwen2.5-7b-q4"
    assert io.make_generator("select.py") == "select.py"


def test_jsonl_round_trip_and_count(tmp_path):
    p = tmp_path / "r.jsonl"
    records = [{"ref": f"MFT#{i}", "n": i} for i in range(5)]
    assert io.write_jsonl(p, records) == 5
    assert list(io.read_jsonl(p)) == records
    assert io.count_jsonl(p) == 5


def test_blank_lines_in_jsonl_are_skipped(tmp_path):
    p = tmp_path / "r.jsonl"
    p.write_text('{"a":1}\n\n{"a":2}\n', encoding="utf-8")
    assert list(io.read_jsonl(p)) == [{"a": 1}, {"a": 2}]


def test_broken_jsonl_reports_the_line_number(tmp_path):
    p = tmp_path / "r.jsonl"
    p.write_text('{"a":1}\n{oops}\n', encoding="utf-8")
    with pytest.raises(ValueError, match=r":2:"):
        list(io.read_jsonl(p))


def test_atomic_write_leaves_no_temp_file_behind(tmp_path):
    io.write_json(tmp_path / "x.json", {"a": 1})
    assert [p.name for p in tmp_path.iterdir()] == ["x.json"]


def test_failed_write_does_not_clobber_the_existing_file(tmp_path):
    p = tmp_path / "x.json"
    io.write_json(p, {"good": True})

    class Unserialisable:
        pass

    with pytest.raises(TypeError):
        io.write_json(p, {"bad": Unserialisable()})
    # 반쯤 쓰인 파일이 남으면 다음 실행이 그것을 정상 산출물로 읽는다.
    assert io.read_json(p) == {"good": True}
    assert list(tmp_path.iterdir()) == [p]


# -------------------------------------------------------------- errors


def test_error_log_writes_the_expected_shape(tmp_path):
    log = errors.ErrorLog.for_case(tmp_path)
    entry = log.record(
        "02_normalize",
        "schema_violation",
        {"field": "techniques[0].id", "value": "T9999", "message": "유효하지 않은 ATT&CK ID"},
        action="retry",
        attempt=1,
    )
    assert entry["stage"] == "02_normalize"
    assert entry["attempt"] == 1
    assert list(io.read_jsonl(tmp_path / "errors.jsonl")) == [entry]


def test_attempt_is_omitted_when_not_given(tmp_path):
    log = errors.ErrorLog.for_case(tmp_path)
    entry = log.record("04_parse", "parse_error", {"message": "x"}, action="skip")
    assert "attempt" not in entry


@pytest.mark.parametrize("bad_type", ["parse_err", "PARSE_ERROR", "unknown"])
def test_unregistered_error_type_is_refused(tmp_path, bad_type):
    # 한 번 오타가 들어가면 발표용 실패율이 조용히 낮게 집계된다.
    log = errors.ErrorLog.for_case(tmp_path)
    with pytest.raises(ValueError, match="미등록 오류 유형"):
        log.record("04_parse", bad_type, {}, action="skip")
    assert not (tmp_path / "errors.jsonl").exists()


def test_unregistered_action_is_refused(tmp_path):
    log = errors.ErrorLog.for_case(tmp_path)
    with pytest.raises(ValueError, match="미등록 조치"):
        log.record("04_parse", "parse_error", {}, action="continue")


def test_abort_records_then_exits_nonzero(tmp_path):
    log = errors.ErrorLog.for_case(tmp_path)
    with pytest.raises(SystemExit) as e:
        log.abort("02_normalize", "empty_result", {"message": "techniques 비어 있음"})
    assert e.value.code == 1
    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert logged[0]["action"] == "abort"


def test_tally_produces_the_presentation_numbers():
    stats = errors.tally(
        FIXTURES / "errors.jsonl"
    )
    assert stats["total"] == 4
    assert stats["by_type"]["schema_violation"] == 2
    assert stats["by_stage_type"]["02_normalize/schema_violation"] == 2
    assert stats["by_action"]["retry"] == 3
    # detail.field 분포가 "어느 필드에서 sLLM이 자주 틀리는가"를 보여준다.
    assert stats["by_field"] == {"techniques[0].id": 1, "confidence": 1}


# -------------------------------------------------------------- attack


def test_format_and_membership_are_separate_checks():
    # T9999는 형식은 맞고 실재하지 않는다. 이 둘을 나눠야
    # "존재하지 않는 ATT&CK ID 생성" 비율이 따로 집계된다.
    assert attack.is_valid_format("T9999")
    assert not attack.is_known("T9999")
    assert attack.is_valid_format("T1505.003")
    assert attack.is_known("T1505.003")


@pytest.mark.parametrize("bad", ["웹셸", "T150", "T15055", "1505.003", "t1505.003", "T1505.3", None])
def test_malformed_technique_ids_are_rejected(bad):
    assert not attack.is_valid_format(bad)


def test_check_id_distinguishes_the_two_failure_modes():
    with pytest.raises(attack.AttackIdError, match="형식 위반"):
        attack.check_id("웹셸")
    with pytest.raises(attack.AttackIdError, match="유효하지 않은"):
        attack.check_id("T9999")
    assert attack.check_id("T9999", require_known=False) == "T9999"


def test_known_catalogue_covers_every_mapping_file():
    # 매핑 테이블이 있는데 카탈로그에 없으면, 정상 기법이 스키마 위반으로
    # 기각되면서 원인이 모델 탓으로 잘못 집계된다.
    mapped = attack.mapped_techniques(REPO_ROOT / "mappings")
    assert mapped, "mappings/ 에서 기법 파일을 찾지 못했다"
    assert mapped <= set(attack.KNOWN_TECHNIQUES)


def test_unmapped_finds_techniques_without_a_mapping_table():
    result = attack.unmapped(["T1505.003", "T1486"], REPO_ROOT / "mappings")
    # T1486(랜섬웨어)은 카탈로그에는 있으나 매핑 파일이 아직 없다.
    assert result == ["T1486"]


# ==================================================== UTF-8로 쓸 수 없는 값


def test_an_unencodable_record_names_itself_instead_of_a_bare_position(tmp_path):
    """맨 ``UnicodeEncodeError``는 "position 112"만 말한다.

    수십만 건 중 어느 레코드인지 못 찾고, 임시 파일까지 지워져 되짚을
    것도 안 남는다. **어느 레코드의 어느 키인지**가 남아야 한다.
    """
    p = tmp_path / "r.jsonl"
    records = [
        {"ref": "USN#0", "name": "fine.txt"},
        {"ref": "USN#1", "name": "bad\udcffname.txt"},
    ]
    with pytest.raises(io.JsonlEncodeError) as excinfo:
        io.write_jsonl(p, records)

    err = excinfo.value
    assert err.ref == "USN#1"
    assert err.index == 1
    assert err.field == "name"


def test_the_unencodable_value_is_found_inside_fields(tmp_path):
    """파서가 자유 형식으로 싣는 자리라 실제로 자주 걸린다."""
    p = tmp_path / "r.jsonl"
    with pytest.raises(io.JsonlEncodeError) as excinfo:
        io.write_jsonl(p, [{"ref": "EVTX-SEC#1", "fields": {"Data": "x\udc00"}}])

    assert excinfo.value.field == "fields.Data"


def test_nothing_is_left_behind_when_the_write_fails(tmp_path):
    """원자성은 그대로다. 반쯤 쓰인 파일도 임시 파일도 남으면 안 된다."""
    p = tmp_path / "r.jsonl"
    with pytest.raises(io.JsonlEncodeError):
        io.write_jsonl(p, [{"ref": "USN#0", "name": "bad\udcff"}])

    assert list(tmp_path.iterdir()) == []


def test_the_detail_can_itself_be_written_to_errors_jsonl(tmp_path):
    """**이것이 이 설계의 핵심이다.**

    원인이 인코딩할 수 없는 문자열인데 그것을 그대로 detail 에 담으면,
    오류를 기록하는 ``append_jsonl`` 이 같은 이유로 또 터진다. 그러면
    중단은 하는데 사유가 아무 데도 안 남는다.
    """
    log = errors.ErrorLog(tmp_path / "errors.jsonl")
    try:
        io.write_jsonl(tmp_path / "r.jsonl", [{"ref": "USN#7", "name": "bad\udcff"}])
    except io.JsonlEncodeError as e:
        log.record("04_parse", "malformed_output", e.as_detail(), action="abort")

    entries = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    assert len(entries) == 1
    assert entries[0]["detail"]["value"]["ref"] == "USN#7"
    assert entries[0]["type"] == "malformed_output"


def test_a_normal_record_with_korean_still_writes_as_is(tmp_path):
    """``ensure_ascii=False`` 를 유지한다 — 한글이 escape 되면 눈으로 못 읽는다."""
    p = tmp_path / "r.jsonl"
    io.write_jsonl(p, [{"ref": "MFT#1", "path": "C:\사용자\문서.txt"}])

    assert "사용자" in p.read_text(encoding="utf-8")
