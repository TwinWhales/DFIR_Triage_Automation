"""증거 접근 계층과 범위(Scope) 테스트.

파서가 짜이기 전에 고정해 두는 계약입니다. 파서는 "증거가 어떤 형태로
왔는지"와 "범위를 어떻게 해석하는지"를 다시 정하지 않습니다.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.common import io
from src.stage04_parse import evidence
from src.stage04_parse.parsers.base import Scope

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK = REPO_ROOT / "benchmark/datasets/C-001-webshell/mock"


def _utc(text: str) -> datetime:
    parsed = io.parse_timestamp(text)
    assert parsed is not None
    return parsed


# =============================================================== Scope


def test_scope_reads_the_real_selection():
    selection = io.read_json(MOCK / "03_selection.json")
    mft = next(e for e in selection["selected"] if e["artifact"] == "$MFT")
    scope = Scope.from_selection(mft["scope"])

    assert scope.extensions == (".aspx", ".asp", ".ashx", ".asmx")
    assert scope.path_prefix == ("c:/inetpub/wwwroot",)
    assert scope.start == _utc("2026-07-18T00:00:00Z")


def test_an_empty_scope_means_no_restriction():
    scope = Scope.from_selection(None)
    assert scope.matches_path("C:\\anything\\at\\all.txt")
    assert scope.matches_event_id(9999)
    assert scope.matches_time(_utc("1999-01-01T00:00:00Z"))


@pytest.mark.parametrize(
    "path",
    [
        "C:\\inetpub\\wwwroot\\upload\\shell.aspx",
        "c:/inetpub/wwwroot/upload/shell.ASPX",
        "C:\\INETPUB\\WWWROOT\\a.asp",
    ],
)
def test_path_matching_ignores_case_and_separators(path):
    scope = Scope.from_selection(
        {"path_prefix": ["C:\\inetpub\\wwwroot"], "extensions": [".aspx", ".asp"]}
    )
    assert scope.matches_path(path)


def test_a_sibling_directory_with_a_shared_prefix_does_not_match():
    # "C:\web" 이 "C:\website" 를 잡으면 범위가 조용히 넓어진다.
    scope = Scope.from_selection({"path_prefix": ["C:\\web"]})
    assert scope.matches_prefix("C:\\web\\a.aspx")
    assert scope.matches_prefix("C:\\web")
    assert not scope.matches_prefix("C:\\website\\a.aspx")


def test_wrong_extension_is_excluded():
    scope = Scope.from_selection({"extensions": [".aspx"]})
    assert not scope.matches_extension("C:\\a\\readme.txt")


def test_event_id_filter():
    scope = Scope.from_selection({"event_ids": [4720, 4732]})
    assert scope.matches_event_id(4720)
    assert not scope.matches_event_id(4624)


def test_time_range_boundaries_are_inclusive():
    scope = Scope.from_selection(
        {"time_range": {"start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z"}}
    )
    assert scope.matches_time(_utc("2026-07-18T00:00:00Z"))
    assert scope.matches_time(_utc("2026-07-22T23:59:59Z"))
    assert not scope.matches_time(_utc("2026-07-17T23:59:59Z"))
    assert not scope.matches_time(datetime(2026, 7, 23, tzinfo=timezone.utc))


def test_an_unreadable_timestamp_does_not_exclude_the_record():
    # 읽을 수 없는 타임스탬프 때문에 레코드를 버리면, 정작 그 이상함이
    # 증거인 경우를 놓친다.
    scope = Scope.from_selection(
        {"time_range": {"start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z"}}
    )
    assert scope.matches_time(None)


def test_any_timestamp_inside_the_window_keeps_the_record():
    scope = Scope.from_selection(
        {"time_range": {"start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z"}}
    )
    assert scope.in_any_time([_utc("2020-01-01T00:00:00Z"), _utc("2026-07-20T03:00:00Z")])
    assert not scope.in_any_time([_utc("2020-01-01T00:00:00Z")])
    assert scope.in_any_time([None])


# ============================================================ evidence


@pytest.fixture
def collected(tmp_path):
    """수집 도구가 원본 경로 구조를 유지해 뽑아 놓은 모양."""
    deep = tmp_path / "C" / "Windows" / "System32" / "winevt" / "Logs"
    deep.mkdir(parents=True)
    (deep / "Security.evtx").write_bytes(b"evtx")
    (tmp_path / "C").mkdir(exist_ok=True)
    (tmp_path / "C" / "$MFT").write_bytes(b"FILE")
    return tmp_path


def test_file_source_finds_artifacts_anywhere_under_the_root(collected):
    source = evidence.FileSource(collected)
    with source.open("$MFT") as stream:
        assert stream.read() == b"FILE"
    with source.open("evtx:Security") as stream:
        assert stream.read() == b"evtx"


def test_file_source_lists_what_it_can_read(collected):
    assert set(evidence.FileSource(collected).available()) == {"$MFT", "evtx:Security"}


def test_missing_artifact_is_reported_not_silently_empty(collected):
    # 수집 누락은 "봤는데 없었다"가 아니라 "아예 못 봤다"이므로 구별해야 한다.
    source = evidence.FileSource(collected)
    with pytest.raises(evidence.ArtifactNotFound, match=r"\$UsnJrnl"):
        source.open("$UsnJrnl")


def test_filename_matching_ignores_case(tmp_path):
    (tmp_path / "security.evtx").write_bytes(b"x")
    assert "evtx:Security" in evidence.FileSource(tmp_path).available()


def test_alternate_usnjrnl_names_are_recognised(tmp_path):
    # 콜론이 파일명에 못 들어가 수집 도구마다 이름이 다르다.
    (tmp_path / "$J").write_bytes(b"x")
    assert "$UsnJrnl" in evidence.FileSource(tmp_path).available()


def test_path_of_reports_where_it_read_from(collected):
    source = evidence.FileSource(collected)
    assert source.path_of("$MFT").name == "$MFT"
    assert source.path_of("registry:SYSTEM") is None


def test_open_source_picks_file_source_for_a_directory(collected):
    assert isinstance(evidence.open_source(collected), evidence.FileSource)


def test_open_source_explains_that_images_are_unsupported(tmp_path):
    image = tmp_path / "disk.dd"
    image.write_bytes(b"\x00" * 16)
    with pytest.raises(evidence.EvidenceError, match="미구현"):
        evidence.open_source(image)


def test_open_source_rejects_a_missing_path(tmp_path):
    with pytest.raises(evidence.EvidenceError, match="증거 경로 없음"):
        evidence.open_source(tmp_path / "nope")


def test_volume_source_says_what_still_needs_building(tmp_path):
    stream = (tmp_path / "x.dd")
    stream.write_bytes(b"\x00")
    with stream.open("rb") as fh:
        source = evidence.VolumeSource(fh)
        with pytest.raises(NotImplementedError, match="미구현"):
            source.open("$MFT")


def test_every_catalogued_artifact_has_a_filename_layout():
    # 카탈로그에 있는데 파일명 후보가 없으면 FileSource가 영원히 못 찾는다.
    from src.stage03_select import mapping_loader

    catalog = mapping_loader.load_catalog(REPO_ROOT / "mappings")
    readable = [
        name
        for name, spec in catalog.artifacts.items()
        if spec.unusable_reason("windows") is None
    ]
    assert readable
    for name in readable:
        assert name in evidence.FILE_LAYOUT, name
