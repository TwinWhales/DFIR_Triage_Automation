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


def _write(path, data=b"x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


@pytest.fixture
def volume(tmp_path):
    """볼륨 구조를 보존해 뽑은 결과. --evidence 가 가리켜야 할 자리."""
    root = tmp_path / "C"
    _write(root / "$MFT", b"FILE")
    _write(root / "Windows/System32/winevt/Logs/Security.evtx", b"evtx")
    _write(root / "Windows/System32/config/SYSTEM", b"hive")
    return root


@pytest.fixture
def flat(tmp_path):
    """필요한 파일만 모아 둔 폴더."""
    root = tmp_path / "extracted"
    _write(root / "$MFT", b"FILE")
    _write(root / "Security.evtx", b"evtx")
    return root


# ------------------------------------------------- 제자리로 찾는가


def test_artifacts_are_found_at_their_place_in_the_volume(volume):
    source = evidence.FileSource(volume)
    for artifact in ("$MFT", "evtx:Security", "registry:SYSTEM"):
        assert source.locate(artifact).method == "volume_path", artifact


def test_a_flat_folder_still_works(flat):
    source = evidence.FileSource(flat)
    assert source.locate("$MFT").method in {"volume_path", "root_file"}
    assert source.locate("evtx:Security").method == "root_file"
    with source.open("evtx:Security") as stream:
        assert stream.read() == b"evtx"


def test_a_lookalike_in_downloads_does_not_win(volume):
    # SYSTEM은 흔한 파일명이다. 이름만으로 찾으면 사용자 다운로드 폴더의
    # 동명 파일이 하이브를 선점해 **엉뚱한 데이터를 증거로 보고**한다.
    _write(volume / "Users/admin/Downloads/SYSTEM", b"WRONG")

    found = evidence.FileSource(volume).locate("registry:SYSTEM")
    assert found.path == volume / "Windows/System32/config/SYSTEM"
    with evidence.FileSource(volume).open("registry:SYSTEM") as stream:
        assert stream.read() == b"hive"


def test_path_resolution_ignores_case(tmp_path):
    # 추출 결과를 리눅스에서 분석하면 파일시스템이 대소문자를 구별한다.
    root = tmp_path / "C"
    _write(root / "windows/system32/config/system", b"hive")
    assert evidence.FileSource(root).locate("registry:SYSTEM") is not None


def test_alternate_usnjrnl_names_are_recognised(tmp_path):
    # 콜론이 파일명에 못 들어가 수집 도구마다 이름이 다르다.
    root = tmp_path / "C"
    _write(root / "$Extend/$J")
    assert "$UsnJrnl" in evidence.FileSource(root).available()


# ------------------------------------------- 0바이트 껍데기 (실측 회귀)


def test_an_empty_candidate_does_not_shadow_the_real_file(tmp_path):
    """실측 회귀 (docs/limitations.md 4-0).

    FTK Imager 추출본은 ``$Extend/$UsnJrnl`` 에 이름 없는 ``$DATA``
    (0바이트)를 쓰고 실제 저널을 ``$J`` 로 따로 내놓는다. 0바이트를 유효한
    후보로 받으면 **30만 건이 든 진짜 저널을 옆에 두고 "레코드 0건"을
    보고한다.** 실제 증거(evidence/[root])에서 그렇게 됐다.
    """
    root = tmp_path / "C"
    _write(root / "$Extend/$UsnJrnl", b"")  # 껍데기
    _write(root / "$J", b"\xd0\x00\x00\x00\x02\x00\x00\x00" + b"x" * 200)  # 알맹이

    found = evidence.FileSource(root).locate("$UsnJrnl")
    assert found is not None
    assert found.path.name == "$J", "0바이트 껍데기가 진짜 저널을 가렸다"


def test_the_skipped_empty_candidate_is_reported_not_discarded(tmp_path):
    """건너뛴 사실 자체가 진단이다. 추출을 고쳐야 한다는 신호."""
    root = tmp_path / "C"
    _write(root / "$Extend/$UsnJrnl", b"")
    _write(root / "$J", b"\xd0\x00\x00\x00\x02\x00\x00\x00" + b"x" * 200)

    found = evidence.FileSource(root).locate("$UsnJrnl")
    assert [p.name for p in found.empty_candidates] == ["$UsnJrnl"]


def test_all_candidates_empty_is_distinguished_from_not_collected(tmp_path):
    """"수집 안 됨"과 "수집됐는데 0바이트"는 분석가가 취할 조치가 다르다."""
    root = tmp_path / "C"
    _write(root / "$Extend/$UsnJrnl", b"")

    source = evidence.FileSource(root)
    with pytest.raises(evidence.EmptyArtifact, match="0바이트"):
        source.open("$UsnJrnl")


def test_empty_artifact_is_still_handled_like_not_found_by_stage_04(tmp_path):
    """04단계는 둘을 같이 처리해야 한다 — 건너뛰고 기록한다."""
    assert issubclass(evidence.EmptyArtifact, evidence.ArtifactNotFound)


def test_an_empty_artifact_is_not_listed_as_available(tmp_path):
    root = tmp_path / "C"
    _write(root / "$MFT", b"")
    assert "$MFT" not in evidence.FileSource(root).available()


def test_search_also_skips_empty_candidates(tmp_path):
    root = tmp_path / "C"
    _write(root / "odd/place/SYSTEM", b"")
    _write(root / "deeper/still/SYSTEM", b"hive")

    found = evidence.FileSource(root).locate("registry:SYSTEM")
    assert found is not None
    assert found.path.read_bytes() == b"hive"


# ----------------------------------------------- 재귀 검색 (마지막 수단)


def test_search_is_only_a_fallback_and_records_that_fact(tmp_path):
    root = tmp_path / "C"
    _write(root / "odd/place/SYSTEM", b"hive")
    found = evidence.FileSource(root).locate("registry:SYSTEM")
    assert found.method == "search"


def test_available_does_not_pay_for_a_full_walk(tmp_path):
    # available()은 빠른 경로만 본다. 목록을 보려고 폴더 전체를 훑는 것은
    # 10만 개짜리 추출 폴더에서 감당이 안 된다.
    root = tmp_path / "C"
    _write(root / "odd/place/SYSTEM", b"hive")
    assert evidence.FileSource(root).available() == []
    assert evidence.FileSource(root).locate("registry:SYSTEM") is not None


def test_search_prefers_the_shallower_candidate(tmp_path):
    # rglob은 깊이 우선이라 깊은 것이 먼저 나온다. 정렬하지 않으면
    # 같은 증거가 머신마다 다른 결과를 낸다.
    root = tmp_path / "C"
    _write(root / "a/deep/deeper/SYSTEM", b"deep")
    _write(root / "b/SYSTEM", b"shallow")

    found = evidence.FileSource(root).locate("registry:SYSTEM")
    assert found.path.read_bytes() == b"shallow"
    assert found.alternates == (root / "a/deep/deeper/SYSTEM",)


def test_search_result_is_stable_across_runs(tmp_path):
    root = tmp_path / "C"
    for name in ("z/SYSTEM", "a/SYSTEM", "m/SYSTEM"):
        _write(root / name)
    first = evidence.FileSource(root).locate("registry:SYSTEM")
    second = evidence.FileSource(root).locate("registry:SYSTEM")
    assert first.path == second.path


# ------------------------------------------------------- 볼륨 지정 안내


def test_pointing_at_the_collection_root_explains_what_to_do(tmp_path):
    # 사용자가 가장 실수하기 쉬운 지점. 혼란스러운 결과 대신 행동 가능한
    # 메시지를 낸다.
    _write(tmp_path / "C" / "$MFT")
    _write(tmp_path / "D" / "$MFT")

    with pytest.raises(evidence.NotAVolumeRoot) as e:
        evidence.open_source(tmp_path)
    message = str(e.value)
    assert "C, D" in message
    assert str(tmp_path / "C") in message
    assert "C-001-C" in message  # 케이스를 나누라는 안내


def test_a_real_volume_root_opens_without_complaint(volume):
    assert isinstance(evidence.open_source(volume), evidence.FileSource)


def test_volume_candidates_recognise_common_encodings(tmp_path):
    for name in ("C", "D%3A", "E_"):
        (tmp_path / name).mkdir()
    (tmp_path / "Windows").mkdir()  # 볼륨 이름이 아니다
    assert evidence.volume_candidates(tmp_path) == ["C", "D%3A", "E_"]


# ------------------------------------------------------------- 그 외


def test_missing_artifact_is_reported_not_silently_empty(volume):
    # 수집 누락은 "봤는데 없었다"가 아니라 "아예 못 봤다"이므로 구별해야 한다.
    with pytest.raises(evidence.ArtifactNotFound, match=r"\$UsnJrnl"):
        evidence.FileSource(volume).open("$UsnJrnl")


def test_not_found_message_names_the_expected_place(volume):
    with pytest.raises(evidence.ArtifactNotFound, match="Extend"):
        evidence.FileSource(volume).open("$UsnJrnl")


def test_open_source_rejects_an_image_without_ntfs(tmp_path):
    """NTFS도 파티션 테이블도 아닌 파일은 dissect가 열어도 볼륨이 안 나온다.

    dissect 설치 여부에 따라 메시지가 갈린다 — 없으면 설치 안내,
    있으면 "NTFS 못 찾음". 둘 다 EvidenceError면 충분하다.
    """
    image = tmp_path / "disk.dd"
    image.write_bytes(b"\x00" * 16)
    with pytest.raises(evidence.EvidenceError, match="dissect|NTFS"):
        evidence.open_source(image)


def test_open_source_rejects_a_missing_path(tmp_path):
    with pytest.raises(evidence.EvidenceError, match="증거 경로 없음"):
        evidence.open_source(tmp_path / "nope")


# ============================================================ VolumeSource


class _FakeStat:
    def __init__(self, size: int) -> None:
        self.st_size = size


class _FakeEntry:
    """``dissect`` ``TargetPath`` 흉내. ``VolumeSource``가 쓰는 메서드만."""

    def __init__(self, size: int, *, is_dir: bool = False, name: str = "") -> None:
        self._size = size
        self._is_dir = is_dir
        self.name = name

    def exists(self) -> bool:
        return True

    def is_dir(self) -> bool:
        return self._is_dir

    def is_file(self) -> bool:
        return not self._is_dir

    def stat(self) -> _FakeStat:
        return _FakeStat(self._size)

    def open(self):
        import io as _io

        return _io.BytesIO(b"\x46\x49\x4c\x45" * (self._size // 4 or 1))

    def __str__(self) -> str:  # noqa: D105
        return self.name or "<fake volume entry>"


class _FakeDirectory:
    """``.pf`` 가 든 폴더 흉내. 폴더 아티팩트 경로만 건드린다."""

    def __init__(self, children: "list[_FakeEntry]", *, name: str = "Prefetch") -> None:
        self._children = children
        self.name = name

    def exists(self) -> bool:
        return True

    def is_dir(self) -> bool:
        return True

    def iterdir(self):
        # 일부러 뒤섞어 둔다 — 정렬은 VolumeSource 의 책임이다.
        return list(reversed(self._children))

    def __str__(self) -> str:  # noqa: D105
        return self.name


class _MissingEntry:
    def exists(self) -> bool:
        return False


class _FakeFilesystem:
    """``dissect`` ``Filesystem`` 흉내. ``.path(relative)``만 있으면 된다."""

    def __init__(self, table: dict[str, _FakeEntry]) -> None:
        self._table = table

    def path(self, relative: str):
        return self._table.get(relative, _MissingEntry())


def test_volume_source_reads_a_registered_layout_path():
    fs = _FakeFilesystem({"$MFT": _FakeEntry(16)})
    source = evidence.VolumeSource(fs, description="테스트 볼륨")

    with source.open("$MFT") as stream:
        assert stream.read(4) == b"FILE"

    found = source.locate("$MFT")
    assert found is not None and found.method == "volume_path"


def test_volume_source_missing_artifact_is_not_found():
    source = evidence.VolumeSource(_FakeFilesystem({}), description="테스트 볼륨")
    with pytest.raises(evidence.ArtifactNotFound):
        source.open("$MFT")


def test_volume_source_zero_byte_file_is_empty_not_missing():
    """추출본과 같은 이유다 — 있는데 비어 있으면 조치가 다르다."""
    fs = _FakeFilesystem({"$MFT": _FakeEntry(0)})
    source = evidence.VolumeSource(fs, description="테스트 볼륨")
    with pytest.raises(evidence.EmptyArtifact):
        source.open("$MFT")


def test_volume_source_available_lists_only_whats_found():
    fs = _FakeFilesystem(
        {
            "$MFT": _FakeEntry(16),
            "Windows/System32/config/SYSTEM": _FakeEntry(16),
        }
    )
    source = evidence.VolumeSource(fs, description="테스트 볼륨")

    available = source.available()
    assert "$MFT" in available
    assert "registry:SYSTEM" in available
    assert "registry:SOFTWARE" not in available


# ------------------------------------------- 폴더 아티팩트 (프리패치)


def _prefetch_filesystem(children: "list[_FakeEntry]") -> _FakeFilesystem:
    return _FakeFilesystem({"Windows/Prefetch": _FakeDirectory(children)})


def test_volume_source_collects_every_pf_in_the_folder():
    fs = _prefetch_filesystem(
        [_FakeEntry(16, name="A.EXE-1111.pf"), _FakeEntry(16, name="B.EXE-2222.pf")]
    )
    source = evidence.VolumeSource(fs, description="테스트 볼륨")

    assert [f.path.name for f in source.locate_all("prefetch")] == [
        "A.EXE-1111.pf",
        "B.EXE-2222.pf",
    ]


def test_volume_source_pf_order_is_stable_not_filesystem_order():
    """정렬하지 않으면 같은 이미지에서 prefetch.jsonl 의 줄 순서가 달라진다."""
    fs = _prefetch_filesystem(
        [_FakeEntry(16, name="a.pf"), _FakeEntry(16, name="B.pf"), _FakeEntry(16, name="c.pf")]
    )
    source = evidence.VolumeSource(fs, description="테스트 볼륨")

    assert [f.path.name for f in source.locate_all("prefetch")] == ["a.pf", "B.pf", "c.pf"]


def test_volume_source_ignores_non_pf_and_zero_byte_files():
    fs = _prefetch_filesystem(
        [
            _FakeEntry(16, name="real.pf"),
            _FakeEntry(16, name="ReadyBoot.etl"),
            _FakeEntry(0, name="hollow.pf"),
        ]
    )
    source = evidence.VolumeSource(fs, description="테스트 볼륨")

    assert [f.path.name for f in source.locate_all("prefetch")] == ["real.pf"]


def test_volume_source_locate_points_at_the_folder_for_the_manifest():
    fs = _prefetch_filesystem([_FakeEntry(16, name="real.pf")])
    source = evidence.VolumeSource(fs, description="테스트 볼륨")

    found = source.locate("prefetch")
    assert found is not None and str(found.path) == "Prefetch"


def test_volume_source_open_all_yields_one_stream_per_pf():
    fs = _prefetch_filesystem(
        [_FakeEntry(16, name="A.pf"), _FakeEntry(16, name="B.pf")]
    )
    source = evidence.VolumeSource(fs, description="테스트 볼륨")

    assert [opened.path.name for opened in source.open_all("prefetch")] == ["A.pf", "B.pf"]


def test_volume_source_open_refuses_a_folder_artifact():
    """아무거나 하나를 골라 주면 나머지가 조용히 빠진 결과가 나온다."""
    fs = _prefetch_filesystem([_FakeEntry(16, name="real.pf")])
    source = evidence.VolumeSource(fs, description="테스트 볼륨")

    with pytest.raises(evidence.EvidenceError, match="open_all"):
        source.open("prefetch")


def test_volume_source_empty_prefetch_folder_is_not_found():
    fs = _prefetch_filesystem([])
    source = evidence.VolumeSource(fs, description="테스트 볼륨")

    assert source.locate_all("prefetch") == ()
    assert "prefetch" not in source.available()
    with pytest.raises(evidence.ArtifactNotFound, match=r"Windows/Prefetch/\*\.pf"):
        list(source.open_all("prefetch"))


# ------------------------------------------- 볼륨 선택 (--volume)


class _FakeVolume:
    def __init__(self, size: int, name: str) -> None:
        self.size = size
        self.name = name


class _FakeNtfs(_FakeFilesystem):
    """``__type__``과 ``volume``을 갖춘 파일시스템. 볼륨 선택이 이 둘을 본다."""

    __type__ = "ntfs"

    def __init__(self, table, *, size: int, name: str = "Basic data partition") -> None:
        super().__init__(table)
        self.volume = _FakeVolume(size, name)


@pytest.fixture
def image_of(monkeypatch, tmp_path):
    """``dissect.target``을 갈아 끼워 이미지 파일 하나를 흉내 낸다.

    실물 이미지 없이 볼륨 선택 분기를 돌리기 위한 것이다. ``dissect``가
    설치돼 있든 아니든 같게 동작한다.
    """
    import sys as _sys
    import types as _types

    def install(*filesystems):
        image = tmp_path / "disk.001"
        image.write_bytes(b"\x00" * 16)

        module = _types.ModuleType("dissect.target")

        class _Target:
            @staticmethod
            def open(_path):
                target = _types.SimpleNamespace()
                target.filesystems = list(filesystems)
                return target

        module.Target = _Target
        package = _types.ModuleType("dissect")
        package.target = module
        monkeypatch.setitem(_sys.modules, "dissect", package)
        monkeypatch.setitem(_sys.modules, "dissect.target", module)
        return image

    return install


def test_one_ntfs_needs_no_volume_flag(image_of):
    """볼륨이 하나면 고를 것이 없다. --volume 을 요구하면 회귀다."""
    image = image_of(_FakeNtfs({"$MFT": _FakeEntry(16)}, size=60 * 1024**3))

    source = evidence.open_source(image)

    assert isinstance(source, evidence.VolumeSource)
    assert "$MFT" in source.available()


def test_two_ntfs_volumes_stop_and_show_the_choices(image_of):
    """복구 파티션도 NTFS다. 도구가 크기로 추측하면 조용히 틀린다."""
    image = image_of(
        _FakeNtfs({"$MFT": _FakeEntry(16)}, size=471858688),
        _FakeNtfs({"$MFT": _FakeEntry(16)}, size=63829966336),
    )

    with pytest.raises(evidence.EvidenceError) as caught:
        evidence.open_source(image)

    message = str(caught.value)
    assert "--volume 0" in message and "--volume 1" in message
    assert "0.4GiB" in message and "59.4GiB" in message


def test_volume_flag_picks_the_named_one(image_of):
    image = image_of(
        _FakeNtfs({}, size=471858688),
        _FakeNtfs({"Windows/System32/config/SYSTEM": _FakeEntry(16)}, size=63829966336),
    )

    source = evidence.open_source(image, volume=1)

    assert "registry:SYSTEM" in source.available()
    assert "볼륨 1" in source.describe()


def test_a_volume_out_of_range_names_the_range(image_of):
    image = image_of(_FakeNtfs({}, size=471858688), _FakeNtfs({}, size=63829966336))

    with pytest.raises(evidence.EvidenceError, match=r"0\.\.1"):
        evidence.open_source(image, volume=2)


def test_no_ntfs_at_all_is_a_different_message(image_of):
    image = image_of()

    with pytest.raises(evidence.EvidenceError, match="NTFS 파일시스템을 찾지 못했습니다"):
        evidence.open_source(image)


# ================================================== 실물 이미지 (test_image.001)

REAL_IMAGE = REPO_ROOT / "evidence" / "test_image.001"
pytestmark_real_image = pytest.mark.skipif(
    not REAL_IMAGE.exists(), reason="실물 이미지 없음 (evidence/ 는 저장소에 없다)"
)


@pytestmark_real_image
def test_real_image_every_catalogued_layout_path_is_found():
    """raw NTFS 볼륨 이미지 하나로 카탈로그의 자리 정의가 전부 맞는지 본다."""
    source = evidence.open_source(REAL_IMAGE)
    assert isinstance(source, evidence.VolumeSource)

    missing = [name for name in evidence.FILE_LAYOUT if source.locate(name) is None]
    assert not missing, f"이 이미지에서 못 찾은 아티팩트: {missing}"


@pytestmark_real_image
def test_real_image_streams_are_seekable_and_reread_matches():
    """raw 이미지 직접 읽기의 핵심 전제 — RunlistStream이 두 번 순회를 견디는가."""
    source = evidence.open_source(REAL_IMAGE)

    with source.open("$MFT") as stream:
        assert stream.seekable()
        first = stream.read(4096)
        stream.seek(0)
        second = stream.read(4096)
    assert first == second
    assert first[:4] == b"FILE"


def test_every_catalogued_artifact_has_a_layout():
    # 카탈로그에 있는데 자리 정의가 없으면 FileSource가 영원히 못 찾는다.
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
        location = evidence.FILE_LAYOUT[name]
        if location.is_directory:
            # 폴더 단위 아티팩트(프리패치). 파일 하나가 아니므로
            # relative_paths/filenames 가 아니라 폴더 후보를 본다.
            assert location.directory_paths, name
            assert not location.relative_paths, name
        else:
            assert location.relative_paths, name
            assert location.filenames, name


def test_no_artifact_lists_the_same_filename_twice():
    """``filenames`` 는 수집 도구마다 다른 이름의 **후보 목록**이다.

    같은 값이 두 번 있으면 같은 자리를 두 번 뒤진다. 동작에는 영향이
    없지만, 목록을 손으로 늘리다 실수했다는 신호다 — 실제로
    ``evtx:Application`` 을 넣을 때 ``%4`` 치환이 아무것도 안 바꿔
    같은 이름이 둘 들어갔다(2026-08-25).
    """
    from src.stage04_parse.evidence import FILE_LAYOUT

    for artifact, location in FILE_LAYOUT.items():
        assert len(location.filenames) == len(set(location.filenames)), artifact
        assert len(location.relative_paths) == len(set(location.relative_paths)), artifact
