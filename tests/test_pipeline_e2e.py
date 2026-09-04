"""04단계 입력 처리와 파이프라인 관통 테스트.

파서는 아직 없다. 여기서 확인하는 것은 **단계 간 배선**이다. 파일 계약이
어긋난 곳은 이 테스트에서 드러난다. LLM을 실제로 붙이기 전에 선형 경로가
안정되어야 파이프라인 버그와 모델 한계를 구분할 수 있다.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from src.common import io, schema
from src.stage02_normalize import normalize as normalize_mod
from src.stage03_select import select as select_mod
from src.stage04_parse import parse as parse_mod
from src.stage04_parse.parse import group_by_artifact, merge_scopes
from src.stage05_interpret import interpret as interpret_mod
from src.stage06_verify import verify as verify_mod
from src.stage07_report import report as report_mod
from casepaths import FIXTURES, GOLDEN

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = REPO_ROOT / "mappings"


# ==================================================== 04단계 입력 처리


def test_scopes_are_widened_not_narrowed():
    # 교집합을 취하면 한 기법의 증거를 놓친다. 그것이 선별 방식의
    # 가장 큰 리스크다.
    merged = merge_scopes(
        [
            {"path_prefix": ["C:\\web"], "extensions": [".aspx"]},
            {"path_prefix": ["C:\\tasks"], "extensions": [".aspx", ".asp"]},
        ]
    )
    assert merged["path_prefix"] == ["C:\\web", "C:\\tasks"]
    assert merged["extensions"] == [".aspx", ".asp"]


def test_time_ranges_merge_to_the_outer_bounds():
    merged = merge_scopes(
        [
            {"time_range": {"start": "2026-07-18T00:00:00Z", "end": "2026-07-20T00:00:00Z"}},
            {"time_range": {"start": "2026-07-19T00:00:00Z", "end": "2026-07-22T00:00:00Z"}},
        ]
    )
    assert merged["time_range"] == {
        "start": "2026-07-18T00:00:00Z",
        "end": "2026-07-22T00:00:00Z",
    }


def test_the_same_artifact_requested_twice_is_read_once():
    # 03단계는 기법마다 "왜 필요한지"를 보존하려고 합치지 않는다.
    # 같은 파일을 두 번 파싱하지 않도록 여기서 묶는다.
    selection = {
        "selected": [
            {"artifact": "$MFT", "scope": {"path_prefix": ["C:\\web"]}},
            {"artifact": "$MFT", "scope": {"path_prefix": ["C:\\tasks"]}},
            {"artifact": "evtx:Security", "scope": {"event_ids": [4720]}},
        ]
    }
    grouped = group_by_artifact(selection)
    assert set(grouped) == {"$MFT", "evtx:Security"}
    assert grouped["$MFT"]["path_prefix"] == ["C:\\web", "C:\\tasks"]


def test_real_selection_groups_cleanly():
    grouped = group_by_artifact(io.read_json(GOLDEN / "03_selection.json"))
    assert set(grouped) == {"$MFT", "evtx:Security"}
    assert grouped["$MFT"]["extensions"] == [".aspx", ".asp", ".ashx", ".asmx"]


def test_parse_skips_when_output_already_exists(tmp_path):
    out = tmp_path / "04_parsed"
    shutil.copytree(FIXTURES / "04_parsed", out)
    code = parse_mod.main(
        [
            "--in", str(GOLDEN / "03_selection.json"),
            "--out", str(out),
            "--evidence", str(tmp_path),
            "--skip-existing",
        ]
    )
    assert code == 0


def test_parse_records_which_artifacts_it_could_not_read(tmp_path, capsys):
    # 증거 디렉터리가 비어 있는 경우. 파서는 등록돼 있으나 읽을 파일이
    # 없으므로 아티팩트마다 왜 못 읽었는지를 남기고 중단한다. 조용히 빈
    # 산출물을 만들면 05단계가 그걸 정상으로 읽어 원인 파악이 불가능해진다.
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    with pytest.raises(SystemExit) as e:
        parse_mod.main(
            [
                "--in", str(GOLDEN / "03_selection.json"),
                "--out", str(tmp_path / "04_parsed"),
                "--evidence", str(evidence_dir),
            ]
        )
    assert e.value.code == 1

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    skipped = {entry["detail"]["value"] for entry in logged if entry["action"] == "skip"}
    assert skipped == {"$MFT", "evtx:Security"}
    assert logged[-1]["action"] == "abort"
    assert "--skip-existing" in logged[-1]["detail"]["message"]


def _selection_for(tmp_path: Path, artifacts: "list[str]") -> Path:
    """아티팩트 몇 개만 요청하는 최소 선별 문서를 쓴다."""
    document = io.new_document(
        "C-999",
        "03_select",
        "select.py",
        mapping_table_version="1.0",
        selected=[
            {
                "artifact": artifact,
                "tier": 1,
                "priority": 1,
                "scope": {},
                "reason": {"technique": "T1547.001", "rationale": "테스트"},
            }
            for artifact in artifacts
        ],
        deferred=[],
        excluded=[],
        stats={"selected_count": len(artifacts), "deferred_count": 0, "excluded_count": 0},
    )
    schema.validate(document, "selection")
    path = tmp_path / "03_selection.json"
    io.write_json(path, document)
    return path


def test_parse_separates_not_applicable_from_not_collected(tmp_path, monkeypatch):
    """Win7 이미지의 Amcache 는 "수집 누락"이 아니라 "이 버전에 없음"이다.

    가르지 않으면 보고서가 "증거에 없음 (수집 누락)"이라고 말하고, 그것을
    읽은 분석가는 **존재하지 않는 파일을 다시 뽑으러 간다.**

    버전 판정 자체는 tests/test_osinfo.py 가 본다. 여기서 고정하는 것은
    판정 결과가 04단계의 스킵 사유까지 실제로 이어지는가다.
    """
    evidence_dir = tmp_path / "evidence"
    (evidence_dir / "Windows/AppCompat/Programs").mkdir(parents=True)
    # Win7 에는 RecentFileCache.bcf 만 있고 Amcache.hve 는 없다.
    (evidence_dir / "Windows/AppCompat/Programs/RecentFileCache.bcf").write_bytes(
        b"\xfe\xff\xee\xff" + b"\x00" * 16
    )

    monkeypatch.setattr(
        parse_mod.osinfo,
        "detect",
        lambda source: parse_mod.osinfo.WindowsVersion(
            build=7601, family="win7", product_name="Windows 7 Professional"
        ),
    )

    code = parse_mod.main(
        [
            "--in", str(_selection_for(tmp_path, ["registry:Amcache", "recentfilecache"])),
            "--out", str(tmp_path / "04_parsed"),
            "--evidence", str(evidence_dir),
        ]
    )
    # RecentFileCache 는 열렸다(항목 0건). 04단계는 정상 종료한다.
    assert code == 0

    manifest = io.read_json(tmp_path / "04_parsed/_manifest.json")
    assert manifest["windows"]["build"] == 7601
    assert manifest["windows"]["family"] == "win7"
    assert [entry["reason"] for entry in manifest["skipped"]] == ["version_not_applicable"]

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    reasons = {
        entry["detail"]["value"]: entry["detail"]["message"]
        for entry in logged
        if entry["action"] == "skip"
    }
    assert "registry:Amcache" in reasons
    assert "7601" in reasons["registry:Amcache"]
    assert "RecentFileCache" in reasons["registry:Amcache"]
    # RecentFileCache 쪽은 버전 미해당이 아니다. 실제로 열렸고 항목이
    # 0건이었을 뿐이므로 이 사유로 빠지면 안 된다.
    assert "recentfilecache" not in reasons


def test_parse_filters_nothing_when_the_version_is_undetermined(tmp_path, monkeypatch):
    """판정 실패는 거르지 않을 이유다. 잘못 거르면 있는 증거를 안 읽는다."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    def refuse(source):
        raise parse_mod.osinfo.VersionUndetermined("SOFTWARE 하이브를 찾지 못했습니다")

    monkeypatch.setattr(parse_mod.osinfo, "detect", refuse)

    with pytest.raises(SystemExit):
        parse_mod.main(
            [
                "--in", str(_selection_for(tmp_path, ["registry:Amcache"])),
                "--out", str(tmp_path / "04_parsed"),
                "--evidence", str(evidence_dir),
            ]
        )

    logged = list(io.read_jsonl(tmp_path / "errors.jsonl"))
    skips = [e for e in logged if e["action"] == "skip"]
    # 버전 미해당이 아니라 "증거에 없음"으로 빠져야 한다 — 실제로 없으니까.
    assert [e["detail"]["value"] for e in skips] == ["registry:Amcache"]
    assert "버전" not in skips[0]["detail"]["message"]


def test_parse_skips_artifacts_without_a_registered_parser(tmp_path):
    # 파서 등록이 유일한 확장 지점이라는 것을 고정한다. 구현된 아티팩트는
    # 인스턴스가 나오고, 아직 파서가 없는 것은 None 이라 parse 가 건너뛴다.
    #
    # 미구현 쪽으로는 $LogFile 을 쓴다. 카탈로그에 supported: false 로
    # 올라 있어 항상 excluded 로 전달되며, 파서는 없다. 구현하면 이
    # 테스트가 깨지는데, 그때 함께 볼 것은 mappings/_artifacts.yaml 이다 —
    # 카탈로그와 파서가 어긋난 채로 두면 보고서가 "분석했다"고 말하면서
    # 실제로는 아무것도 읽지 않는다(docs/limitations.md 4-1).
    #
    # registry 와 prefetch 가 차례로 이 자리에 있었다. 파서가 생기면서
    # 옮겼고, 같은 커밋에서 카탈로그에도 등재했다.
    from src.stage04_parse import parsers

    for artifact in (
        "$MFT",
        "$UsnJrnl",
        "evtx:Security",
        "evtx:System",
        "registry:SYSTEM",
        "registry:SOFTWARE",
        "prefetch",
    ):
        assert parsers.get(artifact) is not None, f"{artifact} 파서가 등록되지 않았다"

    assert parsers.get("$LogFile") is None


def test_every_supported_artifact_in_the_catalog_has_a_parser(tmp_path):
    """카탈로그와 파서 등록소가 어긋나지 않는지 본다.

    ``supported: true`` 인데 파서가 없으면 03단계가 선별하고 04단계가
    건너뛴다. 보고서에는 "확인하지 못한 아티팩트"로 실리므로 거짓말은
    아니지만, 카탈로그를 고치면서 파서를 안 붙인 실수는 조용히 남는다.

    반대 방향(파서가 있는데 카탈로그에 없음)은 더 나쁘다. 그 아티팩트는
    **선별될 수도 제외될 수도 없어** 보고서에 아예 나타나지 않는다
    (docs/limitations.md 4-1-1).
    """
    from src.stage03_select import mapping_loader
    from src.stage04_parse import parsers

    catalog = mapping_loader.load_catalog(MAPPINGS)

    for name, spec in catalog.artifacts.items():
        if spec.supported:
            assert parsers.get(name) is not None, f"카탈로그가 {name} 을 지원한다는데 파서가 없다"

    for name in parsers.registered():
        assert name in catalog.artifacts, f"{name} 파서가 있는데 카탈로그에 없다"


# ================================================== 크기 기반 시간 하드 컷


def _mft_with_one_record_outside_the_window(tmp_path: Path):
    """웹루트 트리 + 창 밖 레코드 하나를 담은 진짜 ``$MFT`` 바이트.

    ``test_mft_parser.py``의 ``WEBSHELL_TREE``를 재사용해, 04단계 스캐폴딩이
    아니라 실제 파서 출력으로 하드 컷을 확인한다.
    """
    import datetime as dt

    from src.stage04_parse import evidence
    from tests.test_mft_parser import WEBSHELL_TREE, build_mft

    old = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    tree = dict(WEBSHELL_TREE)
    tree[10] = {
        **WEBSHELL_TREE[10],
        "si_times": {k: old for k in ("btime", "ctime", "mtime", "atime")},
    }

    root = tmp_path / "C"
    (root).mkdir()
    (root / "$MFT").write_bytes(build_mft(tree))
    return evidence.FileSource(root)


def _mft_scope_dict():
    return {"time_range": {"start": "2026-07-18T00:00:00Z", "end": "2026-07-22T23:59:59Z"}}


def test_a_large_artifact_gets_its_out_of_range_records_cut(tmp_path):
    source = _mft_with_one_record_outside_the_window(tmp_path)
    out_dir = tmp_path / "04_parsed"
    out_dir.mkdir()

    entry = parse_mod.parse_artifact(
        "$MFT", _mft_scope_dict(), source, out_dir, large_artifact_bytes=0
    )

    assert entry["time_range_pruned_count"] == 1
    written = {r["record_num"] for r in io.read_jsonl(out_dir / entry["path"])}
    assert 10 not in written  # 창 밖 레코드는 아예 안 나갔다
    assert 9 in written  # 창 안 레코드는 그대로 남는다


def test_a_small_artifact_keeps_the_soft_flag(tmp_path):
    # 임계치 미만이면 예전과 동일하게 outside_time_range 플래그만 붙고
    # 레코드는 그대로 남는다 — 시간 추론이 틀렸을 때 되짚을 수 있어야 한다.
    source = _mft_with_one_record_outside_the_window(tmp_path)
    out_dir = tmp_path / "04_parsed"
    out_dir.mkdir()

    entry = parse_mod.parse_artifact(
        "$MFT", _mft_scope_dict(), source, out_dir, large_artifact_bytes=10 * 1024 * 1024
    )

    assert "time_range_pruned_count" not in entry
    records = {r["record_num"]: r for r in io.read_jsonl(out_dir / entry["path"])}
    assert "outside_time_range" in records[10]["flags"]


def test_prune_large_artifacts_false_disables_the_hard_cut(tmp_path):
    source = _mft_with_one_record_outside_the_window(tmp_path)
    out_dir = tmp_path / "04_parsed"
    out_dir.mkdir()

    entry = parse_mod.parse_artifact(
        "$MFT",
        _mft_scope_dict(),
        source,
        out_dir,
        large_artifact_bytes=0,
        prune_large_artifacts=False,
    )

    assert "time_range_pruned_count" not in entry
    written = {r["record_num"] for r in io.read_jsonl(out_dir / entry["path"])}
    assert 10 in written


# ============================== 파서가 센 것이 매니페스트까지 가는가


class _StatsParser:
    """레코드 하나를 내고 지정한 ``stats`` 를 남기는 파서.

    확인하려는 것은 파싱이 아니라 **운반**이다. 파서 쪽은 이미 시험이
    있는데(`test_registry_parser.test_a_dirty_hive_is_reported`) 그 값이
    04단계 밖으로 안 나가고 있었다.
    """

    def __init__(self, stats):
        self.stats = dict(stats)

    def parse(self, stream, scope):
        yield {
            "ref": "MFT#1",
            "artifact": "$MFT",
            "record_num": 1,
            "offset": 0,
            "timestamp": "2026-07-20T00:00:00.0000000Z",
            "path": "C:\\x",
            "fields": {},
        }


def _entry_with_stats(tmp_path, monkeypatch, stats):
    from src.stage04_parse import evidence

    root = tmp_path / "C"
    root.mkdir()
    (root / "$MFT").write_bytes(b"\x00" * 16)
    out_dir = tmp_path / "04_parsed"
    out_dir.mkdir()

    monkeypatch.setattr(parse_mod.parsers, "get", lambda *a, **k: _StatsParser(stats))
    return parse_mod.parse_artifact("$MFT", {}, evidence.FileSource(root), out_dir)


def test_a_dirty_hive_reaches_the_manifest(tmp_path, monkeypatch):
    """파일이 있고, 파서가 성공하고, 값이 낡았다.

    ``parse_errors`` 가 0 이라 매니페스트만 보면 정상으로 보인다. 그 사실이
    콘솔 경고에만 있으면 보고서를 읽는 사람은 알 수 없다.
    """
    entry = _entry_with_stats(tmp_path, monkeypatch, {"dirty_hive": 1})
    assert entry["dirty_hive"] == 1


def test_bad_chunks_are_not_swallowed_by_parse_errors(tmp_path, monkeypatch):
    """evtx 는 체크섬이 안 맞는 청크를 ``parse_errors`` 에 세지 않는다.

    그래서 지금까지 통째로 건너뛴 청크가 매니페스트 어디에도 없었다.
    """
    entry = _entry_with_stats(tmp_path, monkeypatch, {"bad_chunks": 5})
    assert entry["bad_chunks"] == 5
    assert entry["parse_errors"] == 0, "둘은 다른 사실이다 — 합치면 규모를 못 읽는다"


def test_zero_counts_do_not_create_keys(tmp_path, monkeypatch):
    """``unreadable_bytes`` 와 같은 규약. 0을 실으면 표가 잡음이 된다."""
    entry = _entry_with_stats(
        tmp_path, monkeypatch, {"dirty_hive": 0, "fixup_errors": 0, "bad_chunks": 0}
    )
    for key in parse_mod.RELIABILITY_STATS:
        assert key not in entry


def test_reliability_stats_never_shadow_the_entrys_own_keys(tmp_path, monkeypatch):
    """매니페스트 항목에 평평하게 싣는 구조라, 이름이 겹치면 조용히 덮는다."""
    entry = _entry_with_stats(tmp_path, monkeypatch, {})
    assert not set(parse_mod.RELIABILITY_STATS) & set(entry)


def test_every_forwarded_stat_has_a_sentence_in_the_report():
    """04가 보내는데 07이 문구를 모르면 그 값은 다시 아무 데도 안 보인다."""
    assert set(parse_mod.RELIABILITY_STATS) == {
        key for key, _ in report_mod.RELIABILITY_NOTES
    }


def test_a_hard_cut_without_a_time_range_is_a_no_op():
    # 시간 범위가 없으면 컷할 기준이 없다. 크기만으로 자르면 "왜 없어졌는지"
    # 설명할 수 없는 레코드가 생긴다.
    scope = parse_mod.Scope.from_selection({"path_prefix": ["C:\\inetpub\\wwwroot"]})
    assert not parse_mod._should_prune_outside_range(
        scope, 999_999_999, threshold_bytes=0, enabled=True
    )


# ============================================================ 관통 실행


@pytest.fixture
def case(tmp_path):
    """04_parsed를 미리 채운 케이스 디렉터리."""
    case_dir = tmp_path / "C-001"
    case_dir.mkdir()
    shutil.copy(FIXTURES / "01_input.json", case_dir / "01_input.json")
    shutil.copytree(FIXTURES / "04_parsed", case_dir / "04_parsed")
    return case_dir


def run_pipeline(case_dir: Path) -> None:
    c = str(case_dir)
    assert normalize_mod.main(
        ["--in", f"{c}/01_input.json", "--out", f"{c}/02_scenario.json",
         "--llm", "stub", "--replay", str(FIXTURES / "02_scenario.json")]
    ) == 0
    assert select_mod.main(
        ["--in", f"{c}/02_scenario.json", "--out", f"{c}/03_selection.json",
         "--mappings", str(MAPPINGS)]
    ) == 0
    assert parse_mod.main(
        ["--in", f"{c}/03_selection.json", "--out", f"{c}/04_parsed",
         "--evidence", "/mnt/evidence/WEB01", "--skip-existing"]
    ) == 0
    assert interpret_mod.main(
        ["--in", f"{c}/04_parsed", "--scenario", f"{c}/02_scenario.json",
         "--selection", f"{c}/03_selection.json", "--mappings", str(MAPPINGS),
         "--out", f"{c}/05_findings.json",
         "--llm", "stub", "--replay", str(FIXTURES / "05_findings.json"),
         # 이 시험이 보는 것은 모델이 문장을 직접 쓰는 예전 경로다.
         # 기본이 assemble 로 바뀌었으므로 명시한다.
         "--mode", "model"]
    ) == 0
    assert verify_mod.main(
        ["--findings", f"{c}/05_findings.json", "--parsed", f"{c}/04_parsed",
         "--out", f"{c}/06_verified.json"]
    ) == 0
    assert report_mod.main(
        ["--in", f"{c}/06_verified.json", "--findings", f"{c}/05_findings.json",
         "--selection", f"{c}/03_selection.json", "--scenario", f"{c}/02_scenario.json",
         "--parsed", f"{c}/04_parsed", "--out", f"{c}/07_report.md"]
    ) == 0


def test_the_whole_pipeline_runs_and_every_stage_validates(case):
    run_pipeline(case)

    for filename, schema_name in [
        ("02_scenario.json", "scenario"),
        ("03_selection.json", "selection"),
        ("05_findings.json", "findings"),
        ("06_verified.json", "verified"),
    ]:
        schema.validate(io.read_json(case / filename), schema_name)
    assert (case / "07_report.md").is_file()


def test_a_clean_run_leaves_no_errors_behind(case):
    run_pipeline(case)
    assert not (case / "errors.jsonl").exists()


def test_case_id_is_carried_through_every_stage(case):
    run_pipeline(case)
    for filename in ["02_scenario.json", "03_selection.json", "05_findings.json", "06_verified.json"]:
        assert io.read_json(case / filename)["case_id"] == "C-001"


def test_the_experiment_conditions_survive_in_the_output(case):
    # 결과 파일만 보고 어떤 모델로 돌렸는지 복원할 수 있어야
    # 모델별 비교가 성립한다.
    run_pipeline(case)
    assert io.read_json(case / "02_scenario.json")["generator"].startswith("normalize.py / stub")
    assert io.read_json(case / "05_findings.json")["generator"].startswith("interpret.py / stub")
    # 리터럴로 박지 않는다. 여기서 볼 것은 "버전이 산출물에 실렸는가"이지
    # 그 값이 무엇인가가 아니다. 카탈로그 내용 고정은
    # test_mapping_loader.test_catalog_loads_every_artifact 의 몫이다.
    from src.stage03_select import mapping_loader

    catalog_version = mapping_loader.load_catalog(MAPPINGS).mapping_table_version
    assert io.read_json(case / "03_selection.json")["mapping_table_version"] == catalog_version


def test_the_report_only_contains_verified_statements(case):
    run_pipeline(case)
    verified = io.read_json(case / "06_verified.json")
    findings = {f["id"]: f for f in io.read_json(case / "05_findings.json")["findings"]}
    text = (case / "07_report.md").read_text(encoding="utf-8")

    for entry in verified["passed"]:
        assert findings[entry["id"]]["statement"] in text
    for entry in verified["rejected"]:
        assert findings[entry["id"]]["statement"] not in text


def test_rerunning_is_idempotent(case):
    # 중간 단계부터 재실행이 가능해야 한다. 파싱은 오래 걸리므로
    # 실험 반복에서 매번 처음부터 돌릴 수 없다.
    run_pipeline(case)
    first = (case / "06_verified.json").read_text(encoding="utf-8")
    run_pipeline(case)
    second = (case / "06_verified.json").read_text(encoding="utf-8")

    def strip_time(text: str) -> list[str]:
        return [line for line in text.splitlines() if "generated_at" not in line]

    assert strip_time(first) == strip_time(second)


def test_a_broken_stage_stops_the_pipeline_instead_of_passing_junk_on(case):
    # 조용히 넘어가면 뒤 단계가 빈 입력을 정상으로 받아 원인 파악이
    # 불가능해진다.
    io.write_json(case / "01_input.json", {"case_id": "C-001", "stage": "01_input"})
    with pytest.raises(SystemExit):
        normalize_mod.main(
            ["--in", str(case / "01_input.json"), "--out", str(case / "02_scenario.json"),
             "--llm", "stub", "--replay", str(FIXTURES / "02_scenario.json")]
        )
    assert not (case / "02_scenario.json").exists()
    assert (case / "errors.jsonl").is_file()


# ================================== 파싱 실패가 errors.jsonl 에 남는가


def _unreadable_pf(name: str = "ROGUE.EXE", path_hash: int = 0xDEADBEEF) -> bytes:
    """레이아웃 표에 없는 ``.pf``. 파서가 ``UnknownLayout`` 으로 건너뛴다.

    실물에서 이 모양을 만났습니다 — Windows 10 19045 의 파일 정보 블록이
    212바이트인데 표에 없어 192건이 전부 실패했습니다. 여기서는 표에
    없을 것이 확실한 크기(200)를 씁니다.
    """
    import struct

    from src.stage04_parse.structs import prefetch_record as pf

    info_size = 200
    assert (30, info_size) not in pf.FILE_INFORMATION, "표에 있으면 이 시험이 무의미하다"

    info = bytes(info_size)
    total = pf.HEADER_SIZE + info_size
    header = (
        struct.pack("<I4sII", 30, pf.SIGNATURE, 0x11, total)
        + name.encode("utf-16-le")[:58].ljust(60, b"\x00")
        + struct.pack("<II", path_hash, 0)
    )
    return header + info


def test_an_artifact_that_fails_completely_is_written_to_the_error_log(tmp_path, capsys):
    """**아티팩트 하나가 100% 실패해도 예전에는 조용했다.**

    ``parse_errors`` 가 ``_manifest.json`` 에만 남아, 단계는 정상 종료하고
    ``errors.jsonl`` 은 만들어지지도 않았습니다. 실측에서 프리패치 192건이
    전부 실패했는데 ``tools/live_check.py`` 가 "재시도·실패 0건 — 모든
    단계가 첫 시도에 통과"로 결산했습니다 (``docs/limitations.md``
    2026-09-01 절). 같은 리포트가 위쪽에서는 "파싱 오류 192건"을 찍고
    있었으므로, 산출물이 아니라 **결산이** 틀린 것이었습니다.
    """
    evidence_dir = tmp_path / "evidence"
    prefetch_dir = evidence_dir / "Windows" / "Prefetch"
    prefetch_dir.mkdir(parents=True)
    for i in range(3):
        (prefetch_dir / f"ROGUE{i}.EXE-DEADBEE{i}.pf").write_bytes(
            _unreadable_pf(f"ROGUE{i}.EXE", 0xDEADBEE0 + i)
        )

    selection = tmp_path / "03_selection.json"
    io.write_json(
        selection,
        {
            "case_id": "PARSE-ERR",
            "stage": "03_select",
            "schema_version": "1.0",
            "generated_at": "2026-09-01T00:00:00Z",
            "generator": "test",
            "mapping_table_version": "1.2",
            "selected": [
                {
                    "artifact": "prefetch",
                    "tier": 1,
                    "priority": 1,
                    "scope": {},
                    "reason": {"technique": "T1204.002", "rationale": "USB 실행 흔적"},
                }
            ],
            "deferred": [],
            "excluded": [],
            "stats": {"selected_count": 1, "deferred_count": 0, "excluded_count": 0},
        },
    )

    code = parse_mod.main(
        [
            "--in", str(selection),
            "--out", str(tmp_path / "04_parsed"),
            "--evidence", str(evidence_dir),
        ]
    )
    assert code == 0, "읽을 파일은 있었으므로 단계 자체는 성공한다"

    manifest = io.read_json(tmp_path / "04_parsed" / "_manifest.json")
    entry = next(f for f in manifest["files"] if f["artifact"] == "prefetch")
    assert entry["record_count"] == 0
    assert entry["parse_errors"] == 3

    logged = [e for e in io.read_jsonl(tmp_path / "errors.jsonl") if e["type"] == "parse_error"]
    assert len(logged) == 1, "아티팩트당 한 줄이다 — 파일마다 쓰면 다른 실패가 묻힌다"
    detail = logged[0]["detail"]
    assert detail["value"] == "prefetch"
    assert detail["parse_errors"] == 3
    assert detail["record_count"] == 0
    assert detail["total_failure"] is True, "전량 실패와 일부 실패는 조치가 다르다"

    # 화면에서도 소리를 내야 한다. 실측에서 이 실패가 evtx 청크 복구 경고
    # 215줄 사이에 묻혔다.
    assert "전량 실패" in capsys.readouterr().err


# ============================ 미지원 버전이 결산에 도달하는가


def _usn_record(*, name: str, usn: int, major_version: int = 2) -> bytes:
    """``USN_RECORD`` 하나. ``major_version`` 만 바꿔 v3 를 만든다.

    v3 는 **손상이 아니라 실재하는 버전**입니다. 파서는 그것을 알아보고
    레코드 하나를 통째로 건너뛰며 ``stats["unsupported_version"]`` 을
    올립니다 — 8바이트씩 걸어 들어가면 본문을 레코드로 오해해 가짜 손상이
    잡히기 때문입니다.
    """
    import struct

    from src.stage04_parse.structs import usn_record as u

    encoded = name.encode("utf-16-le")
    unpadded = u.V2_HEADER_SIZE + len(encoded)
    padded = (unpadded + u.RECORD_ALIGNMENT - 1) // u.RECORD_ALIGNMENT * u.RECORD_ALIGNMENT
    # 2026-07-20T03:14:22Z 를 FILETIME 으로.
    filetime = 133_662_296_620_000_000
    header = struct.pack(
        "<IHHQQQQIIIIHH",
        padded,
        major_version,
        0,
        (1 << 48) | 100,
        (5 << 48) | 5,
        usn,
        filetime,
        int(u.UsnReason.FILE_CREATE),
        0,
        0,
        0x20,  # FILE_ATTRIBUTE_ARCHIVE
        len(encoded),
        u.V2_HEADER_SIZE,
    )
    return header + encoded + b"\x00" * (padded - unpadded)


def _journal_evidence(root: Path, records: list[bytes]) -> Path:
    """``$Extend/$UsnJrnl$J`` 하나만 있는 증거 폴더."""
    extend = root / "$Extend"
    extend.mkdir(parents=True)
    (extend / "$UsnJrnl$J").write_bytes(b"".join(records))
    return root


def _usn_selection(path: Path, case_id: str) -> Path:
    io.write_json(
        path,
        {
            "case_id": case_id,
            "stage": "03_select",
            "schema_version": "1.0",
            "generated_at": "2026-09-01T00:00:00Z",
            "generator": "test",
            "mapping_table_version": "1.2",
            "selected": [
                {
                    "artifact": "$UsnJrnl",
                    "tier": 1,
                    "priority": 1,
                    "scope": {},
                    "reason": {"technique": "T1070.004", "rationale": "파일 삭제 흔적"},
                }
            ],
            "deferred": [],
            "excluded": [],
            "stats": {"selected_count": 1, "deferred_count": 0, "excluded_count": 0},
        },
    )
    return path


def test_a_journal_we_cannot_read_the_version_of_is_not_reported_as_clean(tmp_path, capsys):
    """**미지원 버전이 04단계 밖으로 나오지 않았다.**

    파서는 ``$UsnJrnl`` v3/v4 를 알아보고 따로 세는데, 그 집계가
    ``_manifest.json`` 에도 ``errors.jsonl`` 에도 실리지 않았습니다.
    남는 것은 레코드마다 찍히는 stderr 경고뿐이었고, 그 경고는 2026-09-01
    실측에서 evtx 청크 복구 경고 215줄 사이에 묻힌 전례가 있습니다.

    결과가 이랬습니다 — **저널이 통째로 비는데 결산은 "정상"이라고 말한다.**
    2026-09-01 에 고친 프리패치 전량 실패와 같은 부류입니다.
    """
    evidence_dir = _journal_evidence(
        tmp_path / "evidence",
        [
            _usn_record(name=f"v3-{i}.dll", usn=i * 80, major_version=3)
            for i in range(3)
        ],
    )

    code = parse_mod.main(
        [
            "--in", str(_usn_selection(tmp_path / "03_selection.json", "USN-V3")),
            "--out", str(tmp_path / "04_parsed"),
            "--evidence", str(evidence_dir),
        ]
    )
    assert code == 0, "읽을 파일은 있었으므로 단계 자체는 성공한다"

    manifest = io.read_json(tmp_path / "04_parsed" / "_manifest.json")
    entry = next(f for f in manifest["files"] if f["artifact"] == "$UsnJrnl")
    assert entry["record_count"] == 0
    assert entry["unsupported_version"] == 3
    assert entry["parse_errors"] == 0, "손상이 아니다 — 두 수를 합치면 조치가 갈리지 않는다"

    logged = [e for e in io.read_jsonl(tmp_path / "errors.jsonl") if e["type"] == "parse_error"]
    assert len(logged) == 1, "아티팩트당 한 줄이다"
    detail = logged[0]["detail"]
    assert detail["value"] == "$UsnJrnl"
    assert detail["unsupported_version"] == 3
    assert detail["parse_errors"] == 0
    assert detail["total_failure"] is True
    assert "지원 범위 밖" in detail["message"], "손상과 구분되는 문장이어야 한다"

    assert "전량 실패" in capsys.readouterr().err


def test_a_journal_that_is_only_partly_unreadable_still_says_so(tmp_path, capsys):
    """일부만 미지원이면 전량 실패가 아니다 — 그래도 남아야 한다.

    레코드가 나왔다는 사실이 "다 읽었다"는 뜻이 아닙니다. 저널의 절반이
    빠졌는데 결산이 조용하면, 없는 것과 못 읽은 것이 구분되지 않습니다.
    """
    evidence_dir = _journal_evidence(
        tmp_path / "evidence",
        [
            _usn_record(name="kept.txt", usn=0),
            _usn_record(name="skipped.dll", usn=80, major_version=3),
        ],
    )

    parse_mod.main(
        [
            "--in", str(_usn_selection(tmp_path / "03_selection.json", "USN-MIX")),
            "--out", str(tmp_path / "04_parsed"),
            "--evidence", str(evidence_dir),
        ]
    )

    manifest = io.read_json(tmp_path / "04_parsed" / "_manifest.json")
    entry = next(f for f in manifest["files"] if f["artifact"] == "$UsnJrnl")
    assert entry["record_count"] == 1
    assert entry["unsupported_version"] == 1

    detail = [
        e for e in io.read_jsonl(tmp_path / "errors.jsonl") if e["type"] == "parse_error"
    ][0]["detail"]
    assert detail["total_failure"] is False
    assert detail["record_count"] == 1

    out = capsys.readouterr().out
    assert "미지원 버전 1건" in out, "요약 줄에 없으면 화면에서 0건의 이유를 알 수 없다"
