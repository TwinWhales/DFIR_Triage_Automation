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

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK = REPO_ROOT / "benchmark/datasets/C-001-webshell/mock"
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
    grouped = group_by_artifact(io.read_json(MOCK / "03_selection.json"))
    assert set(grouped) == {"$MFT", "evtx:Security"}
    assert grouped["$MFT"]["extensions"] == [".aspx", ".asp", ".ashx", ".asmx"]


def test_parse_skips_when_output_already_exists(tmp_path):
    out = tmp_path / "04_parsed"
    shutil.copytree(MOCK / "04_parsed", out)
    code = parse_mod.main(
        [
            "--in", str(MOCK / "03_selection.json"),
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
                "--in", str(MOCK / "03_selection.json"),
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


def test_parse_skips_artifacts_without_a_registered_parser(tmp_path):
    # 파서 등록이 유일한 확장 지점이라는 것을 고정한다. 구현된 아티팩트는
    # 인스턴스가 나오고, 아직 파서가 없는 것은 None 이라 parse 가 건너뛴다.
    #
    # 미구현 쪽으로는 prefetch 를 쓴다. 카탈로그에 supported: false 로
    # 올라 있어 항상 excluded 로 전달되며, 파서는 없다. 구현하면 이
    # 테스트가 깨지는데, 그때 함께 볼 것은 mappings/_artifacts.yaml 이다 —
    # 카탈로그와 파서가 어긋난 채로 두면 보고서가 "분석했다"고 말하면서
    # 실제로는 아무것도 읽지 않는다(docs/limitations.md 4-1).
    #
    # registry 가 한때 이 자리에 있었다. 파서가 생기면서 옮겼고, 같은
    # 커밋에서 카탈로그에도 등재했다.
    from src.stage04_parse import parsers

    for artifact in (
        "$MFT",
        "$UsnJrnl",
        "evtx:Security",
        "evtx:System",
        "registry:SYSTEM",
        "registry:SOFTWARE",
    ):
        assert parsers.get(artifact) is not None, f"{artifact} 파서가 등록되지 않았다"

    assert parsers.get("prefetch") is None


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
    shutil.copy(MOCK / "01_input.json", case_dir / "01_input.json")
    shutil.copytree(MOCK / "04_parsed", case_dir / "04_parsed")
    return case_dir


def run_pipeline(case_dir: Path) -> None:
    c = str(case_dir)
    assert normalize_mod.main(
        ["--in", f"{c}/01_input.json", "--out", f"{c}/02_scenario.json",
         "--llm", "stub", "--replay", str(MOCK / "02_scenario.json")]
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
         "--out", f"{c}/05_findings.json",
         "--llm", "stub", "--replay", str(MOCK / "05_findings.json")]
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
             "--llm", "stub", "--replay", str(MOCK / "02_scenario.json")]
        )
    assert not (case / "02_scenario.json").exists()
    assert (case / "errors.jsonl").is_file()
