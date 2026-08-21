"""``_flags.yaml`` 의 룰 엔진 테스트.

어휘와 룰의 원본은 YAML 하나입니다. 그 약속이 깨지는 경우가 둘 있습니다.

1. **YAML을 고쳤는데 반영되지 않는다** — 원본이 원본이 아니게 된 것이라
   프로토타입 시절 하드코딩으로 되돌아간 것과 같습니다.
2. **틀리게 쓴 YAML이 조용히 통과한다** — 오타 난 룰은 플래그를 안 붙이고,
   플래그가 안 붙은 레코드는 05단계에 가지 않으며, 그 결손은 "선별
   재현율 저하"로 잘못 집계됩니다.

그래서 "YAML만 고쳐도 되는가"와 "틀리게 쓰면 멈추는가"를 같은 비중으로
확인합니다. 개별 플래그가 옳게 붙는지는 ``test_flagging.py`` 가 봅니다.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from src.common import schema
from src.stage04_parse import flagging

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = REPO_ROOT / "mappings"
SYNC_TOOL = REPO_ROOT / "tools/sync_flag_enum.py"


@pytest.fixture
def flags_dir(tmp_path):
    """수정해도 되는 ``mappings/`` 사본. 룰을 바꿔 가며 로드해 본다."""
    directory = tmp_path / "mappings"
    directory.mkdir()
    shutil.copy(MAPPINGS / "_flags.yaml", directory / "_flags.yaml")
    return directory


def _write(directory: Path, flags: dict) -> str:
    """``flags`` 만 갈아 끼운 ``_flags.yaml`` 을 쓰고 경로를 돌려준다."""
    path = directory / "_flags.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["flags"] = flags
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    flagging.load_vocabulary.cache_clear()
    return str(directory)


@pytest.fixture(autouse=True)
def _restore_cache():
    """캐시를 건드리는 테스트가 뒤 테스트에 새지 않게 한다."""
    yield
    flagging.load_vocabulary.cache_clear()
    flagging.privileged_groups.cache_clear()


# ================================================ YAML 만으로 어휘가 는다


def test_a_new_flag_needs_no_python(flags_dir):
    # 이 프로젝트가 이 구조를 택한 이유 그 자체다. 여기가 깨지면
    # 어휘 추가가 다시 코드 수정 작업이 된다.
    where = _write(
        flags_dir,
        {
            "service_installed": {
                "artifacts": ["evtx:System"],
                "condition": "EVTX 7045",
                "rule": {"when": [{"artifact": "evtx:*", "match": "event_id", "values": [7045]}]},
            }
        },
    )
    vocabulary = flagging.load_vocabulary(where)
    assert vocabulary.names == ("service_installed",)

    record = {"artifact": "evtx:System", "ref": "EVTX-SYS#1", "event_id": 7045, "fields": {}}
    rule = vocabulary.rules[0]
    assert rule.matches(record, flagging.Context(groups=frozenset()))


def test_the_vocabulary_comes_from_the_yaml_not_the_module():
    declared = yaml.safe_load((MAPPINGS / "_flags.yaml").read_text(encoding="utf-8"))["flags"]
    assert flagging.FLAGS == tuple(declared)


# ============================================================ 선언형 매처


@pytest.mark.parametrize("event_id,expected", [(7045, True), (4624, False)])
def test_event_id_matches_only_listed_values(event_id, expected):
    clause = flagging.Clause(artifact="evtx:*", match="event_id", values=(7045,))
    assert clause.matches({"artifact": "evtx:System", "event_id": event_id}) is expected


def test_event_id_as_a_string_does_not_match():
    # 파서 회귀로 event_id 가 문자열이 되면 조용히 통과시키지 않는다.
    clause = flagging.Clause(artifact="evtx:*", match="event_id", values=(7045,))
    assert clause.matches({"artifact": "evtx:System", "event_id": "7045"}) is False


def test_list_contains_needs_an_actual_list():
    clause = flagging.Clause(
        artifact="$UsnJrnl", match="list_contains", field="reason", values=("file_create",)
    )
    assert clause.matches({"artifact": "$UsnJrnl", "reason": ["file_create"]}) is True
    assert clause.matches({"artifact": "$UsnJrnl", "reason": "file_create"}) is False


def test_field_equals_distinguishes_a_missing_key_from_a_different_value():
    # allocated 가 없는 레코드를 "미할당"으로 읽으면 전 레코드에 deleted 가 붙는다.
    clause = flagging.Clause(
        artifact="$MFT", match="field_equals", field="allocated", values=(False,)
    )
    assert clause.matches({"artifact": "$MFT", "allocated": False}) is True
    assert clause.matches({"artifact": "$MFT", "allocated": True}) is False
    assert clause.matches({"artifact": "$MFT"}) is False


@pytest.mark.parametrize(
    "pattern,artifact,expected",
    [
        ("$MFT", "$MFT", True),
        ("$MFT", "$UsnJrnl", False),
        ("evtx:*", "evtx:Security", True),
        ("evtx:*", "registry:SYSTEM", False),
        ("*", "registry:SOFTWARE", True),
    ],
)
def test_artifact_patterns(pattern, artifact, expected):
    clause = flagging.Clause(artifact=pattern)
    assert clause.matches({"artifact": artifact}) is expected


def test_clauses_are_or_not_and():
    # deleted 가 $MFT 와 $UsnJrnl 양쪽에서 나오는 것이 이 규칙에 달려 있다.
    rule = next(r for r in flagging.load_vocabulary().rules if r.name == "deleted")
    ctx = flagging.Context(groups=frozenset())
    assert rule.matches({"artifact": "$MFT", "allocated": False}, ctx)
    assert rule.matches({"artifact": "$UsnJrnl", "reason": ["file_delete"]}, ctx)


def test_when_and_handler_must_both_hold(flags_dir):
    # when 이 대상을 좁히고 handler 가 판정한다. 4728 이어도 대상이
    # 특권 그룹이 아니면 붙지 않아야 한다.
    rule = next(r for r in flagging.load_vocabulary().rules if r.name == "privileged_group_add")
    ctx = flagging.Context(groups=frozenset({"administrators"}))
    assert rule.matches(
        {"artifact": "evtx:Security", "event_id": 4728, "fields": {"TargetUserName": "Administrators"}}, ctx
    )
    assert not rule.matches(
        {"artifact": "evtx:Security", "event_id": 4728, "fields": {"TargetUserName": "Users"}}, ctx
    )
    assert not rule.matches(
        {"artifact": "evtx:Security", "event_id": 4624, "fields": {"TargetUserName": "Administrators"}}, ctx
    )


# ====================================================== 틀리게 쓰면 멈춘다


def test_a_flag_without_a_rule_is_refused(flags_dir):
    # 룰 없는 어휘는 "등록은 됐는데 아무 레코드에도 안 붙는" 플래그가 된다.
    # 그 상태는 파서 버그와 구별되지 않는다.
    where = _write(flags_dir, {"orphan": {"artifacts": ["$MFT"], "condition": "없음"}})
    with pytest.raises(flagging.VocabularyError, match="rule 블록이 없음"):
        flagging.load_vocabulary(where)


def test_an_unknown_match_is_refused(flags_dir):
    where = _write(
        flags_dir,
        {"typo": {"rule": {"when": [{"artifact": "$MFT", "match": "event_ids", "values": [1]}]}}},
    )
    with pytest.raises(flagging.VocabularyError, match="알 수 없는 match"):
        flagging.load_vocabulary(where)


def test_an_unknown_handler_is_refused(flags_dir):
    where = _write(flags_dir, {"typo": {"rule": {"handler": "does_not_exist"}}})
    with pytest.raises(flagging.VocabularyError, match="알 수 없는 handler"):
        flagging.load_vocabulary(where)


def test_a_match_missing_its_arguments_is_refused(flags_dir):
    # values 를 빠뜨린 event_id 는 "아무 이벤트도 안 맞는" 조건이 된다.
    where = _write(flags_dir, {"typo": {"rule": {"when": [{"artifact": "evtx:*", "match": "event_id"}]}}})
    with pytest.raises(flagging.VocabularyError, match="values 가 필요함"):
        flagging.load_vocabulary(where)


def test_a_clause_without_an_artifact_is_refused(flags_dir):
    where = _write(flags_dir, {"typo": {"rule": {"when": [{"match": "event_id", "values": [1]}]}}})
    with pytest.raises(flagging.VocabularyError, match="artifact 없음"):
        flagging.load_vocabulary(where)


def test_an_empty_rule_is_refused(flags_dir):
    where = _write(flags_dir, {"typo": {"rule": {}}})
    with pytest.raises(flagging.VocabularyError, match="rule 이 비어 있음"):
        flagging.load_vocabulary(where)


def test_a_missing_file_stops_instead_of_falling_back(tmp_path):
    # 폴백을 만들지 않는다. 어휘가 조용히 비면 04단계가 플래그를 하나도
    # 안 붙이고, 그러면 05단계에 레코드가 한 건도 가지 않는다.
    with pytest.raises(flagging.VocabularyError, match="어휘 파일 없음"):
        flagging.load_vocabulary(str(tmp_path))


# ============================================== 스키마 enum 은 생성물이다


def test_the_schema_enum_is_in_sync():
    in_schema = schema.load_schema("parsed_record")["properties"]["flags"]["items"]["enum"]
    assert list(flagging.FLAGS) == in_schema, (
        "parsed_record 스키마의 enum 이 mappings/_flags.yaml 과 어긋났다. "
        "손으로 고치지 말고 tools/sync_flag_enum.py 를 돌린다."
    )


def test_the_sync_tool_reports_no_drift():
    # 테스트가 통과하는 상태에서는 생성기가 할 일이 없어야 한다.
    result = subprocess.run(
        [sys.executable, str(SYNC_TOOL), "--check"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr
