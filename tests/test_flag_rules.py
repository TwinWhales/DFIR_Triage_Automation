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
    flagging.prompt_drop_fields.cache_clear()
    flagging.claim_fields.cache_clear()


# ================================================== claims 로 삼을 필드 (어휘)


def _write_claim(directory, value) -> str:
    path = directory / "_flags.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if value is None:
        data.pop("claim_fields", None)
    else:
        data["claim_fields"] = value
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    flagging.claim_fields.cache_clear()
    return str(directory)


def test_the_claim_field_order_comes_from_the_yaml(flags_dir):
    # 순서가 우선순위다. 코드에 박으면 새 파서가 붙을 때 고칠 자리를 놓친다.
    directory = _write_claim(flags_dir, {"max_items": 2, "fields": ["b", "a"]})

    fields = flagging.claim_fields(directory)

    assert fields.names == ("b", "a")
    assert fields.max_items == 2


def test_no_claim_key_turns_the_assembler_off(flags_dir):
    # claims 가 비면 그 소견은 06단계에서 unverifiable 이 된다. 조용히
    # 틀리는 것이 아니라 검증 대상에서 빠지는 것이라 드러난다.
    directory = _write_claim(flags_dir, None)

    assert flagging.claim_fields(directory) == flagging.NO_CLAIM_FIELDS


@pytest.mark.parametrize(
    "bad",
    [
        ["path"],
        {"max_items": -1, "fields": ["path"]},
        {"max_items": True, "fields": ["path"]},
        {"max_items": 4, "fields": "path"},
        {"max_items": 4, "fields": ["path", 3]},
    ],
)
def test_a_misshapen_claim_spec_stops_instead_of_being_ignored(flags_dir, bad):
    directory = _write_claim(flags_dir, bad)

    with pytest.raises(flagging.VocabularyError, match="claim_fields"):
        flagging.claim_fields(directory)


# ============================================ 프롬프트에서 뺄 필드 (어휘)


def _write_drop(directory: Path, value) -> str:
    """``prompt_drop_fields`` 만 갈아 끼운다. ``None`` 이면 키를 지운다."""
    path = directory / "_flags.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if value is None:
        data.pop("prompt_drop_fields", None)
    else:
        data["prompt_drop_fields"] = value
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    flagging.prompt_drop_fields.cache_clear()
    return str(directory)


def test_the_drop_list_comes_from_the_yaml(flags_dir):
    # 코드에 목록을 박으면 add-parser 로 새 파서가 붙을 때 고칠 자리를
    # 놓치고, 그 결손은 아무 데도 안 남는다.
    directory = _write_drop(flags_dir, ["Nonce", "AnotherOne"])

    assert flagging.prompt_drop_fields(directory) == frozenset({"nonce", "anotherone"})


def test_the_drop_list_ignores_case(flags_dir):
    # 같은 뜻의 필드가 아티팩트마다 다른 표기로 오는 것을 놓치는 쪽이,
    # 열거한 이름을 지우는 것보다 나쁘다.
    directory = _write_drop(flags_dir, ["ProcessGuid"])

    assert "processguid" in flagging.prompt_drop_fields(directory)


def test_no_drop_key_means_the_feature_is_off(flags_dir):
    # 키가 없을 때의 동작은 이 기능이 생기기 전과 같다 — 아무것도 빼지
    # 않는다. 조용히 틀리는 자리가 아니다.
    directory = _write_drop(flags_dir, None)

    assert flagging.prompt_drop_fields(directory) == frozenset()


@pytest.mark.parametrize("bad", ["Hashes", {"a": 1}, ["Hashes", 3]])
def test_a_misshapen_drop_list_stops_instead_of_being_ignored(flags_dir, bad):
    # 슬쩍 무시하면 "왜 그 필드가 프롬프트에 그대로 있지"를 되짚을 방법이 없다.
    directory = _write_drop(flags_dir, bad)

    with pytest.raises(flagging.VocabularyError, match="prompt_drop_fields"):
        flagging.prompt_drop_fields(directory)


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


def test_event_ids_narrows_the_clause_like_artifact_does():
    # artifact 와 같은 자리다 — 둘 다 대상을 좁히고(AND) 그다음 match 가 판정한다.
    clause = flagging.Clause(
        artifact="evtx:Sysmon",
        event_ids=(1,),
        match="field_endswith",
        field="fields.Image",
        values=("\\cmd.exe",),
    )
    fields = {"Image": "C:\\Windows\\System32\\cmd.exe"}
    assert clause.matches({"artifact": "evtx:Sysmon", "event_id": 1, "fields": fields}) is True
    assert clause.matches({"artifact": "evtx:Sysmon", "event_id": 5, "fields": fields}) is False


def test_an_empty_event_ids_is_refused(flags_dir):
    directory = _write(
        flags_dir,
        {"x": {"rule": {"when": [{"artifact": "evtx:Sysmon", "event_ids": []}]}}},
    )
    with pytest.raises(flagging.VocabularyError, match="event_ids"):
        flagging.load_vocabulary(directory)


def test_a_non_integer_event_id_is_refused(flags_dir):
    directory = _write(
        flags_dir,
        {"x": {"rule": {"when": [{"artifact": "evtx:Sysmon", "event_ids": ["one"]}]}}},
    )
    with pytest.raises(flagging.VocabularyError, match="event_ids"):
        flagging.load_vocabulary(directory)


def test_event_ids_and_match_event_id_together_are_refused(flags_dir):
    # 뜻이 다르다. 함께 쓰면 어느 쪽 의도인지 읽는 사람이 알 수 없다.
    directory = _write(
        flags_dir,
        {
            "x": {
                "rule": {
                    "when": [
                        {
                            "artifact": "evtx:Sysmon",
                            "event_ids": [1],
                            "match": "event_id",
                            "values": [1],
                        }
                    ]
                }
            }
        },
    )
    with pytest.raises(flagging.VocabularyError, match="event_ids"):
        flagging.load_vocabulary(directory)


@pytest.mark.parametrize(
    "flag,fields",
    [
        # 셋 다 win10_sysmon_testimage 에서 실제로 EID 5 에 붙던 모양이다.
        ("shell_spawned", {"Image": "C:\\Windows\\System32\\cmd.exe"}),
        ("execution_from_unusual_path", {"Image": "C:\\Windows\\Temp\\{GUID}\\DismHost.exe"}),
        ("unexpected_parent_process", {"ParentImage": "C:\\Windows\\explorer.exe"}),
    ],
)
def test_the_sysmon_process_rules_ignore_process_terminate(flag, fields):
    """세 룰의 condition 은 "Sysmon 1" 이라고 적혀 있다. 실제로 그런지 본다.

    2026-08-26 win10_sysmon_testimage 실측에서 세 룰이 EID 5(ProcessTerminate)
    에도 붙었다. 같은 fields.Image 가 생성·종료 양쪽에 실려 있어서다. 한
    프로세스가 두 번 세어지는데, 종료 레코드에는 ParentImage 도 CommandLine
    도 없어 **05단계 자리는 먹고 정보는 더 적다.**
    """
    rule = next(r for r in flagging.load_vocabulary().rules if r.name == flag)
    ctx = flagging.Context(groups=frozenset())

    assert rule.matches({"artifact": "evtx:Sysmon", "event_id": 1, "fields": fields}, ctx)
    assert not rule.matches({"artifact": "evtx:Sysmon", "event_id": 5, "fields": fields}, ctx)


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
        # 도구가 UTF-8 로 찍지 못하는 상황이 와도 실패 내역은 읽혀야 한다.
        # 이것이 없으면 디코딩이 터져 stdout 이 None 이 되고, 아래 assert 가
        # 진짜 원인 대신 TypeError 를 낸다.
        errors="replace",
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ============================== 매핑이 요청한 event_id 를 flags 가 받는가
#
# **게이트 4가 조용히 실패하는 자리다**(`.claude/skills/add-scenario`).
# 매핑에 event_id 를 적어도 그것을 받는 flag 가 없으면, 03단계는 "봤다"고
# 적고 04단계는 파싱까지 하는데 모델에는 한 건도 가지 않는다. errors.jsonl
# 에도 안 남는다 — 보고서에는 그냥 소견이 없는 걸로 보인다.
#
# 2026-08-25 에 실제로 밟았다. K-001 매핑을 쓰면서 Sysmon 11·22 와 Security
# 4634·4722·4738 등을 적었는데 받을 flag 가 없었고, 같은 검사로 T1053.005
# (예약 작업)과 T1200(PnP)이 **예전부터** 같은 상태였다는 것도 드러났다.

#: ``artifact: "*"`` 인 절은 커버리지로 세지 않는다.
#:
#: 모든 아티팩트의 모든 레코드에 붙는 flag 는 **정의상 필터가 아니다.**
#: ``outside_time_range`` 가 그런 표식이고, 커버리지에 넣으면 모든 조합이
#: "덮였다"로 계산돼 아래 검사가 통째로 무력해진다.
#:
#: 예전에는 그 flag 의 **이름을 박아** 제외했다. 그러면 나중에 전역 표식이
#: 하나 더 생기는 순간 검사가 조용히 죽는다 — 실패하지 않으므로 죽었다는
#: 사실도 안 드러난다. 이름이 아니라 **성질**로 거른다.
def _is_marker(clause: dict) -> bool:
    return clause["artifact"] == "*" and clause.get("match") is None

#: event_id 가 아니라 **필드 조건**으로 받는 (아티팩트, event_id).
#:
#: 이 조합은 룰에 event_id 가 안 적혀 있어 자동으로는 커버리지가 안 보인다.
#: 자동 판정 대신 여기 손으로 적어, 새로 추가할 때마다 사람이 한 번
#: 생각하게 한다. **"그냥 통과시키려고" 적지 말 것** — 그러면 이 검사가
#: 없는 것과 같아진다.
_COVERED_BY_FIELD_CONDITION = {
    # Sysmon 1 은 세 flag 가 **맥락으로** 나눠 받는다. event_id 로 적혀
    # 있지 않아 자동으로는 커버리지가 안 보인다.
    #   shell_spawned                 무엇이 실행됐나 (fields.Image 가 셸)
    #   execution_from_unusual_path   어디에 있나 (비시스템 볼륨·쓰기 가능 경로)
    #   unexpected_parent_process     누가 실행시켰나 (fields.ParentImage)
    # EID 1 전체에 붙이면 필터가 일을 안 하므로 일부러 좁힌 것이다.
    ("evtx:Sysmon", 1),
}

#: 받을 flag 가 없다고 **알고서** 남겨 둔 것. 사유가 없으면 적지 않는다.
_KNOWN_GAPS = {
    # 7036(서비스 상태 변경)은 정상 부팅에서만 수백 건이 나온다. flag 를
    # 만들면 필터가 죽고, 안 만들면 이 요청이 모델에 닿지 않는다. 어느
    # 쪽이 나은지는 실제 키오스크 로그의 분포를 봐야 정해진다.
    # 7034(비정상 종료)는 드물지만 7036 과 같은 채널·같은 판단이라 함께 둔다.
    ("evtx:System", 7034),
    ("evtx:System", 7036),
}


def _flag_coverage():
    """``(아티팩트 패턴, event_id)`` 로 본 flags 커버리지."""
    vocab = yaml.safe_load((MAPPINGS / "_flags.yaml").read_text(encoding="utf-8"))["flags"]
    by_event: dict[str, set[int]] = {}
    whole: set[str] = set()
    for spec in vocab.values():
        for clause in (spec.get("rule") or {}).get("when", []):
            if _is_marker(clause):
                continue
            pattern = clause["artifact"]
            if clause.get("match") == "event_id":
                by_event.setdefault(pattern, set()).update(clause["values"])
            elif clause.get("match") is None:
                whole.add(pattern)
    return by_event, whole


def _pattern_matches(artifact: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return artifact.startswith(pattern[:-1])
    return artifact == pattern


def test_every_mapped_event_id_has_a_flag_that_receives_it():
    from src.stage03_select.mapping_loader import load_catalog, load_mapping

    catalog = load_catalog(MAPPINGS)
    by_event, whole = _flag_coverage()

    uncovered = []
    for path in sorted((MAPPINGS / "windows").glob("*.yaml")):
        mapping = load_mapping(path, catalog)
        for request in mapping.requests:
            artifact = request.artifact
            spec = catalog.artifacts.get(artifact)
            # signal_source: scope 인 아티팩트는 flag 가 없는 것이 정상이다.
            if spec is None or spec.signal_source != "flags":
                continue
            for raw in (request.scope_template or {}).get("event_ids", []):
                event_id = int(raw)
                pair = (artifact, event_id)
                if pair in _COVERED_BY_FIELD_CONDITION or pair in _KNOWN_GAPS:
                    continue
                if any(_pattern_matches(artifact, p) for p in whole):
                    continue
                if any(
                    _pattern_matches(artifact, p) and event_id in ids
                    for p, ids in by_event.items()
                ):
                    continue
                uncovered.append(f"{mapping.technique} → {artifact} EID {event_id}")

    assert uncovered == [], (
        "매핑이 요청하는데 받을 flag 가 없다. 이 레코드들은 04단계까지 가고 "
        "05단계에 한 건도 도달하지 않는다:\n  " + "\n  ".join(sorted(set(uncovered)))
    )


def test_the_known_gap_list_does_not_rot():
    """``_KNOWN_GAPS`` 에 적힌 조합이 실제로 매핑에 남아 있는가.

    매핑에서 그 event_id 를 빼면 예외도 함께 빼야 한다. 안 그러면 목록이
    "예전에 문제였던 것"의 무덤이 되고, 다음 사람이 이 검사를 믿지 못한다.
    """
    from src.stage03_select.mapping_loader import load_catalog, load_mapping

    catalog = load_catalog(MAPPINGS)
    requested = set()
    for path in sorted((MAPPINGS / "windows").glob("*.yaml")):
        for request in load_mapping(path, catalog).requests:
            for raw in (request.scope_template or {}).get("event_ids", []):
                requested.add((request.artifact, int(raw)))

    stale = sorted((_KNOWN_GAPS | _COVERED_BY_FIELD_CONDITION) - requested)
    assert stale == [], f"매핑에 없는 조합이 예외 목록에 남아 있다: {stale}"


def test_no_event_id_rule_uses_a_wildcard_artifact():
    """``match: event_id`` 절은 아티팩트를 **정확히** 지목해야 한다.

    EventID 는 제공자 안에서만 유일하다. 채널이 그 근사치이고(실측:
    Win7 System.evtx 하나에 제공자 22개, 다만 채널 안에서 ID 가 겹친
    경우는 0건), 진짜 위험은 **채널 사이**다 — NetworkProfile 의
    10000(네트워크 연결)과 Kernel-PnP 의 10000(장치 구성)이 실제로 겹친다.

    와일드카드로 두면 **카탈로그에 채널을 더할 때마다 사정거리가 조용히
    넓어진다.** 2026-08-25 에 채널이 5개에서 14개가 되면서 여섯 룰이
    그렇게 됐고, 그중 AssignedAccess 세 채널은 event_id 필터 없이 전량
    파싱되던 터라 그 채널의 ID 를 모르는 채로 노출돼 있었다.

    ``artifact: "*"`` 인 표식(``outside_time_range``)은 ``match`` 가 없어
    이 검사에 걸리지 않는다.
    """
    vocab = yaml.safe_load((MAPPINGS / "_flags.yaml").read_text(encoding="utf-8"))["flags"]

    offenders = [
        f"{name}: artifact={clause['artifact']!r} values={clause.get('values')}"
        for name, spec in vocab.items()
        for clause in (spec.get("rule") or {}).get("when", [])
        if clause.get("match") == "event_id" and clause["artifact"].endswith("*")
    ]
    assert offenders == [], (
        "event_id 로 거는 절이 와일드카드 아티팩트를 쓴다. 채널을 늘리면 "
        "사정거리가 조용히 넓어진다:\n  " + "\n  ".join(offenders)
    )


def test_a_whole_channel_request_has_a_flag_that_can_receive_it():
    """``event_ids`` 없이 채널 전체를 요구하면 그 채널을 통째로 받는 flag 가 있어야 한다.

    앞의 ``test_every_mapped_event_id_...`` 는 **event_ids 를 적은 요청만**
    본다. 빈 ``scope_template`` 으로 "이 채널을 다 읽겠다"고 하면 검사를
    통째로 빠져나가는데, 그 채널의 flag 가 특정 event_id 에만 걸려 있으면
    나머지 레코드는 04단계까지 가고 05단계에 도달하지 않는다.

    실제로 밟았다(2026-08-25). ``T1041``·``T1048`` 이 ``evtx:Firewall`` 을
    빈 scope 로 Tier 1 요청하면서 rationale 에 "아웃바운드 연결의 허용·차단
    기록"이라고 적었는데, **그 채널에는 그런 기록이 없다** — 규칙·프로필
    구성 변경만 담고, 그것만 ``firewall_config_changed`` 가 받는다.

    **이 검사가 아는 것은 기계적 증상뿐이다** — "받아 줄 절이 없다"까지다.
    rationale 이 틀렸는지는 사람이 채널 내용을 확인해야 나온다. 여기서
    걸리면 "고쳐라"가 아니라 "왜 그런지 보라"는 신호로 읽는다.
    """
    from src.stage03_select.mapping_loader import load_catalog, load_mapping

    catalog = load_catalog(MAPPINGS)
    vocab = yaml.safe_load((MAPPINGS / "_flags.yaml").read_text(encoding="utf-8"))["flags"]

    unrestricted = {
        clause["artifact"]
        for spec in vocab.values()
        for clause in (spec.get("rule") or {}).get("when", [])
        if not _is_marker(clause) and clause.get("match") != "event_id"
    }

    def receivable(artifact: str) -> bool:
        return any(
            artifact == p or (p.endswith("*") and artifact.startswith(p[:-1]))
            for p in unrestricted
        )

    uncovered = []
    for path in sorted((MAPPINGS / "windows").glob("*.yaml")):
        mapping = load_mapping(path, catalog)
        for request in mapping.requests:
            spec = catalog.artifacts.get(request.artifact)
            if spec is None or spec.signal_source != "flags" or request.tier != 1:
                continue
            if (request.scope_template or {}).get("event_ids"):
                continue
            if not receivable(request.artifact):
                uncovered.append(f"{mapping.technique} → {request.artifact}")

    assert uncovered == [], (
        "채널 전체를 Tier 1 로 요구하는데 그 채널을 통째로 받는 flag 가 없다. "
        "event_id 로만 걸린 레코드 말고는 05단계에 가지 않는다:\n  "
        + "\n  ".join(sorted(set(uncovered)))
    )
