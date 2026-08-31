"""모델 출력 스키마가 동결 스키마와 갈라지지 않는가.

이 파일이 지키는 것은 하나다 — **진실이 둘이 되지 않는 것.**

02·05단계는 모델에게 "이 모양으로 내라"고 스키마를 넘기고, 받은 것을
``schemas/``로 검증한다. 둘이 갈라지면 최악의 실패가 난다. 모델은 시킨
대로 냈는데 검증에서 떨어지고, 그 실패가 ``errors.jsonl``에
``schema_violation``으로 쌓여 **환각률에 집계된다.** 발표에서 말할 수치가
우리 배선 실수로 오염되는 것이다. 선례가 있다 — ``findings.schema.json``의
``ref`` 패턴에 ``PF``가 빠져 프리패치가 닿는 케이스는 모델이 무엇을 내든
통과할 수 없었고, 그것이 모델의 환각으로 집계됐다
(``docs/limitations.md`` 2026-08-24 절 ①).

그래서 출력 스키마를 손으로 쓰지 않고 ``llm.output_schema``가 동결
스키마에서 파생시킨다. 여기 있는 시험은 그 파생이 실제로 부분집합인지,
그리고 갈아 끼운 enum이 우리가 아는 목록과 같은지를 본다.
"""

from __future__ import annotations

import json

import pytest

from src.common import attack, llm, schema
from src.stage02_normalize import llm_client as normalize_client
from src.stage05_interpret import llm_client as interpret_client

# ------------------------------------------------------- 헤더를 요구하지 않는가

HEADER_FIELDS = ("case_id", "stage", "schema_version", "generated_at", "generator")


@pytest.mark.parametrize(
    "built, frozen_name",
    [
        (normalize_client.constrained_schema(), "scenario"),
        (
            interpret_client.constrained_schema(
                {"techniques": [{"id": "T1505.003"}]}, [{"ref": "MFT#1"}]
            ),
            "findings",
        ),
    ],
    ids=["02", "05"],
)
def test_the_model_is_never_asked_for_fields_we_fill_in_ourselves(built, frozen_name):
    """헤더 다섯 개는 우리 코드가 붙인다.

    동결 스키마를 그대로 넘기면 모델이 ``case_id``와 ``generated_at``을
    지어내고, 그 값이 스키마 위반으로 집계된다. 05단계는 ``input_refs``가
    하나 더 있다 — 무엇을 보냈는지는 우리가 알고, 모델이 보고하게 하면
    실제로 받지 않은 ref를 목록에 넣어 검사를 무력화할 수 있다.
    """
    for field in HEADER_FIELDS:
        assert field not in built["properties"], f"{frozen_name}: {field} 를 모델에게 요구한다"
    assert "input_refs" not in built["properties"]


# ------------------------------------------------------------ 부분집합인가


@pytest.mark.parametrize(
    "built, frozen_name",
    [
        (normalize_client.constrained_schema(), "scenario"),
        (
            interpret_client.constrained_schema(
                {"techniques": [{"id": "T1505.003"}]}, [{"ref": "MFT#1"}]
            ),
            "findings",
        ),
    ],
    ids=["02", "05"],
)
def test_every_field_we_ask_for_exists_in_the_frozen_schema(built, frozen_name):
    """요구하는 필드가 동결 스키마에 없으면 통과할 수 없는 것을 시킨 것이다."""
    frozen = schema.load_schema(frozen_name)
    unknown = set(built["properties"]) - set(frozen["properties"])
    assert unknown == set(), f"{frozen_name}에 없는 필드를 요구한다: {sorted(unknown)}"

    # required 도 마찬가지다. 동결 스키마가 선택으로 둔 것을 필수로 올리면
    # 모델이 생략했을 때 우리 쪽에서만 실패한다.
    extra_required = set(built["required"]) - set(frozen["required"])
    assert extra_required == set(), f"동결 스키마보다 엄격하다: {sorted(extra_required)}"


# ------------------------------------------------------------ enum 이 맞는가


def test_the_technique_enum_is_exactly_the_list_we_know():
    """기법 목록의 원본은 ``attack.KNOWN_TECHNIQUES`` 하나다.

    여기 없는 ID를 모델이 내면 ``is_known``이 기각한다. 그러므로 enum이
    이 목록보다 넓으면 기각될 답을 허락하는 것이고, 좁으면 정상 기법을
    낼 수 없게 막는 것이다. 어느 쪽도 조용히 틀린다.
    """
    built = normalize_client.constrained_schema()
    enum = built["properties"]["techniques"]["items"]["properties"]["id"]["enum"]
    assert set(enum) == set(attack.KNOWN_TECHNIQUES)


def test_the_hallucinated_subtechnique_from_K_001_cannot_be_produced():
    """``limitations.md`` 2026-08-24 절 ⑤ 의 그 값이다.

    ``T1200``은 실재하고 ``T1200.001``은 실재하지 않는다. 형식만 보면
    구별되지 않아 패턴으로는 막을 수 없었고, ``temperature 0``에서는
    재시도가 같은 답을 받아 왔다.
    """
    enum = normalize_client.constrained_schema()["properties"]["techniques"]["items"][
        "properties"
    ]["id"]["enum"]
    assert "T1200" in enum
    assert "T1200.001" not in enum


def test_the_ref_enum_is_only_what_we_actually_sent():
    """``ref``는 세 자리에서 쓰인다. 정의 하나를 갈아 끼워 셋을 함께 묶는다."""
    records = [{"ref": "MFT#12345"}, {"ref": "EVTX-SEC#88"}, {"ref": "MFT#12345"}]
    built = interpret_client.constrained_schema({"techniques": []}, records)

    assert built["$defs"]["ref"] == {"enum": ["EVTX-SEC#88", "MFT#12345"]}

    # 셋이 모두 이 정의를 가리키는지 — 자리마다 손대면 언젠가 하나를 빠뜨린다.
    findings = built["properties"]["findings"]["items"]["properties"]
    assert findings["refs"]["items"] == {"$ref": "#/$defs/ref"}
    assert findings["claims"]["items"]["properties"]["ref"] == {"$ref": "#/$defs/ref"}
    assert built["properties"]["timeline"]["items"]["properties"]["refs"]["items"] == {
        "$ref": "#/$defs/ref"
    }


def test_an_empty_batch_does_not_produce_an_empty_enum():
    """빈 enum 은 아무 값도 만족시키지 못한다.

    레코드를 한 건도 못 받은 것은 앞 단계의 문제다. 그때 빈 enum 을 걸면
    모델이 무엇을 내든 실패하고, 그 실패가 05단계 환각으로 둔갑한다.
    묶지 못하면 묶지 않는다 — 판정은 어차피 ``schemas/`` 가 한다.
    """
    built = interpret_client.constrained_schema({"techniques": []}, [])
    assert "enum" not in built["$defs"]["ref"]


def test_regexes_never_reach_the_grammar():
    """``pattern`` 은 걷어낸다. 문법 변환기가 우리 정규식을 못 삼킨다.

    2026-08-31 Ollama 0.32.14 실측 — 앵커 없는 패턴은 ``Pattern must start
    with`` 로 거부하고, 앵커가 있어도 ``\\d`` 가 들어가면 ``failed to parse
    grammar`` 로 400 이 온다. 우리 정규식 둘이 모두 걸린다.

    이것을 지키지 않으면 **02·05가 실제 모델에서 통째로 죽는다.** 스텁
    경로는 ``fmt`` 를 버리므로 이 결함이 전체 테스트를 통과한다.
    """

    def patterns(node, path=""):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "pattern":
                    yield f"{path}/{key}"
                else:
                    yield from patterns(value, f"{path}/{key}")
        elif isinstance(node, list):
            for i, value in enumerate(node):
                yield from patterns(value, f"{path}[{i}]")

    built02 = normalize_client.constrained_schema()
    built05 = interpret_client.constrained_schema(
        {"techniques": [{"id": "T1505.003"}]}, [{"ref": "MFT#1"}]
    )
    assert list(patterns(built02)) == []
    assert list(patterns(built05)) == []

    # 걷어낸 것은 제약 스키마뿐이다. 판정하는 쪽은 그대로여야 한다.
    frozen = schema.load_schema("scenario")
    assert "pattern" in frozen["properties"]["techniques"]["items"]["properties"]["id"]


def test_the_technique_of_a_finding_stays_nullable():
    """동결 스키마가 ``null``을 허용한다 — 특정 기법에 귀속되지 않을 수 있다.

    enum 으로 묶으면서 ``None``을 빠뜨리면, 귀속을 못 정한 소견을 모델이
    낼 수 없게 되어 억지로 아무 기법에나 붙인다.
    """
    built = interpret_client.constrained_schema(
        {"techniques": [{"id": "T1505.003"}]}, [{"ref": "MFT#1"}]
    )
    enum = built["properties"]["findings"]["items"]["properties"]["technique"]["enum"]
    assert None in enum
    assert "T1505.003" in enum


# ------------------------------------------- 동결 스키마를 오염시키지 않는가


def test_building_the_output_schema_does_not_touch_the_frozen_one():
    """``schema.load_schema``는 캐시된 객체를 돌려준다.

    얕게 넘겨 받아 enum 을 꽂으면 **검증기가 쓰는 스키마까지** 바뀐다.
    그러면 05단계가 꽂은 배치별 ref enum 이 06단계 검증에 그대로 남아,
    다음 케이스의 정상 ref 가 전부 기각된다.
    """
    before = json.dumps(schema.load_schema("findings"), sort_keys=True)

    interpret_client.constrained_schema(
        {"techniques": [{"id": "T1505.003"}]}, [{"ref": "MFT#1"}]
    )
    normalize_client.constrained_schema()

    assert json.dumps(schema.load_schema("findings"), sort_keys=True) == before
    assert "enum" not in schema.load_schema("scenario")["properties"]["techniques"][
        "items"
    ]["properties"]["id"]


# ------------------------------------------------------------ 전송 계층


def test_no_format_key_is_sent_when_nothing_constrains_the_output():
    """끈 실행은 예전과 **같은 요청**을 보내야 한다.

    ``format``이 있으면 Ollama 가 문법을 컴파일한다. 빈 값을 넣어 두면
    제약이 없는데도 비용이 붙어, 켰을 때와 껐을 때의 차이가 제약 때문인지
    말할 수 없게 된다.
    """
    backend = llm.OllamaBackend("qwen2.5:7b")
    assert "format" not in backend.payload("s", "u")
    assert "format" not in backend.payload("s", "u", fmt=None)
    assert "format" not in backend.payload("s", "u", fmt={})


def test_the_schema_reaches_the_request_body_when_it_is_given():
    backend = llm.OllamaBackend("qwen2.5:7b")
    body = backend.payload("s", "u", fmt={"type": "object"})
    assert body["format"] == {"type": "object"}
    # 나머지는 건드리지 않는다.
    assert body["options"]["num_ctx"] == llm.DEFAULT_NUM_CTX
    assert body["stream"] is False


def test_the_replay_backend_ignores_the_format(tmp_path):
    """리플레이는 기록해 둔 응답을 그대로 낸다. 강제할 디코딩이 없다."""
    fixture = tmp_path / "response.json"
    fixture.write_text('{"findings": []}', encoding="utf-8")
    backend = llm.StubBackend(fixture)
    assert backend.complete("s", "u", fmt={"type": "object"}) == '{"findings": []}'
