"""실제 모델을 부르는 테스트. **기본으로는 돌지 않는다.**

나머지 테스트는 `StubBackend` 리플레이로 돕니다. 그래야 04·06·07을
결정론 구간으로 유지할 수 있고, 05단계 호출 한 번이 200초를 넘는
장비에서도 전체 스위트가 10초 안에 끝납니다.

**그런데 스텁만으로는 확인되지 않는 것이 있습니다.** 프롬프트가 실제
모델에게 말이 되는지, 응답이 우리 파서를 통과하는지, 모델이 지어낸 `ref`를
우리가 잡아내는지는 실제로 불러 봐야 압니다. 실측에서 드러난 결함 여섯 개
중 넷은 스텁으로는 나올 수 없는 것이었습니다(`docs/limitations.md` 5장 —
스키마의 `ref` 패턴 누락, 배분의 실물 규모, 120초 타임아웃, `num_ctx` 4096).

## 켜는 법

이 프로젝트의 기본 셸은 PowerShell 이다. **`VAR=값 명령` 형식이 안 먹는다** —
PowerShell 은 그것을 명령 이름으로 읽고 `CommandNotFoundException` 을 낸다.

```powershell
$env:DFIR_LIVE_MODEL = "qwen2.5:7b"
$env:DFIR_LIVE_TIMEOUT = "600"
.venv/Scripts/python.exe -m pytest tests/test_llm_live.py -v
Remove-Item Env:DFIR_LIVE_MODEL, Env:DFIR_LIVE_TIMEOUT
```

**끝나면 지운다.** 안 지우면 그 세션의 이후 `pytest` 가 전부 모델을 부르고,
10초에 끝나던 스위트가 몇 분이 된다.

bash(Git Bash) 에서는 예전 형식 그대로다.

```bash
DFIR_LIVE_MODEL=qwen2.5:7b .venv/Scripts/python.exe -m pytest tests/test_llm_live.py -v
```

환경 변수가 없으면 **전부 건너뜁니다.** 있는데 Ollama 가 응답하지 않거나
그 모델이 없으면 **실패합니다** — 켜 달라고 한 것은 사람이고, 그때
조용히 건너뛰면 "돌았는데 통과"와 "안 돌았다"가 같아 보입니다.

======================  =====================================================
변수                     뜻
======================  =====================================================
``DFIR_LIVE_MODEL``     필수. ``ollama list`` 의 이름 그대로
``DFIR_LIVE_HOST``      기본 ``http://localhost:11434``
``DFIR_LIVE_TIMEOUT``   한 번 호출의 상한(초). 기본 900
``DFIR_LIVE_NUM_CTX``   컨텍스트 창. **비우면 ``--mode`` 가 정한다**
                        (model 32,768 / assemble 8,192)
======================  =====================================================

## 무엇을 확인하나

**모델이 무엇을 말하는지는 보지 않습니다.** 같은 입력에 같은 답이 나온다는
보장이 없으므로, 여기서 고정할 수 있는 것은 **모델이 무엇을 말하든 성립해야
하는 것**뿐입니다.

- 응답이 스키마를 통과하는가 (통과 못 하면 단계가 중단해야 한다)
- 모델이 **인용한 `ref`가 실제로 존재하는가** — 지어낸 것이면 06단계가
  환각으로 셀 값입니다. 05단계 산출물에서 이미 걸러져야 합니다
- 산출물이 **어느 모델로 돈 것인지** 남기는가 (`generator`)
- 모델을 못 부르면 **소리를 내고 멈추는가** — 이건 추론이 없어 빠릅니다

## 조립 경로(``--mode assemble``)에서 더 보는 것

모델이 고르기만 하고 파이썬이 조립하는 경로는 **스텁으로 확인되지 않는 층이
더 있습니다.** 스텁은 우리가 적어 둔 응답을 그대로 돌려주므로, "모델이
무엇을 골랐든" 성립해야 할 성질이 실제로 서는지 알 수 없습니다.

- `claims` 의 값이 **원본 레코드와 글자 그대로 같은가** — 이 경로의 논지가
  "모델은 이름만 고르고 값은 파이썬이 옮긴다" 입니다
- 레코드가 **다른 레코드의 필드를 근거로 대지 못하는가** — 합집합 enum 으로
  두었을 때 실물에서 무너진 자리입니다(2026-09-03). 지금은 레코드마다
  `oneOf` 갈래를 따로 둡니다
- 조각으로 나눠도 **`input_refs` 가 전부 남는가** — 마지막 조각만 남으면
  06단계의 `ref_in_input` 검사가 통째로 헐거워집니다
- 조립한 문서가 **06단계를 통과하는가** — 이 통과는 성능이 아니라 항등식
  이지만, 떨어지면 조립기가 검증기와 다른 자리를 본다는 뜻입니다

## 선별·종합 스키마의 문법 변환

`oneOf`·`const`·`minItems` 가 Ollama 문법으로 내려가야 합니다. 안 내려가면
조립 경로가 **통째로** 죽습니다 — HTTP 400 이고 소견이 0건이 아니라 아예
없습니다. `pattern` 으로 한 번 물린 자리라(2026-08-31) 새 스키마도 같은
시험을 받습니다.
"""

from __future__ import annotations

import json
import os
import shutil
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from src.common import io, llm, refs, schema
from src.stage02_normalize import coverage
from src.stage02_normalize import llm_client as normalize_client
from src.stage02_normalize import normalize as normalize_mod
from src.stage03_select import select as select_mod
from src.stage05_interpret import interpret as interpret_mod
from src.stage04_parse import flagging
from src.stage05_interpret import assembly as assembly_mod
from src.stage05_interpret import llm_client as interpret_client
from src.stage06_verify import verify as verify_mod
from casepaths import FIXTURES, GOLDEN

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = REPO_ROOT / "mappings"

MODEL = os.environ.get("DFIR_LIVE_MODEL", "")
HOST = os.environ.get("DFIR_LIVE_HOST", "http://localhost:11434")
TIMEOUT = os.environ.get("DFIR_LIVE_TIMEOUT", "900")
#: 창을 **비워 두면 `--mode` 가 정한다** (model 32,768 / assemble 8,192).
#: 값을 주면 두 모드 다 그 값으로 돈다.
NUM_CTX = os.environ.get("DFIR_LIVE_NUM_CTX", "")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not MODEL, reason="DFIR_LIVE_MODEL 없음 (실제 모델 테스트는 선택)"),
]


def _installed_models() -> "list[str]":
    """Ollama 가 들고 있는 모델 이름. 못 물으면 예외를 그대로 올린다."""
    with urllib.request.urlopen(f"{HOST}/api/tags", timeout=10) as response:
        body = json.loads(response.read().decode("utf-8"))
    return [entry["name"] for entry in body.get("models", [])]


@pytest.fixture(scope="module", autouse=True)
def live_model_is_available() -> None:
    """켜 달라고 했으면 켜져 있어야 한다. 없으면 건너뛰지 않고 실패한다."""
    try:
        installed = _installed_models()
    except (urllib.error.URLError, OSError) as e:
        pytest.fail(
            f"DFIR_LIVE_MODEL={MODEL} 로 켰는데 {HOST} 가 응답하지 않는다 — {e}\n"
            "  Ollama 를 띄우거나 DFIR_LIVE_MODEL 을 빼고 돌린다."
        )
    if MODEL not in installed:
        pytest.fail(
            f"{HOST} 에 {MODEL} 이 없다. 설치된 것: {', '.join(installed) or '(없음)'}"
        )


@pytest.fixture
def case(tmp_path: Path) -> Path:
    """목업 입력만 있는 케이스. 증거 이미지가 필요 없다."""
    case_dir = tmp_path / "LIVE"
    case_dir.mkdir()
    shutil.copy(FIXTURES / "01_input.json", case_dir / "01_input.json")
    shutil.copy(FIXTURES / "02_scenario.json", case_dir / "02_scenario.json")
    shutil.copy(GOLDEN / "03_selection.json", case_dir / "03_selection.json")
    shutil.copytree(FIXTURES / "04_parsed", case_dir / "04_parsed")
    return case_dir


def _live_args(mode: "str | None" = None) -> "list[str]":
    args = [
        "--llm", "ollama",
        "--model", MODEL,
        "--host", HOST,
        "--timeout", TIMEOUT,
        # 0 이면 재시도가 같은 답을 반복한다(docs/limitations.md 5장 ⑤).
        # 테스트가 모델 사정으로 한 번에 실패하는 것을 막는다.
        "--temperature", "0.3",
    ]
    if NUM_CTX:
        args += ["--num-ctx", NUM_CTX]
    if mode:
        args += ["--mode", mode]
    return args


def _run_interpret(case: Path, out: str, mode: "str | None" = None, *extra: str) -> Path:
    """05단계를 실제 모델로 한 번 돌리고 산출물 경로를 돌려준다."""
    path = case / out
    code = interpret_mod.main(
        [
            "--in", str(case / "04_parsed"),
            "--scenario", str(case / "02_scenario.json"),
            "--selection", str(case / "03_selection.json"),
            "--mappings", str(MAPPINGS),
            "--out", str(path),
            *extra,
        ]
        + _live_args(mode)
    )
    assert code == 0
    return path


# =============================================================== 02단계


def test_normalize_produces_a_schema_valid_scenario(case: Path) -> None:
    """실제 추론 결과가 우리 스키마를 통과하는가.

    통과하지 못하면 단계가 재시도 끝에 중단합니다. 그 경로까지가 확인
    대상이고, **모델이 무엇을 골랐는지는 보지 않습니다.**
    """
    code = normalize_mod.main(
        ["--in", str(case / "01_input.json"), "--out", str(case / "02_live.json")]
        + _live_args()
    )
    assert code == 0

    scenario = io.read_json(case / "02_live.json")
    schema.validate(scenario, "scenario")
    assert scenario["techniques"], "기법이 하나도 없으면 03단계가 아무것도 선별하지 못한다"


def test_the_scenario_records_which_model_produced_it(case: Path) -> None:
    """`generator` 로 실험 조건을 복원할 수 있어야 모델별 비교가 성립한다."""
    assert (
        normalize_mod.main(
            ["--in", str(case / "01_input.json"), "--out", str(case / "02_live.json")]
            + _live_args()
        )
        == 0
    )
    generator = io.read_json(case / "02_live.json")["generator"]
    assert MODEL in generator, generator


# =============================================================== 05단계


def _assert_refs_exist(findings_doc: dict, known: set) -> None:
    """소견이 인용한 ref 가 전부 04단계 산출물에 있는가.

    **``finding["refs"]`` 를 본다.** 예전에는 ``finding["input_refs"]`` 를
    돌았는데 그 키는 소견이 아니라 **문서**에 있다 — 언제나 빈 목록이라
    이 검사가 아무것도 보지 않았다(2026-09-03 발견).
    """
    for finding in findings_doc["findings"]:
        for ref in finding.get("refs", []):
            assert refs.is_valid(ref), f"ref 형식 위반: {ref}"
            assert ref in known, f"{ref} 는 04단계 산출물에 없다 (지어낸 참조)"
        for claim in finding.get("claims", []):
            ref = claim.get("ref")
            if ref is not None:
                assert ref in known, f"claims 의 {ref} 가 04단계 산출물에 없다"

    for ref in findings_doc["input_refs"]:
        assert ref in known, f"input_refs 의 {ref} 가 04단계 산출물에 없다"


@pytest.mark.parametrize("mode", ["model", "assemble"])
def test_every_ref_the_model_cites_actually_exists(case: Path, mode: str) -> None:
    """**이 파일에서 가장 중요한 확인이다.**

    모델이 지어낸 `ref` 는 06단계가 환각으로 셉니다. 05단계 산출물에서
    이미 걸러져 있어야 하고, 걸러지지 않으면 환각률이 오염됩니다.

    두 경로를 다 봅니다 — 모델이 문장을 쓰는 쪽과, 고르기만 하고 파이썬이
    조립하는 쪽은 ``ref`` 가 나오는 자리가 다릅니다.
    """
    out = _run_interpret(case, f"05_live_{mode}.json", mode)

    findings_doc = io.read_json(out)
    schema.validate(findings_doc, "findings")
    _assert_refs_exist(findings_doc, set(io.read_parsed_records(case / "04_parsed")))


# ============================================ 조립 경로 (Map · Reduce)


def test_the_assembled_claims_are_copies_of_the_record_not_the_models_typing(
    case: Path,
) -> None:
    """**조립 경로의 논지가 이것이다.**

    모델은 `ref` 와 근거 **필드 이름**만 고르고, 값은 파이썬이 원본에서
    옮깁니다. 그래서 옮겨 적기 오류가 원리적으로 없어야 합니다 — 스텁으로는
    확인이 안 되는 층입니다. 스텁은 우리가 적어 둔 값을 그대로 돌려주므로
    "모델이 무엇을 골랐든" 이 성질이 서는지 알 수 없습니다.
    """
    out = _run_interpret(case, "05_assembled.json", "assemble")

    doc = io.read_json(out)
    records = io.read_parsed_records(case / "04_parsed")
    for finding in doc["findings"]:
        for claim in finding["claims"]:
            record = records[claim["ref"]]
            found, actual = assembly_mod.walk_field(record, claim["field"])
            assert found, f"{claim['ref']} 에 {claim['field']} 가 없다"
            assert claim["value"] == actual, (
                f"{claim['ref']}.{claim['field']} 가 원본과 다르다 — "
                f"조립기가 값을 손댔다: {claim['value']!r} != {actual!r}"
            )


def test_the_grammar_stops_a_record_from_citing_another_records_field(
    case: Path,
) -> None:
    """레코드마다 갈래를 따로 두는 것이 실제 모델에서 서는가.

    **합집합 enum 으로는 실물에서 무너졌습니다** (2026-09-03). 파일 생성
    이벤트에 프로세스 생성 이벤트의 `fields.CommandLine` 을 붙이는 것이
    문법상 합법이었고, `temperature 0` 이라 재시도 세 번이 같은 답을 냈습니다.
    지금은 `oneOf` + `const` 로 각 레코드가 자기 필드만 고릅니다.

    조립이 그것을 뒤에서 잡기는 하지만(`SelectionError`), 잡히면 재시도가
    돕니다. 여기서 보는 것은 **애초에 나오지 않는가**입니다.
    """
    out = _run_interpret(case, "05_fields.json", "assemble")

    doc = io.read_json(out)
    records = io.read_parsed_records(case / "04_parsed")
    for finding in doc["findings"]:
        for claim in finding["claims"]:
            assert claim["field"] in flagging.claim_fields().names, (
                f"{claim['field']} 는 claim_fields 어휘에 없다 — "
                "문법이 어휘 밖 이름을 허용했다"
            )
            assert assembly_mod.walk_field(records[claim["ref"]], claim["field"])[0]


def test_the_assembled_findings_pass_stage_six(case: Path) -> None:
    """조립한 문서가 06단계를 통과하는가.

    **이 통과는 성능이 아니라 항등식입니다** — `value_match` 는 우리가
    복사한 값을 우리가 원본과 대조합니다. 그래도 확인할 값이 있습니다:
    떨어지면 조립기가 06단계와 다른 자리를 본다는 뜻이고, 그것은 우리
    버그입니다.
    """
    out = _run_interpret(case, "05_verify_me.json", "assemble")

    verified = verify_mod.verify(
        io.read_json(out),
        io.read_parsed_records(case / "04_parsed"),
        supported_artifacts=verify_mod.technique_artifacts(MAPPINGS),
    )
    schema.validate(verified, "verified")

    rejected = [r for r in verified["rejected"] if r["reason"] != "technique_unsupported"]
    assert not rejected, f"조립기와 검증기가 다른 자리를 본다: {rejected}"


def test_splitting_the_query_does_not_lose_records(case: Path) -> None:
    """조각으로 나눠도 전달한 것이 전부 `input_refs` 에 남는가.

    `input_refs` 는 06단계가 "전달하지 않은 레코드를 인용했는가"를 보는
    근거입니다. 조각이 여럿일 때 합집합이 아니라 마지막 조각만 남으면 그
    검사가 통째로 헐거워집니다.

    창을 좁혀 조각을 강제합니다 — 픽스처는 작아서 기본 창에서는 한 번에
    들어갑니다.
    """
    out = _run_interpret(
        case, "05_chunked.json", "assemble",
        "--num-ctx", "5400", "--reserve-output-tokens", "4096", "--max-chunks", "8",
    )

    doc = io.read_json(out)
    known = set(io.read_parsed_records(case / "04_parsed"))
    assert doc["input_refs"], "전달한 레코드가 하나도 기록되지 않았다"
    assert len(doc["input_refs"]) == len(set(doc["input_refs"])), "input_refs 에 중복이 있다"
    _assert_refs_exist(doc, known)


# ====================================================== 출력 제약 (문법 변환)


@pytest.mark.parametrize(
    "stage, built",
    [
        ("02", normalize_client.constrained_schema()),
        (
            "05 소견",
            interpret_client.constrained_schema(
                {"techniques": [{"id": "T1505.003", "name": "Web Shell"}]},
                [{"ref": "MFT#12345"}, {"ref": "EVTX-SEC#88"}],
            ),
        ),
        # 선별 스키마는 레코드마다 `oneOf` 갈래를 만든다. `const` 와 `oneOf`
        # 가 문법으로 내려가야 하고, 안 내려가면 조립 경로가 통째로 죽는다.
        (
            "05 선별",
            interpret_client.selection_schema(
                {"techniques": [{"id": "T1505.003", "name": "Web Shell"}]},
                [
                    {"ref": "MFT#12345", "path": r"C:\web\shell.aspx"},
                    {"ref": "SYSMON#88", "fields": {"CommandLine": "cmd /c x"}},
                ],
                flagging.claim_fields().names,
            ),
        ),
        # 종합 스키마는 `minItems` 로 "둘 이상" 을 요구한다.
        (
            "05 종합",
            interpret_client.connection_schema(
                {"techniques": [{"id": "T1505.003", "name": "Web Shell"}]},
                [{"ref": "MFT#12345"}, {"ref": "SYSMON#88"}],
            ),
        ),
    ],
)
def test_the_output_schema_survives_grammar_conversion(stage: str, built: dict) -> None:
    """제약 스키마가 문법으로 **변환되는가**. 스텁으로는 절대 안 잡히는 층이다.

    ``StubBackend`` 는 ``fmt`` 를 받고 버리므로, 서버가 삼키지 못하는
    스키마를 보내도 단위 테스트는 전부 통과한다. 그리고 실제 모델에서는
    단계가 **통째로** 죽는다 — HTTP 400 이고 소견이 0건이 아니라 아예 없다.

    실제로 한 번 물렸다 (2026-08-31, Ollama 0.32.14). 동결 스키마의
    ``pattern`` 을 그대로 실어 보내다가 ``failed to parse grammar`` 로
    400 을 받았다. 지금은 ``llm.output_schema`` 가 정규식을 걷어낸다.

    **생성이 끝나는 것까지 요구하지 않는다.** 문법이 걸리면 토큰이 느려져
    시간이 오래 걸릴 수 있고, 그것은 이 시험이 볼 것이 아니다. 400 만
    실패로 본다.
    """
    backend = llm.OllamaBackend(MODEL, host=HOST, timeout=60.0)
    try:
        backend.complete("JSON 객체 하나만 출력한다.", "최소한으로 채워라.", fmt=built)
    except llm.LLMTimeout:
        pass  # 느린 것은 여기서 볼 문제가 아니다.
    except llm.LLMError as e:
        pytest.fail(f"{stage}단계 제약 스키마를 서버가 거부했다 — {e}")


# =============================================================== 실패 경로


def test_a_missing_model_stops_the_stage_instead_of_writing_nothing_quietly(
    case: Path,
) -> None:
    """모델을 못 부르면 소리를 내고 멈추는가. **추론이 없어 빠르다.**

    폴백이 없다는 것이 이 프로젝트의 규약이고, 그 규약이 실제 네트워크
    실패에서도 지켜지는지는 스텁으로 확인할 수 없습니다.
    """
    with pytest.raises(SystemExit):
        normalize_mod.main(
            [
                "--in", str(case / "01_input.json"),
                "--out", str(case / "02_nope.json"),
                "--llm", "ollama",
                "--model", "존재하지-않는-모델:v0",
                "--host", HOST,
                "--timeout", "30",
                "--max-attempts", "1",
            ]
        )
    assert not (case / "02_nope.json").exists(), "실패했는데 산출물이 남았다"
    assert (case / "errors.jsonl").is_file(), "실패가 errors.jsonl 에 남지 않았다"


def test_an_account_clause_reaches_an_account_technique(tmp_path: Path) -> None:
    """계정 축을 물으면 계정 기법이 나오는가 — **03단계까지 이어지는가.**

    2026-09-04 `K-LIVE-0902-wide` 에서 입력이 "계정 관련 변경"을 물었는데
    `T1136`·`T1098`·`T1078` 이 하나도 나오지 않았다. 02 의 기법 목록이
    03 의 유일한 입력이라 `evtx:Security` 가 요청되지 않았고, 보고서는
    그것을 "식별된 기법에 매핑된 아티팩트가 아님"으로 인쇄했다 — 그 파일은
    같은 수집 안에 15.8MB 로 있었다.

    프롬프트를 고쳐 8/8 로 나오게 됐다(고치기 전 0/8). **기법 ID 를 못박지
    않는다** — 계정 축에 닿기만 하면 되고, 어느 하위 기법인지는 모델의
    몫이다.
    """
    raw = (
        "키오스크 단말에서 침해사고가 발생했습니다. "
        "USB 저장장치가 연결된 뒤 그 안의 실행 파일이 실행됐고, "
        "이후 명령 셸과 PowerShell이 사용된 정황이 있습니다. "
        "재부팅 뒤에도 남는 자동 실행 등록과 계정 관련 변경이 "
        "있었는지도 확인해야 합니다. 사고 발생일은 2026년 8월 31일입니다."
    )
    # 픽스처를 복사해 `raw` 만 바꾼다. 입력 스키마를 손으로 다시 쓰면
    # 스키마가 늘어날 때 이 테스트만 조용히 낡는다.
    case_dir = tmp_path / "ACCOUNT"
    case_dir.mkdir()
    document = io.read_json(FIXTURES / "01_input.json")
    document["raw"] = raw
    io.write_json(case_dir / "01_input.json", document)

    assert (
        normalize_mod.main(
            ["--in", str(case_dir / "01_input.json"), "--out", str(case_dir / "02.json")]
            + _live_args()
        )
        == 0
    )
    scenario = io.read_json(case_dir / "02.json")
    families = {t["id"].split(".")[0] for t in scenario["techniques"]}
    assert families & {"T1136", "T1098", "T1078"}, (
        f"계정 축이 기법으로 옮겨지지 않았다: {[t['id'] for t in scenario['techniques']]}"
    )

    # 기법이 나온 것만으로는 부족하다. 03 이 실제로 그 아티팩트를 요청해야
    # 조사 대상이 된다 — 여기가 이 축이 죽던 자리다.
    assert (
        select_mod.main(
            [
                "--in", str(case_dir / "02.json"),
                "--out", str(case_dir / "03.json"),
                "--mappings", str(MAPPINGS),
            ]
        )
        == 0
    )
    selected = {entry["artifact"] for entry in io.read_json(case_dir / "03.json")["selected"]}
    assert "evtx:Security" in selected, sorted(selected)


def test_the_model_still_paraphrases_its_quotes(tmp_path: Path) -> None:
    """`evidence_text` 가 원문 그대로인지 — **재는 것이지 판정이 아니다.**

    실측에서 소형 모델은 인용을 완결된 문장으로 다듬는다(8/8). 그래서
    02단계는 이것으로 재시도하지 않고 `nonverbatim_evidence` 로 기록만
    한다(`src/stage02_normalize/coverage.py`). 여기서도 **세어서 남기기만**
    한다 — 모델이 나아지면 이 테스트가 조용해지고, 그 사실 자체가 신호다.
    """
    case_dir = tmp_path / "QUOTE"
    case_dir.mkdir()
    shutil.copy(FIXTURES / "01_input.json", case_dir / "01_input.json")
    assert (
        normalize_mod.main(
            ["--in", str(case_dir / "01_input.json"), "--out", str(case_dir / "02.json")]
            + _live_args()
        )
        == 0
    )
    scenario = io.read_json(case_dir / "02.json")
    raw = io.read_json(case_dir / "01_input.json")["raw"]
    reported = coverage.nonverbatim_quotes(scenario, raw)
    print(f"\n다듬어진 인용 {len(reported)}/{len(scenario['techniques'])}건: {reported}")


def test_the_model_still_invents_paths_and_we_drop_them(tmp_path: Path) -> None:
    """`entities.paths` 가 입력에서 오는가 — **재는 것이지 판정이 아니다.**

    2026-09-05 실측에서 모델은 경로를 **16/16 전부** 지어냈다(두 입력 8회씩).
    02단계가 그것을 떨구므로 산출물에는 남지 않는다. 여기서는 **떨어진 뒤에
    남은 값이 전부 입력에서 온 것인지**만 본다 — 그것이 이 단계의 불변식이다.

    지어낸 횟수 자체는 `errors.jsonl` 의 `ungrounded_entity` 가 센다. 모델이
    나아지면 그 수가 줄고, 이 테스트는 그대로 조용하다.
    """
    case_dir = tmp_path / "ENTITY"
    case_dir.mkdir()
    shutil.copy(FIXTURES / "01_input.json", case_dir / "01_input.json")
    assert (
        normalize_mod.main(
            ["--in", str(case_dir / "01_input.json"), "--out", str(case_dir / "02.json")]
            + _live_args()
        )
        == 0
    )
    scenario = io.read_json(case_dir / "02.json")
    raw = io.read_json(case_dir / "01_input.json")["raw"]
    left = coverage.ungrounded_entities(scenario, raw)
    assert left == {}, f"입력에 없는 값이 살아남았다: {left}"
    print(f"\n남은 entities: {scenario['entities']}")
