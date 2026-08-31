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

```bash
DFIR_LIVE_MODEL=qwen2.5:14b .venv/Scripts/python.exe -m pytest tests/test_llm_live.py -v
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
``DFIR_LIVE_NUM_CTX``   컨텍스트 창. 기본 32768
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
"""

from __future__ import annotations

import json
import os
import shutil
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from src.common import io, refs, schema
from src.stage02_normalize import normalize as normalize_mod
from src.stage05_interpret import interpret as interpret_mod

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK = REPO_ROOT / "benchmark/datasets/C-001-webshell/mock"
MAPPINGS = REPO_ROOT / "mappings"

MODEL = os.environ.get("DFIR_LIVE_MODEL", "")
HOST = os.environ.get("DFIR_LIVE_HOST", "http://localhost:11434")
TIMEOUT = os.environ.get("DFIR_LIVE_TIMEOUT", "900")
NUM_CTX = os.environ.get("DFIR_LIVE_NUM_CTX", "32768")

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
    shutil.copy(MOCK / "01_input.json", case_dir / "01_input.json")
    shutil.copy(MOCK / "02_scenario.json", case_dir / "02_scenario.json")
    shutil.copy(MOCK / "03_selection.json", case_dir / "03_selection.json")
    shutil.copytree(MOCK / "04_parsed", case_dir / "04_parsed")
    return case_dir


def _live_args() -> "list[str]":
    return [
        "--llm", "ollama",
        "--model", MODEL,
        "--host", HOST,
        "--timeout", TIMEOUT,
        "--num-ctx", NUM_CTX,
        # 0 이면 재시도가 같은 답을 반복한다(docs/limitations.md 5장 ⑤).
        # 테스트가 모델 사정으로 한 번에 실패하는 것을 막는다.
        "--temperature", "0.3",
    ]


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


def test_every_ref_the_model_cites_actually_exists(case: Path) -> None:
    """**이 파일에서 가장 중요한 확인이다.**

    모델이 지어낸 `ref` 는 06단계가 환각으로 셉니다. 05단계 산출물에서
    이미 걸러져 있어야 하고, 걸러지지 않으면 환각률이 오염됩니다.
    """
    code = interpret_mod.main(
        [
            "--in", str(case / "04_parsed"),
            "--scenario", str(case / "02_scenario.json"),
            "--selection", str(case / "03_selection.json"),
            "--mappings", str(MAPPINGS),
            "--out", str(case / "05_live.json"),
        ]
        + _live_args()
    )
    assert code == 0

    findings_doc = io.read_json(case / "05_live.json")
    schema.validate(findings_doc, "findings")

    known = set(io.read_parsed_records(case / "04_parsed"))
    for finding in findings_doc["findings"]:
        for ref in finding.get("input_refs", []):
            assert refs.is_valid(ref), f"ref 형식 위반: {ref}"
            assert ref in known, f"{ref} 는 04단계 산출물에 없다 (지어낸 참조)"
        for claim in finding.get("claims", []):
            ref = claim.get("ref")
            if ref is not None:
                assert ref in known, f"claims 의 {ref} 가 04단계 산출물에 없다"


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
