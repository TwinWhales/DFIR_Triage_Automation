import json
from pathlib import Path

from src.stage05_interpret import attention
from src.stage06_verify import verify


#: SVCStealer 실측(2026-09-07)의 정답 데이터. **픽스처를 픽스처로 검사하지
#: 않는다** — `len(direct_children) == 7` 같은 단언은 프로덕션 코드를 한 줄도
#: 건드리지 않아 어떤 회귀에도 실패하지 못한다. 통과 수만 늘려 수치를 흐린다.
#: 아래 둘처럼 이 값으로 **코드를 돌려 본 것**만 테스트다.
EXPECTED = json.loads((Path(__file__).parent / "data" / "svcstealer_expected.json").read_text(encoding="utf-8"))


def test_required_observations_are_implemented_as_attention_not_verdicts():
    implemented = set(attention.signal_ids({
        "timestamp": "1970-01-01T00:00:00Z",
        "fields": {"CommandLine": "netsh wlan export profile key=clear --no-sandbox /VERYSILENT", "loaded_files": [r"C:\\Browser\\Login Data"]},
    }))
    assert set(EXPECTED["required_observations"]) <= implemented


def test_popats_outside_path_regression_is_rejected():
    assertion = {"predicate": "outside_path", "subject": {"ref": "AMCACHE#1", "field": "canonical.subject_path"}, "object": r"C:\\Program Files"}
    doc = {"case_id": "K-LIVE-SVCSTEALER", "input_refs": ["AMCACHE#1"], "findings": [
        {"id": "F3", "statement": EXPECTED["forbidden_claims"][0], "refs": ["AMCACHE#1"], "claims": [], "assertions": [assertion], "technique": None, "severity": "medium"}
    ]}
    records = {"AMCACHE#1": {"ref": "AMCACHE#1", "artifact": "registry:Amcache", "canonical": {"subject_path": r"C:\\Program Files (x86)\\ESTsoft\\ALZip\\popats.exe"}}}
    assert verify.verify(doc, records)["rejected"][0]["reason"] == "assertion_contradicted"
