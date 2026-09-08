"""구두점만 다른 표기를 봐주되, 그 대가로 무엇을 잃는지 함께 고정한다.

`_COMPACT` 완화는 검사기를 **넓히는** 변경이다. 넓힌 자리가 정확히 어디까지인지
테스트로 못 박아 두지 않으면, 다음 사람이 "점을 지웠으니 밑줄도" 하는 식으로
조금씩 늘려 검사기가 아무것도 안 잡게 된다.
"""

from src.stage06_verify.checkers import statement_grounded as sg


def _finding(statement: str, value: str) -> dict:
    return {
        "statement": statement,
        "refs": ["SYSMON#1"],
        "claims": [{"ref": "SYSMON#1", "field": "fields.Image", "value": value}],
    }


def _records(**fields: str) -> dict:
    return {"SYSMON#1": {"ref": "SYSMON#1", "artifact": "evtx:Sysmon", "fields": dict(fields)}}


def test_product_name_matches_a_directory_that_differs_only_by_a_dot():
    """실측(2026-09-08, K-KIOSK-USB-0908-FIX)에서 이 한 건이 소견을 통째로 떨궜다."""
    finding = _finding(
        "Node.js 애플리케이션이 실행됐습니다.", r"C:\Windows\System32\cmd.exe"
    )
    records = _records(
        Image=r"C:\Windows\System32\cmd.exe",
        ParentImage=r"C:\Program Files\nodejs\node.exe",
    )

    assert sg.ungrounded(finding, records) == []


def test_swapping_an_extension_is_still_caught():
    """**여기서 멈춘다.** 같은 어간에 다른 확장자는 여전히 날조다.

    증거에 `report.txt` 뿐인데 문장이 `report.exe` 를 말하면, 점을 지워도
    ``reportexe`` 와 ``reporttxt`` 라 어긋난다. 어간 비교였다면 이것이
    통과했을 것이고, 그래서 어간이 아니라 구두점만 지운다.
    """
    finding = _finding("report.exe 가 실행됐습니다.", r"C:\tmp\report.txt")
    records = _records(Image=r"C:\tmp\report.txt")

    assert sg.ungrounded(finding, records) == ["report.exe"]


def test_a_name_absent_from_the_evidence_is_still_caught():
    finding = _finding("mimikatz.exe 가 실행됐습니다.", r"C:\Windows\System32\cmd.exe")
    records = _records(Image=r"C:\Windows\System32\cmd.exe")

    assert sg.ungrounded(finding, records) == ["mimikatz.exe"]


def test_short_tokens_do_not_get_the_relaxation():
    """점을 지운 뒤 `MIN_COMPACT` 보다 짧으면 완화를 쓰지 않는다.

    짧은 토큰은 아무 문자열에나 들어 있어, 봐주기 시작하면 대조가 뜻을 잃는다.
    """
    assert sg.MIN_COMPACT == 4

    finding = _finding("a.b 가 실행됐습니다.", r"C:\ab\cmd.exe")
    records = _records(Image=r"C:\ab\cmd.exe")

    assert sg.ungrounded(finding, records) == ["a.b"]


def test_relaxation_applies_to_filenames_not_to_numbers():
    """수는 완화 대상이 아니다 — 레코드 번호가 구두점 차이로 통과하면 안 된다."""
    finding = _finding("레코드 123456 을 확인했습니다.", r"C:\Windows\cmd.exe")
    records = _records(Image=r"C:\Windows\cmd.exe", RecordNumber="12.3456")

    assert sg.ungrounded(finding, records) == ["123456"]
