import re


STAGE_LABELS = {
    "01": "Input",
    "02": "Normalize",
    "03": "Select",
    "04": "Parse",
    "05": "Interpret",
    "06": "Verify",
    "07": "Report",
}


def detect_stage(line: str) -> str | None:
    """
    live_check.py stdout 한 줄을 받아
    현재 실행 중인 DFIR Stage 번호를 반환한다.

    반환값:
        "01" ~ "07"
        또는 감지 실패 시 None
    """

    match = re.search(r"\]\s+(0[1-7])\s", line)

    if match:
        return match.group(1)

    # Stage04 내부 검산 단계
    if "04 검산" in line:
        return "04"

    return None