"""프리패치 파서 테스트.

온디스크 구조는 전부 우리 구현이라(``structs/prefetch_record.py``)
레지스트리·evtx 테스트와 달리 **구조 읽기까지 여기서 고정합니다.** 다만
바이너리 픽스처는 두지 않습니다 — 아래 ``build_pf``가 버전 23 파일을
합성하므로, 무엇이 어떤 값을 만드는지 테스트 안에서 다 보입니다.

여기서 고정하는 것:

- ``ref``/``record_num``/``offset`` 규약 (해시 → ``PF#<10진수>``)
- 파일 하나가 레코드 하나라는 것
- 장치 경로를 드라이브 문자로 바꾸는 규칙과 **바꾸지 않는** 경우
- 실행 파일 전체 경로를 목록에서 찾는 규칙
- 범위 한정 (실행 파일이든 적재 파일이든 하나라도 걸리면 통과)
- 같은 해시가 두 번 나왔을 때
- 모르는 레이아웃·비정상 값에서 **그 파일만** 건너뛰는 것

압축 해제 자체는 ``tests/test_xpress_huffman.py``가 봅니다. 여기서는
``MAM`` 컨테이너를 붙였다 떼는 배선만 확인합니다.

실물 대조는 맨 아래 통합 테스트가 맡습니다. ``evidence/``는 저장소에
없으므로(gitignore) 없으면 건너뜁니다.
"""

from __future__ import annotations

import datetime as dt
import io as _io
import json
import struct
from pathlib import Path
from typing import NamedTuple

import pytest

from src.common import refs, schema
from src.stage04_parse import flagging
from src.stage04_parse.parsers import prefetch
from src.stage04_parse.parsers.base import Scope
from src.stage04_parse.structs import prefetch_record as pf

UTC = dt.timezone.utc
REPO_ROOT = Path(__file__).resolve().parents[1]

#: 실물 프리패치 폴더. 없으면 통합 테스트를 건너뛴다.
REAL_PREFETCH = REPO_ROOT / "evidence" / "[root]" / "Windows" / "Prefetch"

_FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=UTC)

DEVICE = "\\DEVICE\\HARDDISKVOLUME2"
SHADOW = "\\DEVICE\\HARDDISKVOLUMESHADOWCOPY1"

#: 마운트 관리자의 영구 볼륨 이름. 2026-08-26 실물
#: (win10_sysmon_testimage.001) 의 프리패치 127건 전부가 이 형태였다.
GUID_VOLUME = "\\VOLUME{01d8e7bd02796420-a202ae01}"

#: 버전 23의 파일 정보 블록 크기. 메트릭 배열이 바로 뒤에 붙는다.
_V23_INFO_SIZE = 156


class Spec(NamedTuple):
    """레이아웃 하나. ``pf.FileInfoLayout``과 **일부러 별개**다."""

    run_time_offset: int
    run_time_count: int
    run_count_offset: int
    metrics_entry_size: int
    volume_entry_size: int


#: ``(버전, 파일 정보 블록 크기)`` → 자리. **손으로 적은 명세 값이다.**
#:
#: `structs/prefetch_record.py`의 ``FILE_INFORMATION``을 가져다 쓰지 않는
#: 것이 요점입니다. 표를 가져다 픽스처를 만들면 픽스처와 파서가 같은 값을
#: 공유하게 되어, **표를 잘못 고쳐도 테스트가 통과합니다.** 그러면 회귀
#: 테스트가 아니라 항등식입니다.
#:
#: 줄 끝 주석이 어느 Windows인지, 실물로 확인한 것인지 말합니다. 버전
#: 23과 30/220만 실측이고 나머지는 [LIBSCCA] 명세입니다
#: (`docs/limitations.md` "프리패치에서 확인되지 않은 것"). 명세만 있는
#: 줄은 **"이 값이 맞다"가 아니라 "이 값을 쓰기로 했다"**를 고정합니다.
SPEC: dict[tuple[int, int], Spec] = {
    (17, 68): Spec(0x24, 1, 0x3C, 20, 40),      # XP/2003
    (23, 156): Spec(0x2C, 1, 0x44, 32, 104),    # Win7 — 실측
    (26, 224): Spec(0x2C, 8, 0x7C, 32, 104),    # Win8/8.1
    (30, 224): Spec(0x2C, 8, 0x7C, 32, 96),     # Win10
    (30, 220): Spec(0x2C, 8, 0x7C, 32, 96),     # Win10 — 실측(빌드 15063)
    (30, 216): Spec(0x2C, 8, 0x74, 32, 96),     # Win10 1903+
    (30, 212): Spec(0x2C, 8, 0x74, 32, 96),     # Win10 22H2 — 실측(빌드 19045.6466)
    (31, 224): Spec(0x2C, 8, 0x7C, 32, 96),     # Win11
}


def to_filetime(moment: dt.datetime) -> int:
    delta = moment - _FILETIME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def _metrics_entry(entry_size: int, name_offset: int, char_count: int) -> bytes:
    """파일 메트릭 원소 하나.

    **문자열 오프셋의 자리가 버전 17과 23 이상에서 다릅니다.** 17에는
    평균 지속 필드가 없어 뒤가 4바이트씩 당겨집니다. 파서가 원소 크기로
    그 차이를 가르므로(``read_filenames``), 픽스처도 크기로 가릅니다.
    """
    if entry_size == 20:
        return struct.pack("<IIIII", 0, 0, name_offset, char_count, 0x200)
    return struct.pack("<IIIIIIQ", 0, 0, 0, name_offset, char_count, 0x200, 0)


def build_pf(
    executable: str = "CMD.EXE",
    path_hash: int = 0x4A81B364,
    loaded: "list[str] | None" = None,
    volumes: "list[tuple[str, int, int]] | None" = None,
    run_count: int = 2,
    run_time: "int | None" = None,
    version: int = 23,
    info_size: int = _V23_INFO_SIZE,
) -> bytes:
    """.pf 하나를 합성한다. 기본은 버전 23이다.

    ``(version, info_size)``가 ``SPEC``에 있으면 **그 버전의 자리대로**
    씁니다. 없으면 버전 23의 자리를 쓰되 헤더의 버전 번호만 바꿉니다 —
    ``UnknownLayout`` 경로를 시험하는 데 그 조합을 씁니다.
    """
    spec = SPEC.get((version, info_size), SPEC[(23, _V23_INFO_SIZE)])
    loaded = [f"{DEVICE}\\WINDOWS\\SYSTEM32\\{executable}"] if loaded is None else loaded
    volumes = [(DEVICE, 0x2EC87543, to_filetime(dt.datetime(2019, 1, 10, tzinfo=UTC)))] \
        if volumes is None else volumes
    if run_time is None:
        run_time = to_filetime(dt.datetime(2019, 1, 10, 8, 45, 16, tzinfo=UTC))

    metrics_offset = pf.HEADER_SIZE + info_size
    strings_offset = metrics_offset + spec.metrics_entry_size * len(loaded)

    strings = b""
    entries = b""
    for name in loaded:
        encoded = name.encode("utf-16-le") + b"\x00\x00"
        entries += _metrics_entry(spec.metrics_entry_size, len(strings), len(name))
        strings += encoded

    volumes_offset = strings_offset + len(strings)
    volume_entries = b""
    volume_strings = b""
    header_bytes = spec.volume_entry_size * len(volumes)
    # 앞 36바이트만 우리가 읽는 필드고 나머지는 미상 영역이다. 원소 크기를
    # 맞춰 두지 않으면 두 번째 볼륨부터 자리가 밀린다.
    _VOLUME_FIELDS = "<IIQIIIII"
    for device, serial, created in volumes:
        volume_entries += struct.pack(
            _VOLUME_FIELDS,
            header_bytes + len(volume_strings),
            len(device),
            created,
            serial,
            0,
            0,
            0,
            7,
        ) + b"\x00" * (spec.volume_entry_size - struct.calcsize(_VOLUME_FIELDS))
        volume_strings += device.encode("utf-16-le") + b"\x00\x00"
    volumes_block = volume_entries + volume_strings

    info = bytearray(info_size)
    struct.pack_into(
        "<9I",
        info,
        0,
        metrics_offset,
        len(loaded),
        metrics_offset,  # 트레이스 체인 — 파서가 쓰지 않는다
        0,
        strings_offset,
        len(strings),
        volumes_offset,
        len(volumes),
        len(volumes_block),
    )
    # 최신 실행이 0번 칸이다. 나머지 칸은 0으로 두는데, FILETIME 0 은
    # 파서가 None 으로 읽는다 — 실행 이력이 덜 쌓인 실물과 같은 모양이다.
    struct.pack_into("<Q", info, spec.run_time_offset, run_time)
    struct.pack_into("<I", info, spec.run_count_offset, run_count)

    name_field = executable.encode("utf-16-le")[:58].ljust(60, b"\x00")
    total = pf.HEADER_SIZE + info_size + len(entries) + len(strings) + len(volumes_block)
    header = (
        struct.pack("<I4sII", version, pf.SIGNATURE, 0x11, total)
        + name_field
        + struct.pack("<II", path_hash, 0)
    )
    return header + bytes(info) + entries + strings + volumes_block


def run(parser: prefetch.PrefetchParser, data: bytes, scope: Scope, name: str = "CMD.EXE-4A81B364.pf"):
    """파서를 파일 하나에 돌린다. 04단계가 하는 것과 같은 순서다."""
    parser.source_path = Path(name)
    return list(parser.parse(_io.BytesIO(data), scope))


@pytest.fixture
def parser():
    p = prefetch.PrefetchParser()
    p.begin_artifact()
    p.volume_letter = "C:"
    return p


EMPTY = Scope()


# ============================================================ 기본 규약


def test_one_file_becomes_one_record(parser):
    assert len(run(parser, build_pf(), EMPTY)) == 1


def test_the_ref_is_the_path_hash_in_decimal(parser):
    record = run(parser, build_pf(path_hash=0x4A81B364), EMPTY)[0]

    assert record["ref"] == f"PF#{0x4A81B364}"
    assert record["record_num"] == 0x4A81B364
    assert refs.parse_ref(record["ref"]).artifact == "prefetch"
    # 16진 표기는 fields 에 남는다. .pf 파일명 뒤 8자리와 대조할 값이다.
    assert record["fields"]["path_hash"] == "4A81B364"


def test_the_offset_is_the_start_of_the_file(parser):
    # 레코드가 곧 파일이라 되짚을 자리가 파일 시작뿐이다. 어느 파일이었는지는
    # fields.prefetch_file 이 들고 있어야 한다.
    record = run(parser, build_pf(), EMPTY, name="CMD.EXE-4A81B364.pf")[0]
    assert record["offset"] == "0x0"
    assert record["fields"]["prefetch_file"] == "CMD.EXE-4A81B364.pf"


def test_the_record_validates_against_the_schema(parser):
    record = flagging.apply(run(parser, build_pf(), EMPTY)[0], EMPTY)
    schema.validate(record, "parsed_record")


def test_the_record_is_json_serialisable(parser):
    # fields 에 datetime 이나 bytes 가 새어 들어가면 04단계가 쓰다가 죽는다.
    json.dumps(run(parser, build_pf(), EMPTY)[0], ensure_ascii=False)


def test_run_count_and_run_times_come_through(parser):
    moment = dt.datetime(2019, 1, 10, 8, 45, 16, tzinfo=UTC)
    record = run(parser, build_pf(run_count=5, run_time=to_filetime(moment)), EMPTY)[0]

    assert record["fields"]["run_count"] == 5
    assert record["fields"]["run_times"] == ["2019-01-10T08:45:16.0000000Z"]
    # timestamp 는 가장 최근 실행 시각이다. flagging 이 이 값으로
    # outside_time_range 를 판정한다.
    assert record["timestamp"] == "2019-01-10T08:45:16.0000000Z"


def test_a_missing_run_time_drops_the_key(parser):
    # null 은 스키마가 막는다. 실행 시각이 없어도 "실행된 적 있다"는
    # 사실 자체가 증거이므로 레코드는 남는다($UsnJrnl 과 같은 규약).
    record = run(parser, build_pf(run_time=0), EMPTY)[0]

    assert "timestamp" not in record
    assert record["fields"]["run_times"] == []
    schema.validate(flagging.apply(record, EMPTY), "parsed_record")


def test_loaded_files_get_the_drive_letter_too(parser):
    # path 와 같은 규칙을 건다. 목록만 장치 경로로 남으면 경로 기준 비교가
    # 거기서만 성립하지 않는다 — 실측에서 "Windows 폴더 밖"이 100% 로
    # 나온 것이 그 증상이었다.
    loaded = [f"{DEVICE}\\WINDOWS\\SYSTEM32\\CMD.EXE", f"{DEVICE}\\WINDOWS\\SYSTEM32\\NTDLL.DLL"]
    record = run(parser, build_pf(loaded=loaded), EMPTY)[0]

    assert record["fields"]["loaded_files"] == [
        "C:\\WINDOWS\\SYSTEM32\\CMD.EXE",
        "C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
    ]
    # 개수는 변환과 무관하다. 원본 개수 그대로다.
    assert record["fields"]["loaded_file_count"] == 2
    assert parser.stats["loaded_paths_converted"] == 2


def test_nothing_converted_is_visible_in_the_stats(parser):
    # 레코드는 나오는데 이 수가 0이면 접두어를 못 알아본 것이다. 조용히
    # 지나가면 프롬프트에 실을 항목 고르기가 통째로 죽는다.
    volumes = [(GUID_VOLUME, 1, 0), (DEVICE, 2, 0)]  # 둘이라 변환하지 않는다
    loaded = [f"{GUID_VOLUME}\\WINDOWS\\SYSTEM32\\CMD.EXE"]
    record = run(parser, build_pf(loaded=loaded, volumes=volumes), EMPTY)[0]

    assert record["fields"]["loaded_files"] == loaded
    assert parser.stats["loaded_paths_converted"] == 0


# ================================================ 장치 경로 → 드라이브 문자


def test_a_single_live_volume_becomes_the_drive_letter(parser):
    record = run(parser, build_pf(), EMPTY)[0]
    assert record["path"] == "C:\\WINDOWS\\SYSTEM32\\CMD.EXE"


def test_the_volume_letter_comes_from_the_evidence_path(parser):
    parser.volume_letter = "D:"
    record = run(parser, build_pf(), EMPTY)[0]
    assert record["path"] == "D:\\WINDOWS\\SYSTEM32\\CMD.EXE"


def test_a_shadow_copy_is_not_the_live_volume(parser):
    # 섀도 카피 안의 파일은 살아 있는 볼륨의 그 경로가 아니다. 실측
    # evidence/[root] 73건 중 17건이 섀도 카피를 함께 참조한다.
    volumes = [
        (DEVICE, 1, to_filetime(dt.datetime(2019, 1, 10, tzinfo=UTC))),
        (SHADOW, 2, to_filetime(dt.datetime(2019, 1, 10, tzinfo=UTC))),
    ]
    loaded = [f"{SHADOW}\\WINDOWS\\SYSTEM32\\CMD.EXE"]
    record = run(parser, build_pf(loaded=loaded, volumes=volumes), EMPTY)[0]

    assert record["path"] == f"{SHADOW}\\WINDOWS\\SYSTEM32\\CMD.EXE"
    # 목록도 같은 규칙이다. 접두어가 안 맞으므로 그대로 남는다 —
    # 섀도 카피 안의 파일은 살아 있는 볼륨의 그 경로가 아니다.
    assert record["fields"]["loaded_files"] == loaded
    assert parser.stats["loaded_paths_converted"] == 0


def test_a_shadow_copy_entry_survives_next_to_a_converted_one(parser):
    # 한 레코드가 둘을 함께 참조하는 경우다(실측 evidence/[root] 73건 중
    # 17건). 살아 있는 볼륨 것만 바뀌고 섀도 것은 남는다.
    volumes = [(DEVICE, 1, 0), (SHADOW, 2, 0)]
    loaded = [
        f"{DEVICE}\\WINDOWS\\SYSTEM32\\CMD.EXE",
        f"{SHADOW}\\WINDOWS\\SYSTEM32\\CMD.EXE",
    ]
    record = run(parser, build_pf(loaded=loaded, volumes=volumes), EMPTY)[0]

    assert record["fields"]["loaded_files"] == [
        "C:\\WINDOWS\\SYSTEM32\\CMD.EXE",
        f"{SHADOW}\\WINDOWS\\SYSTEM32\\CMD.EXE",
    ]
    assert parser.stats["loaded_paths_converted"] == 1


def test_a_guid_volume_name_becomes_a_drive_letter(parser):
    # 2026-08-26 실물의 127건 전부가 이 형태였고, 하나도 안 바뀌고 있었다.
    # 06단계는 모델이 쓴 C:\... 와 레코드의 \VOLUME{...}\... 를 대조해
    # 정상 문장을 환각으로 셌다.
    volumes = [(GUID_VOLUME, 1, 0)]
    loaded = [f"{GUID_VOLUME}\\WINDOWS\\SYSTEM32\\CMD.EXE"]
    record = run(parser, build_pf(loaded=loaded, volumes=volumes), EMPTY)[0]

    assert record["path"] == "C:\\WINDOWS\\SYSTEM32\\CMD.EXE"


@pytest.mark.parametrize(
    "device",
    [
        "\\VOLUME{01d8e7bd02796420-a202ae01}",
        "\\volume{01d8e7bd02796420-a202ae01}",  # 대소문자 무시
        "\\DEVICE\\HARDDISKVOLUME2",
    ],
)
def test_the_live_volume_forms_we_accept(device):
    assert prefetch.DEVICE_VOLUME.match(device)


@pytest.mark.parametrize(
    "device",
    [
        SHADOW,
        "\\DEVICE\\HARDDISKVOLUMESHADOWCOPY12",
        # GUID 자리에 16진수가 아닌 것이 오면 우리가 아는 형태가 아니다.
        "\\VOLUME{SHADOWCOPY1-a202ae01}",
        "\\VOLUME{01d8e7bd02796420}",  # 일련번호 자리가 없다
        "\\VOLUME{01d8e7bd02796420-a202ae01}\\WINDOWS",  # 접두어가 아니라 경로
    ],
)
def test_the_forms_we_refuse_to_call_a_live_volume(device):
    # 느슨하게 풀면 섀도 카피의 경로가 C: 로 둔갑한다.
    assert not prefetch.DEVICE_VOLUME.match(device)


def test_a_shadow_copy_next_to_a_guid_volume_is_still_excluded(parser):
    # 정규식을 넓히면서 SHADOWCOPY 가 함께 들어오지 않았는지 본다.
    volumes = [
        (GUID_VOLUME, 1, 0),
        (SHADOW, 2, 0),
    ]
    loaded = [f"{SHADOW}\\WINDOWS\\SYSTEM32\\CMD.EXE"]
    record = run(parser, build_pf(loaded=loaded, volumes=volumes), EMPTY)[0]

    assert record["path"] == f"{SHADOW}\\WINDOWS\\SYSTEM32\\CMD.EXE"


def test_two_live_volumes_of_different_forms_leave_the_path_alone(parser):
    # 형태가 섞여도 같은 볼륨인지 우리는 모른다. 둘로 세어 포기하는 것이 맞다.
    volumes = [(GUID_VOLUME, 1, 0), (DEVICE, 2, 0)]
    loaded = [f"{GUID_VOLUME}\\WINDOWS\\SYSTEM32\\CMD.EXE"]
    record = run(parser, build_pf(loaded=loaded, volumes=volumes), EMPTY)[0]

    assert record["path"] == f"{GUID_VOLUME}\\WINDOWS\\SYSTEM32\\CMD.EXE"


def test_two_live_volumes_leave_the_device_path_alone(parser):
    # 어느 쪽이 우리가 분석 중인 볼륨인지 알 방법이 없다. 틀린 드라이브
    # 문자를 단 경로가 보고서에 실리는 것보다 안 바꾸는 편이 낫다.
    other = "\\DEVICE\\HARDDISKVOLUME3"
    volumes = [(DEVICE, 1, 0), (other, 2, 0)]
    record = run(parser, build_pf(volumes=volumes), EMPTY)[0]

    assert record["path"] == f"{DEVICE}\\WINDOWS\\SYSTEM32\\CMD.EXE"


# ============================================== 실행 파일 경로 찾기


def test_the_executable_path_is_not_guessed_when_ambiguous(parser):
    # 32비트와 64비트에 같은 이름이 있는 경우. 실측에서 MSIEXEC.EXE 가
    # 그랬다. 아무거나 고르면 보고서가 틀린 경로를 말한다.
    loaded = [
        f"{DEVICE}\\WINDOWS\\SYSTEM32\\CMD.EXE",
        f"{DEVICE}\\WINDOWS\\SYSWOW64\\CMD.EXE",
    ]
    record = run(parser, build_pf(loaded=loaded), EMPTY)[0]

    assert "path" not in record
    assert parser.stats["path_unresolved"] == 1
    # 경로를 몰라도 레코드는 남는다. 이름과 실행 시각은 여전히 증거다.
    assert record["name"] == "CMD.EXE"


def test_an_executable_missing_from_the_list_has_no_path(parser):
    # 적재 목록이 잘려 자기 자신이 빠질 수 있다. 실측에서 RUNDLL32.EXE 가
    # 그랬다.
    record = run(parser, build_pf(loaded=[f"{DEVICE}\\WINDOWS\\SYSTEM32\\NTDLL.DLL"]), EMPTY)[0]
    assert "path" not in record


def test_a_truncated_name_matches_by_prefix_but_only_executables(parser):
    # 헤더의 이름 자리는 29자에서 잘린다. 나머지를 알 수 없으므로
    # 접두어로 맞추되, 옆에 있는 .config 를 실행 파일로 착각하면 안 된다.
    name = "SERVICEHUB.ROSLYNCODEANALYSIS"
    assert len(name) == 29
    full = f"{DEVICE}\\VS\\{name}SERVICE32.EXE"
    loaded = [full, full + ".CONFIG"]
    record = run(parser, build_pf(executable=name, loaded=loaded), EMPTY)[0]

    assert record["path"] == f"C:\\VS\\{name}SERVICE32.EXE"


def test_an_exact_name_wins_over_its_own_config_file(parser):
    # 이름이 딱 29자인데 잘리지 않은 경우. 정확 일치를 먼저 보지 않으면
    # 자기 .config 까지 후보가 되어 "모르겠다"가 된다.
    name = "SERVICEHUB.VSDETOUREDHOST.EXE"
    assert len(name) == 29
    full = f"{DEVICE}\\VS\\{name}"
    record = run(parser, build_pf(executable=name, loaded=[full, full + ".CONFIG"]), EMPTY)[0]

    assert record["path"] == f"C:\\VS\\{name}"


# ==================================================================== 범위


def test_an_empty_scope_takes_everything(parser):
    assert run(parser, build_pf(), Scope()) != []


def test_the_executable_path_can_put_a_record_in_scope(parser):
    scope = Scope(path_prefix=("c:/windows/system32",))
    assert run(parser, build_pf(), scope) != []


def test_a_loaded_file_can_put_a_record_in_scope(parser):
    # "웹루트 아래 파일을 열었다"도 봐야 할 신호다. 실행 파일 경로만
    # 보면 w3wp.exe 가 연 웹셸을 놓친다.
    loaded = [
        f"{DEVICE}\\WINDOWS\\SYSTEM32\\CMD.EXE",
        f"{DEVICE}\\INETPUB\\WWWROOT\\SHELL.ASPX",
    ]
    scope = Scope(path_prefix=("c:/inetpub/wwwroot",))
    assert run(parser, build_pf(loaded=loaded), scope) != []


def test_a_record_outside_the_scope_is_not_emitted(parser):
    scope = Scope(path_prefix=("c:/inetpub/wwwroot",))
    assert run(parser, build_pf(), scope) == []
    assert parser.stats["out_of_scope"] == 1
    assert parser.stats["parse_errors"] == 0


def test_the_raw_device_path_also_matches_a_scope(parser):
    # 드라이브 문자로 못 바꾼 경우에도 매칭할 길은 남아 있어야 한다.
    scope = Scope(path_prefix=("/device/harddiskvolume2/windows",))
    assert run(parser, build_pf(), scope) != []


def test_time_is_not_filtered_here_but_flagged(parser):
    # 범위 밖이라도 버리지 않는다. 시간 추론이 틀렸을 때 되짚으려면
    # 레코드가 남아 있어야 한다(parsers/base.py).
    scope = Scope(
        start=dt.datetime(2020, 1, 1, tzinfo=UTC), end=dt.datetime(2020, 12, 31, tzinfo=UTC)
    )
    records = run(parser, build_pf(), scope)
    assert len(records) == 1
    assert flagging.apply(records[0], scope)["flags"] == ["outside_time_range"]


# ======================================================= 같은 해시·틀린 해시


def test_the_same_hash_twice_is_skipped_not_emitted(parser):
    # 같은 ref 를 두 번 내면 io.read_parsed_records 가 DuplicateRefError 로
    # 05·06단계를 통째로 세운다. 한 건을 잃는 쪽이 낫다.
    data = build_pf(path_hash=0xAABBCCDD)
    assert len(run(parser, data, EMPTY, name="A.EXE-AABBCCDD.pf")) == 1
    assert run(parser, data, EMPTY, name="B.EXE-AABBCCDD.pf") == []
    assert parser.stats["duplicate_refs"] == 1


def test_begin_artifact_clears_the_duplicate_guard(parser):
    data = build_pf(path_hash=0xAABBCCDD)
    run(parser, data, EMPTY, name="A.EXE-AABBCCDD.pf")
    parser.begin_artifact()
    assert len(run(parser, data, EMPTY, name="A.EXE-AABBCCDD.pf")) == 1
    assert parser.stats["duplicate_refs"] == 0


def test_the_header_hash_wins_over_the_filename(parser):
    # 파일명은 복사·이름 변경으로 바뀔 수 있지만 헤더는 원본이 만들어질 때
    # 쓰인 값이다. 다르다는 사실 자체가 정보이므로 센다.
    record = run(parser, build_pf(path_hash=0x11112222), EMPTY, name="CMD.EXE-99999999.pf")[0]

    assert record["record_num"] == 0x11112222
    assert parser.stats["hash_mismatch"] == 1


# ================================================ Windows 버전별 레이아웃
#
# 여기서 지키려는 것은 **"명세가 맞다"가 아니라 "표를 말없이 바꾸지 못한다"**
# 입니다. 명세가 맞는지는 실물로만 알 수 있고, 지금 실물이 있는 것은 버전
# 23(Win7)과 30/220(Win10)뿐입니다. 나머지는 여기서 자리를 고정해 두고,
# 실물이 들어오면 맨 아래 통합 테스트가 진짜 대조를 합니다.


def test_the_layout_table_matches_the_written_spec():
    """모듈의 표와 이 파일의 ``SPEC``이 한 글자도 다르지 않아야 한다.

    둘 중 하나만 고치면 여기서 깨집니다. **그것이 이 테스트의 전부입니다** —
    오프셋을 "정리"하다 한쪽만 손대는 것이 프리패치에서 가장 조용히
    틀리는 방법이라, 두 번 적게 하고 대조합니다.
    """
    assert set(pf.FILE_INFORMATION) == set(SPEC), "아는 (버전, 크기) 조합이 다르다"

    for key, spec in SPEC.items():
        layout = pf.FILE_INFORMATION[key]
        version, size = key
        assert layout.size == size, f"{key}: 블록 크기"
        assert layout.run_time_offset == spec.run_time_offset, f"{key}: 실행 시각 자리"
        assert layout.run_time_count == spec.run_time_count, f"{key}: 실행 시각 개수"
        assert layout.run_count_offset == spec.run_count_offset, f"{key}: 실행 횟수 자리"
        assert layout.metrics_entry_size == spec.metrics_entry_size, f"{key}: 메트릭 원소"
        assert layout.volume_entry_size == spec.volume_entry_size, f"{key}: 볼륨 원소"
        assert layout.source, f"{key}: 출처가 비었다 — 실측인지 명세인지 적는다"


@pytest.mark.parametrize(("version", "info_size"), sorted(SPEC))
def test_every_known_version_round_trips(parser, version, info_size):
    """버전마다 합성 → 파싱이 같은 값을 되돌려주는가.

    버전이 갈리는 자리를 **전부** 한 번에 지나갑니다 — 실행 시각(17·23은
    한 칸, 26 이상은 여덟 칸), 실행 횟수, 메트릭 원소 크기(17만 20바이트),
    볼륨 원소 크기(96/104/40).
    """
    when = dt.datetime(2019, 1, 10, 8, 45, 16, tzinfo=UTC)
    data = build_pf(
        run_count=7, run_time=to_filetime(when), version=version, info_size=info_size
    )

    record = run(parser, data, EMPTY)[0]

    assert parser.stats["parse_errors"] == 0
    assert record["name"] == "CMD.EXE"
    assert record["fields"]["format_version"] == version
    assert record["fields"]["run_count"] == 7
    assert record["timestamp"] == "2019-01-10T08:45:16.0000000Z"
    # 적재 목록이 메트릭 원소를 거쳐 나온다. 원소 크기를 잘못 잡으면
    # 여기가 빈 목록이 되거나 쓰레기 문자열이 된다.
    assert record["fields"]["loaded_files"] == ["C:\\WINDOWS\\SYSTEM32\\CMD.EXE"]
    # 볼륨 원소 크기가 어긋나면 장치 경로가 깨져 드라이브 문자를 못 만든다.
    assert record["fields"]["volumes"][0]["device_path"] == DEVICE
    assert record["path"] == "C:\\WINDOWS\\SYSTEM32\\CMD.EXE"


def test_the_run_time_slots_beyond_the_first_are_read_on_new_versions(parser):
    """26 이상은 실행 시각이 여덟 칸이다.

    한 칸만 읽으면 "마지막 실행"은 맞아도 **그 앞의 일곱 번**이 사라집니다.
    사고 시간창을 잡는 데 쓰는 값이라 조용히 비면 안 됩니다.
    """
    older = [
        to_filetime(dt.datetime(2019, 1, 10, 8, 45, 16, tzinfo=UTC)),
        to_filetime(dt.datetime(2019, 1, 9, 7, 30, 0, tzinfo=UTC)),
        to_filetime(dt.datetime(2019, 1, 8, 6, 15, 0, tzinfo=UTC)),
    ]
    spec = SPEC[(30, 220)]
    data = bytearray(build_pf(version=30, info_size=220))
    for index, moment in enumerate(older):
        struct.pack_into(
            "<Q", data, pf.HEADER_SIZE + spec.run_time_offset + index * 8, moment
        )

    record = run(parser, bytes(data), EMPTY)[0]

    assert record["fields"]["run_times"][:3] == [
        "2019-01-10T08:45:16.0000000Z",
        "2019-01-09T07:30:00.0000000Z",
        "2019-01-08T06:15:00.0000000Z",
    ]


# ============================================== 못 읽는 파일은 그것만 건너뛴다


def test_a_file_that_is_not_prefetch_is_skipped(parser):
    assert run(parser, b"NOT A PREFETCH FILE" * 10, EMPTY) == []
    assert parser.stats["parse_errors"] == 1


def test_a_truncated_file_is_skipped(parser):
    assert run(parser, build_pf()[:40], EMPTY) == []
    assert parser.stats["parse_errors"] == 1


def test_an_unknown_layout_names_both_numbers(parser):
    # 새 Windows 빌드가 블록 크기를 바꾸면 여기로 온다. 손상이 아니라
    # 우리가 모르는 것이므로, 표에 한 줄 추가하면 되는 일임이 드러나야 한다.
    with pytest.raises(pf.UnknownLayout) as e:
        pf.read_file_information(build_pf(version=99))
    assert "99" in str(e.value) and "156" in str(e.value)

    assert run(parser, build_pf(version=99), EMPTY) == []
    assert parser.stats["parse_errors"] == 1


def test_an_implausible_run_count_is_refused(parser):
    # 자리를 잘못 잡으면 예외도 경고도 없이 그럴듯한 숫자가 나오고,
    # 그것이 보고서에 "N회 실행됨"으로 실린다.
    assert run(parser, build_pf(run_count=0x7FFFFFFF), EMPTY) == []
    assert parser.stats["parse_errors"] == 1


def test_one_bad_file_does_not_stop_the_next(parser):
    assert run(parser, b"garbage", EMPTY) == []
    assert len(run(parser, build_pf(), EMPTY)) == 1


# ================================================================ MAM 압축


def test_a_mam_container_is_unwrapped():
    from src.stage04_parse.structs.xpress_huffman import decompress

    from tests.test_xpress_huffman import compress

    if compress is None:  # pragma: no cover - Windows 아님
        pytest.skip("RtlCompressBuffer 를 쓸 수 없음")

    plain = build_pf()
    wrapped = pf.MAM_SIGNATURE + struct.pack("<I", len(plain)) + compress(plain)
    assert pf.is_compressed(wrapped)
    assert pf.decompress_mam(wrapped) == plain
    assert decompress(wrapped[8:], len(plain)) == plain

    parser = prefetch.PrefetchParser()
    parser.begin_artifact()
    records = run(parser, wrapped, EMPTY)
    assert len(records) == 1
    assert parser.stats["compressed_files"] == 1


def test_an_unknown_compression_container_is_refused():
    with pytest.raises(pf.PrefetchError) as e:
        pf.decompress_mam(b"MAM\x02" + struct.pack("<I", 100) + b"xxxx")
    assert "압축 컨테이너" in str(e.value)


def test_an_absurd_decompressed_size_is_refused():
    with pytest.raises(pf.PrefetchError):
        pf.decompress_mam(pf.MAM_SIGNATURE + struct.pack("<I", 0xFFFFFFF0) + b"xxxx")


# ========================================================= 실물 증거 대조


@pytest.mark.skipif(not REAL_PREFETCH.is_dir(), reason="evidence/ 없음 (gitignore)")
def test_every_real_prefetch_file_parses():
    """실물 폴더 전부를 읽어 규약이 깨지지 않는지 본다.

    ``ref``가 겹치면 05·06단계가 서므로 유일성이 핵심입니다.
    """
    parser = prefetch.PrefetchParser()
    parser.begin_artifact()

    records = []
    for path in sorted(REAL_PREFETCH.glob("*.pf")):
        if path.stat().st_size == 0:
            continue  # 04단계에서는 evidence.py 가 걸러 낸다
        parser.source_path = path
        with path.open("rb") as fh:
            records.extend(parser.parse(fh, EMPTY))

    assert records
    assert parser.stats["parse_errors"] == 0
    assert len({r["ref"] for r in records}) == len(records)
    for record in records:
        schema.validate(flagging.apply(record, EMPTY), "parsed_record")
        # 헤더 해시와 .pf 파일명 뒤 8자리가 같아야 정상이다.
        assert record["fields"]["path_hash"] in record["fields"]["prefetch_file"].upper()


# ============================================ 볼륨을 못 정했을 때의 범위 판정

#: 살아 있는 두 번째 볼륨. 이것이 함께 있으면 드라이브 문자를 정할 수 없다.
_SECOND_DEVICE = "\\DEVICE\\HARDDISKVOLUME3"


def _two_volumes() -> "list[tuple[str, int, int]]":
    stamp = to_filetime(dt.datetime(2019, 1, 10, tzinfo=UTC))
    return [(DEVICE, 0x2EC87543, stamp), (_SECOND_DEVICE, 0x11112222, stamp)]


def test_a_record_is_kept_when_the_volume_letter_cannot_be_decided(parser):
    """**못 좁히면 넓게 낸다.**

    ``device_prefixes`` 가 살아 있는 볼륨 둘을 보고 ``None`` 을 내는 것은
    옳다 — D: 의 실행 파일을 C: 로 보고하지 않으려는 것이다. 그런데 그
    보수성이 표기가 아니라 **필터**로 넘어오면 뒤집힌다. ``C:\\...`` 로
    적힌 매핑에서 프리패치가 통째로 빠진다.

    선별 실패로 증거를 놓치는 것이 이 프로젝트의 최대 리스크다.
    """
    loaded = [
        f"{DEVICE}\\INETPUB\\WWWROOT\\SHELL.ASPX",
        f"{_SECOND_DEVICE}\\DATA\\X.DLL",
    ]
    scope = Scope(path_prefix=("c:/inetpub/wwwroot",))
    records = run(parser, build_pf(loaded=loaded, volumes=_two_volumes()), scope)

    assert records != []
    assert parser.stats["scope_undecidable"] == 1
    assert parser.stats["out_of_scope"] == 0


def test_the_extension_filter_still_applies_when_the_volume_is_undecided(parser):
    """접두어만 못 보는 것이지 판정을 통째로 포기하는 것이 아니다.

    확장자는 장치 경로에서도 그대로 판정할 수 있다.
    """
    loaded = [f"{DEVICE}\\WINDOWS\\SYSTEM32\\CMD.EXE"]
    scope = Scope(path_prefix=("c:/inetpub/wwwroot",), extensions=(".aspx",))
    records = run(parser, build_pf(loaded=loaded, volumes=_two_volumes()), scope)

    assert records == []
    assert parser.stats["out_of_scope"] == 1


def test_a_single_volume_still_filters_normally(parser):
    """문자를 정할 수 있으면 예전 그대로다. 넓게 내는 것은 못 정할 때뿐이다."""
    scope = Scope(path_prefix=("c:/inetpub/wwwroot",))
    assert run(parser, build_pf(), scope) == []
    assert parser.stats["out_of_scope"] == 1
    assert parser.stats["scope_undecidable"] == 0


# ================================================== PECmd 대조 (tools/compare_prefetch.py)
#
# 저 도구는 PECmd 가 있어야 돌지만, **짝을 짓고 채점하는 규칙 자체**는
# 여기서 고정한다. 열 이름이 하나 바뀌었을 때 "짝지은 0건 전부 일치" 라는
# 무의미한 통과가 나오지 않는지가 핵심이다.


def our_record(**overrides) -> dict:
    """우리 prefetch.jsonl 한 줄. 파서가 내는 모양 그대로."""
    fields = {
        "prefetch_file": "CMD.EXE-4A81B364.pf",
        "format_version": 30,
        "path_hash": "4A81B364",
        "run_count": 3,
        "run_times": [
            "2026-09-01T10:00:00.0000000Z",
            "2026-08-31T09:00:00.0000000Z",
        ],
        "loaded_file_count": 2,
        "loaded_files": ["C:\\WINDOWS\\SYSTEM32\\CMD.EXE", "C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL"],
        "volumes": [
            {
                "device_path": DEVICE,
                "serial_number": "2EC87543",
                "directory_count": 4,
                "created": "2019-01-10T00:00:00.0000000Z",
            }
        ],
    }
    fields.update(overrides.pop("fields", {}))
    record = {
        "ref": "PF#1250981220",
        "artifact": "prefetch",
        "record_num": 0x4A81B364,
        "offset": "0x0",
        "name": "CMD.EXE",
        "path": "C:\\WINDOWS\\SYSTEM32\\CMD.EXE",
        "timestamp": "2026-09-01T10:00:00.0000000Z",
        "fields": fields,
    }
    record.update(overrides)
    return record


PECMD_COLUMNS = [
    "SourceFilename",
    "ExecutableName",
    "Hash",
    "Size",
    "Version",
    "RunCount",
    "LastRun",
    *[f"PreviousRun{n}" for n in range(7)],
    "Volume0Name",
    "Volume0Serial",
    "Volume0Created",
    "FilesLoaded",
]


def pecmd_row(record: dict) -> dict:
    """같은 사실을 PECmd 가 내는 모양으로. 시각은 초 단위 표기다."""
    fields = record["fields"]
    times = [t.replace("T", " ")[:19] for t in fields["run_times"]]
    row = {name: "" for name in PECMD_COLUMNS}
    row.update(
        {
            "SourceFilename": "C:\\KAPE\\C\\Windows\\Prefetch\\" + fields["prefetch_file"],
            "ExecutableName": record["name"],
            "Hash": fields["path_hash"],
            "Version": "Win10OrWin11",
            "RunCount": str(fields["run_count"]),
            "LastRun": times[0] if times else "",
            "Volume0Serial": fields["volumes"][0]["serial_number"],
            "Volume0Created": fields["volumes"][0]["created"].replace("T", " ")[:19],
            "FilesLoaded": ", ".join(fields["loaded_files"]),
        }
    )
    for n, moment in enumerate(times[1:]):
        row[f"PreviousRun{n}"] = moment
    return row


def write_pair(tmp_path: Path, records: list, rows=None, columns=None):
    """(우리 jsonl, PECmd csv) 를 쓴다. rows 를 주면 그것을 CSV 로 쓴다."""
    import csv as _csv

    from src.common import io as _common_io

    ours = tmp_path / "prefetch.jsonl"
    _common_io.write_jsonl(ours, records)

    csv_path = tmp_path / "20260902_PECmd_Output.csv"
    names = columns or PECMD_COLUMNS
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = _csv.DictWriter(handle, fieldnames=names)
        writer.writeheader()
        for row in rows if rows is not None else [pecmd_row(r) for r in records]:
            writer.writerow({name: row.get(name, "") for name in names})
    return ours, csv_path


def grade(tmp_path: Path, records: list, rows=None, columns=None, **kwargs):
    from tools import compare_prefetch

    ours, csv_path = write_pair(tmp_path, records, rows, columns)
    theirs, absent = compare_prefetch.load_pecmd(csv_path)
    return compare_prefetch.compare(
        compare_prefetch.load_ours(ours), theirs, ungraded=absent, **kwargs
    )


def test_the_same_facts_in_both_shapes_agree(tmp_path):
    """같은 사실을 우리 모양과 PECmd 모양으로 쓰면 전건 일치해야 한다.

    표기가 다르다(초 단위 vs 100ns, 전체 경로 vs 파일명, 16진 해시).
    그 차이를 도구가 흡수하지 못하면 실물에서 전건 불일치가 난다.
    """
    report = grade(tmp_path, [our_record()], full=True)
    assert report.passed(), report.summary()
    assert report.mismatches == []
    assert report.ungraded == ()


def test_a_wrong_run_count_is_caught(tmp_path):
    """실행 횟수는 FILE_INFORMATION 안에서 버전마다 자리가 달라지는 값이다.

    빌드가 바뀌었을 때 가장 먼저 어긋나는 자리라 이 도구의 존재 이유다.
    """
    record = our_record()
    rows = [pecmd_row(record)]
    record["fields"]["run_count"] = 7

    report = grade(tmp_path, [record], rows=rows)
    assert not report.passed()
    assert [m.field for m in report.mismatches] == ["run_count"]


def test_a_missing_run_time_slot_is_caught_by_the_count(tmp_path):
    """시각은 개수와 순서까지 본다. 자리를 잘못 잡으면 값보다 개수가 먼저 어긋난다."""
    record = our_record()
    rows = [pecmd_row(record)]
    record["fields"]["run_times"] = record["fields"]["run_times"][:1]

    report = grade(tmp_path, [record], rows=rows)
    assert [m.field for m in report.mismatches] == ["run_times"]


def test_a_column_pecmd_did_not_write_is_not_graded_but_is_named(tmp_path):
    """도구 버전의 차이를 파서의 오류로 세지 않는다. 대신 조용히 넘기지도 않는다."""
    columns = [name for name in PECMD_COLUMNS if name != "Hash"]
    record = our_record()
    rows = [pecmd_row(record)]
    # 저쪽이 안 낸 열이니, 우리 값이 무엇이든 채점 대상이 아니다.
    record["fields"]["path_hash"] = "DEADBEEF"

    report = grade(tmp_path, [record], rows=rows, columns=columns)
    assert report.passed(), report.summary()
    assert "Hash" in report.ungraded


def test_a_missing_required_column_stops_with_the_real_header(tmp_path):
    """짝을 못 지으면 멈춘다. '짝지은 0건 전부 일치' 는 통과가 아니다."""
    from tools import compare_prefetch

    columns = [name for name in PECMD_COLUMNS if name != "RunCount"]
    _, csv_path = write_pair(tmp_path, [our_record()], columns=columns)

    with pytest.raises(ValueError) as caught:
        compare_prefetch.load_pecmd(csv_path)
    assert "RunCount" in str(caught.value)
    assert "ExecutableName" in str(caught.value)  # 실제 열 목록을 보여 준다


def test_records_are_paired_by_filename_not_by_hash(tmp_path):
    """헤더 해시와 파일명이 다른 .pf 는 이 파서의 관심사다.

    해시로 짝을 지으면 바로 그 경우에 짝이 안 지어져, 불일치가 아니라
    '저쪽에만 있음' 으로 둔갑한다.
    """
    record = our_record()
    rows = [pecmd_row(record)]
    rows[0]["Hash"] = "FFFFFFFF"

    report = grade(tmp_path, [record], rows=rows, full=True)
    assert report.missing_from_ours == []
    assert report.extra_in_ours == []
    assert [m.field for m in report.mismatches] == ["path_hash"]


def test_a_record_only_we_have_always_fails(tmp_path):
    """없는 것을 지어낸 쪽은 범위와 무관하게 오류다."""
    report = grade(tmp_path, [our_record()], rows=[])
    assert not report.passed()
    assert report.extra_in_ours == ["cmd.exe-4a81b364.pf"]


def test_a_record_only_pecmd_has_is_an_error_only_with_full(tmp_path):
    """우리 파서는 선별된 범위만 낸다. --full 이 아니면 정상이다."""
    rows = [pecmd_row(our_record())]
    assert grade(tmp_path, [], rows=rows).passed()
    assert not grade(tmp_path, [], rows=rows, full=True).passed()


def test_the_version_pair_is_counted_not_graded(tmp_path):
    """PECmd 의 Version 표기가 바뀐 것을 우리 파서의 오류로 세지 않는다."""
    report = grade(tmp_path, [our_record()])
    assert report.passed()
    assert report.versions == {("30", "Win10OrWin11"): 1}


def test_a_jsonl_without_prefetch_file_stops(tmp_path):
    """열쇠가 없으면 멈춘다. 짝을 못 지은 채로 통과를 내면 안 된다."""
    from src.common import io as _common_io
    from tools import compare_prefetch

    record = our_record()
    del record["fields"]["prefetch_file"]
    path = tmp_path / "prefetch.jsonl"
    _common_io.write_jsonl(path, [record])

    with pytest.raises(ValueError, match="prefetch_file"):
        compare_prefetch.load_ours(path)


def test_the_timeline_csv_is_not_picked_up(tmp_path):
    """_Timeline.csv 는 실행 시각을 한 줄씩 편 것이라 레코드 대조에 쓸 수 없다."""
    from tools import compare_prefetch

    (tmp_path / "20260902_PECmd_Output_Timeline.csv").write_text("x\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="PECmd_Output.csv"):
        compare_prefetch.find_csv(tmp_path)

    wanted = tmp_path / "20260902_PECmd_Output.csv"
    wanted.write_text("x\n", encoding="utf-8")
    assert compare_prefetch.find_csv(tmp_path) == wanted


# ------------------------------------------------ 2026-09-05 실물 대조에서 나온 것
#
# 첫 실물 대조(192건)의 유일한 "불일치"가 파서가 아니라 이 도구였다.
# 그 부류를 여기서 고정한다.


@pytest.mark.parametrize(
    "text, expected",
    [
        # 터진 자리. .NET 어셈블리 경로는 이름 안에 쉼표를 품는다 —
        # 항목은 둘인데 쉼표가 넷이다.
        (
            r"\VOLUME{a}\NTDLL.DLL, \VOLUME{a}\ASM\GCM,"
            r" VERSION=2.9.0.0, CULTURE=NEUTRAL, PUBLICKEYTOKEN=NULL\X.DLL",
            2,
        ),
        (r"\VOLUME{a}\A.DLL, \VOLUME{a}\B.DLL", 2),
        (r"C:\A.DLL, C:\B.DLL", 2),
        (r"\VOLUME{a}\A.DLL|\VOLUME{a}\B.DLL|\VOLUME{a}\C.DLL", 3),
        # 개수(정수)로 내는 판.
        ("42", 42),
        # 경로처럼 안 생긴 표기 하나. 0 으로 뭉개지 않는다 —
        # 0 은 "적재 파일이 없다"라는 다른 뜻이다.
        ("SOMETHING", 1),
    ],
)
def test_a_comma_inside_a_loaded_path_is_not_a_separator(text, expected):
    from tools.compare_prefetch import _loaded_count

    assert _loaded_count(text) == expected


def test_an_empty_files_loaded_column_is_not_zero():
    """빈 칸은 "저쪽이 안 냈다"이다. 0 으로 뭉개면 채점돼 버린다."""
    from tools.compare_prefetch import _loaded_count

    assert _loaded_count("") is None
    assert _loaded_count(None) is None


def test_an_assembly_path_does_not_become_a_mismatch(tmp_path):
    """실물 재현. 이 경로 하나가 192건 대조의 유일한 오탐이었다."""
    record = our_record(
        fields={
            "loaded_file_count": 2,
            "loaded_files": [
                r"C:\WINDOWS\SYSTEM32\NTDLL.DLL",
                r"C:\WINDOWS\ASSEMBLY\GCM,"
                r" VERSION=2.9.0.0, CULTURE=NEUTRAL, PUBLICKEYTOKEN=NULL\GCM.DLL",
            ],
        }
    )

    report = grade(tmp_path, [record], full=True)
    assert report.passed(), report.summary()
    # 채점을 건너뛰어서 통과한 것이 아님을 못박는다.
    assert report.ungraded == ()


def test_a_wrong_loaded_file_count_is_caught(tmp_path):
    """위 테스트가 공허하지 않다는 증거. 이 자리는 실제로 채점된다."""
    record = our_record()
    rows = [pecmd_row(record)]
    record["fields"]["loaded_file_count"] = 5

    report = grade(tmp_path, [record], rows=rows)
    assert [m.field for m in report.mismatches] == ["loaded_count"]


def test_a_wrong_path_hash_is_caught(tmp_path):
    """``ref`` 의 근거다. 여기가 틀리면 원본 대조가 통째로 무너진다."""
    record = our_record()
    rows = [pecmd_row(record)]
    record["fields"]["path_hash"] = "DEADBEEF"

    report = grade(tmp_path, [record], rows=rows)
    assert [m.field for m in report.mismatches] == ["path_hash"]


@pytest.mark.parametrize(
    "mangle, 왜",
    [
        (lambda times: list(reversed(times)), "순서가 뒤집혔다"),
        (lambda times: ["2001-01-01T00:00:00.0000000Z", *times[1:]], "값 하나가 틀렸다"),
    ],
)
def test_run_times_are_graded_by_order_and_value_too(tmp_path, mangle, 왜):
    """개수만 보면 자리를 반쯤 잘못 잡은 것을 놓친다.

    실물에서 이 셋을 따로 겨눠야 했다 — 처음 시도한 "개수 줄이기" 는
    시각이 1개뿐인 레코드에 걸려 아무 일도 하지 않았다.
    """
    record = our_record()
    rows = [pecmd_row(record)]
    record["fields"]["run_times"] = mangle(record["fields"]["run_times"])

    report = grade(tmp_path, [record], rows=rows)
    assert [m.field for m in report.mismatches] == ["run_times"], 왜
