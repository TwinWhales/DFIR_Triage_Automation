"""레지스트리 파서 테스트.

온디스크 계층은 python-registry가 소유하므로(``parsers/registry.py``)
여기서 고정할 것은 **그 위에 우리가 얹은 판단**입니다.

- 경로를 다시 만드는 규칙 (하이브 내부 루트 이름을 떼고 하이브 이름을 답)
- ``CurrentControlSet`` 해석
- 범위 밖 서브트리 가지치기
- 값 타입을 ``fields``로 옮기는 규칙
- 순환·깊이·손상에 대한 방어
- ``ref``/``offset`` 규약

바이너리 픽스처 없이 검증합니다. 파서가 python-registry에서 실제로 쓰는
것은 메서드 몇 개뿐이라(``name``·``values``·``subkeys``·``timestamp``·
``_nkrecord.offset``) 그 모양만 흉내 내면 우리 로직 전부가 시험됩니다.

실물 하이브 대조는 맨 아래 통합 테스트가 맡습니다. ``evidence/``는 저장소에
없으므로(gitignore) 없으면 건너뜁니다.
"""

from __future__ import annotations

import datetime as dt
import io as _io
import struct
from pathlib import Path

import pytest

from src.common import refs, schema
from src.stage04_parse import flagging
from src.stage04_parse.parsers import registry
from src.stage04_parse.parsers.base import Scope

UTC = dt.timezone.utc
REPO_ROOT = Path(__file__).resolve().parents[1]

# 실물 하이브. 없으면 통합 테스트를 건너뛴다.
REAL_HIVES = REPO_ROOT / "evidence" / "[root]" / "Windows" / "System32" / "config"

_FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=UTC)


def to_filetime(moment: dt.datetime) -> int:
    """정수 연산만 쓴다. 파서가 절삭하므로 픽스처도 절삭 기준이어야 한다."""
    delta = moment - _FILETIME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


# ============================================================ 가짜 객체


class FakeNk:
    """``NKRecord`` 흉내. 파서는 오프셋과 raw FILETIME 만 여기서 가져간다."""

    def __init__(self, offset: int, filetime: int = 0) -> None:
        self._offset = offset
        self._filetime = filetime

    def offset(self) -> int:
        return self._offset

    def unpack_qword(self, at: int) -> int:
        assert at == registry.NK_TIMESTAMP_OFFSET
        if isinstance(self._filetime, Exception):
            raise self._filetime
        return self._filetime


class FakeValue:
    """``RegistryValue`` 흉내. ``raises``를 주면 값을 읽을 때 터진다.

    파서는 타입에 따라 두 경로로 갑니다. 문자열 타입이면 ``raw_data()``를
    직접 디코딩하고(라이브러리가 한글을 자르므로), 나머지는 ``value()``를
    씁니다. 그래서 가짜도 둘 다 흉내 냅니다.

    ``value_type``을 주지 않으면 파이썬 타입에서 짐작합니다 — 문자열
    픽스처를 쓰는 테스트가 매번 타입을 적지 않아도 되게 하려는 것입니다.
    문자열이면 ``raw_data``도 UTF-16LE로 만들어 줍니다.
    """

    def __init__(
        self,
        name: str,
        value=None,
        raises: Exception | None = None,
        value_type: str | None = None,
        raw: bytes | None = None,
    ) -> None:
        self._name = name
        self._value = value
        self._raises = raises
        self._type = value_type or self._guess_type(value)
        self._raw = raw

    @staticmethod
    def _guess_type(value) -> str:
        if isinstance(value, str):
            return "RegSZ"
        if isinstance(value, list):
            return "RegMultiSZ"
        if isinstance(value, bytes):
            return "RegBin"
        return "RegDWord"

    def name(self) -> str:
        return self._name

    def value_type_str(self) -> str:
        return self._type

    def raw_data(self) -> bytes:
        if self._raises is not None:
            raise self._raises
        if self._raw is not None:
            return self._raw
        if isinstance(self._value, str):
            return (self._value + "\x00").encode("utf-16-le")
        if isinstance(self._value, list):
            return ("\x00".join(self._value) + "\x00\x00").encode("utf-16-le")
        return b""

    def value(self):
        if self._raises is not None:
            raise self._raises
        return self._value


class FakeKey:
    """``RegistryKey`` 흉내."""

    def __init__(
        self,
        name: str,
        offset: int,
        *,
        values: list | None = None,
        subkeys: list | None = None,
        timestamp: dt.datetime | None = None,
        subkeys_raise: Exception | None = None,
        values_raise: Exception | None = None,
        timestamp_raise: Exception | None = None,
    ) -> None:
        self._name = name
        moment = timestamp or dt.datetime(2026, 7, 24, 0, 28, 36, 123456, tzinfo=UTC)
        self._nkrecord = FakeNk(
            offset, timestamp_raise if timestamp_raise is not None else to_filetime(moment)
        )
        self._values = values or []
        self._subkeys = subkeys or []
        self._subkeys_raise = subkeys_raise
        self._values_raise = values_raise

    def name(self) -> str:
        return self._name

    def timestamp(self):
        """파서는 이것을 쓰지 않는다 — 반올림 때문에 우회한다.

        실물 API 를 흉내 내려고 남겨 두되, 파서가 실수로 쓰면 드러나도록
        일부러 틀린 값을 준다.
        """
        return dt.datetime(1601, 1, 1, tzinfo=UTC)

    def values(self):
        if self._values_raise is not None:
            raise self._values_raise
        return self._values

    def value(self, name: str):
        """이름으로 값 하나. 없으면 실물처럼 예외."""
        for value in self.values():
            if value.name() == name:
                return value
        raise KeyError(name)

    def subkeys(self):
        if self._subkeys_raise is not None:
            raise self._subkeys_raise
        return self._subkeys


class FakeHive:
    """``Registry`` 흉내. ``Select\\Current`` 조회에만 쓴다."""

    def __init__(self, current: int | None = 1) -> None:
        self._current = current

    def open(self, path: str):
        if path != "Select" or self._current is None:
            raise KeyError(path)
        return FakeKey("Select", 0x100, values=[FakeValue("Current", self._current)])


def _parser(artifact: str = "registry:SYSTEM") -> registry.RegistryParser:
    p = registry.RegistryParser(artifact)
    p.stats = p._new_stats()
    return p


def _walk(parser, root, prefixes=()):
    return list(parser._walk(root, tuple(prefixes)))


# ============================================================ 아티팩트


def test_unknown_artifact_is_refused_at_construction():
    """SAM·SECURITY는 아직 지원하지 않는다. 조용히 받으면 ref 접두어가 없다."""
    with pytest.raises(ValueError, match="registry:SAM"):
        registry.RegistryParser("registry:SAM")


def test_hive_designator():
    assert registry.hive_designator("registry:SYSTEM") == "SYSTEM"
    assert registry.hive_designator("registry:SOFTWARE") == "SOFTWARE"
    assert registry.hive_designator("registry:Amcache") == "Amcache"


# ============================================================ 값 변환


def test_strings_and_numbers_pass_through():
    assert registry.value_to_field(FakeValue("x", "svchost.exe")) == "svchost.exe"
    assert registry.value_to_field(FakeValue("x", 2)) == 2


def test_binary_becomes_hex_not_bytes():
    """bytes 는 JSON 으로 나가지 않고, base64 는 사람이 대조할 수 없다."""
    assert registry.value_to_field(FakeValue("x", b"\x80\x00\xff")) == "8000ff"


def test_filetime_type_becomes_an_iso_string_not_a_raw_datetime():
    """python-registry가 RegFileTime을 datetime으로 돌려준다 — JSON이 못 삼킨다.

    실물 SYSTEM 하이브(USB\\...\\Properties\\{GUID}\\####, 디바이스 속성의
    설치 일시)에서 실측된 값이다. 라이브러리의 datetime을 그대로 내보내면
    04단계 전체가 json.dumps에서 TypeError로 죽는다.
    """
    moment = dt.datetime(2006, 6, 21, tzinfo=UTC)
    raw = struct.pack("<Q", to_filetime(moment))
    value = FakeValue("(default)", value_type="RegFileTime", raw=raw)

    assert registry.value_to_field(value) == "2006-06-21T00:00:00.0000000Z"


def test_filetime_type_zero_falls_back_to_hex_not_null():
    """0은 '값 없음'이라 filetime_to_datetime이 None을 준다.

    None을 그대로 내보내면 "값이 없었다"와 "0이었다"가 구별되지 않는다.
    RegBin과 같은 표기(raw hex)로 남긴다.
    """
    value = FakeValue("(default)", value_type="RegFileTime", raw=b"\x00" * 8)
    assert registry.value_to_field(value) == "0000000000000000"


def test_multi_sz_stays_a_list():
    """06단계 compare 가 리스트를 '원소 중 하나라도 일치'로 본다.

    문자열로 합치면 여러 값 중 하나를 지목한 문장이 검증되지 않는다.
    """
    assert registry.value_to_field(FakeValue("x", ["Tdx", "nsi"])) == ["Tdx", "nsi"]


def test_multi_sz_terminators_are_not_values():
    """``MULTI_SZ`` 끝의 널 종결자가 빈 문자열로 남으면 안 된다.

    구조는 "각 문자열이 널로 끝나고 목록 전체가 널 하나로 더 끝나는"
    것이라, 널 기준으로 그냥 쪼개면 빈 항목이 둘 남는다. python-registry
    가 그렇게 한다.

        raw_data : b'r\\x00p\\x00c\\x00s\\x00s\\x00\\x00\\x00\\x00\\x00'
        라이브러리 : ['rpcss', '', '']
        실제 내용  : ['rpcss']

    **06단계에 실제 영향이 있다.** compare 가 리스트를 "원소 중 하나라도
    일치"로 보므로, 빈 문자열이 남으면 모델이 지어낸 value: "" 주장이
    검증을 통과한다.

    실측 SYSTEM\\ControlSet001\\Services 1,754개 키 중 249개가 이 형태였다.
    """
    value = FakeValue(
        "DependOnService",
        raw=b"r\x00p\x00c\x00s\x00s\x00\x00\x00\x00\x00",
        value_type="RegMultiSZ",
    )

    assert registry.value_to_field(value) == ["rpcss"]


def test_a_multi_sz_gap_in_the_middle_survives():
    """가운데 빈 문자열은 종결자가 아니라 위치가 의미를 가진다."""
    value = FakeValue("x", raw="a\x00\x00b\x00\x00".encode("utf-16-le"), value_type="RegMultiSZ")

    assert registry.value_to_field(value) == ["a", "", "b"]


def test_korean_strings_are_not_truncated_at_a_false_terminator():
    """python-registry 가 UTF-16LE 종결자를 정렬 없이 찾아 한글을 자른다.

        '볼륨 관리자 드라이버'
         fc bc │ 68 b9 │ 20 00 │ 00 ad │ ...
          볼      륨    공백    관
                        └─ 00 00 ─┘   ← 오프셋 5(홀수)에서 끊긴다

    공백(U+0020, 고위 바이트 0x00) 다음에 U+XX00 형태 한글이 오면 두
    문자에 걸쳐 00 00 이 만들어진다. 한글에 흔한 배치다 —
    U+AC00(가) U+AD00(관) 처럼 하위 바이트가 0x00 인 음절이 많다.

    실측 SYSTEM 하이브: 문자열 값 42,578건 중 56건(0.13%)이 잘렸다.
    예외도 경고도 없고 잘린 문자열은 그 자체로 그럴듯해 보인다.

    이 프로젝트는 한국어 환경을 대상으로 하므로 회귀로 고정한다.
    """
    text = "볼륨 관리자 드라이버"
    raw = (text + "\x00").encode("utf-16-le")
    assert b"\x00\x00" in raw  # 가짜 종결자가 실제로 들어 있다

    assert registry.value_to_field(FakeValue("DisplayName", raw=raw, value_type="RegSZ")) == text


def test_an_odd_length_string_drops_the_stray_byte():
    """반쪽짜리 문자는 복원할 수 없다. 널을 붙이면 없던 문자가 생긴다."""
    raw = "ab".encode("utf-16-le") + b"\x41"

    assert registry.value_to_field(FakeValue("x", raw=raw, value_type="RegSZ")) == "ab"


def test_binary_inside_a_list_is_also_hex():
    """문자열 아닌 타입이 리스트를 돌려주는 경우의 방어선.

    ``RegMultiSZ``는 이제 ``raw_data()``를 직접 디코딩하므로 여기에
    bytes 가 섞일 수 없습니다. 다른 타입에서 라이브러리가 예상 밖의
    리스트를 주면 bytes 가 그대로 JSON 으로 나가려 하는데, 그때 막습니다.
    """
    value = FakeValue("x", [b"\x01", "b"], value_type="RegResourceList")
    assert registry.value_to_field(value) == ["01", "b"]


# ============================================================ 레코드 형식


def test_ref_is_the_nk_offset_in_decimal_and_offset_is_the_same_in_hex():
    """refs.py 규약. 레지스트리에는 MFT 레코드 번호 같은 일련번호가 없다."""
    parser = _parser()
    key = FakeKey("Dnscache", 0x79F24)

    record = parser._build(key, "SYSTEM\\ControlSet001\\services\\Dnscache", 0x79F24)

    assert record["ref"] == refs.make_ref("registry:SYSTEM", 0x79F24)
    assert record["ref"] == "REG-SYS#499492"
    assert record["record_num"] == 499492
    assert record["offset"] == "0x79F24"
    assert int(record["offset"], 16) == record["record_num"]


def test_software_records_carry_the_software_prefix():
    """인스턴스를 공유하면 SOFTWARE 레코드가 REG-SYS# 로 나가 환각이 된다."""
    record = _parser("registry:SOFTWARE")._build(FakeKey("Run", 0x2000), "SOFTWARE\\...", 0x2000)
    assert record["ref"].startswith("REG-SW#")


def test_amcache_records_carry_the_amcache_prefix():
    """Amcache.hve도 regf라 같은 클래스를 쓴다 — 인스턴스를 공유하면 안 된다."""
    record = _parser("registry:Amcache")._build(
        FakeKey("00001a2b", 0x3000), "Amcache\\Root\\InventoryApplicationFile\\...", 0x3000
    )
    assert record["ref"].startswith("AMCACHE#")
    assert record["ref"] == "AMCACHE#12288"


def test_values_land_in_fields_by_name():
    parser = _parser()
    key = FakeKey(
        "Dnscache",
        0x1000,
        values=[FakeValue("ImagePath", "svchost.exe"), FakeValue("Start", 2)],
    )

    record = parser._build(key, "SYSTEM\\services\\Dnscache", 0x1000)

    assert record["fields"] == {"ImagePath": "svchost.exe", "Start": 2}


def test_the_unnamed_default_value_gets_a_usable_key():
    """빈 문자열을 키로 쓰면 06단계가 'fields.' 로 끝나는 필드를 가리켜야 한다.

    **상수는 python-registry가 쓰는 값과 같아야 한다.** 라이브러리는 이름
    없는 값에 `"(default)"`를 이미 돌려주므로, 상수가 다르면 그것은 죽은
    코드가 되고 실제 키는 라이브러리 것이 된다. 한때 `"(Default)"`였고
    정확히 그렇게 됐다 — 독립 디코더 대조에서 드러났다.
    """
    assert registry.DEFAULT_VALUE_NAME == "(default)"

    parser = _parser()
    from_library = parser._build(  # 라이브러리가 실제로 주는 형태
        FakeKey("k", 0x1000, values=[FakeValue("(default)", "d")]), "SYSTEM\\k", 0x1000
    )
    from_empty = parser._build(  # 빈 문자열이 올 경우의 안전망
        FakeKey("k", 0x2000, values=[FakeValue("", "d")]), "SYSTEM\\k", 0x2000
    )

    assert from_library["fields"] == {"(default)": "d"}
    assert from_empty["fields"] == {"(default)": "d"}


def test_a_key_with_no_values_is_still_a_record():
    """존재와 LastWrite 자체가 증거다. 값이 없다고 버리지 않는다."""
    record = _parser()._build(FakeKey("empty", 0x1000), "SYSTEM\\empty", 0x1000)
    assert record["fields"] == {}
    assert record["name"] == "empty"


def test_timestamp_key_is_omitted_when_unreadable_not_set_to_null():
    """null 은 스키마가 막는다. $UsnJrnl 과 같은 규약이다."""
    parser = _parser()
    key = FakeKey("k", 0x1000, timestamp_raise=ValueError("bad filetime"))

    record = parser._build(key, "SYSTEM\\k", 0x1000)

    assert "timestamp" not in record
    schema.validate(flagging.apply(record), "parsed_record")


def test_one_bad_value_does_not_lose_the_key():
    """나머지 값과 키의 존재는 여전히 증거다. 대신 센다."""
    parser = _parser()
    key = FakeKey(
        "k",
        0x1000,
        values=[
            FakeValue("good", "ok"),
            FakeValue("broken", raises=ValueError("corrupt cell")),
        ],
    )

    record = parser._build(key, "SYSTEM\\k", 0x1000)

    assert record["fields"] == {"good": "ok"}
    assert parser.stats["value_errors"] == 1
    assert parser.stats["parse_errors"] == 1


def test_records_match_the_parsed_record_schema():
    parser = _parser()
    root = FakeKey(
        "CMI-CreateHive{2A7FB991-7BBE-4F9D-B91E-7CB51D4737F5}",
        0x20,
        subkeys=[FakeKey("Services", 0x1000, values=[FakeValue("x", b"\x01\x02")])],
    )

    for record in flagging.apply_all(parser._walk(root, ()), None):
        schema.validate(record, "parsed_record")


# ================================================== Amcache 숫자 값 이름

_AMCACHE_FILE_KEY = "Amcache\\Root\\File\\{f1472678-0000}\\10000b539"


def _amcache_fields(path: str, values: list) -> dict:
    """Amcache 파서로 키 하나를 만들고 ``fields`` 만 돌려준다."""
    parser = _parser("registry:Amcache")
    record = parser._build(FakeKey("10000b539", 0x3000, values=values), path, 0x3000)
    return record["fields"]


def test_amcache_numeric_value_names_become_the_inventory_vocabulary():
    """대응은 같은 이미지 안에서 FileId 로 조인해 얻었다 — 상수의 docstring."""
    fields = _amcache_fields(
        _AMCACHE_FILE_KEY,
        [
            FakeValue("15", "C:\\WINDOWS\\SYSTEM32\\sppsvc.exe"),
            FakeValue("101", "00009b5b7c08"),
            FakeValue("100", "0000e2ce9887"),
            FakeValue("6", 382680),
        ],
    )

    assert fields == {
        "LowerCaseLongPath": "C:\\WINDOWS\\SYSTEM32\\sppsvc.exe",
        "FileId": "00009b5b7c08",
        "ProgramId": "0000e2ce9887",
        "Size": 382680,
    }


def test_amcache_names_we_could_not_confirm_stay_numeric():
    """모르는 것은 모르는 채로 나가야 한다.

    ``17``·``16`` 은 이 이미지 안에 대조할 상대가 없었다. 공개 자료로
    채우면 틀렸을 때 조용히 틀리고, 숫자로 남으면 최소한 드러난다.
    """
    fields = _amcache_fields(
        _AMCACHE_FILE_KEY,
        [FakeValue("17", 131343442490135143), FakeValue("16", 1)],
    )

    assert fields == {"17": 131343442490135143, "16": 1}


def test_the_inventory_subtree_is_left_alone():
    """저쪽은 이미 이름이 있다. 넓게 걸면 다른 서브키의 15 까지 경로로 둔갑한다."""
    fields = _amcache_fields(
        "Amcache\\Root\\InventoryApplicationFile\\0000ff17",
        [FakeValue("LowerCaseLongPath", "c:\\windows\\system32\\sppsvc.exe"), FakeValue("15", 3)],
    )

    assert fields == {"LowerCaseLongPath": "c:\\windows\\system32\\sppsvc.exe", "15": 3}


def test_other_registry_artifacts_never_get_renamed():
    """SYSTEM 하이브에도 15 라는 이름의 값이 있을 수 있다."""
    parser = _parser("registry:SYSTEM")
    record = parser._build(
        FakeKey("Params", 0x1000, values=[FakeValue("15", "C:\\x.exe")]),
        "SYSTEM\\CurrentControlSet\\Services\\Params",
        0x1000,
    )

    assert record["fields"] == {"15": "C:\\x.exe"}


def test_an_existing_target_name_is_not_overwritten():
    """두 어휘가 한 키에 섞이면 어느 쪽이 원본이었는지 사라지면 안 된다."""
    fields = _amcache_fields(
        _AMCACHE_FILE_KEY,
        [FakeValue("15", "C:\\a.exe"), FakeValue("LowerCaseLongPath", "c:\\b.exe")],
    )

    assert fields == {"15": "C:\\a.exe", "LowerCaseLongPath": "c:\\b.exe"}


def test_the_rename_is_counted_so_a_silent_miss_is_visible():
    """0 이면 그 서브트리를 못 만난 것 — 매핑이 안 걸린 것과 구별된다."""
    parser = _parser("registry:Amcache")
    parser._build(
        FakeKey("10000b539", 0x3000, values=[FakeValue("15", "C:\\x.exe"), FakeValue("17", 1)]),
        _AMCACHE_FILE_KEY,
        0x3000,
    )

    assert parser.stats["amcache_values_renamed"] == 1


def test_the_renamed_path_is_a_path_field_for_stage_six():
    """04 가 이름을 바꿔도 06 이 그 이름을 안 받으면 아무것도 안 풀린다.

    Amcache 값은 소문자로 저장되고 모델은 대문자로 쓴다. 두 단계가 함께
    맞아야 정상 문장이 통과한다 — 이 사슬을 여기서 한 번에 못 박는다.
    """
    from src.stage06_verify import comparators

    fields = _amcache_fields(_AMCACHE_FILE_KEY, [FakeValue("15", "c:\\windows\\x.exe")])
    (name,) = fields

    assert comparators.is_path_field("fields." + name)


def test_the_internal_root_name_is_replaced_by_the_hive_name():
    """라이브러리는 CMI-CreateHive{GUID}\\... 를 준다. 분석가가 쓰는 경로가 아니다."""
    parser = _parser()
    root = FakeKey(
        "CMI-CreateHive{2A7FB991-7BBE-4F9D-B91E-7CB51D4737F5}",
        0x20,
        subkeys=[FakeKey("ControlSet001", 0x30, subkeys=[FakeKey("services", 0x40)])],
    )

    paths = [r["path"] for r in _walk(parser, root)]

    assert paths[0] == "SYSTEM"
    assert "SYSTEM\\ControlSet001\\services" in paths
    assert not any("CMI-CreateHive" in p for p in paths)


def test_on_disk_letter_case_is_preserved():
    """대소문자 무시는 normalize_path 가 양쪽에 적용한다.

    여기서 바꾸면 원본과 다른 값을 기록하게 된다.
    """
    parser = _parser()
    root = FakeKey("root", 0x20, subkeys=[FakeKey("services", 0x30)])

    assert "SYSTEM\\services" in [r["path"] for r in _walk(parser, root)]


# ============================================================ CurrentControlSet


def test_current_control_set_is_resolved_from_select():
    parser = _parser()
    scope = Scope.from_selection({"path_prefix": ["SYSTEM\\CurrentControlSet\\Services"]})

    resolved = parser._resolve_prefixes(FakeHive(current=2), scope)

    assert resolved == ("system/controlset002/services",)


def test_prefixes_without_current_control_set_are_left_alone():
    parser = _parser()
    scope = Scope.from_selection({"path_prefix": ["SYSTEM\\ControlSet001\\Services"]})

    assert parser._resolve_prefixes(FakeHive(), scope) == ("system/controlset001/services",)


def test_unresolvable_current_control_set_keeps_the_prefix():
    """지어낸 이름으로 바꾸면 범위 안의 증거를 통째로 놓치고 원인도 모른다."""
    parser = _parser()
    scope = Scope.from_selection({"path_prefix": ["SYSTEM\\CurrentControlSet\\Services"]})

    resolved = parser._resolve_prefixes(FakeHive(current=None), scope)

    assert resolved == ("system/currentcontrolset/services",)


# ============================================================ 범위·가지치기


def _tree() -> FakeKey:
    """루트 / Services{Dnscache, Tcpip} / Enum / Control 을 가진 트리."""
    return FakeKey(
        "root",
        0x10,
        subkeys=[
            FakeKey(
                "ControlSet001",
                0x20,
                subkeys=[
                    FakeKey(
                        "Services",
                        0x30,
                        subkeys=[FakeKey("Dnscache", 0x40), FakeKey("Tcpip", 0x50)],
                    ),
                    FakeKey("Enum", 0x60, subkeys=[FakeKey("PCI", 0x70)]),
                ],
            ),
            FakeKey("Control", 0x80),
        ],
    )


def test_no_prefix_means_everything():
    """좁히는 조건이 없으면 넓게 본다 (parsers/base.py Scope)."""
    assert len(_walk(_parser(), _tree())) == 8


def test_only_the_requested_subtree_comes_out():
    parser = _parser()

    paths = [r["path"] for r in _walk(parser, _tree(), ["system/controlset001/services"])]

    assert paths == [
        "SYSTEM\\ControlSet001\\Services",
        "SYSTEM\\ControlSet001\\Services\\Tcpip",
        "SYSTEM\\ControlSet001\\Services\\Dnscache",
    ]


def test_out_of_scope_subtrees_are_not_walked_at_all():
    """가지치기가 곧 성능이다. 49MB 하이브에서 키 서른 개를 읽는 것이 정상 사용례다."""
    parser = _parser()

    _walk(parser, _tree(), ["system/controlset001/services"])

    # Enum 과 Control 두 서브트리를 통째로 건너뛴다.
    assert parser.stats["pruned_subtrees"] == 2


def test_the_path_down_to_the_target_is_walked_but_not_emitted():
    """루트와 ControlSet001 은 범위 밖이지만 지나가야 Services 에 닿는다."""
    parser = _parser()

    paths = [r["path"] for r in _walk(parser, _tree(), ["system/controlset001/services"])]

    assert "SYSTEM" not in paths
    assert "SYSTEM\\ControlSet001" not in paths


def test_several_prefixes_are_unioned():
    parser = _parser()

    paths = [
        r["path"]
        for r in _walk(parser, _tree(), ["system/controlset001/enum", "system/control"])
    ]

    assert set(paths) == {
        "SYSTEM\\ControlSet001\\Enum",
        "SYSTEM\\ControlSet001\\Enum\\PCI",
        "SYSTEM\\Control",
    }


# ============================================================ 방어


def test_a_cycle_does_not_hang_and_does_not_duplicate_refs():
    """같은 nk 를 두 번 내면 io.read_parsed_records 가 05·06단계를 세운다."""
    parser = _parser()
    child = FakeKey("child", 0x40)
    root = FakeKey("root", 0x10, subkeys=[child])
    child._subkeys = [root]  # 순환

    records = _walk(parser, root)

    assert len({r["ref"] for r in records}) == len(records)
    assert parser.stats["parse_errors"] >= 1


def test_depth_is_bounded(monkeypatch):
    monkeypatch.setattr(registry, "MAX_DEPTH", 3)
    leaf = FakeKey("deep", 0x1000)
    node = leaf
    for i in range(10):
        node = FakeKey(f"n{i}", 0x1000 + (i + 1) * 0x10, subkeys=[node])

    parser = _parser()
    records = _walk(parser, node)

    assert len(records) == 4  # 깊이 0..3
    assert parser.stats["parse_errors"] >= 1


def test_an_unreadable_subkey_list_does_not_stop_the_walk():
    """서브트리 하나가 깨져도 나머지는 읽는다. 대신 조용히 넘어가지 않는다."""
    parser = _parser()
    root = FakeKey(
        "root",
        0x10,
        subkeys=[
            FakeKey("broken", 0x20, subkeys_raise=OSError("corrupt lf cell")),
            FakeKey("fine", 0x30),
        ],
    )

    paths = [r["path"] for r in _walk(parser, root)]

    assert "SYSTEM\\fine" in paths
    assert "SYSTEM\\broken" in paths  # 키 자체는 나온다
    assert parser.stats["parse_errors"] == 1


def test_a_key_without_an_offset_is_skipped():
    """오프셋이 곧 ref 다. 없으면 06단계가 전부 기각하므로 낼 수 없다."""
    parser = _parser()
    orphan = FakeKey("no-offset", 0x40)
    orphan._nkrecord = None

    assert _walk(parser, orphan) == []


# ============================================================ 하이브 상태


def test_an_empty_hive_is_refused():
    parser = _parser()
    with pytest.raises(ValueError, match="비어 있"):
        list(parser.parse(_io.BytesIO(b""), Scope.from_selection({})))


def test_a_non_hive_file_is_refused_by_magic():
    parser = _parser()
    with pytest.raises(ValueError, match="하이브가 아닙니다"):
        list(parser.parse(_io.BytesIO(b"NOTREGF" + b"\x00" * 4096), Scope.from_selection({})))


def test_a_dirty_hive_is_reported():
    """더티 하이브는 정상적으로 열리고 파싱되는데 값이 낡았다.

    $UsnJrnl 의 0바이트 껍데기와 같은 유형이다 — 파일이 있고, 파서가
    성공하고, 답이 틀린다.
    """
    parser = _parser()
    parser._warn_if_dirty(b"regf" + struct.pack("<II", 1240, 1239))
    assert parser.stats["dirty_hive"] == 1


def test_a_clean_hive_is_not_reported():
    parser = _parser()
    parser._warn_if_dirty(b"regf" + struct.pack("<II", 1240, 1240))
    assert parser.stats["dirty_hive"] == 0


# ============================================================ 실물 하이브

pytestmark_real = pytest.mark.skipif(
    not (REAL_HIVES / "SYSTEM").exists() and not (REAL_HIVES / "system").exists(),
    reason="실물 하이브 없음 (evidence/ 는 저장소에 없다)",
)


def _real_hive(name: str) -> Path:
    for candidate in (REAL_HIVES / name, REAL_HIVES / name.lower()):
        if candidate.exists():
            return candidate
    pytest.skip(f"{name} 하이브 없음")


@pytestmark_real
def test_real_hive_walk_matches_the_raw_cell_scan():
    """서브키 목록을 따라간 결과와, 셀을 직접 센 결과가 같아야 한다.

    python-registry 가 서브트리를 통째로 놓치면 여기서 잡힌다 —
    ``tools/scan_hive_cells.py`` 와 같은 대조다.
    """
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from tools.scan_hive_cells import scan

    hive = _real_hive("SYSTEM")
    parser = registry.RegistryParser("registry:SYSTEM")

    with hive.open("rb") as stream:
        ours = sum(1 for _ in parser.parse(stream, Scope.from_selection({})))

    assert ours == scan(hive).allocated


@pytestmark_real
def test_real_hive_scoped_read_resolves_current_control_set():
    hive = _real_hive("SYSTEM")
    parser = registry.RegistryParser("registry:SYSTEM")
    scope = Scope.from_selection({"path_prefix": ["SYSTEM\\CurrentControlSet\\Services"]})

    with hive.open("rb") as stream:
        records = list(parser.parse(stream, scope))

    assert records, "CurrentControlSet 해석에 실패하면 0건이 나온다"
    assert all("controlset" in r["path"].lower() for r in records)
    assert not any("currentcontrolset" in r["path"].lower() for r in records)


@pytestmark_real
def test_real_hive_records_pass_the_schema():
    hive = _real_hive("SYSTEM")
    parser = registry.RegistryParser("registry:SYSTEM")
    scope = Scope.from_selection({"path_prefix": ["SYSTEM\\CurrentControlSet\\Services"]})

    with hive.open("rb") as stream:
        for record in flagging.apply_all(parser.parse(stream, scope), scope):
            schema.validate(record, "parsed_record")


# ============================== AmcacheParser 대조기 (tools/compare_amcache.py)


def test_the_installdate_notation_difference_is_not_counted_as_a_mismatch():
    """`InstallDate` 는 FILETIME 이 아니라 하이브에 그렇게 적힌 문자열이다.

    실물 하이브에서 `RegSZ` 로 `'03/20/2017 03:53:52'` 이고, 우리는 원본
    그대로 낸다(`registry.py` 는 문자열을 생김새로 재해석하지 않는다).
    AmcacheParser 는 파싱해 ISO 로 다시 쓴다. **표기 차이지 값 차이가
    아니므로** 대조기가 둘을 같게 봐야 한다 — 안 그러면 78건이 통째로
    거짓 불일치로 잡히고, 진짜 불일치가 그 속에 묻힌다.
    """
    from tools.compare_amcache import _date

    assert _date("03/20/2017 03:53:52") == _date("2017-03-20 03:53:52")
    assert _date("10/25/2022 00:00:00") == "2022-10-25 00:00:00"


def test_our_iso_timestamps_are_cut_to_the_second_for_comparison():
    """우리는 100ns 자리까지, AmcacheParser 는 기본이 초 단위다."""
    from tools.compare_amcache import _date

    assert _date("2022-10-24T15:31:17.9368910Z") == "2022-10-24 15:31:17"


def test_a_date_that_is_neither_notation_is_left_alone():
    """모르는 표기를 억지로 바꾸면 진짜 불일치를 지운다."""
    from tools.compare_amcache import _date

    assert _date("") == ""
    assert _date("not a date") == "not a date"


def test_the_container_key_itself_is_not_an_entry():
    """``Amcache\\Root\\InventoryApplicationFile`` 자체는 항목이 아니다.

    이것을 세면 우리가 AmcacheParser 보다 범주마다 +1 이 되어, 실제로는
    일치하는데 불일치로 보고된다.
    """
    from tools.compare_amcache import is_leaf, subkey_of

    container = {"path": "Amcache\\Root\\InventoryApplicationFile"}
    entry = {"path": "Amcache\\Root\\InventoryApplicationFile\\0000ff17"}

    assert not is_leaf(container)
    assert is_leaf(entry)
    assert subkey_of(entry) == "InventoryApplicationFile"
