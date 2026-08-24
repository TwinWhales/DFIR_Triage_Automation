"""evtx 파서 테스트.

온디스크 계층은 python-evtx가 소유하므로(``work-guide.md`` 3.1) 여기서
고정할 것은 **그 위에 우리가 얹은 판단**입니다.

- 렌더된 XML을 ``fields``로 옮기는 규칙
- 라이브러리가 조용히 버린 구간을 잡아내는 계산
- 우리 레코드 형식과 ``ref``·``offset`` 규약

바이너리 픽스처 없이 검증합니다. 파서가 python-evtx의 ``Record``·
``ChunkHeader``에서 실제로 쓰는 것은 메서드 몇 개뿐이라, 그 모양만 흉내
내면 우리 로직 전부가 시험됩니다. 증거 파일을 저장소에 넣지 않아도 되고,
테스트가 0.1초에 끝납니다.

실제 로그 대조는 ``docs/artifact-notes.md``의 ``wevtutil`` 기록이 맡습니다.
"""

from __future__ import annotations

import datetime as dt
import io as _io
import xml.etree.ElementTree as ET

import pytest

from pathlib import Path

from src.common import refs, schema
from src.stage03_select import mapping_loader
from src.stage04_parse import flagging
from src.stage04_parse.parsers import evtx
from src.stage04_parse.parsers.base import Scope

REPO_ROOT = Path(__file__).resolve().parents[1]

UTC = dt.timezone.utc
_FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=UTC)

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def to_filetime(moment: dt.datetime) -> int:
    """정수 연산만 쓴다. float를 쓰면 마이크로초가 조용히 틀어진다."""
    delta = moment - _FILETIME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def build_xml(
    *,
    event_id: int = 4720,
    provider: str = "Microsoft-Windows-Security-Auditing",
    channel: str = "Security",
    computer: str = "WEB01",
    event_data: str = "",
    user_data: str = "",
    system_extra: str = "",
) -> str:
    """``Record.xml()``이 내놓는 모양의 XML을 만든다.

    실물에서 확인한 특징을 그대로 둡니다 — 기본 네임스페이스가 붙고,
    ``<EventID>``에 ``Qualifiers`` 속성이 오며, 닫는 태그가 따로 나옵니다.
    """
    body = ""
    if event_data:
        body += f"<EventData>{event_data}</EventData>"
    elif not user_data:
        body += "<EventData></EventData>"
    if user_data:
        body += f"<UserData>{user_data}</UserData>"

    return (
        f'<Event xmlns="{NS}"><System>'
        f'<Provider Name="{provider}"></Provider>'
        f'<EventID Qualifiers="">{event_id}</EventID>'
        f"<Channel>{channel}</Channel>"
        f"<Computer>{computer}</Computer>"
        f"{system_extra}"
        f"</System>{body}</Event>"
    )


class FakeRecord:
    """python-evtx ``Record``에서 파서가 실제로 쓰는 것만 흉내 낸다."""

    def __init__(
        self,
        *,
        record_num: int = 1,
        offset: int = 0x1200,
        xml: str | None = None,
        timestamp: dt.datetime | None = None,
        filetime: int | None = None,
        length: int = 512,
    ) -> None:
        self._record_num = record_num
        self._offset = offset
        self._xml = build_xml() if xml is None else xml
        self._length = length
        if filetime is not None:
            self._filetime = filetime
        else:
            moment = timestamp or dt.datetime(2026, 7, 20, 3, 22, 15, tzinfo=UTC)
            self._filetime = to_filetime(moment)

    def record_num(self) -> int:
        return self._record_num

    def offset(self) -> int:
        return self._offset

    def length(self) -> int:
        return self._length

    def xml(self) -> str:
        return self._xml

    def unpack_qword(self, offset: int) -> int:
        assert offset == evtx.TIMESTAMP_OFFSET
        return self._filetime


class FakeChunk:
    """``ChunkHeader``에서 파서가 쓰는 네 가지만."""

    def __init__(self, records, *, offset=0x1000, header_size=0x80, next_record_offset=None):
        self._records = list(records)
        self._offset = offset
        self._header_size = header_size
        if next_record_offset is None:
            end = max((r.offset() + r.length() for r in self._records), default=offset)
            next_record_offset = end - offset
        self._next_record_offset = next_record_offset

    def offset(self) -> int:
        return self._offset

    def header_size(self) -> int:
        return self._header_size

    def next_record_offset(self) -> int:
        return self._next_record_offset

    def records(self):
        return iter(self._records)


def parse_xml(xml: str) -> "ET.Element":
    return ET.fromstring(xml)


# --------------------------------------------------------------- 등록


def test_both_evtx_artifacts_are_registered():
    from src.stage04_parse import parsers

    for artifact in ("evtx:Security", "evtx:System"):
        for implementation in parsers.IMPLEMENTATIONS:
            assert parsers.get(artifact, implementation) is not None, (
                f"{artifact} 가 {implementation} 에 등록되지 않았다. "
                "등록이 빠지면 04단계가 조용히 건너뛰고 evtx 없는 보고서가 나온다."
            )


def test_security_and_system_do_not_share_an_instance():
    """공유하면 System 레코드가 EVTX-SEC# 으로 나가 환각으로 집계된다."""
    from src.stage04_parse import parsers

    security = parsers.get("evtx:Security")
    system = parsers.get("evtx:System")
    assert security is not system
    assert security.artifact == "evtx:Security"
    assert system.artifact == "evtx:System"


def test_unknown_artifact_is_rejected_at_construction():
    with pytest.raises(ValueError, match="evtx"):
        evtx.EvtxParser("evtx:Application")


# ------------------------------------------------------- strip_namespace


def test_strip_namespace_handles_default_and_provider_namespaces():
    assert evtx.strip_namespace(f"{{{NS}}}EventID") == "EventID"
    # <UserData> 하위는 제공자 고유 네임스페이스를 쓴다 (실측 확인)
    assert evtx.strip_namespace("{http://manifests.microsoft.com/win/2006/windows/WMI}Provider") == "Provider"
    assert evtx.strip_namespace("EventID") == "EventID"


# ----------------------------------------------------------- event_fields


def test_named_data_becomes_field_keys():
    xml = build_xml(
        event_data=(
            '<Data Name="TargetUserName">svc_backup</Data>'
            '<Data Name="SubjectUserName">IIS APPPOOL\\DefaultAppPool</Data>'
        )
    )
    fields = evtx.event_fields(parse_xml(xml))
    assert fields["TargetUserName"] == "svc_backup"
    assert fields["SubjectUserName"] == "IIS APPPOOL\\DefaultAppPool"


def test_unnamed_data_is_kept_with_positional_keys():
    """실측 Application 로그에서 이름 없는 <Data>가 91%였다. 버리면 안 된다."""
    xml = build_xml(event_data="<Data>first</Data><Data>second</Data>")
    fields = evtx.event_fields(parse_xml(xml))
    assert fields["Data[0]"] == "first"
    assert fields["Data[1]"] == "second"


def test_named_and_unnamed_data_can_mix():
    xml = build_xml(event_data='<Data Name="User">alice</Data><Data>tail</Data>')
    fields = evtx.event_fields(parse_xml(xml))
    assert fields["User"] == "alice"
    assert fields["Data[0]"] == "tail"


def test_non_data_children_keep_their_tag_name():
    """<Binary>는 <Data>가 아니다. Data[n]으로 세면 위치가 밀린다."""
    xml = build_xml(event_data='<Data Name="User">alice</Data><Binary>DEADBEEF</Binary>')
    fields = evtx.event_fields(parse_xml(xml))
    assert fields["Binary"] == "DEADBEEF"
    assert "Data[0]" not in fields


def test_empty_value_keeps_the_key():
    """키를 빼면 '필드 없음'과 '값이 빔'이 구분되지 않아 정상 문장이 기각된다."""
    xml = build_xml(event_data='<Data Name="TargetUserName"></Data>')
    fields = evtx.event_fields(parse_xml(xml))
    assert fields["TargetUserName"] == ""


def test_duplicate_names_do_not_overwrite():
    xml = build_xml(event_data='<Data Name="X">first</Data><Data Name="X">second</Data>')
    fields = evtx.event_fields(parse_xml(xml))
    assert fields["X"] == "first"
    assert fields["X#2"] == "second"


def test_user_data_is_read_too():
    """실측 8,257건 중 266건이 EventData 없이 UserData만 가졌다."""
    xml = build_xml(
        event_data="",
        user_data=(
            '<data_0x8000003F xmlns="http://manifests.microsoft.com/win/2006/windows/WMI">'
            "<Provider>IntelMEProv</Provider><Namespace>root\\Intel_ME</Namespace>"
            "</data_0x8000003F>"
        ),
    )
    fields = evtx.event_fields(parse_xml(xml))
    assert fields["Namespace"] == "root\\Intel_ME"
    # System 의 Provider 가 먼저 자리를 잡으므로 UserData 쪽은 번호가 붙는다.
    # 덮어쓰지 않는 것이 요점이다 — 덮으면 제공자를 잃는다.
    assert fields["Provider"] == "Microsoft-Windows-Security-Auditing"
    assert fields["Provider#2"] == "IntelMEProv"


def test_provider_is_recorded():
    """이벤트 ID는 제공자 안에서만 유일하다. 7045 가 어느 제공자 것인지 알아야 한다."""
    xml = build_xml(provider="Service Control Manager", event_id=7045)
    fields = evtx.event_fields(parse_xml(xml))
    assert fields["Provider"] == "Service Control Manager"


def test_values_are_not_type_converted():
    """숫자로 바꾸면 원본과 다른 값이 기록된다. 표기 흡수는 06단계 몫이다."""
    xml = build_xml(event_data='<Data Name="Size">4821</Data>')
    fields = evtx.event_fields(parse_xml(xml))
    assert fields["Size"] == "4821"
    assert isinstance(fields["Size"], str)


def test_non_ascii_values_survive():
    xml = build_xml(event_data='<Data Name="Context">로컬 시스템</Data>')
    fields = evtx.event_fields(parse_xml(xml))
    assert fields["Context"] == "로컬 시스템"


# ------------------------------------------------------ record_timestamp


def test_timestamp_uses_integer_math_not_the_library_float():
    """python-evtx 는 float(qword) * 1e-7 로 변환해 µs 가 틀어진다.

    실측: wevtutil 대조에서 8,257건 중 7,938건이 −1.6 µs ~ +2.8 µs 어긋났다.
    원시 FILETIME 을 정수로 변환하면 100ns 절삭만 남는다.
    """
    moment = dt.datetime(2026, 7, 20, 3, 22, 15, 725893, tzinfo=UTC)
    record = FakeRecord(filetime=to_filetime(moment) + 4)  # 100ns 자리에 4
    assert evtx.record_timestamp(record) == "2026-07-20T03:22:15.7258930Z"


def test_zero_filetime_is_none():
    assert evtx.record_timestamp(FakeRecord(filetime=0)) is None


# ------------------------------------------------------------- 레코드 생성


def _one(parser: "evtx.EvtxParser", record: FakeRecord, scope: Scope | None = None):
    chunk = FakeChunk([record])
    return list(parser._chunk_records(chunk, scope or Scope()))


def test_record_shape_matches_the_frozen_schema():
    parser = evtx.EvtxParser("evtx:Security")
    xml = build_xml(event_data='<Data Name="TargetUserName">svc_backup</Data>')
    (record,) = _one(parser, FakeRecord(record_num=40912, offset=0x2A1000, xml=xml))

    flagged = flagging.apply(record, Scope())
    schema.validate(flagged, "parsed_record")

    assert record["ref"] == "EVTX-SEC#40912"
    assert record["artifact"] == "evtx:Security"
    assert record["record_num"] == 40912
    assert record["offset"] == "0x2A1000"
    assert record["event_id"] == 4720
    assert record["channel"] == "Security"
    assert record["computer"] == "WEB01"


def test_ref_is_built_through_refs_module():
    parser = evtx.EvtxParser("evtx:System")
    (record,) = _one(parser, FakeRecord(record_num=1177))
    assert record["ref"] == refs.make_ref("evtx:System", 1177)
    assert refs.record_num_of(record["ref"]) == record["record_num"]


def test_offset_is_the_record_position_in_the_file():
    """근거 추적이 이 필드에 달려 있다. hexdump_record.py 가 여기로 seek 한다."""
    parser = evtx.EvtxParser("evtx:Security")
    (record,) = _one(parser, FakeRecord(offset=0x2A1D40))
    assert record["offset"] == "0x2A1D40"
    assert int(record["offset"], 16) == 0x2A1D40


def test_empty_channel_falls_back_to_the_file_we_opened():
    parser = evtx.EvtxParser("evtx:Security")
    (record,) = _one(parser, FakeRecord(xml=build_xml(channel="")))
    assert record["channel"] == "Security"


def test_parser_does_not_attach_flags():
    """플래그는 flagging.py 가 일괄로 붙인다. 어휘가 갈라지면 05가 레코드를 놓친다."""
    parser = evtx.EvtxParser("evtx:Security")
    (record,) = _one(parser, FakeRecord())
    assert "flags" not in record


def test_flagging_recognises_the_parser_output():
    """4720 → account_created 가 실제로 붙는지. 파서와 flagging 의 접점이다."""
    parser = evtx.EvtxParser("evtx:Security")
    (record,) = _one(parser, FakeRecord(xml=build_xml(event_id=4720)))
    assert "account_created" in flagging.apply(record, Scope())["flags"]


def test_privileged_group_add_uses_target_user_name_as_group():
    parser = evtx.EvtxParser("evtx:Security")
    xml = build_xml(
        event_id=4732,
        event_data='<Data Name="TargetUserName">Administrators</Data>'
        '<Data Name="MemberName">svc_backup</Data>',
    )
    (record,) = _one(parser, FakeRecord(xml=xml))
    assert "privileged_group_add" in flagging.apply(record, Scope())["flags"]


# ------------------------------------------------------------- scope


def test_event_id_outside_scope_is_dropped():
    parser = evtx.EvtxParser("evtx:Security")
    scope = Scope(event_ids=(4720, 4728, 4732))
    assert _one(parser, FakeRecord(xml=build_xml(event_id=1531)), scope) == []
    assert parser.stats["filtered_out"] == 1


def test_empty_event_ids_lets_everything_through():
    """비어 있으면 제한 없음이다. 매핑이 event_ids 를 빠뜨리면 로그 전량이 나온다."""
    parser = evtx.EvtxParser("evtx:Security")
    assert len(_one(parser, FakeRecord(xml=build_xml(event_id=1531)), Scope())) == 1


def test_out_of_time_range_records_are_emitted_with_a_flag():
    """시간 범위로는 거르지 않는다 (parsers/base.py 계약).

    02단계의 시간 추론이 틀렸을 때 되짚을 레코드가 남아야 한다.
    """
    parser = evtx.EvtxParser("evtx:Security")
    scope = Scope(
        start=dt.datetime(2026, 7, 18, tzinfo=UTC),
        end=dt.datetime(2026, 7, 22, tzinfo=UTC),
    )
    old = FakeRecord(timestamp=dt.datetime(2025, 1, 1, tzinfo=UTC))
    (record,) = _one(parser, old, scope)
    assert "outside_time_range" in flagging.apply(record, scope)["flags"]


# ------------------------------------------------- 조용한 실패를 잡는다


def test_truncated_chunk_is_counted():
    """python-evtx 는 깨진 레코드를 만나면 청크 나머지를 조용히 버린다.

    그 사실이 매니페스트에 남지 않으면 "이 시각엔 아무 일도 없었다"로
    잘못 읽게 된다.
    """
    parser = evtx.EvtxParser("evtx:Security")
    record = FakeRecord(offset=0x1080, length=512)
    # 청크는 0x4000 까지 레코드가 있다고 선언하는데 실제로는 0x1280 에서 끝난다
    chunk = FakeChunk([record], offset=0x1000, next_record_offset=0x4000)

    got = list(parser._chunk_records(chunk, Scope()))
    assert len(got) == 1
    assert parser.stats["parse_errors"] == 1


def test_complete_chunk_is_not_counted_as_an_error():
    parser = evtx.EvtxParser("evtx:Security")
    record = FakeRecord(offset=0x1080, length=512)
    chunk = FakeChunk([record], offset=0x1000)  # 경계를 레코드 끝에 맞춤
    list(parser._chunk_records(chunk, Scope()))
    assert parser.stats["parse_errors"] == 0


def test_unparseable_xml_skips_only_that_record():
    parser = evtx.EvtxParser("evtx:Security")
    broken = FakeRecord(record_num=1, offset=0x1080, xml="<Event><System>")
    good = FakeRecord(record_num=2, offset=0x1280)
    got = list(parser._chunk_records(FakeChunk([broken, good]), Scope()))

    assert [r["record_num"] for r in got] == [2]
    assert parser.stats["xml_errors"] == 1
    assert parser.stats["parse_errors"] == 1


def test_missing_system_section_is_counted():
    parser = evtx.EvtxParser("evtx:Security")
    xml = f'<Event xmlns="{NS}"><EventData></EventData></Event>'
    assert _one(parser, FakeRecord(xml=xml)) == []
    assert parser.stats["parse_errors"] == 1


def test_unreadable_event_id_is_counted():
    parser = evtx.EvtxParser("evtx:Security")
    xml = build_xml().replace(">4720<", "><")
    assert _one(parser, FakeRecord(xml=xml)) == []
    assert parser.stats["parse_errors"] == 1


def test_empty_computer_is_counted_not_invented():
    """스키마가 minLength 1 을 요구한다. 값을 지어내면 검증이 무의미해진다."""
    parser = evtx.EvtxParser("evtx:Security")
    assert _one(parser, FakeRecord(xml=build_xml(computer=""))) == []
    assert parser.stats["parse_errors"] == 1


def test_unreadable_timestamp_is_counted():
    """evtx 스키마는 $UsnJrnl 과 달리 timestamp 를 필수로 둔다."""
    parser = evtx.EvtxParser("evtx:Security")
    assert _one(parser, FakeRecord(filetime=0)) == []
    assert parser.stats["parse_errors"] == 1


def test_stats_reset_between_runs():
    """집계가 누적되면 매니페스트의 parse_errors 가 실행마다 부풀어 오른다."""
    parser = evtx.EvtxParser("evtx:Security")
    broken = FakeRecord(xml="<Event><System>")

    list(parser._chunk_records(FakeChunk([broken]), Scope()))
    assert parser.stats["parse_errors"] == 1

    parser.stats = parser._new_stats()
    list(parser._chunk_records(FakeChunk([FakeRecord()]), Scope()))
    assert parser.stats["parse_errors"] == 0
    assert parser.stats["records"] == 1


# --------------------------------------------------------- 파일 수준


def test_empty_file_is_a_hard_error():
    parser = evtx.EvtxParser("evtx:Security")
    with pytest.raises(ValueError, match="비어"):
        list(parser.parse(_io.BytesIO(b""), Scope()))


def test_wrong_magic_is_a_hard_error():
    """evtx 가 아니면 읽을 이유가 없다. 조용히 0건을 내면 안 된다."""
    parser = evtx.EvtxParser("evtx:Security")
    buf = b"NOTEVTX\x00" + b"\x00" * 0x2000
    with pytest.raises(ValueError, match="evtx 파일이 아닙니다"):
        list(parser.parse(_io.BytesIO(buf), Scope()))


def test_file_header_verify_is_not_used_as_a_gate():
    """verify() 는 정상 로그에서도 False 가 난다 (wevtutil 로 내보낸 로그에서 확인).

    이걸로 게이팅하면 멀쩡한 증거를 통째로 버린다. 매직만 본다.
    """
    import inspect

    body = inspect.getsource(evtx.EvtxParser.parse)
    assert "check_magic" in body, "파일 수준 게이트는 매직이어야 한다"
    assert "header.verify()" not in body, (
        "FileHeader.verify() 로 게이팅하면 정상 로그를 거부한다. "
        "엄격한 판정은 청크 단위로 내린다."
    )


# --------------------------------------------------- 목업과의 정합성


def test_mock_records_validate_against_the_parser_shape():
    """저장소의 evtx 목업이 파서 산출물과 같은 모양인지.

    목업은 05~07 개발의 입력이므로, 파서가 다른 모양을 내기 시작하면
    관통 실행만 통과하고 실제 케이스에서 깨진다.
    """
    import json
    from pathlib import Path

    mock = (
        Path(__file__).resolve().parents[1]
        / "benchmark/datasets/C-001-webshell/mock/04_parsed/evtx_security.jsonl"
    )
    parser = evtx.EvtxParser("evtx:Security")
    (built,) = _one(parser, FakeRecord(record_num=40912, offset=0x2A1000))

    for line in mock.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        assert set(record) - {"flags"} == set(built), (
            "목업과 파서의 필드 집합이 다르다. 한쪽만 고치면 05~07이 "
            "실제 케이스에서 깨진다."
        )


# ============================================ 채널 확장 (Firewall/BITS/NetworkProfile)
#
# evtx 파서가 맡는 아티팩트를 늘릴 때 등록 지점이 다섯이다. 넷은
# add-parser 스킬에 적혀 있고, 다섯 번째가 이 파일의 CHANNEL_FALLBACK 이다.
# 빠뜨리면 import 시점에 ValueError 로 죽는다 — 조용하지는 않지만
# 어디를 고쳐야 하는지가 안 드러난다.

NETWORK_ARTIFACTS = ("evtx:Firewall", "evtx:BITS", "evtx:NetworkProfile")


@pytest.mark.parametrize("artifact", NETWORK_ARTIFACTS)
def test_new_evtx_channels_are_constructible(artifact):
    parser = evtx.EvtxParser(artifact)
    assert parser.artifact == artifact


def test_every_catalogued_evtx_artifact_has_a_channel_fallback():
    """카탈로그와 CHANNEL_FALLBACK 이 어긋나면 그 아티팩트는 열리지 않는다."""
    catalog = mapping_loader.load_catalog(REPO_ROOT / "mappings")
    catalogued = {
        name
        for name, spec in catalog.artifacts.items()
        if name.startswith("evtx:") and spec.unusable_reason("windows") is None
    }
    assert catalogued
    assert catalogued <= set(evtx.CHANNEL_FALLBACK)


def test_each_channel_keeps_its_own_ref_prefix():
    """인스턴스를 공유하면 한 채널의 레코드가 다른 접두어로 나간다.

    그건 06단계에서 "존재하지 않는 레코드" = 환각으로 집계된다.
    """
    from src.stage04_parse import parsers

    seen = {}
    for artifact in ("evtx:Security", "evtx:System", *NETWORK_ARTIFACTS):
        prefix = refs.prefix_for(artifact)
        assert prefix not in seen, f"{artifact} 와 {seen.get(prefix)} 가 {prefix} 를 공유한다"
        seen[prefix] = artifact
        assert parsers.PARSERS[artifact].artifact == artifact
        assert parsers.REFERENCE_PARSERS[artifact].artifact == artifact


@pytest.mark.parametrize("artifact", NETWORK_ARTIFACTS)
def test_new_channels_have_an_output_filename(artifact):
    """등록소와 별개 테이블이다. 빠뜨리면 증거를 열기도 전에 KeyError 로 죽는다."""
    from src.stage04_parse.parse import OUTPUT_FILENAMES

    assert OUTPUT_FILENAMES[artifact].endswith(".jsonl")


def test_output_filenames_are_unique():
    """두 아티팩트가 같은 파일에 쓰면 한쪽이 통째로 사라진다."""
    from src.stage04_parse.parse import OUTPUT_FILENAMES

    assert len(set(OUTPUT_FILENAMES.values())) == len(OUTPUT_FILENAMES)
