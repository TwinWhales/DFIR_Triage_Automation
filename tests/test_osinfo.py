"""Windows 버전 판정과 버전별 아티팩트 가용성 테스트.

여기서 고정하는 것은 셋입니다.

1. **빌드 번호로만 판정한다** — ``ProductName``이 거짓말을 해도 흔들리지 않는다
2. **모르면 거르지 않는다** — 판정 실패나 미상 빌드에서 아무것도 빼지 않는다
3. **배타적인 짝이 실제로 갈린다** — Amcache(Win8+)와 RecentFileCache(Win7)

하이브를 합성하지 않고 ``detect_from_hive``를 우회해 ``WindowsVersion``을
직접 만듭니다. regf 합성은 python-registry 의 일이고, 하이브를 읽는 경로
자체는 레지스트리 파서 테스트가 이미 봅니다 — 여기서 다시 시험하면
라이브러리를 시험하는 것이 됩니다.
"""

from __future__ import annotations

import pytest

from src.stage04_parse import osinfo


def version(build: int, **kwargs) -> osinfo.WindowsVersion:
    return osinfo.WindowsVersion(build=build, family=osinfo.family_of(build), **kwargs)


# ============================================================== 구조 세대


@pytest.mark.parametrize(
    ("build", "family"),
    [
        (7600, "win7"),
        (7601, "win7"),    # Win7 SP1 / Server 2008 R2
        (9200, "win8"),    # Win8 / Server 2012
        (9600, "win81"),   # Win8.1 / Server 2012 R2
        (10240, "win10"),  # Win10 1507
        (15063, "win10"),  # 실측 — evidence/0824test.001
        (19045, "win10"),  # Win10 22H2
        (20348, "win10"),  # Server 2022 — 클라이언트에 대응물이 없다
        (22000, "win11"),
        (26100, "win11"),
    ],
)
def test_the_build_number_decides_the_family(build, family):
    assert osinfo.family_of(build) == family


@pytest.mark.parametrize("build", [0, 3790, 6002, 7599])
def test_builds_we_do_not_know_are_unknown(build):
    """Vista 이하는 아는 구간에 없다.

    ``win7``로 뭉뚱그리지 않는다 — 지원한다고 말한 적 없는 것을 지원하는
    척하면, 그 이미지에서 나온 결과가 검증됐다는 인상만 남는다.
    """
    assert osinfo.family_of(build) == osinfo.UNKNOWN_FAMILY
    assert not version(build).known


def test_the_product_name_does_not_decide_anything():
    """Win11 초기 빌드는 ProductName 이 "Windows 10 Pro"였다.

    이름을 믿으면 Win11 이미지를 Win10으로 판정하고, 그 위에서 내리는
    버전별 판단이 전부 한 세대 어긋난다.
    """
    lying = version(22000, product_name="Windows 10 Pro")
    assert lying.family == "win11"


def test_a_server_build_is_the_client_generation():
    """서버판은 클라이언트와 빌드를 공유한다.

    ``family``는 제품이 아니라 **온디스크 구조 세대**다. 제품 구분이
    필요하면 installation_type 이 따로 실린다.
    """
    server = version(9600, installation_type="Server", product_name="Windows Server 2012 R2")
    assert server.family == "win81"
    assert server.as_manifest()["installation_type"] == "Server"


# ============================================================== 매니페스트


def test_the_manifest_block_carries_the_build_and_family():
    info = version(15063, product_name="Windows 10 Pro", release_id="1703", revision=0)
    block = info.as_manifest()

    assert block["determined"] is True
    assert block["build"] == 15063
    assert block["family"] == "win10"
    assert block["release_id"] == "1703"
    assert block["revision"] == 0


def test_empty_values_are_left_out_of_the_manifest():
    # 하이브에 없던 값과 "빈 문자열이 들어 있던 값"을 구분할 이유가 없다.
    # 없는 값을 실으면 07단계가 그것을 표에 그린다.
    block = version(7601).as_manifest()

    assert "product_name" not in block
    assert "display_version" not in block
    assert "revision" not in block


def test_revision_zero_is_kept():
    # 0은 빈 값이 아니다. UBR 0 은 "업데이트가 없다"는 사실이다.
    assert version(15063, revision=0).as_manifest()["revision"] == 0


# ============================================================== 가용성


def test_amcache_is_not_applicable_on_windows_7():
    reason = osinfo.applicability("registry:Amcache", version(7601))

    assert reason is not None
    assert "7601" in reason and "9200" in reason
    # 사유가 보고서에 그대로 실린다. 대안을 말해 주지 않으면 분석가는
    # "그럼 뭘 봐야 하나"를 알 수 없다.
    assert "RecentFileCache" in reason


def test_amcache_is_applicable_from_windows_8():
    assert osinfo.applicability("registry:Amcache", version(9200)) is None
    assert osinfo.applicability("registry:Amcache", version(15063)) is None


def test_recentfilecache_is_not_applicable_after_windows_7():
    reason = osinfo.applicability("recentfilecache", version(9200))

    assert reason is not None
    assert "Amcache" in reason


def test_recentfilecache_is_applicable_on_windows_7():
    assert osinfo.applicability("recentfilecache", version(7600)) is None
    assert osinfo.applicability("recentfilecache", version(7601)) is None


def test_the_pair_is_exclusive_on_every_known_build():
    """어느 빌드에서도 둘 중 정확히 하나만 해당된다.

    둘 다 빠지면 그 버전에서는 "실행된 적 있는가"를 물을 방법이 없어지고,
    둘 다 남으면 없는 파일을 찾다가 artifact_not_found 가 하나 더 는다.
    """
    for build in (7600, 7601, 9200, 9600, 10240, 15063, 19045, 22000):
        applicable = [
            artifact
            for artifact in ("registry:Amcache", "recentfilecache")
            if osinfo.applicability(artifact, version(build)) is None
        ]
        assert len(applicable) == 1, f"빌드 {build}: {applicable}"


# ======================================================= 모르면 거르지 않는다


def test_nothing_is_filtered_when_the_version_is_undetermined():
    """판정 실패는 거르지 않을 이유다.

    잘못 거르면 **있는 증거를 안 읽는다.** 안 거르면 최악이 "없는 파일을
    찾다 못 찾음"이고, 그것은 지금과 같다.
    """
    for artifact in osinfo.AVAILABILITY:
        assert osinfo.applicability(artifact, None) is None


def test_nothing_is_filtered_on_an_unknown_build():
    vista = version(6002)
    for artifact in osinfo.AVAILABILITY:
        assert osinfo.applicability(artifact, vista) is None


def test_an_artifact_without_a_rule_is_never_filtered():
    for build in (7601, 9200, 15063, 22000):
        assert osinfo.applicability("$MFT", version(build)) is None
        assert osinfo.applicability("prefetch", version(build)) is None


def test_every_availability_rule_names_an_artifact_in_the_catalog():
    """가용성 규칙의 이름이 카탈로그와 어긋나면 **조용히 아무 일도 안 한다.**

    04단계는 아티팩트 이름으로 규칙을 찾으므로, 오타가 나면 규칙이 영영
    적용되지 않고 아무도 모른다.
    """
    from src.stage03_select.mapping_loader import load_catalog

    catalog = load_catalog("mappings")
    for artifact in osinfo.AVAILABILITY:
        assert artifact in catalog.artifacts, artifact


def test_every_availability_rule_has_a_note():
    # note 가 보고서의 사유 문장이 된다. 비어 있으면 "이 버전에 없음"까지만
    # 나가고 분석가는 대안을 알 수 없다.
    for artifact, rule in osinfo.AVAILABILITY.items():
        assert rule.note.strip(), artifact
        assert rule.min_build or rule.max_build, artifact
