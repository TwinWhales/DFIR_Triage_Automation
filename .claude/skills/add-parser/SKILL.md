---
name: add-parser
description: 04단계에 새 아티팩트 파서를 추가하거나 기존 파서가 맡는 아티팩트를 늘릴 때 쓴다. 등록 지점이 여러 군데로 흩어져 있고 빠뜨리면 조용히 실패하는 곳이 여럿 있다. $MFT·$UsnJrnl·evtx·registry·prefetch·recentfilecache를 추가하며 실제로 밟은 순서.
---

# 새 아티팩트 파서 추가

파서 여섯(`mft` `usnjrnl` `evtx` `registry` `prefetch` `recentfilecache`)을
추가하며 굳어진 순서다.
**설계 근거는 여기 옮겨 적지 않는다** — 각 파일의 docstring이 권위다.

| 알고 싶은 것 | 볼 곳 |
|---|---|
| 파서가 지켜야 할 세 가지, `Scope` 술어 | `src/stage04_parse/parsers/base.py` 모듈 docstring |
| 등록 규칙, 아티팩트마다 인스턴스를 따로 두는 이유 | `src/stage04_parse/parsers/__init__.py` docstring |
| 카탈로그 작성 규칙 | `docs/mapping-guide.md` |
| 직접 구현 vs 라이브러리 판단 | `work-guide.md` 3.1 |

---

## 순서

**1. 카탈로그에 먼저 등재한다** — `mappings/_artifacts.yaml`

```yaml
  registry:SYSTEM:
    parser: registry
    os: [windows]
    supported: true
    description: SYSTEM 하이브. 서비스·드라이버·장치 설정.
```

파서보다 먼저인 이유는 mapping-guide에 있다. 여기 없는 아티팩트는 선별될
수도 제외될 수도 없다. 이름은 이후 모든 단계에서 그대로 쓰이므로 여기서
확정한다.

**2. `ref` 접두어를 등록한다** — `src/common/refs.py`와 스키마

**네 군데다.** `refs.py`의 딕셔너리 하나, 정규식 하나, 그리고 **스키마
둘** — `schemas/parsed_record.schema.json`과 `schemas/findings.schema.json`.
스키마가 같은 정규식을 따로 들고 있어서, 앞의 둘만 고치면 파서는 도는데
산출물이 스키마 검증에서 전부 기각된다.

`findings.schema.json`을 빠뜨리면 04단계는 멀쩡히 도는데 **05단계 문장이
기각된다.** 04만 보고 있으면 한참 뒤에 드러난다. `tests/test_schemas.py`가
`refs.py`의 접두어 전부를 두 스키마에 걸어 보므로 커밋 전에 잡힌다
(2026-08-25, `recentfilecache` 추가에서 실제로 잡혔다).

```python
ARTIFACT_PREFIX = { ..., "registry:SYSTEM": "REG-SYS" }

REF_PATTERN = re.compile(
    r"^(?P<prefix>MFT|USN|EVTX-SEC|EVTX-SYS|REG-SYS|REG-SW|PF)#(?P<num>0|[1-9]\d*)$"
)
```

스키마는 **동결 대상**이다(`CLAUDE.md`). `ref` 패턴 한 줄과 아티팩트별
`required`를 정하는 `allOf` 분기 하나면 되지만, 고치기 전에 사용자에게
말한다. 속성은 대개 늘릴 필요가 없다 — `fields`가 자유 형식이라 아티팩트
고유 값은 거기 담으면 된다(evtx·registry·prefetch가 그렇다).

딕셔너리만 고치면 `make_ref`는 통과하는데 `parse_ref`가 기각한다.
`tests/test_common.py`는 딕셔너리와 역방향 맵의 길이만 보므로 이 불일치를
잡지 못한다.

레코드 번호로 쓸 고유값이 아티팩트 안에 있어야 한다. 없으면 만들지 말고
기존 값을 쓴다 — 레지스트리는 NK 레코드 오프셋을 10진수로 썼다. 자체
일련번호를 매기면 원본 대조가 불가능해진다.

**2-1. 아티팩트가 파일 하나가 아니면** — `src/stage04_parse/evidence.py`

프리패치는 **폴더 하나에 든 .pf 전부가 아티팩트 하나**다. 그런 경우
`FILE_LAYOUT`에 `directory_paths`/`directory_suffix`를 쓰고
`relative_paths`/`filenames`는 비운다. 04단계는 `open_all()`로 파일마다
`parse()`를 부르므로, 파서는 **파일 하나**를 받고 호출 사이에 상태를
들고 있다가 `begin_artifact()`에서 비운다.

`ref`가 폴더 전체에서 유일해야 한다는 점이 함정이다. 파일마다 고유한 값이
있어야 하고(프리패치는 헤더의 경로 해시), 겹치면 그 파일을 건너뛴다 —
같은 `ref`가 둘이면 `io.read_parsed_records`가 05·06단계를 통째로 세운다.

**3. 파서를 구현한다** — `src/stage04_parse/parsers/<name>.py`

`Parser` 프로토콜은 둘뿐이다. `artifact` 속성과
`parse(stream, scope) -> Iterator[dict]`.

- **`yield` 한다.** 리스트로 모으지 않는다. `$MFT`는 수십만 건이다
- **`flags`는 넣지 않는다.** `flagging.py`가 일괄로 붙인다
- **`offset`은 원본 바이트 위치다.** 이 필드가 직접 구현의 이유다
- 레코드 하나를 못 읽으면 `ParseError`로 **그 레코드만** 건너뛴다

온디스크 구조를 직접 옮길 때는 `structs/`에 분리한다. 명세 문서와 1:1로
대조하기 위해서다.

**4. 등록소에 넣는다** — `src/stage04_parse/parsers/__init__.py`

`PARSERS`와 `REFERENCE_PARSERS` **양쪽**에 넣는다. reference 쪽을 비우면
`--parser reference`로 돌렸을 때 그 아티팩트만 조용히 빠진 보고서가 나온다.

한 클래스가 여러 아티팩트를 맡으면 **인스턴스를 아티팩트마다 따로 만든다.**
`artifact`가 `ref` 접두어와 출력 파일명을 정하므로, 공유하면 한쪽 레코드가
다른 쪽 접두어로 나가고 06단계가 그것을 환각으로 집계한다.

import 실패를 `try/except`로 감싸는 것은 `$MFT`뿐이다 — vendored 코드가
없을 수 있어서다. 나머지는 감싸지 않는다. 우리 오타는 소리를 내야 한다.

**5. 출력 파일명을 등록한다** — `src/stage04_parse/parse.py`의 `OUTPUT_FILENAMES`

```python
OUTPUT_FILENAMES = { ..., "registry:SYSTEM": "registry_system.jsonl" }
```

**등록소와 별개의 테이블이다.** 4번만 하고 여기를 빠뜨리면 파서는 찾았는데
증거를 열기도 전에 `KeyError`로 죽는다.

**6. 플래그가 필요하면 `_flags.yaml`에 적는다**

어휘와 룰의 원본은 `mappings/_flags.yaml` 하나다. 적은 뒤
`tools/sync_flag_enum.py`를 돌리면 스키마 enum이 따라온다.
`tests/test_flag_rules.py`가 어긋남을 잡는다.

`event_id`·USN 사유·필드값 비교로 표현되는 조건이면 **파이썬을 고칠 일이
없다.** 타임스탬프 비교처럼 근거가 코드 주석에 붙어 있어야 하는 것만
`flagging.py`의 `HANDLERS`에 등록하고 YAML에서 이름으로 부른다.

기존 어휘로 될 일이면 새로 만들지 않는다. 이름이 갈라지면 05단계가
레코드를 놓치고, 그 결과가 선별 재현율 저하로 잘못 집계된다.

**신호가 경로에서 나오는 아티팩트라면 플래그를 만들지 않는다.** 카탈로그에
`signal_source: scope`를 적는다. 레지스트리가 그 경우다 — 판정이 이미
03단계 `path_prefix`에서 끝나므로 04단계가 붙일 플래그가 없다. 자세한 것은
아래 "함정".

**7. 매핑에 등재한다** — `mappings/<os>/T####.yaml`

여기 없으면 03단계가 선별하지 않고, 파서는 영영 불리지 않는다.
작성 규칙은 `docs/mapping-guide.md`.

**8. 테스트를 쓴다** — `tests/test_<name>_parser.py`

바이너리 픽스처 없이 쓸 수 있으면 그렇게 한다. 라이브러리를 쓰는 파서라면
**그 위에 우리가 얹은 판단만** 고정한다 — 경로 재구성, 범위 가지치기,
`ref`/`offset` 규약. 라이브러리가 이미 하는 일을 다시 시험하지 않는다.
`tests/test_registry_parser.py`가 그 형태다.

실물 증거를 쓰는 통합 테스트는 `evidence/`가 없으면 건너뛰게 한다
(gitignore 대상이라 CI와 팀원 기계에는 없다).

**9. 대조하고 기록한다** — `docs/artifact-notes.md`

직접 구현의 리스크는 **조용히 틀리는 것**이다. 외부 도구나 명세와 대조한
기록을 남긴다. 대조 없는 파서는 없는 것과 같다.

선례:

| 아티팩트 | 대조 상대 |
|---|---|
| `evtx` | `wevtutil` (Windows 기본 탑재), 8,257 레코드 전부 일치 |
| `registry` | `tools/scan_hive_cells.py` — 셀을 직접 걸어 `nk`를 센다 |
| `$MFT` | `tools/compare_mft.py` + 합성 레코드 테스트 |
| `prefetch` | `tools/scan_prefetch.py` — 메트릭 배열을 보지 않고 문자열 블록을 쪼갠다 |

외부 도구가 없는 아티팩트(프리패치가 그랬다)는 **같은 파일을 다른 경로로
읽는 스캐너**를 만든다. 덤으로, 파일 안에 **Windows가 쓴 값**이 있으면
그것과 맞춰 본다 — 프리패치는 헤더 해시와 .pf 파일명, 헤더의 파일 크기와
실제 크기가 그 자리다. 우리 해석과 독립이라 오프셋을 잘못 잡았으면 맞을
이유가 없다.

**10. 못 하는 것을 적는다** — `docs/limitations.md`

라이브러리를 우회했으면 왜 우회했는지도 여기 적는다. 한계 기록은 감점이
아니라 성숙도의 지표다.

---

## 빠뜨리면 조용히 실패하는 곳

전부 실제로 겪은 것이다.

**`OUTPUT_FILENAMES`** — 등록소(4번)와 별개 테이블이라는 걸 잊는다.

**파서 자체의 허용 목록.** 한 파서가 여러 아티팩트를 맡으면 그 파일 안에
목록이 하나 더 있을 수 있다. evtx 가 그렇다 — `parsers/evtx.py` 의
`CHANNEL_FALLBACK` 에 없는 아티팩트는 `EvtxParser.__init__` 이 거부한다.
카탈로그와 등록소만 고치면 **import 시점에 죽는다.** 조용하지는 않지만
등록 지점이 넷이 아니라 다섯이라는 사실 자체가 함정이다
(2026-08-24, Firewall/BITS/NetworkProfile 추가에서 밟았다).

**`REF_PATTERN`** — `ARTIFACT_PREFIX`만 고치고 정규식을 잊는다.
`tests/test_common.py`는 못 잡는다(딕셔너리 길이만 본다). **스키마 둘에도
같은 정규식이 있고**, 그쪽은 `tests/test_schemas.py`가 잡는다.

**버전에 따라 존재하지 않는 아티팩트라면 `osinfo.AVAILABILITY`에도 적는다.**
`RecentFileCache.bcf`(Win7 전용)와 `Amcache.hve`(Win8 이상)가 그 짝이다.
적지 않으면 그 버전에 원래 없는 파일이 `artifact_not_found` — "수집 누락"
으로 보고서에 실리고, 분석가가 있지도 않은 파일을 다시 뽑으러 간다.
**구조적으로 존재할 수 없는 것만 적는다** — "이 버전에서 흔히 비어 있다"는
`artifact_not_found`가 이미 담당하는 일이고, 잘못 적으면 있는 증거를 안 읽는다.

**미지원 아티팩트를 예시로 쓰던 테스트·문서.** 카탈로그에서 `supported`를
뒤집으면 "미지원이란 이런 것"의 예시로 그 아티팩트를 쓰던 곳이 전부
깨진다. registry·prefetch가 차례로 그랬다. `grep -rn '<이름>' tests/ docs/`
로 한 번 훑는다.

**신호가 어디서 나오는지 카탈로그에 적지 않으면 05단계에 도달하지 못한다.**
기본값 `signal_source: flags`는 "04단계가 전부 훑고 재미있는 것에 플래그를
붙인다"는 뜻이라, 플래그가 안 붙는 아티팩트는 05단계 배분이 후보 0건으로
보고 자리를 주지 않는다. 레지스트리가 그 상태였다(`docs/limitations.md`
6-7) — 파싱은 1,754건이 되고 파일도 나오는데 모델에 한 건도 안 갔다.

**새 아티팩트를 붙이기 전에 둘 중 어느 쪽인지 정한다.**

- 전부 훑고 재미있는 것을 고르는가 → `flags`. 붙을 플래그가 실제로 있는지
  확인한다.
- 03단계가 경로·범위로 이미 골라 오는가 → `signal_source: scope`.
  `mappings/_artifacts.yaml`의 해당 항목에 적는다. 레지스트리와 프리패치가
  이쪽이다 — 모든 레코드에 붙는 플래그는 필터 역할을 못 한다.

---

## 확인

```bash
.venv/Scripts/python.exe -m pytest -q
```

등록됐는지 직접 본다.

```bash
.venv/Scripts/python.exe -c "from src.stage04_parse import parsers; print(parsers.registered())"
```

목록에 없으면 4번이 안 된 것이다.
