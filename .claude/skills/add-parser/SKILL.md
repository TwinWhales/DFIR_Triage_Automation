---
name: add-parser
description: 04단계에 새 아티팩트 파서를 추가하거나 기존 파서가 맡는 아티팩트를 늘릴 때 쓴다. 등록 지점이 네 군데로 흩어져 있고 빠뜨리면 조용히 실패하는 곳이 셋 있다. $MFT·$UsnJrnl·evtx·registry를 추가하며 실제로 밟은 순서.
---

# 새 아티팩트 파서 추가

파서 넷(`mft` `usnjrnl` `evtx` `registry`)을 추가하며 굳어진 순서다.
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

**2. `ref` 접두어를 등록한다** — `src/common/refs.py`

**두 군데다.** 딕셔너리 하나, 정규식 하나.

```python
ARTIFACT_PREFIX = { ..., "registry:SYSTEM": "REG-SYS" }

REF_PATTERN = re.compile(
    r"^(?P<prefix>MFT|USN|EVTX-SEC|EVTX-SYS|REG-SYS|REG-SW)#(?P<num>0|[1-9]\d*)$"
)
```

딕셔너리만 고치면 `make_ref`는 통과하는데 `parse_ref`가 기각한다.
`tests/test_common.py`는 딕셔너리와 역방향 맵의 길이만 보므로 이 불일치를
잡지 못한다.

레코드 번호로 쓸 고유값이 아티팩트 안에 있어야 한다. 없으면 만들지 말고
기존 값을 쓴다 — 레지스트리는 NK 레코드 오프셋을 10진수로 썼다. 자체
일련번호를 매기면 원본 대조가 불가능해진다.

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

기존 어휘로 될 일이면 새로 만들지 않는다. 이름이 갈라지면
`record_filter.py`가 레코드를 놓치고, 그 결과가 선별 재현율 저하로 잘못
집계된다.

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

**10. 못 하는 것을 적는다** — `docs/limitations.md`

라이브러리를 우회했으면 왜 우회했는지도 여기 적는다. 한계 기록은 감점이
아니라 성숙도의 지표다.

---

## 빠뜨리면 조용히 실패하는 곳

셋 다 실제로 겪은 것이다.

**`OUTPUT_FILENAMES`** — 등록소(4번)와 별개 테이블이라는 걸 잊는다.

**`REF_PATTERN`** — `ARTIFACT_PREFIX`만 고치고 정규식을 잊는다. 테스트가
못 잡는다.

**플래그가 안 붙는 아티팩트는 05단계에 도달하지 못한다.** `record_filter.py`가
플래그로 레코드를 추리므로 전부 버려진다. 레지스트리가 지금 이 상태다
(`docs/limitations.md` 6-7). 파싱은 되고 파일도 나오는데 해석에 안 쓰인다.
**새 아티팩트를 붙이기 전에 그 아티팩트에 붙을 플래그가 있는지 먼저 본다.**

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
