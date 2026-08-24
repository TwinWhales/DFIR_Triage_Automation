# work.md — 다음에 할 일

AIFT(Dissect 기반 이미지 직접 파싱 + AI 분석 도구)와 비교 검토하며 나온
결론을 작업 순서로 정리한 문서다. 설계 근거는 여기 옮겨 적지 않는다 —
각 항목에 붙은 문서가 권위다.

---

## 결론: 트랙 B(핵심 파서 확충)를 먼저, 트랙 A(raw 이미지 지원)는 그다음

두 트랙은 **기술적으로 서로 의존하지 않는다.** 확인된 사실:

- 파서 넷(`mft` `usnjrnl` `evtx` `registry`) 전부 `stream: BinaryIO` 하나만
  보고 동작한다. 어디서 온 스트림인지 모른다(`evidence.py` 설계 원칙).
- `mft.py`만 `stream.seekable()`을 요구하는데, Dissect가 `$MFT`에 대해
  돌려주는 `dissect.util.stream.RunlistStream`이 `seekable() == True`이고
  `seek(0)` 후 재읽기 값이 원본과 100% 일치함을 실제 evidence 이미지로
  확인했다.
- 즉 **지금 파서를 더 만들어도 나중에 트랙 A를 붙일 때 다시 손댈 일이
  없다.** 순서를 바꿔도 손해가 없다.

그렇다면 우선순위는 "무엇이 오늘 조사 능력을 더 늘려주는가"로 정한다.

- 트랙 A(`VolumeSource`)는 지금 있는 아티팩트 6종을 "추출 없이" 읽게
  해줄 뿐, **새 조사 능력을 추가하지 않는다.** KAPE/FTK 추출은 이
  바닥의 표준 워크플로우라 없어서 못 쓰는 상황도 아니다.
- 트랙 B(새 파서)는 오늘 당장 분석 가능한 아티팩트 종류를 늘린다.
  지금 카탈로그($MFT·$UsnJrnl·evtx 2종·registry 2종)에는 **실행 흔적
  (execution evidence) 계열이 하나도 없다** — 실무 트리아지에서 가장
  자주 쓰는 축이 비어 있다.

---

## 트랙 B — 핵심 파서 확충

우선순위: **Amcache → Shimcache → Prefetch → LNK**. 이 넷이 채워지면
"파일시스템+로그+설정(기존 6종)" + "실행+사용자 활동(신규 4종)" 조합으로
흔한 웹셸/침해 시나리오 대부분을 커버하는 코어 세트가 완성된다.

각 아티팩트는 `.claude/skills/add-parser/SKILL.md`의 10단계를 그대로
따른다(카탈로그 등재 → `ref` 접두어 → 파서 구현 → 등록소 → 출력 파일명
→ 플래그 → 매핑 → 테스트 → 외부 도구 대조 → 한계 기록). 아래는 이번
검토에서 나온, 각 아티팩트별로 다른 부분만 적는다.

### 1. Amcache — 저비용

- `Amcache.hve`는 새 하이브 파일이지만 regf 포맷이라 **`registry.py`를
  그대로 재사용**한다. 새 파서 클래스가 필요 없다.
- `evidence.py`의 `FILE_LAYOUT`에 `Amcache.hve` 경로
  (`Windows/AppCompat/Programs/Amcache.hve`) 추가.
- 값 해석(실행 파일 경로·SHA1·타임스탬프가 들어있는 서브키 구조)만
  확인하면 됨 — 온디스크 셀 구조는 이미 검증된 코드가 처리.

### 2. Shimcache — 저비용

- SYSTEM 하이브 안의 단일 값(`AppCompatCache`)이라 **하이브 접근은
  이미 있다.** 필요한 건 이 값의 바이너리 인코딩을 디코딩하는 함수뿐.
- Windows 버전별로 인코딩이 다르다는 점은 미리 `docs/limitations.md`
  범위로 명시해 둘 것(이 프로젝트가 "우리가 만든 테스트 이미지에서
  동작하면 통과"를 판정 기준으로 삼는다는 `work-guide.md` 3.3과 같은
  방식으로 범위를 좁혀도 된다).

### 3. Prefetch — 중간 비용, 새 파서 필요

- `.pf` 포맷은 버전별 압축 방식이 다르다(XP~Win8: 없음/LZXPRESS 등).
  새 `structs/prefetch_record.py` + `parsers/prefetch.py` 필요.
- `work-guide.md` 3.1의 판단 기준(직접 구현 vs 라이브러리)을 먼저
  적용해서 결정할 것 — 오프셋 보존이 필요한지, 기존 라이브러리가
  오프셋을 주는지부터 확인.
- 외부 도구 대조 후보: `PECmd`(Eric Zimmerman) 또는 공개 테스트 샘플.

### 4. LNK — 중간 비용, 새 파서 필요

- Shell Link Binary File Format(MS-SHLLINK) — 사양이 공개돼 있어
  직접 구현이 EVTX/레지스트리보다 오히려 수월할 수 있음.
- JumpList(자동/사용자정의)는 LNK 스트림이 OLE 복합파일 안에 또
  들어있는 이중 구조라 **범위 밖으로 미룬다.** LNK 단독 파일(바탕화면
  바로가기, `Recent` 폴더)부터.

### 유의사항 (트랙 B 공통)

- **`Amcache.hve`·`SAM`·`SECURITY`처럼 새 하이브 파일을 늘릴수록,
  나중에 볼륨당 파일 하나만 찾는 지금의 `FileSource._probe` 구조가
  한계에 부딪힌다** — 지금 넷(Amcache/Shimcache/Prefetch/LNK)은
  전부 "볼륨당 하나/폴더"라 문제없지만, 다음 확장 후보인
  Shellbags·UserAssist·MRU류는 **사용자 프로필마다 하나씩**이라
  `evidence.py`에 "여러 개 찾기" 기능이 필요하다. 이건 트랙 A 작업과
  묶어서 처리하는 게 효율적이다(아래 트랙 A 참고).
- 스키마(`schemas/` 6개)는 동결 대상이다. 새 필드가 필요하면 고치기
  전에 팀 공지부터.

---

## 트랙 B 다음 후보 (참고용, 지금 범위 아님)

AIFT의 Windows 60개 아티팩트를 기준으로 나눈 티어. 트랙 B의 위 4종을
마치고 확장할 때 참고.

| 티어 | 예 | 비고 |
|---|---|---|
| 저비용 (레지스트리 재사용) | Services, USB 기록, Network History, 방화벽 규칙, 감사 정책 | 카탈로그·매핑 등록만 |
| 사용자별 하이브 (플러밍 필요) | Shellbags, UserAssist, 각종 MRU, MUIcache | `evidence.py` 다중 매칭 확장 필요 |
| 고비용 (신규 포맷) | SRUM/AD(ESE), JumpList(OLE), Thumbcache, StartupInfo(ETL) | third_party 라이브러리 신규 도입 필요 |
| **예외** | 브라우저 기록, Activities Cache | **SQLite** — `sqlite3`가 실제 파일 경로(+WAL)를 요구해서 "스트림만 있으면 된다"는 지금 패턴이 깨짐. 임시 파일 구체화가 필요할 수 있음 |

---

## 트랙 A — `VolumeSource` (raw 이미지 직접 읽기)

**2026-08-23 부분 완료.** 트랙 B 코어 세트를 다 마치기 전이지만, 실물
raw 이미지(`evidence/test_image.001`, 60GB, 단일 NTFS 볼륨)가 생겨
순서를 바꿔 먼저 구현·검증했다. 아래 5개 남은 작업 중 1·2·3은
끝났고, 카탈로그 7개 아티팩트 전부가 이 이미지로 관통했다
(575,992건, 전수 스키마 검증 통과) — 대조 기록은
`docs/artifact-notes.md` "2026-08-23 · 전 파서 관통" 절, 남은 한계는
`docs/limitations.md` "디스크 이미지를 직접 열 수 있다" 절 참고.
과정에서 실물 데이터에서만 드러나는 버그 둘(`registry.py`의
`RegFileTime`→`datetime` JSON 직렬화 실패, `mft.py`의 판독 불가
타임스탬프 `null` 스키마 위반)을 찾아 고쳤다 — 목업 데이터로는
재현되지 않던 것들이다.

트랙 B 코어 세트 완성 후 착수 예정이었던 것. 확인된 사실과 남은 작업:

- **확인됨**: `dissect.target.Target.open(evidence_path)`으로 이미지를
  열고, `target.filesystems[i].path("$MFT")`로 원시 NTFS 파일시스템
  객체에서 직접 찾아야 한다 — `target.fs.path("/$MFT")`(OS 레벨 병합
  뷰)로는 안 나온다.
- **확인됨**: 반환되는 `dissect.util.stream.RunlistStream`은
  `seekable() == True`, `mft.py`의 두 번 순회 패턴과 호환.
- **남은 작업**:
  1. `requirements.txt`에 `dissect` 계열 패키지 추가 (팀 공지 필요 —
     새 외부 의존성).
  2. `evidence.py`의 `VolumeSource`를 `NotImplementedError`에서 실제
     구현으로. `open(artifact)`가 `FILE_LAYOUT`의 `relative_paths`를
     받아 `target.filesystems[i].path(...)`로 찾아 스트림을 돌려주면
     됨 — 파서 쪽은 무수정.
  3. `evtx.py`/`registry.py`는 `stream.read()` 전체를 한 번에
     메모리로 올리는데(`evtx.py:269`, `registry.py:323`), Dissect
     스트림에서도 `.read()` 인자 없이 전체를 다 읽는지 실측 확인 필요
     (지금까지는 `$MFT`만 테스트함, evtx/registry 하이브도 같은
     이미지로 재현해 볼 것).
  4. 사용자별 하이브 다중 매칭 기능(트랙 B 유의사항 참고)을 이 작업과
     함께 설계하면 `EvidenceSource` 인터페이스를 두 번 안 고쳐도 된다.
  5. `pyewf` 대신 `dissect.evidence`로 E01도 같은 경로로 커버 가능
     (libewf 시스템 의존성 불필요) — 검증은 아직 안 함.

---

## 참고 문서

| 주제 | 문서 |
|---|---|
| 새 파서 추가 절차 | `.claude/skills/add-parser/SKILL.md` |
| 직접 구현 vs 라이브러리 판단 기준 | `work-guide.md` 3.1 |
| 증거 접근 계층 설계 원칙 | `src/stage04_parse/evidence.py` docstring |
| 알려진 한계 | `docs/limitations.md` |
| 매핑 작성 규칙 | `docs/mapping-guide.md` |
