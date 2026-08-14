# analyzeMFT (vendored)

- **원본**: https://github.com/rowingdude/analyzeMFT
- **버전**: 3.1.1 (PyPI `analyzeMFT==3.1.1`)
- **라이선스**: MIT — Copyright 2024 Benjamin Cance (`LICENSE` 참조)
- **가져온 날짜**: 2026-08-14

## 무엇을 가져왔나

레코드 파싱에 필요한 최소 집합만 복사했습니다.

```
constants.py      오프셋·속성 타입 상수
windows_time.py   FILETIME 변환
validators.py     속성 길이 검증
mft_record.py     MftRecord — 레코드 바이트 하나를 파싱
```

가져오지 않은 것: CLI, SQLite 출력, 해시 계산, 파일 라이터, 테스트.
우리는 `MftRecord` 클래스 하나만 씁니다.

## 수정 사항

**없습니다.** 원본 그대로입니다.

필요한 조정은 전부 `src/stage04_parse/parsers/reference_mft.py` 어댑터에서
합니다. 그래야 "우리가 고친 것"과 "원본"이 섞이지 않습니다.

## 알고 쓰는 한계

### fixup(업데이트 시퀀스)을 적용하지 않습니다

`MftRecord`는 헤더의 `upd_off` / `upd_cnt`를 읽기만 하고 **업데이트
시퀀스를 되돌리지 않습니다.** 그대로 쓰면 섹터 경계(1024바이트 레코드
기준 오프셋 510, 1022)의 2바이트가 깨진 채로 파싱됩니다.

→ **어댑터가 넘기기 전에 `structs/mft_record.apply_fixups()`를 적용합니다.**
   원본을 고치지 않고 해결했습니다.

이 한계는 우리 자체 파서가 처음부터 다르게 처리하는 지점이기도 합니다.
대조 결과에서 섹터 경계 근처 값이 어긋나면 이것이 원인일 수 있습니다
(`docs/artifact-notes.md` 참조).

### 파일 크기가 `$FN`에서 나옵니다

`MftRecord.filesize`는 `$FILE_NAME`의 real_size입니다. 그 값은 **이름이
만들어진 시점의 크기**라 나중에 쓰인 파일은 대부분 0입니다. 실제 이미지
57개 문서 중 56개가 0이었습니다.

→ 어댑터가 `$DATA` 속성을 직접 읽습니다. 고친 뒤 57/57이 추출 파일의
   실제 크기와 일치했습니다.

### 정상 레코드에 경고 로그를 냅니다

`validators.py`가 1024바이트 레코드의 584바이트 `$INDEX_ROOT`를 보고
`Large attribute detected` 경고를 냅니다. 실제 문제가 아니며 파싱 진행
상황을 가립니다.

→ 어댑터가 `third_party.analyzeMFT` 로거 수준을 올려 잠급니다.

### 경로 재구성은 쓰지 않습니다

`mft_analyzer.py`의 `build_filepath`는 가져오지 않았습니다. 우리는
레코드 단위 파싱만 빌리고, 부모 참조를 따라 전체 경로를 만드는 것은
어댑터가 합니다. 선별 범위(`scope`)를 경로로 거르려면 우리 규칙이
필요하기 때문입니다.
