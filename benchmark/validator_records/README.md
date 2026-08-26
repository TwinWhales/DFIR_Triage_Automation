# validator_records

`benchmark/validator_check.py` 전용 레코드. **C-001 웹셸 데이터셋과 섞지
않습니다** — 그쪽은 벤치마크 수치의 입력이라 표기 시험용 레코드를 넣으면
파싱 건수와 배분이 함께 흔들립니다.

여기 있는 것은 **표기 경계 사례**입니다. 실제 사건을 재현하지 않고,
비교기(`src/stage06_verify/comparators.py`)가 같은 사실의 다른 표기를
흡수하는지만 봅니다.

| ref | 무엇을 시험하나 | 출처 |
|---|---|---|
| `AMCACHE#15044` | 값 이름이 숫자 문자열(`"15"`)이라 경로 필드로 인식되지 않는다 | 2026-08-26 `K-ALERT` 실측 F4 |
| `SYSMON#77` | Sysmon `Image`·`ParentImage` — K-001 Stage 2·3 의 근거 필드 | 같은 실측에서 예견된 것 |
| `SYSMON#91` | Sysmon `TargetFilename` (EID 11) | 같음 |
| `PF#689046` | 프리패치 `path` 가 장치 이름이 아니라 드라이브 문자로 온다 | 2026-08-26 `win10_sysmon_testimage` 실측 |

`PF#689046` 의 `fields.loaded_files` 는 일부러 `\VOLUME{...}` 형태로
남겨 뒀습니다 — 04단계가 그렇게 냅니다(섀도 카피 경로를 살아 있는 볼륨의
것으로 둔갑시키지 않으려는 것, `docs/artifact-notes.md`). 바뀌는 것은
`path` 하나뿐이라는 사실을 이 레코드가 함께 들고 있습니다.

**새 표기 부류를 만나면 여기에 레코드를 더하고
`benchmark/validator_cases.json` 에 사례를 답니다.** 사례 없이 비교기만
고치면 감시가 100% 통과를 보고하면서 정상 문장을 계속 기각합니다 —
`docs/limitations.md` "검증기가 경로 표기 차이를 환각으로 센다" 참고.
