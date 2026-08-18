# third_party — 남의 코드

**이 디렉터리 아래는 우리가 쓴 코드가 아닙니다.**

`src/` 와 섞지 않고 격리해 둡니다. 발표와 보고서에서 "어디까지가 우리
구현인가"를 분명히 하기 위해서입니다. 먼저 밝히는 편이 나중에 지적받는
것보다 낫습니다.

| 디렉터리 | 원본 | 라이선스 | 용도 |
|---|---|---|---|
| `analyzeMFT/` | [analyzeMFT](https://github.com/rowingdude/analyzeMFT) 3.1.1 | MIT | `$MFT` 메인 파서의 레코드 바이트 → 속성 해석 |

## 무엇을 맡기나

`$MFT` 메인 파서(`src/stage04_parse/parsers/reference_mft.py`)는
하이브리드입니다. **레코드 바이트를 속성으로 해석하는 일만** analyzeMFT에
맡기고, 파일 순회·오프셋 계산·fixup·타임스탬프 정수 변환·경로 재구성·
`scope` 필터는 우리 코드(`reference_mft.py` + `structs/mft_record.py`)가
합니다.

MIT 라이선스라 상용·비상용 모두 자유롭게 쓸 수 있고, 의무는 저작권·라이선스
고지 유지뿐입니다(아래 규칙 3).

## 규칙

1. **여기 있는 파일은 되도록 고치지 않는다.** 필요한 조정은
   `src/stage04_parse/parsers/reference_mft.py` 어댑터에서 한다.
2. 고쳐야 하면 해당 파일 상단에 **무엇을 왜 고쳤는지** 적는다.
3. 원본 `LICENSE`와 저작권 고지(`NOTICE.md`)를 지운다거나 옮기지 않는다.
   메인 파서가 이 코드에 의존하므로 디렉터리는 유지된다.
