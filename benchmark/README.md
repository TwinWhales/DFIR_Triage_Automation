# benchmark — 수치가 어디서 나오는가

이 폴더는 **파이프라인을 대상으로 하는 측정**이다. 파이프라인의 일부가 아니다.
`src/`를 몰라도 CLI만 불러 잴 수 있어야 한다.

## 한 디렉터리는 한 질문에 답한다

| 디렉터리 | 답하는 질문 | 누가 만드나 |
|---|---|---|
| `datasets/<케이스>/` | **무엇을 대상으로 재나** — 입력과 정답 | 사람 |
| `fixtures/<케이스>/` | 코드가 만들 수 없는 것 — 손으로 쓴 입력, 모델 응답 대역 | 사람 |
| `golden/<케이스>/` | 코드가 만든 것을 굳힌 것 — 기대 출력 | 코드 |
| `validator/` | **검증기가 과엄격한가** | 사람 |
| `results/` | 실행이 남긴 수치 (git 제외) | 실행 |

## fixtures 와 golden 을 가르는 이유

예전에는 둘이 `datasets/<케이스>/mock/` 한 폴더에 있었고, 어느 것이 입력이고
어느 것이 기대 출력인지는 README의 표를 봐야 알 수 있었다. **표가 필요하다는
것 자체가 신호였다.**

실제로 위험한 조합이 있었다. `03_selection.json`은 `select.py`의 기대 출력이면서
동시에 04단계 테스트의 **입력**이다. 매핑을 고쳐 골든을 갱신하면 04가 무엇을
받는지도 같이 바뀌는데, 그것이 diff에 드러나지 않는다.

이제 경로가 답한다.

- **`fixtures/`는 재생성하지 않는다.** 고칠 일이 있으면 손으로 고치고 왜
  고쳤는지 남긴다. `--replay` 스텁이 돌려주는 응답도 여기 있다 — 모델이 낼 답을
  사람이 대신 적어 둔 것이므로 코드가 만들 수 있는 물건이 아니다.
- **`golden/`은 의도적으로 재생성한다.** diff가 곧 회귀다.

분류의 유일한 출처는 `tests/casepaths.py`의 `GOLDEN_FILES`다. 여기 없는 이름은
픽스처로 친다 — 새 파일이 조용히 골든이 되지 않게 하려는 것이다.

## 세 수치

발표에서 말할 값은 셋이고, 나오는 자리가 다르다.

| 수치 | 어디서 | 명령 |
|---|---|---|
| **재현율** — 정답 증거를 몇 % 선별했나 | `evaluate.py` | `python benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell` |
| **환각률** — 해석 문장 중 근거 검증에 기각된 비율 | `cases/<id>/06_verified.json`의 `stats` | 파이프라인 실행이 만든다 |
| **효율** — 단계별 소요 시간 | `cases/<id>/live_check.json` | `python tools/live_check.py …` |

세 값을 한 표로 모으려면:

```bash
python benchmark/collect.py                     # results/ 의 실행들을 표로
python benchmark/collect.py --json              # 원본 그대로
```

`tools/live_check.py`는 실행마다 `benchmark/results/<케이스>-<시각>.json`에도
같은 기록을 남긴다. 케이스 디렉터리는 지워지지만 측정치는 남아야 하기 때문이다.

## 검증기 오탐 확인

재현율과 환각률은 **검증기가 정직하다는 전제** 위에 있다. 검증기가 과엄격해지면
정상 문장이 기각되어 환각률이 부풀고, 그 수치는 모델이 아니라 우리 코드를
말하게 된다.

```bash
python benchmark/validator_check.py
```

`validator/cases.json`의 사례가 전부 기대대로 나와야 한다. 하나라도 기각되면
그 실행의 환각률은 오염된 것이다. 새 비교 규칙을 넣었으면 반드시 돌린다.

## 지금 이 폴더의 한계

**정답 데이터가 자기채점이다.** `datasets/C-001-webshell/ground_truth.json`의
`authored_by`가 그렇게 적혀 있다 — `docs/pipeline-io-spec.md`의 예시에서 역산한
것이라 실제 증거를 분석해 정한 정답이 아니다. 재현율 수치를 발표에 쓰려면
사람이 증거를 보고 만든 정답이 필요하다.

**데이터셋이 하나뿐이고, 그것이 목표가 아니다.** 키오스크(K-001)는
`mappings/`·`docs/limitations.md`·`validator/cases.json`에는 있는데 데이터셋으로는
없다. 새 시나리오를 붙이는 절차는 `.claude/skills/add-scenario/SKILL.md`에 있다.

## 새 케이스를 추가할 때

네 곳에 자리를 만든다. 앞의 둘만 있어도 `evaluate.py`는 돈다.

```
datasets/<케이스>/input.json          진입점
datasets/<케이스>/ground_truth.json   정답 (스키마: ground_truth_schema.json)
fixtures/<케이스>/                    모델 없이 뒷단을 돌릴 스텁 응답 (선택)
golden/<케이스>/                      기대 출력 (선택)
```

`fixtures/`를 만들 거라면 `tests/casepaths.py`가 케이스 이름을 상수로 들고 있으므로
거기도 함께 본다.
