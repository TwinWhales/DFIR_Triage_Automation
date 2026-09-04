# Wazuh 알럿을 그대로는 못 받는다 — 배선 설계

> `work.md` 3번의 상세입니다. **무엇을 할 차례인가**는 `work.md` 에 있고,
> 여기에는 다음 세션이 바로 집을 수 있게 적어 둔 배선이 있습니다.
> (2026-09-05 에 `work.md` 에서 옮겨 왔습니다.)

레포 전체에 `wazuh`·`sigma`·`winlogbeat`·`active-response` 참조가 0건이다.
`edr_alert` 경로는 있으나 **자체 형식**을 기대한다. 실측:

```
Wazuh 원본(rule.mitre.id / rule.level / agent.name)  →  AlertAdapterError
평탄화한 자체 형식(mitre / severity / host)          →  정상 변환
```

**할 일 셋.**

- `src/stage02_normalize/alert_adapter.py`에 Wazuh 모양을 평탄화하는 변환
  추가 (약 50줄). `rule.mitre.id`→`mitre`, `rule.level`→`severity`,
  `agent.name`→`host`, `data.win.eventdata.*`→`process.*`
- `tools/make_case.py`에 `--alert` 경로. 지금은 자연어 입력만 만든다
- Wazuh active-response에서 부를 래퍼

**라이브 호스트에서 바로 못 읽는다는 것도 함께 본다.** `open_source()`는
이미지 파일 또는 폴더만 받는다(`\\.\C:` 없음). 알럿이 나면 KAPE가 먼저
돌아 폴더를 만들어야 한다 — 계획서에 KAPE가 있으니 운영으로 메꿔지지만,
그 호출을 감싸는 자리가 지금 없다.

## 다음 세션이 바로 집을 수 있게 — 배선

**먼저 실물 샘플 하나를 `tests/data/` 에 붙이고 시작한다.** 필드 이름을
기억으로 적으면 조용히 틀린다 — Wazuh 는 `alerts.json` 한 줄과 API 응답의
모양이 다르고, `rule.mitre` 는 버전에 따라 `id`/`technique`/`tactic` 이
**전부 배열**이다. 샘플이 붙기 전에는 아래 표를 확정하지 않는다.

**손댈 자리는 하나다.** `convert()` 앞에 평탄화 함수를 세우고, `convert()`
자신은 지금 모양 그대로 둔다.

```
raw(Wazuh)  →  _flatten_wazuh(raw)  →  convert(raw, evidence)  →  시나리오
                     ^ 새로 만드는 것            ^ 안 건드린다
```

`convert()` 를 고쳐 두 모양을 다 받게 하면 **어느 형식이 어느 필드를
채웠는지가 함수 안에서 섞인다.** 지금 `convert()` 는 "기법이 없으면
`AlertAdapterError`" 처럼 실패를 정직하게 내는데, 입력 모양이 둘이 되면 그
메시지가 어느 쪽을 가리키는지 알 수 없게 된다.

**모양을 알아보는 기준**을 먼저 정한다 — `raw` 에 `rule` 이 있고 그것이
객체이면 Wazuh 로 본다. `source_type` 을 새로 만들지 않는다(`edr_alert`
그대로다). 스키마는 동결이고, 이것은 형식 판별이지 새 입력 종류가 아니다.

| Wazuh | 우리 | 주의 |
|---|---|---|
| `rule.mitre.id[]` | `mitre[]` | 배열이다. 하나만 오는 경우도 배열로 온다 |
| `rule.level` (0~15) | `severity` | **숫자→문자열 대응을 정해야 한다.** `SEVERITY_CONFIDENCE` 가 `critical`/`high`/... 를 기대한다 |
| `rule.description` | `rule_name` | |
| `agent.name` | `host` | `agent.ip` 는 `ips[]` 로 |
| `data.win.eventdata.image` | `process.path` | 소문자 키다. Windows 이벤트 경유일 때만 있다 |
| `timestamp` | `detected_at` | Wazuh 는 `+0900` 오프셋을 붙여 보낸다. `_detected_at()` 이 받는지 확인 |

**확인 방법** — 샘플을 넣어 02단계를 돌리고, 지금 자체 형식으로 만든
K-ALERT 시나리오와 `techniques`·`time_range`·`entities` 가 같은지 본다.
같은 사건을 두 입력 형식으로 넣으면 같은 시나리오가 나와야 한다. 다르면
평탄화가 무언가를 흘린 것이다.

**정할 것 하나** — `rule.level` 대응. 12 이상을 `critical` 로 볼지 13
이상으로 볼지에 따라 `overall_confidence` 가 0.9 와 0.95 사이에서 갈리고,
그 값은 보고서에 그대로 실린다. 근거 없이 정하지 말고 Wazuh 문서의 레벨
정의를 인용해 `alert_adapter.py` 주석에 남긴다.
