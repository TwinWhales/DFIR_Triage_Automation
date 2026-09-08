# Wazuh 알럿 입력 — 배선 설계

> `work.md` 3번의 상세입니다. **무엇을 할 차례인가**는 `work.md` 에 있고,
> 여기에는 다음 세션이 바로 집을 수 있게 적어 둔 배선이 있습니다.
> (2026-09-05 에 `work.md` 에서 옮겨 왔습니다.)

`edr_alert` 경로는 자체 형식을 기대하므로 Wazuh 원문을 바로 넣을 수 없었다.
현재는 02단계 경계에서 평탄화한다. 실측:

```
Wazuh 원본(rule.mitre.id / rule.level / agent.name)  →  AlertAdapterError
평탄화한 자체 형식(mitre / severity / host)          →  정상 변환
```

**구현된 배선.**

- `src/stage02_normalize/alert_adapter.py`의 `flatten_wazuh()`가
  `rule.mitre.id`→`mitre`, `rule.level`→`severity`, `agent.name`→`host`,
  `data.win.eventdata.*`→`process.*`로 변환한다.
- `tools/make_case.py --alert alerts/YYYY-MM-DD/<파일>`이 원문을 `01_input.json`의 `raw`에
  보존하면서 `source_type=edr_alert`로 감싼다.
- Wazuh 알럿 파일은 `alerts/` 아래 날짜별 폴더(`alerts/YYYY-MM-DD/`)에 적재된다.
- **원격 호스트 증거 수집 (규섭님 담당)**: `open_source()`는 원격 라이브 호스트를
  직접 읽지 못하므로, Tailscale VPN을 통해 대상 단말에 KAPE를 트리거하여
  `evidence/<노드명>_<타임스탬프>/C/...` 형태로 수집·적재한다. 수집 완료 즉시
  파이프라인이 자동 연계된다.

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

Wazuh `rule.level`은 0~3 informational, 4~6 low, 7~9 medium, 10~12 high,
13~15 critical로 변환한다. `0`은 알럿 파일에 남아 있어도 ATT&CK 기법이 없으면
기존 어댑터 정책에 따라 중단한다.

**확인 방법** — 샘플을 넣어 02단계를 돌리고, 지금 자체 형식으로 만든
K-ALERT 시나리오와 `techniques`·`time_range`·`entities` 가 같은지 본다.
같은 사건을 두 입력 형식으로 넣으면 같은 시나리오가 나와야 한다. 다르면
평탄화가 무언가를 흘린 것이다.

**정할 것 하나** — `rule.level` 대응. 12 이상을 `critical` 로 볼지 13
이상으로 볼지에 따라 `overall_confidence` 가 0.9 와 0.95 사이에서 갈리고,
그 값은 보고서에 그대로 실린다. 근거 없이 정하지 말고 Wazuh 문서의 레벨
정의를 인용해 `alert_adapter.py` 주석에 남긴다.
