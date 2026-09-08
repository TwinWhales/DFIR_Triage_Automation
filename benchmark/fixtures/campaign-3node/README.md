# campaign-3node — 노드 셋짜리 합성 캠페인 픽스처

**실물이 아닙니다.** POS·관리서버 증거가 없어 08단계 배선을 세우고 지키는
용도이며, 값은 키오스크 실측(`K-LIVE-KIOSK-MYTEST`)의 모양을 따라 손으로
지었습니다. **재현율·정확도 수치에 쓰지 마십시오.**

이 픽스처가 담고 있는 것 — 각각 08단계가 지켜야 하는 성질입니다.

| 자리 | 노드 | 무엇을 재는가 |
|---|---|---|
| 같은 페이로드 해시 | kiosk ↔ pos | 노드를 잇는다 (pos 쪽이 Warning 이라 링크도 Warning) |
| 같은 C2 주소 | kiosk ↔ pos | 명령행에 박힌 IP 와 `DestinationIp` 를 함께 본다 |
| 같은 계정 `kioskadmin` | pos ↔ server | 계정 축 |
| 같은 파일명 `s.ps1` | kiosk ↔ pos | 드라이브가 달라도 basename 으로 이어진다 |
| 같은 해시 반복 (kiosk 3건) | kiosk | 한 노드의 반복이 링크를 부풀리지 않는다 |
| `MFT#88120` | pos | 인용되지 않았고 25초 더 이르다 → **대표를 뺏지 못한다**(인용된 `SYSMON#3318` 이 대표) |
| `SYSMON#915` | server | **기각된 소견만 인용** → 링크가 서면 안 된다 |
| `CAMP3-backup` | — | 케이스가 없음 → `missing` 으로 사유와 함께 실린다 |

```bash
.venv/Scripts/python.exe -m src.stage08_campaign.campaign \
  --in benchmark/fixtures/campaign-3node/campaign.json \
  --cases benchmark/fixtures/campaign-3node/cases \
  --out <쓸 곳>
```
