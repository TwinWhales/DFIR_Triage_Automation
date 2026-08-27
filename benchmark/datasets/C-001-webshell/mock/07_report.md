# 침해사고 분석 보고서 — C-001

## 개요

- 대상 호스트: WEB01
- 대상 OS: windows
- 분석 기간: 2026-07-18 ~ 2026-07-22
- 식별 기법: T1505.003 (Server Software Component: Web Shell), T1136.001 (Create Account: Local Account)
- 검증 결과: 통과 2 / 기각 0 / 미검증 1

## 확인된 사항

### F1 — T1505.003 Server Software Component: Web Shell [높음]

웹루트 하위 upload 디렉터리에 shell.aspx가 2026-07-20 03:14:22에 생성되었으며, $SI와 $FN 타임스탬프가 일치하지 않아 타임스탬프 조작 정황이 확인됩니다.

> 근거: $MFT 레코드 12345 (오프셋 0x1E000)

### F2 — T1136.001 Create Account: Local Account [높음]

웹셸 생성 약 8분 후 IIS 애플리케이션 풀 계정에 의해 svc_backup 계정이 생성되고 Administrators 그룹에 추가되었습니다.

> 근거: evtx:Security 레코드 40912 (오프셋 0x2A1000)
> 근거: evtx:Security 레코드 40915 (오프셋 0x2A1D40)

## 타임라인

| 시각 | 사건 | 근거 |
|---|---|---|
| 2026-07-20T03:14:22Z | shell.aspx 생성 | MFT#12345 |
| 2026-07-20T03:22:15Z | svc_backup 계정 생성 | EVTX-SEC#40912 |
| 2026-07-20T03:22:19Z | svc_backup을 Administrators에 추가 | EVTX-SEC#40915 |

## 미검증 항목

다음 서술은 특정 증거로 뒷받침되지 않는 종합 판단이며 분석가 검토가 필요합니다.
- 전반적으로 웹셸을 통한 초기 침투 이후 계정 생성으로 지속성을 확보한 전형적인 공격 흐름으로 판단됩니다.

## 분석 범위

### 확인한 아티팩트

| 아티팩트 | 레코드 | 비고 |
|---|---|---|
| $MFT | 3건 |  |
| evtx:Security | 2건 | 부분 판독 — 구간 1곳 |

레코드 0건은 **해당 범위에서 흔적이 확인되지 않았다**는 뜻이며, 아티팩트를
읽지 못한 것과 다릅니다.

### 확인하지 못한 아티팩트

| 아티팩트 | 사유 |
|---|---|
| evtx:Firewall | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:BITS | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:NetworkProfile | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:Sysmon | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:DriverFrameworks | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:KernelPnP | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:AssignedAccess | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:AssignedAccessAdmin | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:AssignedAccessBroker | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:RDPConnection | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:RDPSession | 식별된 기법에 매핑된 아티팩트가 아님 |
| evtx:Application | 식별된 기법에 매핑된 아티팩트가 아님 |
| registry:SYSTEM | 식별된 기법에 매핑된 아티팩트가 아님 |
| registry:SOFTWARE | 식별된 기법에 매핑된 아티팩트가 아님 |
| registry:Amcache | 식별된 기법에 매핑된 아티팩트가 아님 |
| recentfilecache | 식별된 기법에 매핑된 아티팩트가 아님 |
| prefetch | 식별된 기법에 매핑된 아티팩트가 아님 |
| srum:NetworkUsage | 식별된 기법에 매핑된 아티팩트가 아님 |
| srum:AppResourceUsage | 식별된 기법에 매핑된 아티팩트가 아님 |
| srum:NetworkConnectivity | 식별된 기법에 매핑된 아티팩트가 아님 |
| $LogFile | 본 버전 미지원 (파싱 모듈 범위 외) |
| $UsnJrnl | Tier 2 루프백 미구현으로 미평가 (조건: Tier1 $MFT에서 timestamp_mismatch 또는 deleted 플래그 발견 시) |
| evtx:System | Tier 2 루프백 미구현으로 미평가 (조건: Tier1에서 서비스 관련 정황 발견 시) |

---

본 보고서는 자동 생성되었으며 수사상 참고 자료입니다. 포렌식 감정 결과나
전문가 의견이 아니며, 해석의 타당성은 분석가 검토가 필요합니다.

생성: 2026-08-27T02:44:53Z / report.py
