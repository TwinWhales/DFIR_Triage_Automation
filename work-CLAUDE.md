# work-CLAUDE.md — 키오스크 실측에서 나온 다음 과제

**여기에는 `K-LIVE-KIOSK-0908` 관통(2026-09-08)에서 실제로 관측된 것만 적는다.**
추정으로 넓히지 않는다 — 재현 절차와 원본 위치를 같이 적어, 손대기 전에
그 자리를 다시 볼 수 있게 한다. 설계 근거는 `work-guide.md`, 지금도 참인
제약은 `docs/limitations.md` 가 권위다.

`work.md` 와 갈라 놓은 이유: `work.md` 는 프로젝트 전체의 순서를 매기는
자리이고, 여기는 **한 번의 실측이 낳은 후속**이다. 여기 항목이 커지거나
우선순위 다툼이 생기면 그때 `work.md` 로 올린다.

---

## 실측 요약 — 무엇을 돌렸고 무엇이 나왔나

```bash
.venv/Scripts/python.exe tools/live_check.py --case-id K-LIVE-KIOSK-0908 \
  --evidence "<...>/DFIR_Triage_Automation/evidence/KIOSK_snapshotA_20260908T032657/C" \
  --model qwen2.5:latest --timeout 600 \
  --raw "키오스크 단말(로컬 사용자 kiosk)의 KAPE 수집본이다. …" \
  --artifacts '$MFT' '$UsnJrnl' prefetch registry:Amcache \
              evtx:Sysmon evtx:Security evtx:RDPSession evtx:KernelPnP
```

11개 관문 전부 PASS, 415.2초(04 파싱 235.5 · 05 해석 133.9 · 02 정규화 19.6),
**401,852건** 파싱, 환각률 6.2%(기각 1 / 판정대상 16).

**PASS 는 구조 불변식만 본 것이다.** 아래 넷은 전부 그 PASS 안에서 나왔다.

### 닫힌 것 — 미검증이던 두 채널이 실물을 통과했다

| 아티팩트 | 레코드 | 붙은 flag |
|---|---|---|
| `evtx:KernelPnP` | 397 | `device_connected` 395 |
| `evtx:RDPSession` | 99 | `remote_session` 35 |

파일 경로 매핑과 `event_id` 추정값이 실물에서 맞았다. `work.md` 0번의 다섯
채널 중 둘이다. **나머지 셋(`AssignedAccess` 3종·`DriverFrameworks`·
`RDPConnection`)은 이 스냅샷에도 없다** — 0번은 여전히 Assigned Access 를 켠
스냅샷을 기다린다.

---

## 1. 분석 기간 상한을 증거에서 잡는다 (제일 크다)

**증상.** 보고서에 오른 15건 중 **8건이 시간 범위 오설정의 부산물**이다.
전부 severity `high` 이고, 문장이 서로 거의 같다.

> "2026-09-02T04:43:12.1536390Z이 2026-08-31T23:59:59Z 이후의 시간으로,
> 파일 생성이 의심스럽습니다." (`USN#553648128` 외 7건)

**원인.** 02단계가 시간 단서를 못 찾자 분석 기간을
`2026-07-01 ~ 2026-08-31` 로 잡았다(`02_scenario.json` 의 `time_range.basis`:
"시간 단서 없음, 최근 2개월로 넓게 설정"). 그런데 **이 수집은 2026-09-08 에
이뤄졌다.** 상한이 수집일보다 8일 이르므로 가장 최근의, 가장 볼 만한 활동
전부에 `outside_time_range` 가 붙고, 05단계가 그 flag 를 "의심스럽다"로 읽는다.

**여기서 두 가지가 겹쳤다.** 하나는 02 의 추측이 짧았던 것이고, 하나는
`outside_time_range` 가 "범위 밖"이라는 사실 이상을 뜻하지 않는데 프롬프트가
flag 를 "이 레코드가 당신에게 온 이유"로 제시한다는 것이다. 뒤쪽은
`docs/limitations.md` 의 "Sysmon 종료 이벤트 전량에 flag 가 붙습니다" 와 같은
부류다 — 중립적 맥락 flag 와 의심 신호 flag 가 프롬프트에서 구분되지 않는다.

**할 일.**
1. 증거에서 수집 시각을 읽어 `time_range.end` 의 **상한**으로 쓴다. 후보는
   KAPE `*_CopyLog.csv` 의 파일명 타임스탬프와 `$MFT` 최신 레코드다. 어느
   쪽을 권위로 삼을지부터 정한다 — CopyLog 는 수집 도구의 것이고 `$MFT` 는
   볼륨의 것이라 뜻이 다르다.
2. 02 가 추측한 범위가 그 상한보다 이르면 넓히고, 넓혔다는 사실을
   `time_range.basis` 에 남긴다. **조용히 고치지 않는다.**
3. `outside_time_range` 를 중립 맥락 flag 로 분류하고, 05 프롬프트가 의심
   신호와 섞어 제시하지 않게 한다. 어휘 자체는 `mappings/_flags.yaml` 이 원본.

**확인.** 같은 증거로 다시 돌려 `outside_time_range` 만 근거로 삼은 소견이
0건인가. 지금은 8건이다.

---

## 2. 자격증명 어휘가 저장소 주인을 안 본다

**증상.** `PF#936533914` 이 `must_review` 보장 레인을 먹고, **Reduce 를 세 번
막아 `incident_story` 를 통째로 없앴다**(`errors.jsonl` 의 `malformed_output`
3건). 최종 산출물에 `incident_story` 와 `story_review` 가 비어 있다.

**원인.** 그 레코드는 `MSEDGE.EXE` 의 prefetch 다. `loaded_files` 585개 중
`credential_stores` 어휘에 걸린 것이 6개인데 **전부 Edge 자신의 프로필
경로**다.

```
C:\USERS\KIOSK\APPDATA\LOCAL\MICROSOFT\EDGE\USER DATA\DEFAULT\LOGIN DATA
C:\USERS\KIOSK\APPDATA\LOCAL\MICROSOFT\EDGE\USER DATA KIOSK\DEFAULT\LOGIN DATA FOR ACCOUNT
```

브라우저가 자기 자격증명 저장소를 참조한 것이라 정상이다. 지금 어휘는
**경로만 보고 주체를 안 본다** — `mappings/_attention_signals.yaml` 의
`credential_stores` 는 `contains` 목록뿐이다.

**할 일.** 저장소의 주인이 참조한 것을 제외하는 조건을 **선언형으로** 넣는다.
파이썬에 `msedge.exe` 를 적지 않는다 — 그렇게 하면 `z7hriire.exe` 를 지운
자리에 같은 것을 다시 만드는 것이다(`work.md` 16번). 형태 후보:

```yaml
credential_stores:
  signal: sensitive_credential_store_referenced
  # 이 실행 파일이 참조한 것은 자기 저장소이므로 시그널을 만들지 않는다.
  owned_by:
    '\microsoft\edge\user data\': ['msedge.exe']
    '\google\chrome\user data\':  ['chrome.exe']
```

**주의.** 이것은 "정상이니 무시"가 아니라 **"주체가 소유자면 이 관측은 뜻이
없다"**는 판정이다. 어느 쪽인지 헷갈리면 `docs/mapping-guide.md` 의 "어휘는
판정이 아니다" 절을 먼저 읽는다. 정말로 Edge 가 아닌 것이 그 경로를 읽었다면
그때는 시그널이 살아야 한다.

**확인.** 같은 증거로 다시 돌려 (a) 이 prefetch 가 보장 레인을 안 먹는가,
(b) `incident_story` 가 만들어지는가. 지금은 둘 다 아니다.

---

## 3. `testuser` 반복 생성·삭제 — 이 증거에서 제일 볼 만한 것이 보고서에 없다

**관측.** 원본을 직접 파서 나온 것이다. 계정 이벤트 24건 중:

```
08-26 07:04:23  4728 그룹 추가 → 4720 testuser 생성 → 4732 Users 추가
08-26 07:08:00  4726 testuser 삭제
08-26 07:15:46  4720 testuser 재생성 → 4732 Users 추가
08-26 07:16:28  4726 testuser 재삭제
```

키오스크 단말에서 12분 사이에 생성→그룹추가→삭제가 두 번 반복됐다.

**왜 보고서에 없나.** 05 가 이것으로 소견 하나(`F7`)를 만들었는데 06 이
`technique_unsupported` 로 기각했다 — 모델이 `T1204.002` 를 붙였고 그 기법의
매핑에 `evtx:Security` 가 없다. **규칙대로는 옳은 기각이다.** 결과적으로 정상
셸 갱신(`rundll32 … ShellRefresh`) 중복 5건과 위 1번의 시간범위 부산물 8건은
남고, 계정 생성·삭제 반복은 사라졌다.

**할 일.**
1. **먼저 사람이 가른다.** `evtx:Security` × 계정 생성이 어느 기법에 붙어야
   하는지는 매핑을 넓히는 판단이라 `benchmark/rejections.yaml` 이 그 자리다.
   후보는 `T1136.001`(Create Account: Local Account) 이지만 **확정하지 않았다**
   — 06 의 `also_supports` 에 이미 `T1136.001` 이 있으므로, 문제는 매핑이
   아니라 02·05 가 그 기법을 안 골랐다는 쪽일 수 있다. 어느 쪽인지부터 가른다.
2. 가른 뒤에야 매핑·프롬프트 중 어디를 고칠지 정한다.

**절차는 `.claude/skills/add-scenario/SKILL.md` 를 따른다.** 관문이 넷이고
flags 관문만 조용히 실패한다.

**파이프라인 밖 조사도 남았다.** 4720/4726 을 낸 주체 계정, 같은 시각의
4624 로그온, `$MFT`·`$UsnJrnl` 에 남은 프로필 폴더 생성·삭제를 맞춰 보면
사람이 만든 것인지 스크립트인지 갈린다. 이건 도구 개선이 아니라 조사다.

---

## 4. 배분이 430건의 키오스크 신호를 한 건도 안 골랐다

**증상.** `device_connected` 395건과 `remote_session` 35건이 파싱됐는데
**소견을 하나도 만들지 못했다.** 키오스크에서 원격 세션 35건은 트리아지가
가장 먼저 볼 것인데, 05 가 고른 것은 `rundll32 … ShellRefresh` 중복 5건과
시간범위 부산물 8건이다.

**아직 원인을 안 갈랐다.** 최소한 셋이 겹쳐 있다.

- 1번(시간 범위)이 `high` 를 무더기로 만들어 순위를 밀었을 수 있다.
- `--limit` 기본 60 에 401,852건이 들어왔다. 아티팩트별 자리 배분
  (`allocation.allocate_seats`)이 건수가 적은 채널을 어떻게 다루는지 봐야 한다.
- `device_connected` 395건이 서로 거의 같아 대표 하나로 줄일 여지가 있다.

**할 일.** 1번을 먼저 고치고 **같은 증거로 다시 돌린다.** 그래도 안 올라오면
그때 배분을 본다 — 순서를 바꾸면 무엇이 고쳐 준 것인지 못 가린다.

**확인 도구.** `cases/K-LIVE-KIOSK-0908/05_llm_queries/` 에 질의 6건이 그대로
있다. 프롬프트에 이 레코드들이 실렸는지부터 본다 — 실렸는데 모델이 안 골랐나,
아예 안 실렸나가 갈리는 자리이고 고칠 곳이 다르다.

---

## 손대지 않기로 한 것

- **`recentfilecache` 의 `empty_result`.** 이 증거는 빌드 19045 이고
  `RecentFileCache.bcf` 는 Windows 7 전용이다. 03 이 고른 것이 맞고 04 가
  건너뛴 것도 맞다 — 사유가 `errors.jsonl` 에 남았다. 고칠 것이 없다.
- **02 가 `T1562.004`(방화벽 무력화)를 "외부 저장장치나 원격 세션이 쓰였는지"
  에 붙인 것.** 명백한 오배정이고 인용이 원문 그대로라 커버리지 검사가
  침묵했다 — `docs/limitations.md` 의 "02단계가 축을 놓치면" 이 그대로
  재현된 사례다. **이것은 할 일이 아니라 닫힌 판단이다**(`work.md` 10번).
  여기 적어 두는 것은 키오스크 실물에서 나온 첫 사례라서다.
