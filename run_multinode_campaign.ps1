# ==============================================================================
# Multi-Node Campaign One-Click Automation Script
# KIOSK -> POS -> MGMT 순차 분석 및 Stage 08 캠페인 상관 자동 실행
# ==============================================================================

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

# 증거 경로 설정
$EvidenceBase = "C:\Users\user\Desktop\케이쉴드주니어\DFIR_Triage_Automation\DFIR_Triage_Automation\evidence"
$KioskEvidence = Join-Path $EvidenceBase "KIOSK_snapshotA_20260908T032657\C"
$PosEvidence   = Join-Path $EvidenceBase "POS_snapshotB_20260908T103226\C"
$MgmtEvidence  = Join-Path $EvidenceBase "MGMT_snapshotB_20260908T103233\C"

# 증거 경로 유효성 검사
foreach ($path in @($KioskEvidence, $PosEvidence, $MgmtEvidence)) {
    if (-not (Test-Path $path)) {
        Write-Error "[오류] 증거 경로를 찾을 수 없습니다: $path"
        exit 1
    }
}

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host " [1/4] KIOSK 단말 분석 시작 (Stage 01 ~ 07)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
$KioskRaw = "2026년 9월 7일 밤 22시 30분경 키오스크 단말(100.68.248.78)의 물리 USB 포트에 비인가 장치가 삽입된 후 관리자 권한의 cmd 및 PowerShell이 실행되었습니다. 외부 공격자 서버로부터 스크립트 다운로드 및 4444 포트 아웃바운드 연결이 발생했으며, Windows Defender 실시간 감시가 무력화되고 작업 스케줄러에 지속성 스크립트가 등록되었습니다. 이후 nmap 도구를 이용해 POS 단말(100.70.51.80)의 SMB(445) 및 주요 서비스 포트를 검색한 정황이 있습니다. 단말의 초기 침투, 보안 무력화 및 내부 정찰 행위를 조사해 주세요."

& $PythonExe tools\live_check.py --force --case-id CAMP-KIOSK --evidence $KioskEvidence --raw $KioskRaw
if ($LASTEXITCODE -ne 0) { Write-Error "KIOSK 분석 중 오류 발생"; exit $LASTEXITCODE }

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host " [2/4] POS 단말 분석 시작 (Stage 01 ~ 07)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
$PosRaw = "2026년 9월 7일 밤 22시 35분경부터 23시 사이 POS 단말(100.70.51.80)의 SMB 서비스(445 포트)를 향해 외부로부터 비정상적인 트래픽 및 취약점 공격(CVE-2020-0796 SMBGhost 추정)이 유입되었습니다. 공격 직후 NT AUTHORITY\SYSTEM 권한의 셸 프로세스가 생성되어 외부 4444 포트로 연결되었으며, whoami, ipconfig, netstat 등 내부 정찰 명령이 실행되었습니다. 또한 POS 애플리케이션의 설정 디렉터리 내 mgmt-credentials.ini 등 평문 자격증명 파일에 대한 비인가 접근 흔적이 있습니다. SMB 취약점을 통한 시스템 장악 및 자격증명 유출 행위를 조사해 주세요."

& $PythonExe tools\live_check.py --force --case-id CAMP-POS --evidence $PosEvidence --raw $PosRaw
if ($LASTEXITCODE -ne 0) { Write-Error "POS 분석 중 오류 발생"; exit $LASTEXITCODE }

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host " [3/4] MGMT 관리서버 분석 시작 (Stage 01 ~ 07)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
$MgmtRaw = "2026년 9월 7일 밤 22시 40분경부터 9월 8일 오전 사이 관리서버(100.111.252.29)에 POS에서 유출된 관리자 계정(mgmt_admin)을 이용한 비인가 RDP(3389 포트) 원격 로그온이 발생했습니다. 침투 후 SSMS 및 설정 파일(settings.json)을 통해 MS SQL 데이터베이스(1433 포트)에 접근하여 settlements 테이블의 다지점 결제정보(카드사, 카드번호, 승인번호 등)를 대량 SELECT 조회 및 CSV로 덤프한 정황이 있습니다. 이후 rclone 도구를 반입하여 Google Drive 클라우드 저장소로 데이터를 직접 유출하고, WindowsTelemetry라는 이름의 작업 스케줄러로 자동 반복 유출을 등록한 혐의가 있습니다. RDP 침투부터 DB 탈취 및 외부 반출까지의 전 과정을 조사해 주세요."

& $PythonExe tools\live_check.py --force --case-id CAMP-MGMT --evidence $MgmtEvidence --raw $MgmtRaw
if ($LASTEXITCODE -ne 0) { Write-Error "MGMT 분석 중 오류 발생"; exit $LASTEXITCODE }

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host " [4/4] Stage 08 멀티노드 캠페인 상관분석 합성 시작" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# campaign.json 생성
$CampaignJson = @"
{
  "campaign_id": "CAMP-PAYMENT-EXFIL",
  "nodes": [
    { "node": "kiosk", "case_id": "CAMP-KIOSK", "role": "endpoint" },
    { "node": "pos",   "case_id": "CAMP-POS",   "role": "endpoint" },
    { "node": "mgmt",  "case_id": "CAMP-MGMT",  "role": "server" }
  ]
}
"@
$CampaignJsonPath = Join-Path $ScriptDir "campaign.json"
[System.IO.File]::WriteAllText($CampaignJsonPath, $CampaignJson, [System.Text.Encoding]::UTF8)

# Stage 08 상관 분석 실행
& $PythonExe -m src.stage08_campaign.campaign --in $CampaignJsonPath --cases cases --out cases/CAMP-PAYMENT-EXFIL
if ($LASTEXITCODE -ne 0) { Write-Error "캠페인 상관 분석 중 오류 발생"; exit $LASTEXITCODE }

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host " [완료] 모든 분석과 멀티노드 캠페인 합성이 완료되었습니다!" -ForegroundColor Green
Write-Host " 최종 보고서 위치:" -ForegroundColor Yellow
Write-Host " -> cases\CAMP-PAYMENT-EXFIL\08_report.md" -ForegroundColor Yellow
Write-Host "========================================================`n" -ForegroundColor Green
