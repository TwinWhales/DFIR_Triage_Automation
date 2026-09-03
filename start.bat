@echo off
chcp 65001 >nul
title 8vidence Launcher

cd /d "%~dp0"

echo.
echo ============================================================
echo   8vidence - Evidence-driven DFIR Triage
echo ============================================================
echo.

REM ============================================================
REM 1. Python virtual environment 확인
REM ============================================================

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Python 가상환경을 찾을 수 없습니다.
    echo.
    echo 예상 경로:
    echo %CD%\.venv\Scripts\python.exe
    echo.
    pause
    exit /b 1
)

echo [OK] Python virtual environment


REM ============================================================
REM 2. Ollama 설치 확인
REM ============================================================

where ollama >nul 2>&1

if errorlevel 1 (
    echo [ERROR] Ollama를 찾을 수 없습니다.
    echo Ollama가 설치되어 있고 PATH에 등록되어 있는지 확인해주세요.
    echo.
    pause
    exit /b 1
)

echo [OK] Ollama


REM ============================================================
REM 3. Ollama 서버 확인
REM ============================================================

curl -s http://127.0.0.1:11434/api/tags >nul 2>&1

if errorlevel 1 (
    echo [INFO] Ollama 서버를 시작합니다...

    start "" /min ollama serve

    timeout /t 3 /nobreak >nul
)

curl -s http://127.0.0.1:11434/api/tags >nul 2>&1

if errorlevel 1 (
    echo [ERROR] Ollama 서버에 연결할 수 없습니다.
    echo.
    pause
    exit /b 1
)

echo [OK] Ollama server


REM ============================================================
REM 4. qwen2.5:7b 모델 확인
REM ============================================================

ollama list | findstr /I "qwen2.5:7b" >nul 2>&1

if errorlevel 1 (
    echo [ERROR] qwen2.5:7b 모델을 찾을 수 없습니다.
    echo.
    echo 다음 명령으로 모델을 설치해주세요:
    echo ollama pull qwen2.5:7b
    echo.
    pause
    exit /b 1
)

echo [OK] qwen2.5:7b


REM ============================================================
REM 5. 기존 8vidence 서버 확인
REM ============================================================

curl -s http://127.0.0.1:8000/api/health >nul 2>&1

if not errorlevel 1 (
    echo [OK] 8vidence server already running
    echo [INFO] Browser를 엽니다...
    echo.

    start "" "http://127.0.0.1:8000"

    exit /b 0
)


REM ============================================================
REM 6. FastAPI / Uvicorn 서버 시작
REM ============================================================

echo [INFO] 8vidence server starting...

start "8vidence Server" /min cmd /c ".venv\Scripts\python.exe -m uvicorn ui.app:app --host 127.0.0.1 --port 8000"


REM ============================================================
REM 7. 서버 준비 대기
REM ============================================================

echo [INFO] Waiting for server...

set /a RETRY=0


:WAIT_SERVER

timeout /t 1 /nobreak >nul

curl -s http://127.0.0.1:8000/api/health >nul 2>&1

if not errorlevel 1 goto SERVER_READY

set /a RETRY+=1

if %RETRY% GEQ 15 goto SERVER_FAILED

goto WAIT_SERVER


REM ============================================================
REM 8. 서버 준비 완료
REM ============================================================

:SERVER_READY

echo [OK] 8vidence server
echo.
echo [INFO] Opening 8vidence...
echo.

start "" "http://127.0.0.1:8000"

exit /b 0


REM ============================================================
REM 9. 서버 시작 실패
REM ============================================================

:SERVER_FAILED

echo.
echo [ERROR] 8vidence 서버가 15초 이내에 시작되지 않았습니다.
echo.
echo 다음 명령을 직접 실행하여 오류를 확인할 수 있습니다:
echo.
echo .venv\Scripts\python.exe -m uvicorn ui.app:app --host 127.0.0.1 --port 8000
echo.

pause

exit /b 1