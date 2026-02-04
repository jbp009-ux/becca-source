@echo off
echo ============================================================
echo BECCA WEB CHAT LAUNCHER
echo ============================================================
echo.

if "%ANTHROPIC_API_KEY%"=="" (
    echo ERROR: API key not set!
    echo.
    echo Run this in PowerShell first:
    echo   $env:ANTHROPIC_API_KEY = "sk-ant-YOUR-KEY-HERE"
    echo.
    echo Then run this batch file again.
    pause
    exit /b 1
)

echo API Key detected: %ANTHROPIC_API_KEY:~0,20%...
echo.
echo Starting BECCA chat server...
echo Open: http://localhost:5000
echo.
cd /d d:\projects\becca-kernel
python becca_chat.py
pause
