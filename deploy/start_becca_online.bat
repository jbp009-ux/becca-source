@echo off
echo ============================================
echo BECCA ONLINE - Starting for iam.beccaos.com
echo ============================================
echo.

cd /d D:\projects\becca-kernel

echo [1/3] Starting BECCA server...
start "BECCA Server" cmd /k "python becca_online.py"

timeout /t 3 /nobreak > nul

echo [2/3] Starting Cloudflare Tunnel...
start "Cloudflare Tunnel" cmd /k "cloudflared tunnel run becca-online"

timeout /t 2 /nobreak > nul

echo [3/3] Starting Local Bridge (PC file access)...
start "BECCA Bridge" cmd /k "cd /d D:\projects\becca-kernel\bridge && python becca_bridge.py --server https://iam.beccaos.com --interval 30"

echo.
echo ============================================
echo BECCA Online is starting!
echo.
echo Local:  http://localhost:5001
echo Public: https://iam.beccaos.com
echo.
echo Bridge: Connected - BECCA can see your PC files
echo.
echo Press any key to exit this window...
echo (BECCA, tunnel, and bridge will keep running)
echo ============================================
pause > nul
