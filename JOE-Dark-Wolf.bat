@echo off
title J.O.E. DevSecOps Arsenal - Dark Wolf Security
color 0B
cd /d "c:\Users\micha\JOE\joe-devsecops"

echo.
echo   =============================================
echo.
echo       ^|^|^|     ^|^|^|^|^|     ^|^|^|^|^|^|
echo        ^|^|    ^|^|   ^|^|    ^|^|
echo        ^|^|    ^|^|   ^|^|    ^|^|^|^|^|
echo   ^|^|   ^|^|    ^|^|   ^|^|    ^|^|
echo    ^|^|^|^|^|      ^|^|^|^|^|     ^|^|^|^|^|^|
echo.
echo       DevSecOps Arsenal
echo       Dark Wolf Security Suite
echo.
echo   =============================================
echo.
echo   [*] Initializing J.O.E. AI Security Platform...
echo.

:: Check if shortcut exists, if not create it
if not exist "%USERPROFILE%\Desktop\J.O.E. DevSecOps Arsenal.lnk" (
    echo   [*] Creating desktop shortcut with Dark Wolf icon...
    powershell -ExecutionPolicy Bypass -File "c:\Users\micha\JOE\joe-devsecops\scripts\create-shortcut.ps1"
)

echo   [*] Starting J.O.E. Command Center...
echo.
npm start
