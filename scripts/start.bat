@echo off
REM J.O.E. Windows Launcher - Clears ELECTRON_RUN_AS_NODE for VS Code compatibility
set ELECTRON_RUN_AS_NODE=
set ELECTRON_NO_ATTACH_CONSOLE=
echo [J.O.E.] Starting with clean environment...
cd /d "%~dp0.."
call npx electron-forge start %*
