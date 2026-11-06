@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m opentiger menu
) else (
    python -m opentiger menu
)
pause
