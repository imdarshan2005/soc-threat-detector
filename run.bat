@echo off
title SOC Sentinel - SIEM & Threat Detection Platform
color 0B
echo =====================================================================
echo           SOC SENTINEL ^| SIEM ^& THREAT DETECTION PLATFORM
echo =====================================================================
echo.

REM Check if Python is available via py launcher or python
where py >nul 2>nul
if %errorlevel% equ 0 (
    set PY_CMD=py
) else (
    where python >nul 2>nul
    if %errorlevel% equ 0 (
        set PY_CMD=python
    ) else (
        echo [ERROR] Python was not found in PATH!
        echo Please install Python 3.10+ and re-run.
        pause
        exit /b 1
    )
)

REM Check if virtual environment exists
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment (.venv)...
    %PY_CMD% -m venv .venv
    echo [*] Installing dependencies from requirements.txt...
    .venv\Scripts\python.exe -m pip install --upgrade pip
    .venv\Scripts\python.exe -m pip install -r requirements.txt
    echo [*] Seeding sample data and baseline telemetry...
    .venv\Scripts\python.exe seed_data.py
)

echo.
echo [*] Starting SOC Sentinel Command Center on http://localhost:8501...
echo.
.venv\Scripts\streamlit.exe run app.py

pause
