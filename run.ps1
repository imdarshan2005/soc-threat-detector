# SOC Sentinel PowerShell Launcher
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "          SOC SENTINEL | SIEM & THREAT DETECTION PLATFORM            " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

$pythonCmd = "python"
if (Get-Command "py" -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
} elseif (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python was not found in PATH." -ForegroundColor Red
    Exit 1
}

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "[*] Provisioning virtual environment (.venv)..." -ForegroundColor Yellow
    & $pythonCmd -m venv .venv
    Write-Host "[*] Installing dependencies..." -ForegroundColor Yellow
    & .venv\Scripts\python.exe -m pip install -r requirements.txt
    Write-Host "[*] Seeding threat intelligence and sample logs..." -ForegroundColor Yellow
    & .venv\Scripts\python.exe seed_data.py
}

Write-Host "[*] Launching SOC Sentinel Command Center..." -ForegroundColor Green
& .venv\Scripts\streamlit.exe run app.py
