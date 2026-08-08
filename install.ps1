#Requires -Version 5.1
<#
    One-script setup + run for PlaguardsV2.
    Prefers Docker (docker compose) if the daemon is actually reachable;
    falls back to a local Python virtual environment + waitress
    (pure-Python, Windows-friendly WSGI server) otherwise - including if
    Docker is installed but not running. Either way, ends with the
    dashboard open in your browser at http://localhost:8000.
#>

Set-Location -Path $PSScriptRoot

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Start-LocalFallback {
    Write-Host "Setting up a local Python environment..." -ForegroundColor Cyan
    if (-not (Test-CommandExists "python")) {
        Write-Error "Python was not found on PATH. Install Python 3.11+ or start Docker Desktop, then re-run this script."
        exit 1
    }

    if (-not (Test-Path ".venv")) {
        python -m venv .venv
    }

    $venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    & $venvPython -m pip install --quiet --upgrade pip
    & $venvPython -m pip install --quiet -r requirements.txt

    if (-not (Test-Path "data")) {
        New-Item -ItemType Directory -Path "data" | Out-Null
    }

    Write-Host "Starting PlaguardsV2 with waitress on http://localhost:8000 ..." -ForegroundColor Cyan
    $outLog = Join-Path $PSScriptRoot "data\waitress.log"
    $errLog = Join-Path $PSScriptRoot "data\waitress.err.log"
    Start-Process -FilePath $venvPython -ArgumentList "-m", "waitress", "--listen=0.0.0.0:8000", "wsgi:app" `
        -WorkingDirectory $PSScriptRoot -WindowStyle Minimized `
        -RedirectStandardOutput $outLog -RedirectStandardError $errLog
    Start-Sleep -Seconds 3
}

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example - edit it later to add threat-intel API keys (optional)." -ForegroundColor Yellow
}

$dockerReady = $false
if (Test-CommandExists "docker") {
    docker info 2>$null 1>$null
    $dockerReady = ($LASTEXITCODE -eq 0)
}

if ($dockerReady) {
    Write-Host "Docker detected and running - building and starting PlaguardsV2 in a container..." -ForegroundColor Cyan
    docker compose up --build -d
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Docker build/start failed - falling back to a local Python environment instead." -ForegroundColor Yellow
        Start-LocalFallback
    } else {
        Write-Host "Waiting for the dashboard to come up..." -ForegroundColor Cyan
        Start-Sleep -Seconds 3
    }
} else {
    if (Test-CommandExists "docker") {
        Write-Host "Docker is installed but its daemon isn't running - using a local Python environment instead." -ForegroundColor Yellow
    } else {
        Write-Host "Docker not found - setting up a local Python environment instead." -ForegroundColor Cyan
    }
    Start-LocalFallback
}

Start-Process "http://localhost:8000"
Write-Host "PlaguardsV2 is running at http://localhost:8000" -ForegroundColor Green
