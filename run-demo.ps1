$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
Set-Location $root

$lanAddress = $null
$defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -ne "0.0.0.0" } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1
if ($defaultRoute) {
    $lanAddress = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $defaultRoute.InterfaceIndex `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notlike "127.*" -and
            $_.IPAddress -notlike "169.254.*" -and
            $_.PrefixOrigin -ne "WellKnown"
        } |
        Select-Object -ExpandProperty IPAddress -First 1
}
if (-not $lanAddress) {
    $lanAddress = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notlike "127.*" -and
            $_.IPAddress -notlike "169.254.*" -and
            $_.PrefixOrigin -ne "WellKnown"
        } |
        Select-Object -ExpandProperty IPAddress -First 1
}
if (-not $lanAddress) {
    throw "Could not detect an active local IPv4 address. Check ipconfig and try again."
}

$venvPython = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "[ayn] creating virtual environment..."
    python -m venv .venv
}

Write-Host "[ayn] installing dependencies..."
& $venvPython -m pip install --quiet --disable-pip-version-check -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }

New-Item -ItemType Directory -Force data, logs | Out-Null
& $venvPython -m gateway.db
if ($LASTEXITCODE -ne 0) { throw "Database setup failed." }

$env:GATEWAY_URL = "http://127.0.0.1:8000"
$env:PUBLIC_GATEWAY_URL = "http://$lanAddress`:8000"
$env:ATTACKER_URL = "http://127.0.0.1:5000"
$env:AYN_HOST = "0.0.0.0"
$env:ATTACKER_HOST = "0.0.0.0"
$env:PYTHONUNBUFFERED = "1"

$processes = @()
try {
    Write-Host "[ayn] starting attack site..."
    $processes += Start-Process -FilePath $venvPython `
        -ArgumentList "attacker/server.py" `
        -WorkingDirectory $root `
        -RedirectStandardOutput (Join-Path $root "logs\attacker_server.log") `
        -RedirectStandardError (Join-Path $root "logs\attacker_server.err.log") `
        -PassThru

    $attackerReady = $false
    for ($i = 0; $i -lt 40; $i++) {
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:5000/health" -TimeoutSec 1
            if ($health.status -eq "ok") {
                $attackerReady = $true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $attackerReady) { throw "Attack site did not start on port 5000." }

    Write-Host "[ayn] starting dashboard..."
    $gateway = Start-Process -FilePath $venvPython `
        -ArgumentList "-m gateway.main" `
        -WorkingDirectory $root `
        -RedirectStandardOutput (Join-Path $root "logs\gateway.log") `
        -RedirectStandardError (Join-Path $root "logs\gateway.err.log") `
        -PassThru
    $processes += $gateway

    $gatewayReady = $false
    for ($i = 0; $i -lt 40; $i++) {
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 1
            if ($health.status -eq "ok") {
                $gatewayReady = $true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $gatewayReady) { throw "Dashboard did not start on port 8000." }

    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/demo/reset" | Out-Null

    Write-Host "[ayn] starting benefits agent..."
    $processes += Start-Process -FilePath $venvPython `
        -ArgumentList "agents/benefits_agent.py" `
        -WorkingDirectory $root `
        -RedirectStandardOutput (Join-Path $root "logs\benefits_agent.log") `
        -RedirectStandardError (Join-Path $root "logs\benefits_agent.err.log") `
        -PassThru

    Write-Host ""
    Write-Host "Dashboard (My Laptop): http://$lanAddress`:8000"
    Write-Host "Attacker Console (Friend's Laptop): http://$lanAddress`:5000"
    Write-Host "Press Ctrl+C to stop the demo."
    Write-Host ""

    Wait-Process -Id $gateway.Id
} finally {
    foreach ($process in $processes) {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
        }
    }
}
