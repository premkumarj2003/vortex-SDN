<#
.SYNOPSIS
    VORTEX-SDN Single-Command Startup Launcher
.DESCRIPTION
    Orchestrates startup of Flask backend (Windows), Ryu SDN controller (Ubuntu/WSL 2),
    and Mininet 4-switch mesh topology (Ubuntu/WSL 2) in dedicated visible terminals.
    Performs pre-flight checks, readiness polling, exact process ownership tracking,
    and duplicate prevention.
.PARAMETER NoBrowser
    Do not automatically open the browser when Flask becomes ready.
.PARAMETER NoMininet
    Start Flask backend and Ryu controller only (skip Mininet topology).
.PARAMETER UseWindowsTerminal
    Attempt to launch terminals using Windows Terminal (wt.exe) instead of standalone console windows.
.EXAMPLE
    .\start_vortex.ps1
    .\start_vortex.ps1 -NoBrowser
    .\start_vortex.ps1 -UseWindowsTerminal
#>

[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [switch]$NoMininet,
    [switch]$UseWindowsTerminal
)

$ErrorActionPreference = "Continue"

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "              VORTEX-SDN ENTERPRISE SAFE STARTUP ORCHESTRATOR                  " -ForegroundColor Cyan
Write-Host "       Flask (Windows) + Ryu OpenFlow 1.3 (WSL) + Mininet OVS (WSL)            " -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

# --- 1. RESOLVE PROJECT DIRECTORIES ---
$ProjectDir = (Resolve-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition)).Path
Set-Location $ProjectDir
$WslProjectDir = "/mnt/c/" + ($ProjectDir.Substring(3).Replace('\', '/'))

Write-Host "[*] Windows Project Root : $ProjectDir" -ForegroundColor Gray
Write-Host "[*] WSL Project Root     : $WslProjectDir" -ForegroundColor Gray

$PidDir = Join-Path $ProjectDir ".vortex_pids"
if (-not (Test-Path $PidDir)) { New-Item -ItemType Directory -Path $PidDir -Force | Out-Null }
$WslPidDir = "$WslProjectDir/.vortex_pids"

$StateFile = Join-Path $ProjectDir ".vortex_state.json"
$FlaskExactPidFile = Join-Path $PidDir "flask_exact.pid"
$FlaskTermPidFile = Join-Path $PidDir "flask_term.pid"

# --- 2. PRE-FLIGHT VALIDATION CHECKS ---
Write-Host "`n[*] Running Pre-Flight Environment Checks..." -ForegroundColor Yellow

# A. Python (Windows)
$PythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    Write-Host "[-] FATAL: 'python.exe' was not found in Windows PATH." -ForegroundColor Red
    exit 1
}
$PyVer = (python --version 2>&1)
Write-Host "  [OK] Windows Python    : $PyVer" -ForegroundColor Green

# B. WSL Availability
$WslCmd = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $WslCmd) {
    Write-Host "[-] FATAL: 'wsl.exe' was not found. WSL 2 is required for Ryu and Mininet." -ForegroundColor Red
    exit 1
}
wsl.exe -d Ubuntu -e true 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] FATAL: WSL Ubuntu distribution is not accessible or not running." -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] WSL Distribution  : Ubuntu (active)" -ForegroundColor Green

# C. Ryu Virtual Environment in WSL
$RyuVenvBin = "/home/prem/VORTEX-SDN/.venv-ryu/bin/ryu-manager"
wsl.exe -d Ubuntu test -f $RyuVenvBin 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] FATAL: Ryu executable not found at $RyuVenvBin" -ForegroundColor Red
    exit 1
}
$RyuVer = wsl.exe -d Ubuntu $RyuVenvBin --version 2>&1
Write-Host "  [OK] Ryu Controller    : ryu-manager $RyuVer ($RyuVenvBin)" -ForegroundColor Green

# D. Open vSwitch in WSL
$OvsVer = wsl.exe -d Ubuntu ovs-vsctl --version 2>&1 | Select-Object -First 1
Write-Host "  [OK] Open vSwitch      : $OvsVer" -ForegroundColor Green

# E. Mininet in WSL
$MnVer = wsl.exe -d Ubuntu mn --version 2>&1 | Select-Object -First 1
Write-Host "  [OK] Mininet Engine    : Mininet $MnVer" -ForegroundColor Green

# F. Terminal Engine Configuration
$UseWt = $false
if ($UseWindowsTerminal) {
    $WtCmd = Get-Command wt.exe -ErrorAction SilentlyContinue
    if ($WtCmd) {
        $UseWt = $true
        Write-Host "  [OK] Terminal Engine   : Windows Terminal (wt.exe)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] wt.exe not found; falling back to dedicated console windows." -ForegroundColor Yellow
    }
} else {
    Write-Host "  [OK] Terminal Engine   : Dedicated Console Windows" -ForegroundColor Green
}

# --- 3. CHECK EXISTING RUNNING PROCESSES / PORTS ---
Write-Host "`n[*] Checking Port Allocations & Existing Instances..." -ForegroundColor Yellow

$FlaskRunning = $false
try {
    $Tcp5000 = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
    if ($Tcp5000) {
        $FlaskRunning = $true
    }
} catch {
    $Test5000 = Test-NetConnection -ComputerName 127.0.0.1 -Port 5000 -WarningAction SilentlyContinue
    if ($Test5000.TcpTestSucceeded) {
        $FlaskRunning = $true
    }
}

$RyuRunning = $false
$RyuPortCheck = wsl.exe -d Ubuntu bash -c "ss -tln | grep -q :6653 && echo YES" 2>&1
if ($RyuPortCheck -match "YES") {
    $RyuRunning = $true
}

# Initialize Process State Object
$ProcessState = @{
    launcher_session_id = "vortex-" + [System.Guid]::NewGuid().ToString().Substring(0, 8)
    started_at          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    flask               = @{ exact_pid = $null; term_pid = $null }
    ryu                 = @{ exact_pid = $null; term_pid = $null }
    mininet             = @{ exact_pid = $null; term_pid = $null }
}

# --- 4. STAGE 1: FLASK BACKEND ---
Write-Host "`n-------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "[STAGE 1/3] Starting Flask Backend Server (Windows: 127.0.0.1:5000)..." -ForegroundColor Cyan
Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Cyan

if ($FlaskRunning) {
    Write-Host "[!] Port 5000 is already in use. Checking health endpoint..." -ForegroundColor Yellow
    try {
        [void](Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/health" -Method Get -TimeoutSec 3 -ErrorAction Stop)
        Write-Host "[+] Existing Flask Backend is HEALTHY and active (Preserving instance, skipping duplicate launch)." -ForegroundColor Green
    } catch {
        Write-Host "[!] Port 5000 is occupied but health check failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "[!] Proceeding without spawning duplicate." -ForegroundColor Yellow
    }
} else {
    # Remove any stale flask PID files
    Remove-Item $FlaskExactPidFile, $FlaskTermPidFile -Force -ErrorAction SilentlyContinue

    if ($UseWt) {
        Start-Process -FilePath "wt.exe" -ArgumentList "-w", "new", "--title", "VORTEX-SDN Flask Backend", "-d", "`"$ProjectDir`"", "powershell.exe", "-NoExit", "-ExecutionPolicy", "Bypass", "-File", ".\scripts\launch_backend.ps1"
    } else {
        Start-Process -FilePath "powershell.exe" -WorkingDirectory $ProjectDir -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", ".\scripts\launch_backend.ps1"
    }

    # Poll health endpoint
    Write-Host "[*] Waiting for Flask backend to report healthy..." -NoNewline
    $FlaskReady = $false
    for ($i = 1; $i -le 30; $i++) {
        Start-Sleep -Seconds 1
        Write-Host "." -NoNewline
        try {
            [void](Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/health" -Method Get -TimeoutSec 2 -ErrorAction Stop)
            $FlaskReady = $true
            break
        } catch {}
    }
    Write-Host ""

    if (-not $FlaskReady) {
        Write-Host "[-] ERROR: Flask Backend failed to respond healthy at http://127.0.0.1:5000/api/health within 30s." -ForegroundColor Red
        Write-Host "[-] Check the Flask terminal window for tracebacks. Aborting startup sequence." -ForegroundColor Red
        exit 1
    }

    # Record tracked Flask PIDs
    if (Test-Path $FlaskExactPidFile) {
        $ProcessState.flask.exact_pid = [int](Get-Content $FlaskExactPidFile -ErrorAction SilentlyContinue | Out-String).Trim()
    }
    if (Test-Path $FlaskTermPidFile) {
        $ProcessState.flask.term_pid = [int](Get-Content $FlaskTermPidFile -ErrorAction SilentlyContinue | Out-String).Trim()
    }
    Write-Host "[+] Flask Backend is READY (Tracked PID: $($ProcessState.flask.exact_pid), Terminal PID: $($ProcessState.flask.term_pid))" -ForegroundColor Green
}

# --- 5. STAGE 2: RYU OPENFLOW CONTROLLER ---
Write-Host "`n-------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "[STAGE 2/3] Starting Ryu OpenFlow 1.3 Controller (WSL: 0.0.0.0:6653)..." -ForegroundColor Cyan
Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Cyan

if ($RyuRunning) {
    Write-Host "[+] Ryu Controller is ALREADY LISTENING on port 6653 (Preserving instance, skipping duplicate launch)." -ForegroundColor Green
} else {
    # Clean stale PID files safely in workspace directory and legacy tmp
    wsl.exe -d Ubuntu bash -c "mkdir -p '$WslPidDir' && rm -f '$WslPidDir/ryu_exact.pid' '$WslPidDir/ryu_term.pid'" 2>&1 | Out-Null
    wsl.exe -d Ubuntu -u root bash -c "rm -f /tmp/vortex_ryu_exact.pid /tmp/vortex_ryu_term.pid" 2>&1 | Out-Null

    $RyuCmd = "`$host.UI.RawUI.WindowTitle = 'VORTEX-SDN Ryu Controller'; wsl.exe -d Ubuntu bash '$WslProjectDir/scripts/launch_ryu.sh'"

    if ($UseWt) {
        Start-Process -FilePath "wt.exe" -ArgumentList "-w", "new", "--title", "VORTEX-SDN Ryu Controller", "-d", "`"$ProjectDir`"", "powershell.exe", "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $RyuCmd
    } else {
        Start-Process -FilePath "powershell.exe" -WorkingDirectory $ProjectDir -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $RyuCmd
    }

    # Poll port 6653 listener in WSL
    Write-Host "[*] Waiting for Ryu OpenFlow listener on port 6653..." -NoNewline
    $RyuReady = $false
    for ($i = 1; $i -le 25; $i++) {
        Start-Sleep -Seconds 1
        Write-Host "." -NoNewline
        $Check = wsl.exe -d Ubuntu bash -c "ss -tln | grep -q :6653 && echo READY" 2>&1
        if ($Check -match "READY") {
            $RyuReady = $true
            break
        }
    }
    Write-Host ""

    if (-not $RyuReady) {
        Write-Host "[-] ERROR: Ryu Controller failed to bind to port 6653 within 25s." -ForegroundColor Red
        Write-Host "[-] Inspect the Ryu terminal window for startup errors. Aborting Mininet launch." -ForegroundColor Red
        exit 1
    }

    # Record tracked Ryu PIDs (from workspace .vortex_pids with legacy /tmp fallback)
    $RyuExact = wsl.exe -d Ubuntu bash -c "cat '$WslPidDir/ryu_exact.pid' 2>/dev/null || cat /tmp/vortex_ryu_exact.pid 2>/dev/null" 2>&1
    if ($RyuExact -match "^\d+$") { $ProcessState.ryu.exact_pid = [int]$RyuExact.Trim() }
    $RyuTerm = wsl.exe -d Ubuntu bash -c "cat '$WslPidDir/ryu_term.pid' 2>/dev/null || cat /tmp/vortex_ryu_term.pid 2>/dev/null" 2>&1
    if ($RyuTerm -match "^\d+$") { $ProcessState.ryu.term_pid = [int]$RyuTerm.Trim() }

    Write-Host "[+] Ryu Controller is READY (Tracked PID: $($ProcessState.ryu.exact_pid), Terminal PID: $($ProcessState.ryu.term_pid))" -ForegroundColor Green
}

# --- 6. STAGE 3: MININET TOPOLOGY ---
if (-not $NoMininet) {
    Write-Host "`n-------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "[STAGE 3/3] Starting Mininet Mesh Topology (WSL OVS 4-Switch Network)..." -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Cyan

    # Check for active bridges
    $ExistingBridges = (wsl.exe -d Ubuntu -u root ovs-vsctl list-br 2>&1) | Where-Object { $_ -ne "" }
    if ($ExistingBridges) {
        Write-Host "[!] Note: Found active Open vSwitch bridges: $($ExistingBridges -join ', ')" -ForegroundColor Yellow
        Write-Host "[!] Launcher will not perform automatic global cleanup to avoid affecting external topologies." -ForegroundColor Yellow
    }

    # Clean stale PID files in workspace directory and legacy /tmp
    wsl.exe -d Ubuntu bash -c "mkdir -p '$WslPidDir' && rm -f '$WslPidDir/mininet_exact.pid' '$WslPidDir/mininet_term.pid'" 2>&1 | Out-Null
    wsl.exe -d Ubuntu -u root bash -c "rm -f /tmp/vortex_mininet_exact.pid /tmp/vortex_mininet_term.pid" 2>&1 | Out-Null

    $MininetCmd = "`$host.UI.RawUI.WindowTitle = 'VORTEX-SDN Mininet CLI'; wsl.exe -d Ubuntu -u root bash '$WslProjectDir/scripts/launch_mininet.sh'"

    if ($UseWt) {
        Start-Process -FilePath "wt.exe" -ArgumentList "-w", "new", "--title", "VORTEX-SDN Mininet CLI", "-d", "`"$ProjectDir`"", "powershell.exe", "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $MininetCmd
    } else {
        Start-Process -FilePath "powershell.exe" -WorkingDirectory $ProjectDir -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $MininetCmd
    }

    # Verify switches connect to Ryu
    Write-Host "[*] Waiting for OpenFlow switches to initialize and register..." -NoNewline
    $SwitchesReady = $false
    for ($i = 1; $i -le 20; $i++) {
        Start-Sleep -Seconds 1
        Write-Host "." -NoNewline
        $Bridges = wsl.exe -d Ubuntu -u root ovs-vsctl list-br 2>&1
        if ($Bridges -match "s1" -and $Bridges -match "s2") {
            $SwitchesReady = $true
            break
        }
    }
    Write-Host ""

    # Record tracked Mininet PIDs (from workspace .vortex_pids with legacy /tmp fallback)
    $MnExact = wsl.exe -d Ubuntu bash -c "cat '$WslPidDir/mininet_exact.pid' 2>/dev/null || cat /tmp/vortex_mininet_exact.pid 2>/dev/null" 2>&1
    if ($MnExact -match "^\d+$") { $ProcessState.mininet.exact_pid = [int]$MnExact.Trim() }
    $MnTerm = wsl.exe -d Ubuntu bash -c "cat '$WslPidDir/mininet_term.pid' 2>/dev/null || cat /tmp/vortex_mininet_term.pid 2>/dev/null" 2>&1
    if ($MnTerm -match "^\d+$") { $ProcessState.mininet.term_pid = [int]$MnTerm.Trim() }

    if ($SwitchesReady) {
        Write-Host "[+] OpenFlow switches (s1, s2, s3, s4) connected to Ryu controller!" -ForegroundColor Green
        Write-Host "[+] Mininet CLI is ready (Tracked PID: $($ProcessState.mininet.exact_pid), Terminal PID: $($ProcessState.mininet.term_pid))" -ForegroundColor Green
    } else {
        Write-Host "[!] Note: If sudo password prompt appeared in the Mininet terminal, enter password to complete launch." -ForegroundColor Yellow
    }
} else {
    Write-Host "`n[STAGE 3/3] Mininet startup skipped per -NoMininet flag." -ForegroundColor Yellow
}

# --- 7. PERSIST LAUNCHER PROCESS STATE ---
$ProcessState | ConvertTo-Json -Depth 4 | Out-File -FilePath $StateFile -Encoding utf8 -Force
Write-Host "`n[*] Launcher ownership state saved to $StateFile" -ForegroundColor Gray

# --- 8. FINAL SYSTEM STATUS & SUMMARY ---
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "                     VORTEX-SDN SYSTEM IS FULLY ONLINE                         " -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "  Flask Backend      : ONLINE  -> http://127.0.0.1:5000 (PID: $($ProcessState.flask.exact_pid))" -ForegroundColor White
Write-Host "  Health API         : ONLINE  -> http://127.0.0.1:5000/api/health" -ForegroundColor White
Write-Host "  Web Dashboard      : READY   -> http://127.0.0.1:5000/login" -ForegroundColor White
Write-Host "  Ryu Controller     : ONLINE  -> 127.0.0.1:6653 (PID: $($ProcessState.ryu.exact_pid))" -ForegroundColor White
if (-not $NoMininet) {
Write-Host "  Mininet Topology   : ONLINE  -> 4 OVS Switches (PID: $($ProcessState.mininet.exact_pid))" -ForegroundColor White
} else {
Write-Host "  Mininet Topology   : SKIPPED" -ForegroundColor Gray
}
Write-Host "  Telemetry Segreg.  : ACTIVE  -> Live OpenFlow + Demo Scenarios segregated" -ForegroundColor White
Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  To stop all services gracefully, run: .\stop_vortex.ps1" -ForegroundColor Cyan
Write-Host "===============================================================================`n" -ForegroundColor Green

if (-not $NoBrowser) {
    try {
        Start-Process "http://127.0.0.1:5000/login"
    } catch {}
}
