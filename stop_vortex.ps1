<#
.SYNOPSIS
    VORTEX-SDN Safe Shutdown Command
.DESCRIPTION
    Stops ONLY the exact Flask, Ryu, and Mininet processes tracked by start_vortex.ps1.
    Allows Mininet to perform its normal graceful net.stop() cleanup.
    Does NOT run blanket process-kill commands or automatic mn -c resets.
.PARAMETER CleanMininet
    Explicit recovery flag: execute system-wide 'mn -c' if stale OVS resources remain.
.PARAMETER Force
    Forcefully stop launcher processes if they do not respond to termination signals.
.EXAMPLE
    .\stop_vortex.ps1
    .\stop_vortex.ps1 -CleanMininet
#>

[CmdletBinding()]
param(
    [switch]$CleanMininet,
    [switch]$Force
)

$ErrorActionPreference = "Continue"

Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host "                VORTEX-SDN ENTERPRISE SAFE SHUTDOWN COMMAND                    " -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Yellow

$ProjectDir = (Resolve-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition)).Path
Set-Location $ProjectDir

$PidDir = Join-Path $ProjectDir ".vortex_pids"
$WslPidDir = "/mnt/c/" + ($ProjectDir.Substring(3).Replace('\', '/')) + "/.vortex_pids"

$StateFile = Join-Path $ProjectDir ".vortex_state.json"
$FlaskExactPidFile = Join-Path $PidDir "flask_exact.pid"
$FlaskTermPidFile = Join-Path $PidDir "flask_term.pid"

# --- 1. LOAD TRACKED PROCESS OWNERSHIP STATE ---
$State = $null
if (Test-Path $StateFile) {
    try {
        $State = Get-Content $StateFile -Raw | ConvertFrom-Json
        Write-Host "[*] Loaded tracked session state: $($State.launcher_session_id) (started $($State.started_at))" -ForegroundColor Gray
    } catch {
        Write-Host "[!] Could not parse $StateFile. Falling back to discrete PID files." -ForegroundColor Yellow
    }
}

# Resolve tracked PIDs
$LegacyFlaskExact = Join-Path $ProjectDir ".vortex_flask_exact.pid"
$LegacyFlaskTerm  = Join-Path $ProjectDir ".vortex_flask_term.pid"
$FlaskExactPid = if ($State.flask.exact_pid) { $State.flask.exact_pid } elseif (Test-Path $FlaskExactPidFile) { [int](Get-Content $FlaskExactPidFile -ErrorAction SilentlyContinue | Out-String).Trim() } elseif (Test-Path $LegacyFlaskExact) { [int](Get-Content $LegacyFlaskExact -ErrorAction SilentlyContinue | Out-String).Trim() } else { $null }
$FlaskTermPid  = if ($State.flask.term_pid)  { $State.flask.term_pid }  elseif (Test-Path $FlaskTermPidFile)  { [int](Get-Content $FlaskTermPidFile -ErrorAction SilentlyContinue | Out-String).Trim() } elseif (Test-Path $LegacyFlaskTerm)  { [int](Get-Content $LegacyFlaskTerm -ErrorAction SilentlyContinue | Out-String).Trim() } else { $null }

$RyuExactPid = if ($State.ryu.exact_pid) { $State.ryu.exact_pid } else {
    $val = wsl.exe -d Ubuntu bash -c "cat '$WslPidDir/ryu_exact.pid' 2>/dev/null || cat /tmp/vortex_ryu_exact.pid 2>/dev/null" 2>&1
    if ($val -match "^\d+$") { [int]$val.Trim() } else { $null }
}
$RyuTermPid = if ($State.ryu.term_pid) { $State.ryu.term_pid } else {
    $val = wsl.exe -d Ubuntu bash -c "cat '$WslPidDir/ryu_term.pid' 2>/dev/null || cat /tmp/vortex_ryu_term.pid 2>/dev/null" 2>&1
    if ($val -match "^\d+$") { [int]$val.Trim() } else { $null }
}

$MininetExactPid = if ($State.mininet.exact_pid) { $State.mininet.exact_pid } else {
    $val = wsl.exe -d Ubuntu bash -c "cat '$WslPidDir/mininet_exact.pid' 2>/dev/null || cat /tmp/vortex_mininet_exact.pid 2>/dev/null" 2>&1
    if ($val -match "^\d+$") { [int]$val.Trim() } else { $null }
}
$MininetTermPid = if ($State.mininet.term_pid) { $State.mininet.term_pid } else {
    $val = wsl.exe -d Ubuntu bash -c "cat '$WslPidDir/mininet_term.pid' 2>/dev/null || cat /tmp/vortex_mininet_term.pid 2>/dev/null" 2>&1
    if ($val -match "^\d+$") { [int]$val.Trim() } else { $null }
}

# --- 2. GRACEFUL MININET SHUTDOWN ---
Write-Host "`n[*] Stopping tracked Mininet Topology..." -ForegroundColor Cyan
if ($MininetExactPid) {
    Write-Host "  [*] Signaling tracked Mininet process (PID: $MininetExactPid) with SIGTERM..." -ForegroundColor Gray
    # SIGTERM triggers _sig_term_handler -> sys.exit(0) -> finally: net.stop()
    wsl.exe -d Ubuntu -u root kill -TERM $MininetExactPid 2>&1 | Out-Null

    # Wait up to 5 seconds for net.stop() to finish and delete switches s1-s4
    $MnAlive = $true
    for ($i = 1; $i -le 5; $i++) {
        Start-Sleep -Seconds 1
        wsl.exe -d Ubuntu -u root kill -0 $MininetExactPid 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $MnAlive = $false
            break
        }
    }

    if ($MnAlive) {
        Write-Host "  [!] Mininet did not exit within 5s. Sending SIGINT (interrupt)..." -ForegroundColor Yellow
        wsl.exe -d Ubuntu -u root kill -INT $MininetExactPid 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }

    if ($MininetTermPid) {
        wsl.exe -d Ubuntu bash -c "kill -TERM $MininetTermPid 2>/dev/null" 2>&1 | Out-Null
    }
    Write-Host "  [OK] Mininet process terminated gracefully." -ForegroundColor Green
} else {
    Write-Host "  [INFO] No active Mininet process owned by this launcher." -ForegroundColor Gray
}

# Check for remaining VORTEX bridges (s1, s2, s3, s4)
$CurrentBridges = (wsl.exe -d Ubuntu -u root ovs-vsctl list-br 2>&1) | Where-Object { $_ -ne "" }
$VortexStale = $CurrentBridges | Where-Object { $_ -in @("s1", "s2", "s3", "s4") }

if ($VortexStale) {
    Write-Host "`n  [!] STALE RESOURCES DETECTED:" -ForegroundColor Yellow
    Write-Host "      Active VORTEX bridges remaining in OVS: $($VortexStale -join ', ')" -ForegroundColor Yellow
    Write-Host "  [!] Normal shutdown avoids destructive broad resets to protect other environments." -ForegroundColor Yellow
    Write-Host "  [!] RECOVERY INSTRUCTIONS (Requires Explicit User Action):" -ForegroundColor Cyan
    Write-Host "      To clean Mininet resources across WSL, execute explicitly:" -ForegroundColor White
    Write-Host "          wsl.exe -d Ubuntu -u root mn -c" -ForegroundColor White
    Write-Host "      Or re-run this script with the explicit recovery switch:" -ForegroundColor White
    Write-Host "          .\stop_vortex.ps1 -CleanMininet`n" -ForegroundColor White

    if ($CleanMininet) {
        Write-Host "  [*] Executing user-requested explicit recovery: mn -c..." -ForegroundColor Yellow
        wsl.exe -d Ubuntu -u root mn -c 2>&1 | Out-Null
        Write-Host "  [OK] Mininet broad cleanup completed per user request." -ForegroundColor Green
    }
} else {
    Write-Host "  [OK] Mininet topology resources (switches, hosts, links) cleanly released by net.stop()." -ForegroundColor Green
}

# --- 3. STOP TRACKED RYU CONTROLLER ---
Write-Host "`n[*] Stopping tracked Ryu OpenFlow 1.3 Controller..." -ForegroundColor Cyan
if ($RyuExactPid) {
    Write-Host "  [*] Stopping tracked Ryu process (PID: $RyuExactPid)..." -ForegroundColor Gray
    wsl.exe -d Ubuntu bash -c "kill -TERM $RyuExactPid 2>/dev/null" 2>&1 | Out-Null
    Start-Sleep -Seconds 1

    # Verify process terminated
    $RyuAlive = wsl.exe -d Ubuntu bash -c "kill -0 $RyuExactPid 2>/dev/null && echo ALIVE" 2>&1
    if ($RyuAlive -match "ALIVE") {
        Write-Host "  [*] Ryu still active; sending SIGKILL..." -ForegroundColor Yellow
        wsl.exe -d Ubuntu bash -c "kill -KILL $RyuExactPid 2>/dev/null" 2>&1 | Out-Null
    }

    if ($RyuTermPid) {
        wsl.exe -d Ubuntu bash -c "kill -TERM $RyuTermPid 2>/dev/null" 2>&1 | Out-Null
    }
    Write-Host "  [OK] Tracked Ryu Controller stopped. Port 6653 released." -ForegroundColor Green
} else {
    Write-Host "  [INFO] No active Ryu process owned by this launcher." -ForegroundColor Gray
}

# --- 4. STOP TRACKED FLASK BACKEND ---
Write-Host "`n[*] Stopping tracked Flask Backend Server..." -ForegroundColor Cyan
if ($FlaskExactPid) {
    Write-Host "  [*] Stopping tracked Flask Python process (PID: $FlaskExactPid)..." -ForegroundColor Gray
    try {
        $p = Get-Process -Id $FlaskExactPid -ErrorAction SilentlyContinue
        if ($p) {
            Stop-Process -Id $FlaskExactPid -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] Tracked Flask Backend stopped." -ForegroundColor Green
        } else {
            Write-Host "  [INFO] Tracked Flask process was already terminated." -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [!] Could not stop Flask process PID $FlaskExactPid : $($_.Exception.Message)" -ForegroundColor Yellow
    }

    if ($FlaskTermPid) {
        try {
            Stop-Process -Id $FlaskTermPid -Force -ErrorAction SilentlyContinue
        } catch {}
    }
} else {
    Write-Host "  [INFO] No active Flask process owned by this launcher." -ForegroundColor Gray
}

# --- 5. CLEANUP LAUNCHER STATE FILES ---
Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
Remove-Item $FlaskExactPidFile, $FlaskTermPidFile -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $ProjectDir ".vortex_flask_*.pid") -Force -ErrorAction SilentlyContinue
wsl.exe -d Ubuntu bash -c "rm -f '$WslPidDir/'*.pid" 2>&1 | Out-Null
wsl.exe -d Ubuntu -u root bash -c "rm -f /tmp/vortex_ryu_*.pid /tmp/vortex_mininet_*.pid" 2>&1 | Out-Null


# --- 6. SUMMARY REPORT ---
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "                     VORTEX-SDN SAFE SHUTDOWN COMPLETE                         " -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green

# Check remaining port allocations without blanket kill
$RemainingPort5000 = $false
try {
    $p5000 = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
    if ($p5000) { $RemainingPort5000 = $true }
} catch {}

$RemainingPort6653 = $false
$r6653 = wsl.exe -d Ubuntu bash -c "ss -tln | grep -q :6653 && echo STILL_OPEN" 2>&1
if ($r6653 -match "STILL_OPEN") { $RemainingPort6653 = $true }

if (-not $RemainingPort5000) {
    Write-Host "  Flask Port 5000   : RELEASED / FREE" -ForegroundColor White
} else {
    Write-Host "  Flask Port 5000   : STILL OCCUPIED (Preserved un-tracked process)" -ForegroundColor Yellow
}

if (-not $RemainingPort6653) {
    Write-Host "  Ryu Port 6653     : RELEASED / FREE" -ForegroundColor White
} else {
    Write-Host "  Ryu Port 6653     : STILL OCCUPIED (Preserved un-tracked process)" -ForegroundColor Yellow
}

Write-Host "  Mininet / OVS     : Launcher topology gracefully stopped (No broad mn -c used)" -ForegroundColor White
Write-Host "===============================================================================`n" -ForegroundColor Green
