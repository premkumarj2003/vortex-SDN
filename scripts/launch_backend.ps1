# VORTEX-SDN Flask Backend Launcher
$ProjectDir = (Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) "..")).Path
Set-Location $ProjectDir
$host.UI.RawUI.WindowTitle = "VORTEX-SDN Flask Backend"

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "                       VORTEX-SDN FLASK BACKEND SERVER                         " -ForegroundColor Cyan
Write-Host "                    Serving on http://127.0.0.1:5000                           " -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

$PidFile = Join-Path $ProjectDir ".vortex_flask.pid"
$PID | Out-File -FilePath $PidFile -Encoding ascii -Force

Write-Host "[*] Process PID $PID recorded to $PidFile" -ForegroundColor Gray
Write-Host "[*] Starting Flask application..." -ForegroundColor Yellow

python -m backend.api.server
$PID | Out-File -FilePath $TermPidFile -Encoding ascii -Force
$PID | Out-File -FilePath $LegacyTermPidFile -Encoding ascii -Force

# Launch Python process directly and record its exact process PID
$flaskProc = Start-Process -FilePath "python.exe" -ArgumentList "-m", "backend.api.server" -PassThru -NoNewWindow
$flaskProc.Id | Out-File -FilePath $ExactPidFile -Encoding ascii -Force
$flaskProc.Id | Out-File -FilePath $LegacyExactPidFile -Encoding ascii -Force

Write-Host "[*] Terminal PID $PID recorded to $TermPidFile" -ForegroundColor Gray
Write-Host "[*] Flask Python PID $($flaskProc.Id) recorded to $ExactPidFile" -ForegroundColor Gray
Write-Host "[*] Flask application active..." -ForegroundColor Yellow

$flaskProc.WaitForExit()
