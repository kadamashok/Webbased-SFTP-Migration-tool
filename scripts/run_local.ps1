param(
  [int]$BackendStartPort = 8001,
  [int]$FrontendStartPort = 8080,
  [string]$BindHost = "127.0.0.1",
  [int]$DurationSeconds = 0
)

$ErrorActionPreference = "Stop"

function Get-FreePort {
  param(
    [Parameter(Mandatory = $true)][int]$StartPort,
    [int]$ScanCount = 200
  )

  for ($port = $StartPort; $port -lt ($StartPort + $ScanCount); $port++) {
    $hit = netstat -ano -p tcp | Select-String (":$port\\s") | Select-String "LISTENING"
    if (-not $hit) { return $port }
  }

  throw "No free port found starting at $StartPort (scanned $ScanCount ports)."
}

function Get-ListeningPid {
  param([Parameter(Mandatory = $true)][int]$Port)

  $lines = netstat -ano | Select-String (":$Port\\s") | Select-String "LISTENING"
  foreach ($m in $lines) {
    $parts = ($m.Line -split "\\s+") | Where-Object { $_ }
    $pid = $parts[-1]
    if ($pid -match "^\\d+$") { return [int]$pid }
  }
  return $null
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$py = Join-Path $root ".venv\\Scripts\\python.exe"
if (-not (Test-Path $py)) {
  throw "Missing venv Python at $py. Create it with: py -3 -m venv .venv"
}

$backendPort = Get-FreePort -StartPort $BackendStartPort
$frontendPort = Get-FreePort -StartPort $FrontendStartPort

# Ensure logo exists where the UI expects it.
& $py (Join-Path $root "scripts\\setup_assets.py") | Out-Null

$frontendDirToServe = Join-Path $root "frontend"

function Stop-IfRunning([int]$ProcessId) {
  if (-not $ProcessId) { return }
  try { Stop-Process -Id $ProcessId -Force -ErrorAction Stop } catch {}
}

try {
  $backendArgs = @(
    "-m", "uvicorn", "app.main:app",
    "--host", $BindHost,
    "--port", "$backendPort"
  )
  $backendProc = Start-Process `
    -FilePath $py `
    -ArgumentList $backendArgs `
    -WorkingDirectory (Join-Path $root "backend") `
    -RedirectStandardOutput (Join-Path $root "backend_stdout.log") `
    -RedirectStandardError (Join-Path $root "backend_stderr.log") `
    -PassThru

  $frontendArgs = @("-m", "http.server", "$frontendPort", "--bind", $BindHost)
  $frontendProc = Start-Process `
    -FilePath $py `
    -ArgumentList $frontendArgs `
    -WorkingDirectory $frontendDirToServe `
    -RedirectStandardOutput (Join-Path $root "frontend_stdout.log") `
    -RedirectStandardError (Join-Path $root "frontend_stderr.log") `
    -PassThru

  # Resolve the actual listening PIDs (some processes spawn and the parent exits).
  $backendPid = $null
  $frontendPid = $null
  for ($i = 0; $i -lt 60; $i++) {
    if (-not $backendPid) { $backendPid = Get-ListeningPid -Port $backendPort }
    if (-not $frontendPid) { $frontendPid = Get-ListeningPid -Port $frontendPort }

    if ($backendPid -and $frontendPid) { break }
    Start-Sleep -Milliseconds 250
  }

  $pidFile = Join-Path $root "run_pids.txt"
  "backend_pid=$backendPid`nfrontend_pid=$frontendPid`nbackend_port=$backendPort`nfrontend_port=$frontendPort" | Set-Content -Encoding ASCII $pidFile

  $uiUrl = "http://$BindHost`:$frontendPort/"
  if ($backendPort -ne 8001) {
    $uiUrl = "http://$BindHost`:$frontendPort/?api=http://$BindHost`:$backendPort"
  }

  Write-Host ("Backend health: http://{0}:{1}/health" -f $BindHost, $backendPort)
  Write-Host ("Frontend UI:    {0}" -f $uiUrl)
  Write-Host ("PIDs saved to:  {0}" -f $pidFile)

  if ($DurationSeconds -gt 0) {
    Start-Sleep -Seconds $DurationSeconds
    return
  }

  Write-Host "Press Ctrl+C to stop."
  while ($true) { Start-Sleep -Seconds 1 }
}
finally {
  $backendPidToStop = $backendPid
  if (-not $backendPidToStop) { $backendPidToStop = $backendProc.Id }
  $frontendPidToStop = $frontendPid
  if (-not $frontendPidToStop) { $frontendPidToStop = $frontendProc.Id }

  Stop-IfRunning $frontendPidToStop
  Stop-IfRunning $backendPidToStop
}
