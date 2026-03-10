param(
  [int]$BackendPort = 0,
  [int]$FrontendPort = 0
)

$ErrorActionPreference = "Stop"

function Get-ListeningPids([int]$Port) {
  if (-not $Port) { return @() }
  $lines = netstat -ano | Select-String (":$Port\\s") | Select-String "LISTENING"
  $pids = @()
  foreach ($m in $lines) {
    $parts = ($m.Line -split "\\s+") | Where-Object { $_ }
    $pid = $parts[-1]
    if ($pid -match "^\\d+$") { $pids += [int]$pid }
  }
  return ($pids | Select-Object -Unique)
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pidFile = Join-Path $root "run_pids.txt"

if ((-not $BackendPort) -or (-not $FrontendPort)) {
  if (Test-Path $pidFile) {
    $content = Get-Content $pidFile
    foreach ($line in $content) {
      $t = $line.Trim()
      if ((-not $BackendPort) -and ($t -match '^backend_port=(\d+)')) { $BackendPort = [int]$matches[1] }
      if ((-not $FrontendPort) -and ($t -match '^frontend_port=(\d+)')) { $FrontendPort = [int]$matches[1] }
    }
  }
}

if (-not $BackendPort -and -not $FrontendPort) {
  throw "No ports provided and no ports found in $pidFile."
}

$pids = @()
$pids += Get-ListeningPids -Port $BackendPort
$pids += Get-ListeningPids -Port $FrontendPort
$pids = $pids | Where-Object { $_ } | Select-Object -Unique

if (-not $pids) {
  Write-Host "No listening processes found for the given ports."
  exit 0
}

foreach ($id in $pids) {
  try { Stop-Process -Id $id -Force -ErrorAction Stop; Write-Host "Stopped PID $id" } catch { Write-Host "Failed to stop PID ${id}: $($_.Exception.Message)" }
}
