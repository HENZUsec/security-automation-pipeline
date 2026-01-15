<#
windows_check.ps1 - Windows collector (writes to ../data)
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Resolve-Path (Join-Path $ScriptDir "..")
$DataDir   = Join-Path $RepoRoot "data"

$OutCsv   = Join-Path $DataDir "windows_services.csv"
$SecLog   = Join-Path $DataDir "windows_security_events.log"
$AuthLog  = Join-Path $DataDir "auth.log"
$AnomLog  = Join-Path $DataDir "anomalies.log"
$CritLog  = Join-Path $DataDir "critical_alerts.log"

function TS { (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }

function Write-AuthLog([string]$Msg)    { Add-Content -Path $AuthLog -Value ("{0} AUTH: {1}" -f (TS), $Msg) -Encoding UTF8 }
function Write-Anomaly([string]$Msg)    { Add-Content -Path $AnomLog -Value ("{0} ANOMALY: {1}" -f (TS), $Msg) -Encoding UTF8 }
function Write-Critical([string]$Msg)    {
  Add-Content -Path $CritLog -Value ("{0} CRITICAL: {1}" -f (TS), $Msg) -Encoding UTF8
  Write-Anomaly $Msg
}

try {
  New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
  if (-not (Test-Path $AuthLog)) { New-Item -ItemType File -Path $AuthLog -Force | Out-Null }
  if (-not (Test-Path $AnomLog)) { New-Item -ItemType File -Path $AnomLog -Force | Out-Null }
  if (-not (Test-Path $CritLog)) { New-Item -ItemType File -Path $CritLog -Force | Out-Null }
  Set-Content -Path $SecLog -Value "" -Encoding UTF8

  Write-AuthLog "Windows check started (user=$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name))"
  Write-AuthLog "Repo root: $RepoRoot"

  # Read services (CIM)
  $services = Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, PathName, StartName, ProcessId

  $services | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-AuthLog "Wrote: data/windows_services.csv ($($services.Count) services)"

  # Read Event Viewer snapshot
  $logNames = @("Security","System","Application")
  foreach ($ln in $logNames) {
    try {
      $events = Get-WinEvent -LogName $ln -MaxEvents 100 -ErrorAction Stop
      foreach ($e in $events) {
        $msg = if ($e.Message) { $e.Message } else { "<no message>" }
        $snippet = $msg.Substring(0, [Math]::Min(160, $msg.Length))
        Add-Content -Path $SecLog -Value ("[{0}] {1} | Id={2} | {3}" -f $ln, $e.TimeCreated, $e.Id, $snippet) -Encoding UTF8
      }
    }
    catch {
      Write-Anomaly "Could not read $ln log: $($_.Exception.Message)"
    }
  }

  if (-not (Test-Path $OutCsv) -or ((Get-Item $OutCsv).Length -eq 0)) {
    Write-Anomaly "windows_services.csv missing or empty"
    throw "Output validation failed"
  }

  $stamp = TS
  Write-AuthLog "END OF CHECK $stamp"
  Write-Anomaly "END OF CHECK $stamp"

  Write-Host "[OK] Windows collector finished. Outputs in data/" -ForegroundColor Green
  exit 0
}
catch {
  try { Write-Critical "Windows collector failed: $($_.Exception.Message)" } catch {}
  Write-Host "[X] Windows collector failed: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}
