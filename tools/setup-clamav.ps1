#Requires -Version 5.1
<#
  Optional: configure ClamAV as a local-socket scanner for Feather AV real-time
  protection. Nothing is bundled or linked into feather - clamd is contacted
  over 127.0.0.1:3310 using the documented INSTREAM protocol, so the repo stays
  MIT and the GPL boundary is respected.

  Must run elevated. Safe to re-run; it rewrites only Feather's own config.
#>
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell.'
}

$clamDir = 'C:\Program Files\ClamAV'
if (-not (Test-Path $clamDir)) {
    $found = Get-Command clamd.exe -ErrorAction SilentlyContinue
    if ($found) { $clamDir = Split-Path -Parent $found.Source }
}
$clamd = Join-Path $clamDir 'clamd.exe'
$freshclam = Join-Path $clamDir 'freshclam.exe'
foreach ($required in @($clamd, $freshclam)) {
    if (-not (Test-Path $required)) { throw "ClamAV not found: $required" }
}

$configRoot = Join-Path $env:PROGRAMDATA 'Feather\clamav'
$dbDir = Join-Path $configRoot 'db'
New-Item -ItemType Directory -Path $dbDir -Force | Out-Null

$clamdConf = Join-Path $configRoot 'clamd.conf'
$freshConf = Join-Path $configRoot 'freshclam.conf'

@"
TCPAddress 127.0.0.1
TCPPort 3310
DatabaseDirectory "$dbDir"
LogFile "$configRoot\clamd.log"
LogFileMaxSize 2M
LogTime yes
StreamMaxLength 100M
MaxScanSize 1000M
MaxFileSize 100M
MaxRecursion 4
MaxFiles 10000
AlertExceedsMax no
"@ | Set-Content -Path $clamdConf -Encoding ascii

@"
DatabaseDirectory "$dbDir"
UpdateLogFile "$configRoot\freshclam.log"
LogFileMaxSize 2M
LogTime yes
Checks 12
"@ | Set-Content -Path $freshConf -Encoding ascii

Write-Host 'Updating ClamAV signatures (requires internet access)...'
try {
    & $freshclam "--config-file=$freshConf" --foreground 2>&1 | Select-Object -Last 8 | Out-Host
} catch {
    Write-Warning "freshclam could not update signatures: $($_.Exception.Message)"
}

Write-Host 'Registering the clamd service (local socket only)...'
$existing = Get-Service -Name ClamAV -ErrorAction SilentlyContinue
$binPath = "`"$clamd`" --config-file=`"$clamdConf`""
if ($existing) {
    & sc.exe stop ClamAV 2>&1 | Out-Null
    & sc.exe config ClamAV binPath= $binPath start= auto 2>&1 | Out-Host
} else {
    & sc.exe create ClamAV start= auto displayname= 'ClamAV Scanner' binPath= $binPath 2>&1 | Out-Host
}
& sc.exe description ClamAV 'ClamAV daemon used by Feather AV on 127.0.0.1:3310' 2>&1 | Out-Null
& sc.exe start ClamAV 2>&1 | Out-Host

Write-Host ''
Write-Host '--- status ---'
Get-Service -Name ClamAV -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-Table -AutoSize
Write-Host "config: $clamdConf"
Write-Host 'Feather real-time protection will report ClamAV as reachable once clamd is listening.'
