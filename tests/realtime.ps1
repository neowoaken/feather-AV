#Requires -Version 5.1
<#
  Tests the real-time decision path without needing a loaded kernel driver.
  feathersvc --probe feeds a synthetic filter request through the exact same
  Engine -> verdict -> quarantine code the communication port uses.

  Verifies: clean files are allowed, a locally listed hash is quarantined,
  the original is removed, and the vaulted copy can be restored.
#>
param(
    [string]$Service = (Join-Path $PSScriptRoot "..\build\Release\feathersvc.exe"),
    [string]$Cli = (Join-Path $PSScriptRoot "..\build\Release\feather.exe")
)

$ErrorActionPreference = 'Stop'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAIL: $Message" }
    Write-Host "ok   $Message"
}

foreach ($binary in @($Service, $Cli)) {
    if (-not (Test-Path $binary)) { throw "binary not found: $binary" }
}

$work = Join-Path $env:TEMP ("feather-realtime-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$configDir = Join-Path $env:PROGRAMDATA 'Feather'
New-Item -ItemType Directory -Path $configDir -Force | Out-Null
$configPath = Join-Path $configDir 'realtime.conf'
$hadConfig = Test-Path $configPath
$oldConfig = if ($hadConfig) { Get-Content $configPath -Raw } else { $null }

try {
    $clean = Join-Path $work 'clean.exe'
    $bad = Join-Path $work 'malware.bin'
    [System.IO.File]::WriteAllText($clean, 'ordinary, harmless test content')
    [System.IO.File]::WriteAllText($bad, 'unique payload for the realtime test ' + [guid]::NewGuid())
    $badHash = (Get-FileHash $bad -Algorithm SHA256).Hash.ToLowerInvariant()

    $ioc = Join-Path $work 'ioc.txt'
    Set-Content -Path $ioc -Encoding ascii -Value "sha256 $badHash injected realtime test"

    $vault = Join-Path $work 'vault'
    @(
        "ioc=$ioc",
        'clamd=none',
        "quarantine=$vault"
    ) | Set-Content -Path $configPath -Encoding ascii

    $cleanResult = & $Service --probe $clean
    Write-Host "     clean: $cleanResult"
    Assert-True ($cleanResult -match 'verdict=0 ') 'clean file is allowed'

    $badResult = & $Service --probe $bad
    Write-Host "     malicious: $badResult"
    Assert-True ($badResult -match 'verdict=2 ') 'malicious file is quarantined'
    Assert-True ($badResult -match 'severity=malicious') 'verdict tier is malicious'
    Assert-True (-not (Test-Path $bad)) 'original file was removed'

    $manifest = Join-Path $vault 'manifest.tsv'
    Assert-True (Test-Path $manifest) 'quarantine manifest was written'
    Assert-True ((Get-Content $manifest -Raw).Contains($badHash)) 'manifest records the hash'

    $stored = Join-Path $vault "objects\$badHash.q"
    Assert-True (Test-Path $stored) 'quarantined object exists under its hash'

    $null = & $Cli restore $badHash --quarantine-dir $vault
    Assert-True ($LASTEXITCODE -eq 0) 'restore command succeeds'
    Assert-True (Test-Path $bad) 'file is restored to its original path'
    $restoredHash = (Get-FileHash $bad -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($restoredHash -eq $badHash) 'restored file is byte-identical'

    Write-Host ''
    Write-Host 'all real-time decision tests passed'
}
finally {
    if ($hadConfig) { Set-Content -Path $configPath -Value $oldConfig }
    else { Remove-Item $configPath -ErrorAction SilentlyContinue }
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
