#Requires -Version 5.1
<#
  End-to-end smoke test. Uses a harmless file and its SHA-256 as the known-bad
  entry, so nothing malicious is downloaded or stored.
#>
param(
    [string]$Exe = (Join-Path $PSScriptRoot "..\build\Release\feather.exe")
)

$ErrorActionPreference = "Stop"

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAIL: $Message" }
    Write-Host "ok   $Message"
}

if (-not (Test-Path $Exe)) { throw "binary not found: $Exe" }

$work = Join-Path $env:TEMP ("feather-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
    # --- version ---------------------------------------------------------
    $version = & $Exe version
    Assert-True ($version -match "feather \d+\.\d+\.\d+") "version command"

    # --- hashing agrees with the OS --------------------------------------
    $payload = Join-Path $work "payload.txt"
    Set-Content -Path $payload -Value "feather smoke test payload" -NoNewline
    $expected = (Get-FileHash $payload -Algorithm SHA256).Hash.ToLower()
    $actual = (& $Exe hash $payload | Out-String).Trim()
    Assert-True ($actual -eq $expected) "sha256 matches Get-FileHash"

    # --- known-bad detection ---------------------------------------------
    $ioc = Join-Path $work "ioc.txt"
    Set-Content -Path $ioc -Value "sha256 $expected smoke-test entry"

    $json = Join-Path $work "out.json"
    & $Exe scan $payload --ioc $ioc --json $json --quiet | Out-Null
    Assert-True ($LASTEXITCODE -eq 2) "exit code 2 when malicious found"

    $report = Get-Content $json -Raw | ConvertFrom-Json
    Assert-True ($report.Count -eq 1) "one finding reported"
    Assert-True ($report[0].verdict -eq "malicious") "verdict is malicious"
    Assert-True ($report[0].hits[0].id -eq "hash.known_bad") "rule id is hash.known_bad"

    # --- exclusion suppresses unwanted, never malicious -------------------
    $fix = Join-Path $work "invoice.pdf.exe"
    Set-Content -Path $fix -Value "not on the ioc list" -NoNewline
    $allow = Join-Path $work "allow.txt"
    Set-Content -Path $allow -Value ("path " + $work + "\*  trusted folder")

    & $Exe scan $fix --allow $allow --all --json $json --quiet | Out-Null
    $report = Get-Content $json -Raw | ConvertFrom-Json
    Assert-True ($report[0].verdict -eq "clean") "exclusion suppresses unwanted"
    Assert-True ($report[0].suppressed -eq $true) "suppression is reported"

    & $Exe scan $payload --ioc $ioc --allow $allow --json $json --quiet | Out-Null
    $report = Get-Content $json -Raw | ConvertFrom-Json
    Assert-True ($report[0].verdict -eq "malicious") "exclusion cannot suppress malicious"

    # --- cache ------------------------------------------------------------
    $cache = Join-Path $work "cache.tsv"
    & $Exe scan $work --cache $cache --quiet | Out-Null
    $second = (& $Exe scan $work --cache $cache --quiet | Out-String)
    Assert-True ($second -match "from cache") "second scan uses the cache"

    Write-Host "`nall smoke tests passed"
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
