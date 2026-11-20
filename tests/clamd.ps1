#Requires -Version 5.1
<#
  Tests the ClamAV adapter against tests/mock-clamd.ps1.
  Proves the classification contract: ClamAV's PUA/HackTool verdicts become
  `unwanted`, real malware families become `malicious`, and "OK" stays clean.
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

$mock = (Resolve-Path (Join-Path $PSScriptRoot "mock-clamd.ps1")).Path
$work = Join-Path $env:TEMP ("feather-clamd-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work -Force | Out-Null

function Invoke-MockScan {
    param(
        [string]$Signature = "",
        [ValidateSet("found", "ok")][string]$Mode = "found",
        [string]$Cache = ""
    )

    $port = Get-Random -Minimum 20000 -Maximum 60000
    $ready = Join-Path $work ("ready-" + [guid]::NewGuid().ToString("N"))
    $job = Start-Job -FilePath $mock -ArgumentList $port, $Signature, $ready, $Mode

    try {
        $deadline = (Get-Date).AddSeconds(15)
        while (-not (Test-Path $ready)) {
            if ((Get-Date) -gt $deadline) {
                throw "mock clamd did not start: $(Receive-Job $job -Keep 2>&1)"
            }
            Start-Sleep -Milliseconds 50
        }

        $json = Join-Path $work "out.json"
        $argv = @("scan", $sample, "--clamd", "127.0.0.1:$port")
        if ($Cache) {
            $argv += @("--cache", $Cache)
        } else {
            $argv += "--no-cache"
        }
        $argv += @("--json", $json, "--quiet")

        & $Exe @argv | Out-Null
        $exit = $LASTEXITCODE

        $report = @()
        if ((Test-Path $json) -and (Get-Content $json -Raw).Trim().Length -gt 2) {
            $report = @(Get-Content $json -Raw | ConvertFrom-Json)
        }
        [pscustomobject]@{ Exit = $exit; Report = $report }
    }
    finally {
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        Remove-Item $ready -Force -ErrorAction SilentlyContinue
    }
}

$sample = Join-Path $work "sample.bin"
Set-Content -Path $sample -Value "clamav adapter test payload" -NoNewline

try {
    $pua = Invoke-MockScan -Signature "PUA.HackTool.OnlineFix-9876543-0"
    Assert-True ($pua.Report.Count -eq 1) "PUA finding reported"
    Assert-True ($pua.Report[0].verdict -eq "unwanted") "PUA/HackTool maps to unwanted"
    Assert-True ($pua.Report[0].hits[0].source -eq "clamav") "signal attributed to clamav"

    $trojan = Invoke-MockScan -Signature "Win.Trojan.Agent-1234567-0"
    Assert-True ($trojan.Report[0].verdict -eq "malicious") "trojan signature maps to malicious"
    Assert-True ($trojan.Exit -eq 2) "exit code 2 for malicious"

    $heur = Invoke-MockScan -Signature "Heuristics.Structured.Excel"
    Assert-True ($heur.Report[0].verdict -eq "unwanted") "heuristic signature maps to unwanted"

    $clean = Invoke-MockScan -Mode "ok"
    Assert-True ($clean.Exit -eq 0) "clean clamd reply keeps exit code 0"

    # A dead clamd must degrade, not fail the file.
    & $Exe scan $sample --clamd "127.0.0.1:1" --no-cache --all --json (Join-Path $work "down.json") --quiet | Out-Null
    $down = @(Get-Content (Join-Path $work "down.json") -Raw | ConvertFrom-Json)
    Assert-True ($down[0].warnings.Count -ge 1) "unreachable clamd is reported as a warning"
    Assert-True ($down[0].verdict -eq "clean") "unreachable clamd does not invent a verdict"

    # Regression: a verdict cached without ClamAV must not mask ClamAV later.
    $scopeCache = Join-Path $work "scope.tsv"
    & $Exe scan $sample --cache $scopeCache --quiet | Out-Null
    $scoped = Invoke-MockScan -Signature "PUA.HackTool.Scope-1" -Cache $scopeCache
    Assert-True ($scoped.Report[0].verdict -eq "unwanted") "cache is invalidated when the source set changes"

    Write-Host "`nall clamav adapter tests passed"
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
