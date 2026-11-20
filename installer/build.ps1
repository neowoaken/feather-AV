#Requires -Version 5.1
<#
  Builds the shipping installer (installer/output/feather-setup-<version>.exe).

  Prerequisites:
    - C++ toolchain + CMake (see README)
    - .NET 8 SDK
    - Inno Setup 6 (https://jrsoftware.org/isinfo.php)
#>
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# --- 1. scanner -----------------------------------------------------------
if (-not (Test-Path "build/Release/feather.exe")) {
    cmake -S . -B build
    cmake --build build --config $Configuration
}

# --- 2. GUI (self-contained) ---------------------------------------------
$stage = Join-Path $root "installer/stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null

dotnet publish (Join-Path $root "gui/Feather.Gui.csproj") `
    -c $Configuration -r win-x64 --self-contained true `
    -p:SatelliteResourceLanguages=en -p:DebugType=none -p:DebugSymbols=false `
    -o $stage

New-Item -ItemType Directory -Path (Join-Path $stage "bin") -Force | Out-Null
Copy-Item (Join-Path $root "build/Release/feather.exe") (Join-Path $stage "bin/feather.exe")
# Optional kernel monitor: ship the driver and its activation script.
$driverOut = Join-Path $root "driver\output"
if (Test-Path (Join-Path $driverOut "featherflt.sys")) {
    New-Item -ItemType Directory -Path (Join-Path $stage "driver") -Force | Out-Null
    Copy-Item (Join-Path $driverOut "featherflt.sys") (Join-Path $stage "driver/featherflt.sys")
    Copy-Item (Join-Path $driverOut "featherflt.inf") (Join-Path $stage "driver/featherflt.inf")
    Copy-Item (Join-Path $root "driver/install-driver.ps1") (Join-Path $stage "driver/install-driver.ps1")
}
Copy-Item (Join-Path $root "docs") (Join-Path $stage "docs") -Recurse
Copy-Item (Join-Path $root "rules") (Join-Path $stage "rules") -Recurse
Copy-Item (Join-Path $root "README.md") (Join-Path $stage "README.md")
Copy-Item (Join-Path $root "LICENSE") (Join-Path $stage "LICENSE")
Copy-Item (Join-Path $root "CHANGELOG.md") (Join-Path $stage "CHANGELOG.md")

# --- 3. compile installer --------------------------------------------------
$iscc = $null
foreach ($candidate in @(
    "C:\Users\$env:USERNAME\AppData\Local\Programs\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)) {
    if (Test-Path $candidate) { $iscc = $candidate; break }
}
if (-not $iscc) {
    $found = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($found) { $iscc = $found.Source }
}
if (-not $iscc) { throw "ISCC.exe not found. Install Inno Setup 6." }

& $iscc (Join-Path $root "installer/feather.iss")
if ($LASTEXITCODE -ne 0) { throw "installer build failed" }

Write-Host "`nbuilt: installer/output/feather-setup-0.3.4.exe"
