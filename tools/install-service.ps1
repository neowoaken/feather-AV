#Requires -Version 5.1
<#
  Installs, reconfigures or removes the FeatherRT user-mode service. Called by
  the Inno Setup installer/uninstaller (and usable by hand). The script lives in
  {app}\tools, so the service binary is at ..\bin\feathersvc.exe.

  Keeping this in a script rather than an installer section means upgrades can
  repair the binary path instead of failing on "service already exists".
#>
param(
    [ValidateSet('install', 'uninstall')]
    [string]$Action = 'install'
)

$ErrorActionPreference = 'Stop'
$name = 'FeatherRT'
$display = 'Feather AV Real-Time Protection'
$description = 'Answers Feather AV on-access verdict requests'
$exe = Join-Path (Split-Path -Parent $PSScriptRoot) 'bin\feathersvc.exe'
if (-not (Test-Path $exe)) {
    $exe = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\Release\feathersvc.exe'
}

function Invoke-Sc {
    param([string[]]$Arguments)
    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "sc.exe $($Arguments -join ' ') failed: $output"
    }
}

if ($Action -eq 'uninstall') {
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
        Invoke-Sc @('stop', $name)
        Invoke-Sc @('delete', $name)
    }
    exit 0
}

if (-not (Test-Path $exe)) {
    throw "feathersvc.exe not found: $exe"
}

if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
    # Upgrade: repair the path in case the app was installed elsewhere.
    Invoke-Sc @('stop', $name)
    Invoke-Sc @('config', $name, 'binPath=', "`"$exe`"", 'start=', 'auto')
} else {
    Invoke-Sc @('create', $name, 'start=', 'auto', 'displayname=', "`"$display`"", 'binPath=', "`"$exe`"")
}
Invoke-Sc @('description', $name, "`"$description`"")
Invoke-Sc @('start', $name)

$service = Get-Service -Name $name -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "${name}: $($service.Status)"
} else {
    Write-Warning "$name was not registered. Real-time protection will be inactive."
}
