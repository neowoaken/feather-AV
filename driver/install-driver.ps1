#Requires -Version 5.1
<#
  Installs and activates the featherflt read-only minifilter.

  Must run elevated. It will:
    1. Enable Windows test signing (required for a self-signed driver).
    2. Create/import a local test-signing certificate and trust it.
    3. Sign featherflt.sys.
    4. Copy the driver into System32\drivers.
    5. Register the service (auto-start) so it loads after the reboot.
    6. Report whether a reboot is still required.

  The driver only observes executable file activity; it never blocks or deletes.
#>
$ErrorActionPreference = 'Continue'

$scriptDir = $PSScriptRoot
# Source tree: driver/install-driver.ps1 -> driver/output/featherflt.sys
# Installed:   {app}\driver\install-driver.ps1 -> {app}\driver\featherflt.sys
$outDir = Join-Path $scriptDir 'output'
if (-not (Test-Path (Join-Path $outDir 'featherflt.sys'))) {
    $outDir = $scriptDir
}
$sys    = Join-Path $outDir 'featherflt.sys'
$inf    = Join-Path $outDir 'featherflt.inf'
$logDir = $outDir
$kit    = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64'
$signtool = Join-Path $kit 'signtool.exe'
if (-not (Test-Path $signtool)) {
    $found = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
    if ($found) { $signtool = $found.FullName }
}
$dest   = Join-Path $env:WINDIR 'System32\drivers\featherflt.sys'
$certSubject = 'CN=Feather AV Test Signing'
$serviceName = 'featherflt'
$logFile = Join-Path $logDir 'install-status.txt'
New-Item -ItemType Directory -Force -Path (Split-Path $logFile) | Out-Null
Start-Transcript -Path $logFile -Force | Out-Null

# --- require elevation ----------------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this script from an elevated PowerShell (Run as administrator).'
    exit 1
}

foreach ($f in @($sys, $signtool)) {
    if (-not (Test-Path $f)) { throw "Missing required file: $f" }
}

# --- 1. Secure Boot / test signing ---------------------------------------
$secureBoot = $false
try { $secureBoot = [bool](& Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }

$testSigning = $false
try {
    $bcd = & bcdedit /enum '{current}' 2>&1
    if ($bcd -match 'testsigning\s+Yes') { $testSigning = $true }
} catch { }

$rebootNeeded = $false
if (-not $testSigning) {
    if ($secureBoot) {
        Write-Host ''
        Write-Host 'BLOCKED: Secure Boot is enabled, so test signing cannot be turned on.'
        Write-Host 'To load this self-signed driver you must first disable Secure Boot in'
        Write-Host 'your UEFI firmware setup, then reboot into Windows and run this script'
        Write-Host 'again. The remaining steps will still be prepared below.'
        Write-Host ''
    } else {
        Write-Host 'Enabling test signing (a reboot is required)...'
        & bcdedit /set '{current}' testsigning on 2>&1 | Out-Host
        $rebootNeeded = $true
    }
} else {
    Write-Host 'Test signing is already enabled.'
}

# --- 2. certificate -------------------------------------------------------
# Use the CurrentUser store with an exportable CNG key: signtool reliably finds
# it there, and the elevated process runs as the same user.
$cert = Get-ChildItem 'Cert:\CurrentUser\My' |
        Where-Object { $_.Subject -eq $certSubject -and $_.HasPrivateKey } |
        Select-Object -First 1
if (-not $cert) {
    Write-Host 'Creating a local test-signing certificate...'
    $cert = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject $certSubject `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears(10) `
        -KeyExportPolicy Exportable `
        -FriendlyName 'Feather AV kernel test signing'
}
$thumb = $cert.Thumbprint

$certFile = Join-Path $logDir 'feather-test-signing.cer'
Export-Certificate -Cert $cert -FilePath $certFile -Force | Out-Null
foreach ($store in @('Root', 'TrustedPublisher')) {
    & certutil -addstore -f $store $certFile 2>&1 | Out-Host
}

# --- 3. sign --------------------------------------------------------------
Write-Host 'Signing the driver...'
& $signtool sign /s My /sha1 $thumb /fd sha256 /v $sys 2>&1 | Out-Host

# --- 4. copy --------------------------------------------------------------
Write-Host "Copying driver to $dest ..."
Copy-Item -LiteralPath $sys -Destination $dest -Force

# --- 5. service -----------------------------------------------------------
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    & sc.exe stop $serviceName 2>&1 | Out-Null
    & sc.exe delete $serviceName 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
}
Write-Host 'Registering the minifilter service (auto-start)...'
& sc.exe create $serviceName type= kernel start= auto displayname= 'Feather AV kernel monitor' binPath= $dest 2>&1 | Out-Host
& sc.exe description $serviceName 'Read-only executable activity monitor for Feather AV' 2>&1 | Out-Null
& sc.exe start $serviceName 2>&1 | Out-Host

# --- 6. report ------------------------------------------------------------
Write-Host ''
Write-Host '--- status ---'
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc) { Write-Host "service: $($svc.Status)" }
try { & fltmc filters 2>&1 | Select-String -Pattern 'featherflt|Filter Name' | Out-Host } catch { }

if ($secureBoot -and -not $testSigning) {
    Write-Host ''
    Write-Host 'RESULT: Driver staged but NOT loaded. Disable Secure Boot in UEFI, reboot,'
    Write-Host 'then re-run this script as administrator to activate the kernel monitor.'
} elseif ($rebootNeeded) {
    Write-Host ''
    Write-Host 'RESULT: Test signing enabled. REBOOT required; the driver will load at startup.'
} else {
    Write-Host ''
    Write-Host 'RESULT: No reboot needed. If the service did not start, check fltmc and re-run.'
}
Stop-Transcript | Out-Null
