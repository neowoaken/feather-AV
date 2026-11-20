#Requires -Version 5.1
<#
  Builds the featherflt minifilter with the WDK command-line toolchain.
  Requires the Windows Driver Kit (winget id Microsoft.WindowsWDK.10.0.26100)
  and the Visual Studio 2022 C++ x64 tools.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root 'driver\featherflt'
$out  = Join-Path $root 'driver\output'
New-Item -ItemType Directory -Force -Path $out | Out-Null

$vsdev = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $vsdev)) { throw "VsDevCmd.bat not found: $vsdev" }

$ver = '10.0.26100.0'
$kit = "C:\Program Files (x86)\Windows Kits\10"
$inc = @(
    "$kit\Include\$ver\km",
    "$kit\Include\$ver\km\crt",
    "$kit\Include\$ver\shared",
    "$kit\Include\$ver\ucrt"
) -join ';'
$lib = @(
    "$kit\Lib\$ver\km\x64",
    "$kit\Lib\$ver\ucrt\x64"
) -join ';'

$cmd = @"
call "$vsdev" -arch=x64 -no_logo
set INCLUDE=$inc
set LIB=$lib
cd /d "$src"
cl /nologo /c /kernel /Ox /WX- /DWIN64 /D_WIN64 /D_AMD64_ /DAMD64 /DUNICODE /D_UNICODE /I"$kit\Include\$ver\km" /I"$kit\Include\$ver\shared" featherflt.c
if errorlevel 1 exit /b 1
link /nologo /driver /nodefaultlib /entry:DriverEntry /subsystem:native /machine:x64 /out:"$out\featherflt.sys" featherflt.obj fltMgr.lib ntoskrnl.lib hal.lib BufferOverflowK.lib
if errorlevel 1 exit /b 1
copy /Y featherflt.inf "$out\featherflt.inf" >nul
echo built: $out\featherflt.sys
"@

$cmd | Out-File -FilePath (Join-Path $out 'build.cmd') -Encoding ascii
cmd /c (Join-Path $out 'build.cmd')
