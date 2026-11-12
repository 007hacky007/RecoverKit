<#
.SYNOPSIS
    Build the RecoverKit MSI installer.

.DESCRIPTION
    Publishes the WinForms app and packages it into a standard Windows Installer
    (.msi) with WiX v6. Run this on Windows x64 with the .NET 10 SDK installed.

    By default the publish is self-contained, so the installed app runs without a
    separate .NET runtime. Pass -FrameworkDependent for a much smaller MSI that
    requires the .NET 10 Desktop Runtime on the target machine.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File installer\build.ps1
        Self-contained MSI at installer\out\RecoverKit-1.0.0-x64.msi

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File installer\build.ps1 -FrameworkDependent
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [string]$Version = '1.0.0',
    [switch]$FrameworkDependent,
    # Build without the native kernel library (the slower managed kernels run instead).
    [switch]$AllowManagedOnly
)

$ErrorActionPreference = 'Stop'
# WiX v6 is MIT-licensed and gate-free. v7 requires accepting a paid Open Source
# Maintenance Fee EULA, so this build pins v6. The tool and the UI extension must
# share the same version.
$WixVersion = '6.0.2'
# The WiX CLI targets net8.0; roll forward so it runs on a .NET 10-only machine.
$env:DOTNET_ROLL_FORWARD = 'Major'

$installerDir = $PSScriptRoot
$repoRoot = Split-Path -Parent $installerDir
$stageDir = Join-Path $installerDir 'stage'
$outDir = Join-Path $installerDir 'out'
$selfContained = -not $FrameworkDependent

Write-Host "==> Publishing RecoverKit ($([string]::Format('{0}, self-contained={1}', $Runtime, $selfContained)))" -ForegroundColor Cyan

if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
New-Item -ItemType Directory -Path $stageDir, $outDir -Force | Out-Null

$scArg = if ($selfContained) { 'true' } else { 'false' }
dotnet publish (Join-Path $repoRoot 'src/RecoverKit.App') `
    -c $Configuration `
    -r $Runtime `
    --self-contained $scArg `
    -p:PublishSingleFile=false `
    -p:Version=$Version `
    -p:FileVersion="$Version.0" `
    -o $stageDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed ($LASTEXITCODE)" }

# The fast CPU kernels live in rknative.dll, built by native/build.sh (zig, any host). Without it the
# app silently falls back to slower managed code, so refuse to package unless explicitly allowed.
if (-not (Test-Path (Join-Path $stageDir 'rknative.dll'))) {
    if ($AllowManagedOnly) { Write-Warning 'rknative.dll missing: packaging without the native kernels' }
    else { throw 'rknative.dll is missing. Run native/build.sh first, or pass -AllowManagedOnly.' }
}

# Ensure the pinned WiX v6 CLI is installed (update installs or re-pins the version).
Write-Host "==> Ensuring WiX CLI $WixVersion" -ForegroundColor Cyan
dotnet tool update --global wix --version $WixVersion
if ($LASTEXITCODE -ne 0) { throw "WiX tool install failed ($LASTEXITCODE)" }
$env:PATH = "$env:PATH;$HOME\.dotnet\tools"

# Pin the UI extension to the same version (a mismatched extension will not load).
wix extension remove -g WixToolset.UI.wixext 2>$null | Out-Null
wix extension add -g "WixToolset.UI.wixext/$WixVersion"
if ($LASTEXITCODE -ne 0) { throw "WiX UI extension install failed ($LASTEXITCODE)" }

$msi = Join-Path $outDir "RecoverKit-$Version-x64.msi"
Write-Host "==> Building $msi" -ForegroundColor Cyan

Push-Location $installerDir
try {
    wix build 'Package.wxs' `
        -arch x64 `
        -ext WixToolset.UI.wixext `
        -bindpath "StageDir=$stageDir" `
        -d "ProductVersion=$Version" `
        -o $msi
    if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }
}
finally {
    Pop-Location
}

Write-Host "==> Done: $msi" -ForegroundColor Green
