<#
.SYNOPSIS
    Build the RecoverKit MSI installer.

.DESCRIPTION
    Publishes the Avalonia app and packages it into a standard Windows Installer
    (.msi) with WiX v6. Run this on Windows x64 with the .NET 10 SDK installed.

    By default the publish is self-contained, so the installed app runs without a
    separate .NET runtime. Pass -FrameworkDependent for a much smaller MSI that
    requires the .NET 10 Runtime on the target machine.

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
    [switch]$AllowManagedOnly,
    # Use this hashcat .7z instead of downloading it (offline builds). It must match the pinned SHA-256.
    [string]$HashcatArchive
)

$ErrorActionPreference = 'Stop'
# WiX v6 is MIT-licensed and gate-free. v7 requires accepting a paid Open Source
# Maintenance Fee EULA, so this build pins v6. The tool and the UI extension must
# share the same version.
$WixVersion = '6.0.2'
# The WiX CLI targets net8.0; roll forward so it runs on a .NET 10-only machine.
$env:DOTNET_ROLL_FORWARD = 'Major'

# Pinned hashcat shipped inside every build (hashcat/ beside RecoverKit.exe). Keep in step with
# HashcatInstaller.Version; bump $HashcatBundleRevision when the bundle contents change for the same version.
$HashcatVersion = '8.0.0'
$HashcatSha256 = '9fa86e1bfd5dd898d3c83aa38a67b08db1ba5d2f5252dffa2af44a8c62585f49'
$HashcatBundleRevision = '1'
$HashcatUrl = "https://hashcat.net/files/hashcat-$HashcatVersion.7z"

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

# Bundle hashcat: the app copies hashcat/ (beside RecoverKit.exe) into the user's engines folder on first use.
Write-Host "==> Bundling hashcat $HashcatVersion" -ForegroundColor Cyan
$cacheDir = Join-Path $installerDir 'cache'
New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null

if ($HashcatArchive) {
    $archive = (Resolve-Path -LiteralPath $HashcatArchive).Path
}
else {
    $archive = Join-Path $cacheDir "hashcat-$HashcatVersion.7z"
    if (-not (Test-Path -LiteralPath $archive)) {
        Write-Host "    downloading $HashcatUrl"
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $oldProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try { Invoke-WebRequest -Uri $HashcatUrl -OutFile $archive -UseBasicParsing }
        finally { $ProgressPreference = $oldProgress }
    }
}

$actualSha = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($actualSha -ne $HashcatSha256) {
    if (-not $HashcatArchive) { Remove-Item -LiteralPath $archive -Force }
    throw "hashcat archive SHA-256 mismatch: expected $HashcatSha256, got $actualSha"
}

$sevenZip = $null
$cmd = Get-Command '7z.exe' -ErrorAction SilentlyContinue
if ($cmd) { $sevenZip = $cmd.Source }
else {
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $root) { continue }
        $candidate = Join-Path $root '7-Zip\7z.exe'
        if (Test-Path -LiteralPath $candidate) { $sevenZip = $candidate; break }
    }
}
if (-not $sevenZip) { throw '7z.exe was not found on PATH or in Program Files\7-Zip. Install 7-Zip to bundle hashcat.' }

$extractDir = Join-Path $cacheDir 'hashcat-extract'
if (Test-Path -LiteralPath $extractDir) { Remove-Item -LiteralPath $extractDir -Recurse -Force }
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
& $sevenZip x $archive "-o$extractDir" -y | Out-Null
if ($LASTEXITCODE -ne 0) { throw "7z extraction of the hashcat archive failed ($LASTEXITCODE)" }

$extracted = Join-Path $extractDir "hashcat-$HashcatVersion"
if (-not (Test-Path -LiteralPath (Join-Path $extracted 'hashcat.exe'))) {
    throw "hashcat-$HashcatVersion\hashcat.exe not found in the extracted archive"
}
$hashcatStage = Join-Path $stageDir 'hashcat'
Move-Item -LiteralPath $extracted -Destination $hashcatStage
Remove-Item -LiteralPath $extractDir -Recurse -Force

# The release archive carries Linux files too (hashcat.bin, libhashcat.so.8, bridges/feeds *.so); drop them.
Get-ChildItem -LiteralPath $hashcatStage -Recurse -File |
    Where-Object { $_.Name -eq 'hashcat.bin' -or $_.Name -like '*.so' -or $_.Name -like '*.so.*' -or $_.Name -like '*.dylib' } |
    Remove-Item -Force

# Stamp the bundle (no BOM, so the app reads it back exactly): <hashcat version>-<bundle revision>.
[System.IO.File]::WriteAllText((Join-Path $hashcatStage 'RECOVERKIT_BUNDLE'), "$HashcatVersion-$HashcatBundleRevision",
    (New-Object System.Text.UTF8Encoding($false)))

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
