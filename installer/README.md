# RecoverKit installer

A standard Windows Installer (.msi) for RecoverKit, built with [WiX v6](https://wixtoolset.org).

The MSI installs RecoverKit into `Program Files\RecoverKit`, adds Start Menu and
desktop shortcuts, registers an App Paths entry (so `RecoverKit` launches from
Win+R and Start search), and shows up in Add/Remove Programs with the app icon,
supporting clean uninstall and in-place upgrades.

## Prerequisites

- Windows x64 (WiX is Windows-only; the macOS app is built by `macos/package.sh`).
- .NET 10 SDK (to publish the app).
- Windows PowerShell 5.1 or PowerShell 7. The default execution policy blocks
  scripts, hence `-ExecutionPolicy Bypass`. The build script installs the WiX CLI as a global dotnet tool on
  first run; nothing else is needed.

## Build

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File installer\build.ps1
```

This publishes the app and produces:

```
installer\out\RecoverKit-1.0.0-x64.msi
```

By default the publish is **self-contained**: the MSI carries the .NET runtime, so
the installed app runs on any 64-bit Windows with no prerequisites (larger MSI,
about 40 MB). For a small MSI that relies on the machine having the
.NET 10 Runtime:

```powershell
powershell -ExecutionPolicy Bypass -File installer\build.ps1 -FrameworkDependent
```

## Notes

- WiX v6 is pinned on purpose. v7 requires accepting a paid Open Source
  Maintenance Fee EULA; v6 is MIT-licensed and builds without any gate. The WiX
  CLI and its UI extension are pinned to the same version by the script.
- The installer artwork (`banner.bmp`, `dialog.bmp`) and `recoverkit.ico` are the
  same padlock motif as the app. Regenerate them from `assets/recoverkit.svg` if
  you change the icon.
- `installer\stage` (publish output) and `installer\out` (the MSI) are build
  artifacts and are git-ignored.
- Building the MSI must happen on Windows. WiX reports "undefined behavior" and
  fails with spurious path errors on macOS/Linux.
