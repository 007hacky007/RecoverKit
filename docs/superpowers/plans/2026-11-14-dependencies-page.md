# Dependencies Page and Bundled hashcat Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship hashcat inside every release and replace all scattered dependency prompts with one traffic-light page in the main window that appears at start only when something needs attention.

**Architecture:** Core gets a pure decision function (`DependencyCheck.Evaluate`) over a record of machine facts, a gatherer that collects those facts from the real machine (reusing hashcat's version and device list), and an installer that runs the existing installers in order. The App gets one `DependenciesPage` control shown as a top layer of the main pane; `MainWindow` drives it from start, Tools, actions and Preferences. The Windows build stages the official hashcat release next to `RecoverKit.exe`; at run time it is copied into the engines folder exactly as macOS does today.

**Tech Stack:** .NET 10, C#, Avalonia 12 (code-built UI, no XAML), xunit 2.9, PowerShell + WiX v6 for the Windows build, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-14-dependencies-page-design.md`

## Global Constraints

- RecoverKit's own update never appears on the page (toolbar Update button and `AppUpdater` are untouched).
- NVRTC and the Intel CPU runtime are not bundled; their pinned URLs and SHA-256 values in `NvrtcRuntime.cs` / `CpuRuntime.cs` do not change.
- No network during the start check.
- The user's own hashcat is never modified.
- Elevated processes keep ignoring per-user runtimes (`CpuRuntime.IsElevatedProcess`).
- Pinned hashcat: version `8.0.0`, archive `https://hashcat.net/files/hashcat-8.0.0.7z`, SHA-256 `9fa86e1bfd5dd898d3c83aa38a67b08db1ba5d2f5252dffa2af44a8c62585f49`, bundle stamp `8.0.0-1` (format `<hashcat version>-<bundle revision>`, file `RECOVERKIT_BUNDLE`).
- Generated text, docs and commit messages use only the ASCII hyphen-minus, never em or en dashes.
- Commits: one short imperative subject line, no body, no trailers, no AI attribution. Identity for this repo is already configured (`007hacky007`).
- Light and dark theme: use `Palette` brushes only, no literal colors.
- All tests run with `dotnet test tests/RecoverKit.Tests -c Release` and must stay green on macOS and Windows.

## Review Focus

1. **Bundle copy fails at start** (disk full, antivirus removes `hashcat.exe` mid-copy): the app must still open, the hashcat row is red with the error text, "Install all" retries the copy. Test pinned in Task 4 (`HashcatRedWithErrorWhenBundleCopyFailed`) and Task 5 (`FailedItemDoesNotStopTheOthers`).
2. **Upgrading Windows user whose `Settings.HashcatPath` points at `engines/hashcat-7.1.2/hashcat.exe`** (downloaded by an earlier RecoverKit): `Locate` must pick the bundled 8.0.0 copy and no yellow "use bundled" row may appear. Test in Task 1 (`ConfiguredOldManagedCopyGivesWayToTheBundleOnWindowsLayout`) and Task 4 (`ManagedOlderCopyIsNotOfferedAsSwitch`).
3. **hashcat present but fails to run** (`--version` times out, crashes, Win32Exception): no exception escapes the check; the hashcat row is red with the message and the other rows are "pending". Test in Task 4 (`HashcatThatFailsToRunIsRedAndOthersPending`).
4. **Unfixable yellow rows** (running as administrator with an NVIDIA GPU, NVIDIA driver older than CUDA 12.4): must not bring the page up at every start, since the user can do nothing on it. Test in Task 4 (`UninstallableYellowDoesNotShowAtStart`).
5. **Cancel during "Install all"**: stops the current download, leaves no `.partial` folder, rows not yet installed keep their previous light, the page stays open. Test in Task 5 (`CancelStopsTheRemainingItems`).

---

### Task 1: Find the bundled hashcat on Windows too

**Files:**
- Modify: `src/RecoverKit.Core/Hashcat/HashcatInstaller.cs:130-151` (`ExeName`, `BundledDirectory`, `FindBundle`)
- Modify: `src/RecoverKit.Core/Hashcat/HashcatTool.cs:93-115` (`Locate`)
- Test: `tests/RecoverKit.Tests/BundledHashcatTests.cs` (new)

**Interfaces:**
- Produces: `internal static string HashcatInstaller.ExeName` (`hashcat.exe` on Windows, `hashcat` elsewhere); `public static string? HashcatInstaller.BundledDirectory` now non-null on any OS when `FindBundle(AppContext.BaseDirectory)` finds a folder; `internal static string? HashcatInstaller.FindBundle(string baseDir)` checks `baseDir/../Resources/hashcat` then `baseDir/hashcat`, requiring `ExeName` and `RECOVERKIT_BUNDLE` inside.

- [ ] **Step 1: Write the failing tests** in `BundledHashcatTests.cs` (temp-dir helpers like `MacHashcatTests.MakeApp`, but with an app folder that has `hashcat/` beside the exe):
  - `BundleIsFoundBesideTheExecutable`: `FindBundle(appDir)` returns the full path of `appDir/hashcat` when it holds `ExeName` and the stamp `8.0.0-1`; returns null after the stamp is deleted.
  - `LocateNeverRunsTheCopyBesideTheExecutable`: with only the bundle present, `HashcatTool.Locate(null, appDir, engines)` is null; after `new HashcatInstaller(engines).TryInstallBundledHere(bundle, null, default)` it returns `engines/hashcat-8.0.0/<ExeName>`.
  - `UnstampedEnginesCopyIsReplacedByTheBundle`: an `engines/hashcat-8.0.0` with an exe and no stamp makes `BundleNeedsInstall(bundle)` true; after `TryInstallBundledHere` the engines copy has stamp `8.0.0-1`.
  - `ConfiguredOldManagedCopyGivesWayToTheBundleOnWindowsLayout`: configured `engines/hashcat-7.1.2/<ExeName>` exists; after installing the bundle, `Locate(configured, appDir, engines)!.Exe` is the `hashcat-8.0.0` exe.

- [ ] **Step 2: Run to verify they fail**
  Run: `dotnet test tests/RecoverKit.Tests -c Release --filter BundledHashcatTests`
  Expected: `BundleIsFoundBesideTheExecutable` and `LocateNeverRunsTheCopyBesideTheExecutable` fail (`FindBundle` checks the literal `hashcat`, and `Locate` probes `baseDir/hashcat` off macOS).

- [ ] **Step 3: Implement.** In `HashcatInstaller`: make `ExeName` internal, use it in `FindBundle`, and drop the `OperatingSystem.IsMacOS()` guard from `BundledDirectory`. In `HashcatTool.Locate`: compute `bundle` with `HashcatInstaller.FindBundle(baseDir)` on every OS, and add the pinned engines candidate when `bundle is not null || OperatingSystem.IsMacOS() || File.Exists(pinned)`.

- [ ] **Step 4: Run the whole suite**
  Run: `dotnet test tests/RecoverKit.Tests -c Release`
  Expected: PASS, including the existing `MacHashcatTests`.

- [ ] **Step 5: Commit** - `git commit -m "Find the bundled hashcat beside the executable"`

### Task 2: Remove the hashcat download and the 7-Zip extractor

**Files:**
- Modify: `src/RecoverKit.Core/Hashcat/HashcatInstaller.cs` (delete `ArchiveUrl`, `ArchiveSha256`, `ArchiveSize`, `SevenZrUrl`, `SevenZrSha256`, `SevenZipOverride`, `EnsureSevenZipAsync`, `FindSevenZip`, `ExtractAsync`, `BinaryNames`; rewrite `InstallAsync`; keep `DownloadAsync`, `InstallProgress`, `InstallException`)
- Modify: `src/RecoverKit.Cli/Program.cs:190-235` (`install-hashcat`) and the `crack` "hashcat not found" message
- Test: `tests/RecoverKit.Tests/BundledHashcatTests.cs`

**Interfaces:**
- Consumes: Task 1's `BundledDirectory`.
- Produces: `public Task<HashcatInstallResult> HashcatInstaller.InstallAsync(IProgress<InstallProgress>? progress = null, CancellationToken ct = default)` copies `BundledDirectory` (via `CopyBundle`) on every OS and throws `InstallException(HashcatInstaller.NoBundleMessage)` when there is none. `public const string HashcatInstaller.NoBundleMessage` = "This copy of RecoverKit does not include hashcat. Install hashcat 8 with your package manager, set its location in Preferences > Files and Paths, or run 'recoverkit-cli install-hashcat --from <folder>'."

- [ ] **Step 1: Write the failing test** `InstallWithoutBundleExplainsWhatToDo`: `new HashcatInstaller(tempEngines)` in the test host (no bundle beside the test binaries) - `await Assert.ThrowsAsync<InstallException>(() => inst.InstallAsync())` and the message equals `HashcatInstaller.NoBundleMessage`.

- [ ] **Step 2: Run to verify it fails**
  Run: `dotnet test tests/RecoverKit.Tests -c Release --filter InstallWithoutBundleExplainsWhatToDo`
  Expected: FAIL on macOS (macOS message differs), or a network attempt on Windows.

- [ ] **Step 3: Implement** the rewrite above. CLI: `install-hashcat` without `--from` calls `InstallAsync` (bundle copy). With no bundle it prints the exception message and returns 3. The `crack` message becomes "hashcat not found. Pass --hashcat <path>, or run 'recoverkit-cli install-hashcat --from <folder>'." Update the class summary comment to say hashcat is bundled in every release.

- [ ] **Step 4: Verify that nothing still references the removed members, then run the suite**
  Run: `grep -rn "SevenZ\|ArchiveUrl\|ArchiveSha256" src tests --include='*.cs'` (expect only `SevenZipExtractor`/`SevenZipLzma` hits, which are the 7z format code), then `dotnet build RecoverKit.sln -c Release && dotnet test tests/RecoverKit.Tests -c Release`.
  Expected: the whole solution builds (the App's `HashcatDownloadWindow` still calls `InstallAsync`, whose signature is unchanged; Task 7 deletes it), and the tests PASS.

- [ ] **Step 5: Commit** - `git commit -m "Install hashcat only from the bundled copy"`

### Task 3: Bundle hashcat in the Windows build

**Files:**
- Modify: `installer/build.ps1` (new section after the `rknative.dll` check)
- Modify: `.github/workflows/build.yml` (windows job: cache step)
- Modify: `.gitignore` (add `installer/cache/`)
- Test: `tests/RecoverKit.Tests/BundledHashcatTests.cs`

**Interfaces:**
- Consumes: the constants listed in Global Constraints.
- Produces: `installer/stage/hashcat/` containing the Windows files of the official release plus `RECOVERKIT_BUNDLE` = `8.0.0-1`. `Package.wxs` already harvests `stage/**`, and the portable zip compresses `stage/*`, so neither changes.

- [ ] **Step 1: Write the failing test** `WindowsBuildPinsTheSameHashcatAsTheApp`: read `installer/build.ps1` (walk up from `AppContext.BaseDirectory` to the folder containing `RecoverKit.sln`), assert it contains `$HashcatVersion = '` + `HashcatInstaller.Version` + `'` and the SHA-256 from Global Constraints.

- [ ] **Step 2: Run to verify it fails**
  Run: `dotnet test tests/RecoverKit.Tests -c Release --filter WindowsBuildPinsTheSameHashcatAsTheApp`
  Expected: FAIL (string not found).

- [ ] **Step 3: Implement the build section.** Variables `$HashcatVersion = '8.0.0'`, `$HashcatSha256 = '<sha>'`, `$HashcatBundleRevision = '1'`, URL from the constant. Add a `-HashcatArchive <path>` parameter for offline builds. Steps: download to `installer/cache/hashcat-8.0.0.7z` unless it is already there; verify with `Get-FileHash -Algorithm SHA256` and throw on mismatch (deleting the file); extract with `7z x` (find `7z.exe` on PATH or in `$env:ProgramFiles\7-Zip`, and throw a clear error if it is missing) into a temp folder; move `hashcat-8.0.0` to `stage/hashcat`; delete `hashcat.bin` and every `*.so` / `*.dylib` under it; write `RECOVERKIT_BUNDLE` with `"$HashcatVersion-$HashcatBundleRevision"` (ASCII, no BOM). In `build.yml`, add `actions/cache@v4` for `installer/cache` with key `hashcat-win-${{ hashFiles('installer/build.ps1') }}` before "Build installer".

- [ ] **Step 4: Run the test, then the script if a Windows host is available**
  Run: `dotnet test tests/RecoverKit.Tests -c Release --filter WindowsBuildPinsTheSameHashcatAsTheApp`, Expected: PASS.
  On Windows: `powershell -ExecutionPolicy Bypass -File installer\build.ps1 -Version 0.0.1`, then check that `installer\stage\hashcat\hashcat.exe` and `RECOVERKIT_BUNDLE` exist and that there's no `hashcat.bin`. Without a Windows host, push the branch and confirm the CI windows job succeeds and its artifact zip contains `hashcat/hashcat.exe`.

- [ ] **Step 5: Commit** - `git commit -m "Bundle hashcat in the Windows installer and zip"`

### Task 4: Dependency decision table

**Files:**
- Create: `src/RecoverKit.Core/Dependencies/DependencyItem.cs`, `src/RecoverKit.Core/Dependencies/DependencyCheck.cs`
- Modify: `src/RecoverKit.Core/Settings.cs:92-96` (add `SkippedDependencies`; `DeclinedHashcatUpgrade` stays until Task 7 removes its last use)
- Test: `tests/RecoverKit.Tests/DependencyCheckTests.cs` (new)

**Interfaces:**
- Produces (namespace `RecoverKit.Core.Dependencies`):
  - `public enum Light { Green, Yellow, Red }`
  - `public enum DependencyId { Hashcat, Nvrtc, CpuRuntime }` (also the install order)
  - `public enum DependencyAction { None, CopyBundledHashcat, UseBundledHashcat, DownloadNvrtc, DownloadCpuRuntime }`
  - `public sealed record DependencyItem(DependencyId Id, string Name, Light Light, string Reason, DependencyAction Action, long DownloadBytes = 0, string? LicenseName = null, string? LicenseUrl = null, string? SkipKey = null, bool Pending = false, NvrtcRuntime.Package? NvrtcPackage = null) { public bool Installable => Action != DependencyAction.None; }`
  - `public sealed record MachineFacts` with init properties: `bool IsWindows`, `bool BundleAvailable`, `string? BundleCopyError`, `string? HashcatExe`, `bool HashcatIsManaged`, `string? HashcatVersion` (raw `--version` output), `string? HashcatError`, `IReadOnlyList<BackendDevice>? Devices`, `(int Major, int Minor)? NvidiaDriverCuda`, `bool NvidiaDriverPresent`, `bool NvrtcInstalled`, `bool CpuRuntimeInstalled`, `bool Elevated`, `DeviceStrategy Strategy`, `bool HashcatCpuWithGpu`.
  - `public static IReadOnlyList<DependencyItem> DependencyCheck.Evaluate(MachineFacts f)`: the hashcat row always; NVRTC and CPU runtime rows only when `f.IsWindows`.
  - `public static bool DependencyCheck.ShouldShowAtStart(IReadOnlyList<DependencyItem> items, IReadOnlyCollection<string> skipped)`: true when any row is `Red`, or `Yellow && Installable && SkipKey not in skipped`.
  - `Settings.SkippedDependencies : List<string>` (default empty).

Decision rules (the spec's traffic-light section, made exact):
- **hashcat**
  - Red, `CopyBundledHashcat`: `HashcatExe` null and `BundleAvailable`. Reason is `BundleCopyError` when set.
  - Red, `None`: `HashcatExe` null and no bundle (Reason = `HashcatInstaller.NoBundleMessage`).
  - Red, `None`: `HashcatError` set (Reason = the error).
  - Yellow, `UseBundledHashcat`: `HashcatTool.IsOlderThanPinned(HashcatVersion)` and `!HashcatIsManaged` and `BundleAvailable`. SkipKey `hashcat|{HashcatExe}|{version}`.
  - Yellow, `None`: older and no bundle.
  - Otherwise Green.
- **NVRTC** (Windows): `Pending` when hashcat is not green-or-yellow-runnable (no devices).
  - Green "Not needed": no NVIDIA device among `Devices`, or any device with `Backend == "CUDA"`.
  - Green: `NvrtcInstalled`.
  - Yellow, `None`: `Elevated` (per-user runtimes are ignored).
  - Yellow, `None`: `NvrtcRuntime.Choose(NvidiaDriverCuda)` is null (driver too old or unknown).
  - Otherwise Yellow, `DownloadNvrtc`, with package, size, NVIDIA license and SkipKey `nvrtc|{package.Version}`.
- **CPU runtime** (Windows): `Pending` as above.
  - Green: `CpuRuntimeInstalled && !Elevated`.
  - Red: no usable device (`Devices` empty after `IsSkippedAlias`), or `Strategy == CpuOnly` and no CPU device. Action `DownloadCpuRuntime`, or `None` when `Elevated`.
  - Yellow, `DownloadCpuRuntime`: `HashcatCpuWithGpu` and no CPU device. SkipKey `cpu-runtime|{CpuRuntime.Version}`.
  - Otherwise Green "Not needed: a GPU driver is installed".
  - Size: `CpuRuntime.DownloadBytes`; Intel license.

- [ ] **Step 1: Write the failing tests** (build `MachineFacts` directly; devices via `HashcatTool.ParseDevices` on small `-I` snippets like those in `MacHashcatTests`):
  - `EverythingGreenOnMacWithBundle` - one row, Green; `ShouldShowAtStart` false.
  - `HashcatRedWithErrorWhenBundleCopyFailed` - `BundleCopyError = "Disk full"` gives Red, `CopyBundledHashcat`, Reason contains "Disk full".
  - `NoBundleOnSourceBuildIsRedWithInstructions` - Red, `None`, Reason == `NoBundleMessage`.
  - `HashcatThatFailsToRunIsRedAndOthersPending` - Windows, `HashcatError = "timed out"`: hashcat Red; NVRTC and CPU runtime `Pending`.
  - `UsersOlderHashcatOffersSwitchToBundled` - `HashcatVersion = "v7.1.2"`, not managed, bundle: Yellow, `UseBundledHashcat`, SkipKey contains the exe and `v7.1.2`.
  - `ManagedOlderCopyIsNotOfferedAsSwitch` - `HashcatIsManaged = true`, `v7.1.2`, bundle: Green (Locate already prefers the bundle).
  - `NvidiaOnOpenClWithNewDriverOffersNvrtc` - Windows, NVIDIA OpenCL device, CUDA (12,8): Yellow, `DownloadNvrtc`, package `12.8.93`, SkipKey `nvrtc|12.8.93`, LicenseName == `NvrtcRuntime.LicenseName`.
  - `CudaDeviceMeansNvrtcNotNeeded` - Green.
  - `OldNvidiaDriverIsYellowWithoutAction` - (12,2): Yellow, `None`.
  - `UninstallableYellowDoesNotShowAtStart` - elevated plus NVIDIA: NVRTC Yellow `None`; `ShouldShowAtStart(items, [])` false.
  - `NoDeviceAtAllNeedsCpuRuntime` - Windows, empty devices: CPU Red, `DownloadCpuRuntime`, Intel license; `ShouldShowAtStart` true.
  - `CpuWithGpuWithoutCpuDeviceIsYellow` - GPU device only, `HashcatCpuWithGpu = true`: Yellow, SkipKey `cpu-runtime|2026.1.2`.
  - `SkippedYellowDoesNotShowButRedAlwaysDoes` - skipped `nvrtc|12.8.93`: false; adding a red row: true.
  - `SkipIsForgottenWhenTheChosenPackageChanges` - skipped `nvrtc|12.4.127`, driver now (12,8): `ShouldShowAtStart` true.

- [ ] **Step 2: Run to verify they fail**
  Run: `dotnet test tests/RecoverKit.Tests -c Release --filter DependencyCheckTests`
  Expected: compile failure (types missing).

- [ ] **Step 3: Implement** the types and `Evaluate` per the rules above, and add `Settings.SkippedDependencies`. Reasons are one plain sentence each (wording is the builder's choice).

- [ ] **Step 4: Run the tests**
  Run: `dotnet test tests/RecoverKit.Tests -c Release`
  Expected: PASS.

- [ ] **Step 5: Commit** - `git commit -m "Decide which dependencies need attention"`

### Task 5: Gather facts and install from Core

**Files:**
- Create: `src/RecoverKit.Core/Dependencies/DependencyScan.cs`, `src/RecoverKit.Core/Dependencies/DependencyInstaller.cs`
- Test: `tests/RecoverKit.Tests/DependencyInstallerTests.cs` (new)

**Interfaces:**
- Consumes: Task 4's types; `HashcatTool.Locate/VersionAsync/DevicesAsync`; `HashcatInstaller.TryInstallBundled`, `BundledDirectory`, `ExpectedDirectory`; `NvrtcRuntime.InstallAsync/DriverCudaVersion/Locate`; `CpuRuntime.InstallAsync/Locate/IsElevatedProcess`; `NvidiaSmi.Locate`.
- Produces:
  - `public sealed record DependencyScan(MachineFacts Facts, HashcatTool? Tool, string HashcatVersion, List<BackendDevice> Devices, IReadOnlyList<DependencyItem> Items)`
  - `public static Task<DependencyScan> DependencyScan.RunAsync(Settings settings, string? bundleCopyError = null, CancellationToken ct = default)`. Locates hashcat, runs `--version` and `-I` (catching `TimeoutException`, `Win32Exception`, `InvalidOperationException` into `HashcatError`), queries `nvidia-smi` only when `NvidiaSmi.Locate()` is non-null, then `Evaluate`. It never throws for machine problems.
  - `public sealed class DependencyInstaller(Settings settings, Func<DependencyItem, IProgress<InstallProgress>?, CancellationToken, Task>? run = null)`. The default `run` dispatches on `Action`. `CopyBundledHashcat` uses `new HashcatInstaller().InstallAsync`. `UseBundledHashcat` copies the bundle if needed, then sets `settings.HashcatPath` to the engines exe and calls `settings.Save()`. `DownloadNvrtc` uses `NvrtcRuntime.InstallAsync(item.NvrtcPackage!)`. `DownloadCpuRuntime` uses `CpuRuntime.InstallAsync`.
  - `public Task<IReadOnlyList<(DependencyItem Item, Exception? Error)>> DependencyInstaller.InstallAllAsync(IEnumerable<DependencyItem> items, IProgress<(DependencyItem Item, InstallProgress Progress)>? progress, CancellationToken ct)`. Runs the installable items ordered by `Id`. An `InstallException` / `IOException` / `HttpRequestException` is recorded and the next item runs. `OperationCanceledException` propagates and stops the remaining items.

- [ ] **Step 1: Write the failing tests** with a fake `run`:
  - `ItemsInstallInDependencyOrder` - given CPU runtime, hashcat, NVRTC (shuffled): the recorded call order is `Hashcat, Nvrtc, CpuRuntime`; non-installable items are not called.
  - `FailedItemDoesNotStopTheOthers` - hashcat throws `InstallException("x")`: the result has hashcat with an error and NVRTC with a null error, both called.
  - `CancelStopsTheRemainingItems` - the first item cancels its token: `ThrowsAsync<OperationCanceledException>`, and the second item is never called.
  - `UseBundledPointsSettingsAtTheEnginesCopy` - `DependencyInstaller.PointAtEnginesCopy(settings, enginesExe)` sets `settings.HashcatPath` to `enginesExe` (helper is `internal static void PointAtEnginesCopy(Settings s, string enginesExe)`; the default `run` calls it after the bundle copy, since `Settings.AppDataDir` is fixed per user).

- [ ] **Step 2: Run to verify they fail**
  Run: `dotnet test tests/RecoverKit.Tests -c Release --filter DependencyInstallerTests`
  Expected: compile failure.

- [ ] **Step 3: Implement** `DependencyScan.RunAsync` and `DependencyInstaller`. Log the scan result (one `DebugLog.Info` line per row) and each install start, end and error.

- [ ] **Step 4: Run the tests**
  Run: `dotnet test tests/RecoverKit.Tests -c Release`
  Expected: PASS.

- [ ] **Step 5: Commit** - `git commit -m "Scan and install dependencies in one pass"`

### Task 6: The dependencies page control

**Files:**
- Create: `src/RecoverKit.App/Views/DependenciesPage.cs`

**Interfaces:**
- Consumes: Task 4 and Task 5 types.
- Produces:
  - `public enum DependenciesOutcome { Installed, Skipped }`
  - `public sealed class DependenciesPage : UserControl`
  - `public DependenciesPage(IReadOnlyList<DependencyItem> items, IReadOnlyCollection<string> skipped, Func<Task<IReadOnlyList<DependencyItem>>> rescan, DependencyInstaller installer)`
  - `public Task<(DependenciesOutcome Outcome, IReadOnlyList<string> NewlySkipped)> Completion`. `NewlySkipped` holds the SkipKeys of installable yellow rows that were unchecked when "Install all" ran, or all installable yellow rows on "Skip for now".
  - `public bool Installing { get; }`
  - `public void Skip()`, which completes as `Skipped` and is ignored while installing.

Layout follows the picked mockup A (`.superpowers/brainstorm/*/content/dependencies-layout.html`):
- Heading "Getting RecoverKit ready" and one dim line of explanation.
- Rows: a 12 px light (`Palette.GoodBrush` / `WarnBrush` / `BadTextBrush`, each with its soft brush as a 3 px ring), the name in bold, the reason dim, the size right-aligned (`Fmt` helpers), and a `CheckBox` for installable non-green rows. Red rows are checked and disabled. Yellow rows are checked unless their SkipKey is in `skipped`. Pending rows show the light in `DimBrush` with "Checked once hashcat is ready".
- One license `CheckBox` per checked row with a license, with a `HyperlinkButton` to its URL. These hide when the row is unchecked.
- Footer: "{total} to download" dim, "Check again" link (calls `rescan` and rebuilds the rows), "Skip for now", and the accent "Install all", enabled when at least one row is checked and every visible license is accepted.
- Installing: checkboxes are disabled, "Skip for now" becomes "Cancel", and there's a `ProgressBar` with a status line driven by `InstallProgress` ("Downloading NVIDIA NVRTC 12.8.93... 38%"). Each finished row turns green. A failed row turns red with the exception message as its reason. After `InstallAllAsync`, call `rescan`. If no row is Red and no installable unskipped Yellow is left, complete as `Installed`; otherwise show the new rows and stay open. Cancel calls `Cts.Cancel()`, shows "Cancelled.", and stays open.

- [ ] **Step 1: Implement the control** using the existing `Layout`/`L` helpers, `Palette` and `Ui.Styles` patterns from `SmallDialogs.cs` and `MainWindow.BuildPane`.

- [ ] **Step 2: Build**
  Run: `dotnet build src/RecoverKit.App -c Release`
  Expected: build succeeds.

- [ ] **Step 3: Commit** - `git commit -m "Add the dependencies page"`

### Task 7: Wire the page into the main window and remove the old prompts

**Files:**
- Modify: `src/RecoverKit.App/Views/MainWindow.cs` (pane grid at `BuildPane` ~344-387, `Opened` ~137-153, Tools menu ~224-227, `InitHashcatAsync` ~568-626, `RequireHashcatAsync` and the Offer/Download methods ~676-805, `OpenFileAsync` entry, attack failure ~1248-1251, `ShowPreferences` ~1408-1423)
- Modify: `src/RecoverKit.App/Views/SmallDialogs.cs` (delete `HashcatDownloadWindow`, `CpuRuntimeDownloadWindow`, `NvrtcDownloadWindow`; keep `ProgressDialog` for `UpdateWindow`)
- Modify: `src/RecoverKit.App/Views/PreferencesWindow.cs:231,364-380`
- Modify: `src/RecoverKit.Core/Settings.cs:92-96` (delete `DeclinedHashcatUpgrade`)
- Modify: `src/RecoverKit.Core/Hashcat/HashcatKernels.cs:154`, `src/RecoverKit.Core/Hashcat/HashcatRunner.cs:260,324`

**Interfaces:**
- Consumes: everything above.
- Produces (MainWindow, private): `enum DepsTrigger { Startup, User, NeedHashcat, NeedCpu }` and `Task<bool> ShowDependenciesAsync(DepsTrigger trigger, IReadOnlyList<DependencyItem>? items = null)`. The result is true when the hashcat row (`NeedHashcat`) or the CPU runtime row (`NeedCpu`) is green afterwards, and for other triggers true when the outcome is `Installed`.

Behavior to implement:
- Pane: add `_depsLayer` (a `Border` with `PaneBrush` background) as the last child of the `BuildPane` grid, hidden by default. `ShowDependenciesAsync` puts a new `DependenciesPage` into it, shows it, sets the pill to `PillState.Problem` "Setup needed", and awaits `Completion`. Afterwards it hides the layer. For `Startup`, it appends `NewlySkipped` to `_settings.SkippedDependencies` (distinct) and saves. If anything was installed it runs `InitHashcatAsync(showPage: false)`. It calls `ShowStartPage()` when `_current is null` and opens `_pendingOpen` if one is set. A second call while a page is open returns the current page's `Completion` mapped to bool.
- Start: `InitHashcatAsync(bool showPage = true)` runs `PrepareBundledHashcatAsync()`. If the copy failed it passes the logged error into `DependencyScan.RunAsync(_settings, bundleCopyError)`. Have `TryInstallBundled` return the error text: add `public static string? HashcatInstaller.TryInstallBundledError(...)`, returning null on success, alongside the bool API. From the scan it takes `_hashcat`, `_hashcatVersion` and `_devices`, keeps the existing device lines, pill and log output, and replaces every Offer call and "Tools > Download" notice with one line: "Some components need attention: Tools > Dependencies." This line shows when any row is not green. When `showPage && ShouldShowAtStart(items, _settings.SkippedDependencies)`, it posts `ShowDependenciesAsync(DepsTrigger.Startup, items)`. The `Opened` handler opens the pending file only when no page is shown.
- Tools menu: one idle-only item `"_Dependencies..."` calling `ShowDependenciesAsync(DepsTrigger.User)`, which rescans first. It replaces the three download items.
- `RequireHashcatAsync()` returns `_hashcat is not null || await ShowDependenciesAsync(DepsTrigger.NeedHashcat)`. The existing callers continue unchanged.
- Attack failure (both branches at ~1248-1251): post `ShowDependenciesAsync(DepsTrigger.NeedCpu)`.
- `ShowPreferences`: after save, when `OperatingSystem.IsWindows()` and (`Strategy == CpuOnly` or `HashcatCpuWithGpu`) changed to on and `CpuRuntime.Locate()` is null, call `ShowDependenciesAsync(DepsTrigger.NeedCpu)`.
- `OpenFileAsync` entry: if a page is shown and `Installing`, set `_pendingOpen = path` and return; if shown and idle, call `page.Skip()` and continue.
- Remove `OfferHashcatDownloadAsync`, `OfferHashcatUpgradeAsync`, `OfferCpuRuntimeAsync`, `DownloadHashcatAsync`, `DownloadCpuRuntimeAsync`, `DownloadNvrtcAsync`, `_offeredDownload`, `_offeredUpgrade`, `_offeredCpuRuntime`, and `NoDevicesNotice`'s offer (keep its notice text, pointing at Tools > Dependencies).
- Preferences: replace the hashcat "Install/Download" button with "Default", which clears the path field and sets `HashcatChanged = true`. Line 231 text: "Tools > Dependencies".
- Core texts: `HashcatKernels.cs:154` becomes "...Tools > Dependencies switches to hashcat 8.0.0."; `HashcatRunner.cs:260` becomes "Install it with Tools > Dependencies..."; `HashcatRunner.cs:324` becomes "...use Tools > Dependencies to enable CUDA."

- [ ] **Step 1: Implement** the changes above.

- [ ] **Step 2: Build and check that no stale strings remain**
  Run: `dotnet build RecoverKit.sln -c Release && grep -rn "Tools > Download\|Tools > Install\|DeclinedHashcatUpgrade\|DownloadWindow" src --include='*.cs'`
  Expected: the build succeeds and grep prints nothing.

- [ ] **Step 3: Run the tests**
  Run: `dotnet test tests/RecoverKit.Tests -c Release`
  Expected: PASS.

- [ ] **Step 4: Run the app on macOS and check the paths by hand**
  Run: `dotnet run --project src/RecoverKit.App -c Debug`. Check the following:
  - With hashcat present, there is no page and the start page is as before.
  - With `HashcatPath` set to a nonexistent file and `engines/hashcat-8.0.0` renamed, the page shows a red hashcat row. On a development build without a bundle, the reason is `NoBundleMessage`.
  - Tools > Dependencies shows all rows green.
  - Dropping a file while the page is shown closes it and opens the file.
  Take screenshots in light and dark mode (the `Snapshots` debug hooks, if they cover it).
  On Windows (winbench VM, if available), install the CI-built MSI on a clean snapshot. There should be no page if a GPU driver is present; the VM has none, so expect a red CPU runtime row. "Install all" with the license accepted should end with a green row and the CPU device listed.

- [ ] **Step 5: Commit** - `git commit -m "Show one dependencies page instead of separate prompts"`

### Task 8: Documentation

**Files:**
- Modify: `README.md`, `docs/DEVELOPERS.md` (hashcat install, NVRTC section ~329, CPU runtime section), `installer/README.md` (hashcat staging, `-HashcatArchive`, 7-Zip needed on the build machine), `NOTICE` (hashcat bundled in all releases, 7-Zip extractor removed), `CHANGELOG.md` (`## [Unreleased]`: Added - dependencies page and bundled hashcat on Windows; Removed - hashcat download, 7-Zip extractor download, the three Tools download items).

- [ ] **Step 1: Update the files above**, describing the page as it now behaves. Use only ASCII hyphens.

- [ ] **Step 2: Check for stale references and dashes**
  Run: `grep -rn "Download hashcat\|Download CPU runtime\|Download NVIDIA\|7zr" README.md docs/DEVELOPERS.md installer/README.md NOTICE; grep -rnP "[\x{2013}\x{2014}]" README.md docs/DEVELOPERS.md installer/README.md NOTICE CHANGELOG.md`
  Expected: no hits from the first command except historical CHANGELOG entries (CHANGELOG is not in that list); no hits from the second command.

- [ ] **Step 3: Commit** - `git commit -m "Document the dependencies page and bundled hashcat"`
