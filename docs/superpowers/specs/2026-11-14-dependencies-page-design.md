# Dependencies Page and Bundled hashcat - Design

Date: 2026-11-14
Status: approved

## Intent and why

RecoverKit relies on up to four external components that it downloads or copies into
the per-user engines folder (`Settings.AppDataDir/engines`):

| Component | Platforms | Today |
|---|---|---|
| hashcat 8.0.0 (`HashcatInstaller`) | all | Windows/Linux download; macOS copies the app bundle's build silently at start |
| 7-Zip extractor `7zr.exe` (`HashcatInstaller.EnsureSevenZipAsync`) | Windows (downloaded), Linux (system 7z required) | fetched implicitly inside the hashcat download |
| Intel CPU runtime for OpenCL (`CpuRuntime`) | Windows | offered by a prompt when no device is found or "CPU only" is set; license checkbox |
| NVIDIA NVRTC (`NvrtcRuntime`) | Windows | only a log line pointing to Tools; license checkbox |

Each one is offered by its own prompt or menu item at a different moment
(`OfferHashcatDownloadAsync`, `OfferHashcatUpgradeAsync`, `OfferCpuRuntimeAsync`,
`RequireHashcatAsync`, three Tools menu items, three download dialogs in
`SmallDialogs.cs`). Users find this overwhelming: they get interrupted repeatedly and
have to work out which download they need.

The work has two parts, decided by the user:

1. **Bundle hashcat in every release** (Windows MSI, Windows portable zip, macOS app,
   which already does). hashcat is MIT-licensed and everyone needs it. This removes the
   hashcat download and the 7-Zip extractor entirely.
2. **One dependencies page** that shows what remains as traffic lights (green / yellow /
   red), installs everything that needs it with one click, and is invisible when all
   lights are green. The check runs on every start. After it, the app does not
   interrupt the user about dependencies again.

The NVIDIA CUDA compiler (NVRTC) and Intel's CPU runtime stay downloads (decided by the
user: large, hardware-specific, and Intel's redistribution terms are unclear).

## Goals

- hashcat 8.0.0 ships inside every release and is ready on first start with no prompt.
- On every start, check all dependencies locally (no network) and show the page only
  when something is not green.
- One "Install all" action that installs every selected item in sequence with one
  progress display, after accepting the licenses shown on the page.
- Every row is known up front on a clean machine, so a single click does everything.
- Replace all existing scattered dependency prompts and the three download dialogs.

## Non-goals

- RecoverKit's own update. It stays on the toolbar Update button and Help > Check for
  updates (`AppUpdater`), and never appears on this page (decided by the user).
- Bundling NVRTC or the Intel CPU runtime (decided by the user).
- Installing system-wide drivers (GPU drivers, PoCL). These are shown with
  instructions, not installed.
- A Linux release. None exists today (`.github/workflows/build.yml` builds Windows and
  macOS); Linux source builds are covered below but no Linux package is added.
- Changing pinned versions, URLs or hashes of NVRTC or the CPU runtime.

## Anti-goals

- A page that shows on every start for a user who already decided to skip an optional
  (yellow) item. That would be the same nagging in a new form.
- Any network request during the start check. A start with everything green must be as
  fast as today.
- A modal dialog chain. The page lives inside the main window.

## Approaches

Page:
- **A. Page inside the main window (picked by the user).** The dependency list replaces
  the drop zone in the main pane while setup is needed; the drop zone returns when done.
  One window, no pop-ups, reuses the existing install code.
- B. Separate setup window before the main window. Cleaner split, but an extra window and
  hashcat device detection would run in two places.
- C. Compact traffic-light strip above the drop zone. Shown as a mockup, not picked.
- D. Chain the existing dialogs at start. Rejected: still a series of interruptions.

Bundling (user's decision after comparing): bundle hashcat everywhere; keep NVRTC
(about 74 MB + 20 MB, NVIDIA only) and the Intel CPU runtime (about 110 MB, only PCs
without a GPU driver, redistribution terms unchecked) as downloads on the page.

## Part 1: hashcat bundled in every release

### Build

- **Windows** (`installer/build.ps1`, used by both the MSI and the portable zip in CI):
  download the pinned `hashcat-8.0.0.7z` (`HashcatInstaller.ArchiveUrl`, verify
  `ArchiveSha256`), extract it with the runner's 7-Zip, keep the Windows files (drop
  `hashcat.bin` and other non-Windows binaries), write the `RECOVERKIT_BUNDLE` stamp
  (`<hashcat version>-<bundle revision>`, same format as `macos/build-hashcat.sh`) and
  place the folder as `hashcat/` next to `RecoverKit.exe` in `installer/stage`. Cache the
  archive in CI like the macOS hashcat build. `Package.wxs` installs the folder; the
  portable zip gets it from `stage`.
- **macOS:** unchanged (`macos/build-hashcat.sh`, `macos/package.sh`).
- The pinned URL and SHA-256 move from run time to build time; they stay in one place
  that both the build script and the code can read (builder decides how).

### Run time

- hashcat writes kernel caches and logs into its own folder, and `Program Files` is not
  writable, so Windows does what macOS does today: at start the bundled folder is copied
  into `engines/hashcat-8.0.0` when that copy is missing or has a different stamp
  (`HashcatInstaller.BundledDirectory`, `BundleNeedsInstall`, `TryInstallBundled`,
  `CopyBundle`), silently, with progress in the status bar as on macOS today.
  `BundledDirectory` / `FindBundle` are extended to Windows (`hashcat/` next to the exe,
  with `hashcat.exe` and the stamp). The portable zip behaves the same.
  `HashcatTool.Locate` must skip the bundle folder on Windows as it does on macOS today
  (it currently probes `baseDir/hashcat`, which is exactly where the bundle sits).
- A Windows user who downloaded hashcat 8.0.0 with an earlier RecoverKit has an
  `engines/hashcat-8.0.0` without a stamp; it is replaced by the bundled copy once.
- If the copy fails (disk full, permissions), the hashcat row is red with the error and
  "Install" retries the copy.

### What goes away

- `HashcatInstaller.InstallAsync`'s download path, `EnsureSevenZipAsync`,
  `FindSevenZip`, `ExtractAsync`, `SevenZipOverride`, the `7zr.exe` URL/hash and the
  `engines/tools` folder use. `DownloadAsync` stays (NVRTC and the CPU runtime use it)
  and moves to a neutral place if that reads better.
- The CLI's `install-hashcat` keeps `--from <folder>` and the bundled copy; its
  download mode is removed.
- Linux source builds and development builds without a bundle: the hashcat row is red
  with an instruction (install hashcat 8 with the package manager, or point
  Preferences > Files and Paths at a hashcat 8 folder, or `install-hashcat --from`).
  Nothing is downloaded. (Call made in this design; there is no Linux release.)

### NOTICE, README, installer README

NOTICE says hashcat is bundled in all releases (with its license texts in the bundled
folder's `docs/`) and drops the 7-Zip extractor. README and docs/DEVELOPERS.md describe
the bundled hashcat on Windows and the dependencies page.

## Part 2: the dependencies page

### Rows

| Row | Platforms | Installable from the page |
|---|---|---|
| hashcat 8.0.0 | all | copy from the bundle, or switch to it (see yellow below) |
| NVIDIA CUDA compiler (NVRTC) | Windows | download, NVIDIA license |
| CPU runtime (OpenCL) | Windows | download, Intel license |

On macOS and Linux the page in practice only appears when hashcat is red.

### Traffic light meaning

- **Red** - RecoverKit cannot use hashcat at all until this is fixed: no usable hashcat
  (bundle copy failed, or no bundle on a source build), or no device for hashcat (CPU
  runtime needed on Windows; `CpuOnly` selected with no CPU device is red as well).
- **Yellow** - works, but slower or with less:
  - hashcat in use is older than 8.0.0 because Preferences point at the user's own copy
    (Homebrew, PATH, a configured path). Action: switch to the bundled copy (sets
    `Settings.HashcatPath`; the user's copy is not touched). Replaces
    `OfferHashcatUpgradeAsync` and `DeclinedHashcatUpgrade`.
  - NVRTC missing while an NVIDIA GPU with a CUDA 12.4+ driver is present.
  - CPU runtime missing while Preferences ask for the processor alongside the GPU
    (`HashcatCpuWithGpu`).
- **Green** - installed and current, or not needed on this machine ("Not needed: a GPU
  driver is installed"). The page lists every row that applies to the platform, green
  ones included, so the user sees what is fine as well.

Rows that cannot be fixed from the page (NVIDIA driver older than CUDA 12.4, RecoverKit
running as administrator so per-user runtimes are ignored, no GPU driver on
Linux/macOS, no bundle on a source build) are shown in their color with a one-line
instruction and no checkbox. A "Check again" link re-runs the check after the user
fixes it.

### Start

1. The bundled hashcat copy (Part 1) runs first, silently.
2. `MainWindow.Opened` then runs the check (replacing the dependency parts of
   `InitHashcatAsync`). The check is local only: file existence, `hashcat --version`,
   `hashcat -I` (already done today), `nvidia-smi` (Windows, only when an NVIDIA driver
   is present), elevation.
3. All green: nothing changes for the user; the start page shows as today.
4. Otherwise: the pill shows "Setup needed" and the main pane shows the page. A file
   passed on the command line or opened from Finder waits until the page is closed
   (installed or skipped), then opens.

Because hashcat is now present from the first start, NVRTC and the CPU runtime rows are
decided from hashcat's real device list (`DevicesAsync`), not predicted:
- NVRTC: an NVIDIA device on OpenCL and no CUDA device, plus `NvrtcRuntime.Choose` on
  the driver's CUDA version. A CUDA device already present (CUDA Toolkit installed) is
  green "Not needed".
- CPU runtime: no usable device at all is red; `CpuOnly` or `HashcatCpuWithGpu` with no
  CPU device is red / yellow as above.
- If hashcat itself is red, these two rows show "Checked once hashcat is ready" and are
  decided after it is fixed.

### The page

- Heading "Getting RecoverKit ready" and one line of explanation.
- One row per dependency: light, name with version, one-line status/reason, download
  size, and a checkbox for installable non-green rows. Red rows are checked and cannot
  be unchecked; yellow rows are checked by default and can be unchecked.
- One license line per checked row that has a license (Intel, NVIDIA), each with a link
  to the license text. "Install all" is enabled only when every shown license is
  accepted. Unchecking a row hides its license line.
- Footer: total download size of checked rows, "Skip for now", "Install all".
- While installing: rows install in order (hashcat, NVRTC, CPU runtime), the current
  row shows progress, finished rows turn green, one progress bar and status line below
  the list using `InstallProgress`. Cancel stops the current download (existing
  cancellation tokens). A failed row turns red with the error text; the other rows
  still install.
- When everything checked is green, hashcat initialization runs again so the device
  list picks up the new runtimes, and the page closes.
- Opening a file while the page is shown (drag and drop, File > Open) is allowed when
  nothing is installing and closes the page as "Skip for now"; the light state stays
  visible in the pill. While installing, opening a file waits for the install to finish
  (same as the pending command-line file), so it never cancels an install.

### Where the page sits

The page is a layer of its own in the main pane, above both the drop zone and the
file card/log. When it closes, whatever was underneath is shown unchanged: the drop
zone when no file is open, the open file otherwise. After a successful install the
notices on the start page are redrawn (`ShowStartPage` when `_current is null`), as
`DownloadHashcatAsync` does today.

### Showing the page from an action

Showing the page is awaitable and returns whether the needed items are now installed.
- An action that needs hashcat (`RequireHashcatAsync`: start attack, Benchmark, Rules
  editor, generators) shows the page, waits, and continues by itself when hashcat is
  ready. When the user skips, the action is dropped.
- An attack that fails because hashcat has no CPU device (`MainWindow.cs` call sites of
  `OfferCpuRuntimeAsync(force: true, ...)` after `HashcatRunner.NoCpuDeviceMessage` /
  "No OpenCL, HIP or CUDA compatible platform") shows the page. It does not restart
  the attack; the user starts it again.
- Preferences: switching to "CPU only" or enabling CPU with GPU, when the CPU runtime is
  missing, shows the page.
- These action-triggered displays and Tools > Dependencies always show the page
  regardless of remembered skips: the user asked for something that needs it.

### Skipping

- "Skip for now" with red rows: the page shows again on the next start.
- Unchecking or skipping a yellow row is remembered per item and its reason (a new
  setting replacing `DeclinedHashcatUpgrade`), so that item no longer brings the page up
  at start. It stays yellow in Tools > Dependencies, where it can be installed any time.
  The memory is reset when the reason changes (new pinned version, different hashcat
  path, driver change that makes a different NVRTC package the choice).
- The page shows at start only if at least one row is red, or yellow and not remembered
  as skipped.
- Skips are written only from the page shown at start. Declining a yellow row on a page
  the user opened (Tools, Preferences, an action) is not remembered.
- A remembered-skipped yellow row that is listed because another row brought the page
  up starts unchecked.

### Tools menu

One item "Dependencies..." replaces "Download hashcat" / "Install hashcat", "Download
CPU runtime" and "Download NVIDIA CUDA compiler". It shows the page with all rows.
Disabled while an attack runs (same rule as the current download items).

### What goes away in the app

- `OfferHashcatDownloadAsync`, `OfferHashcatUpgradeAsync`, `OfferCpuRuntimeAsync`,
  `DownloadHashcatAsync`, `DownloadCpuRuntimeAsync`, `DownloadNvrtcAsync`,
  `PrepareBundledHashcatAsync` (folded into the start sequence) in `MainWindow.cs` and
  their prompts.
- `HashcatDownloadWindow`, `CpuRuntimeDownloadWindow`, `NvrtcDownloadWindow` in
  `SmallDialogs.cs` (keep `ProgressDialog` only if `UpdateWindow` still uses it).
- Log and notice texts that say "Tools > Download ..." or "Install hashcat"
  (`MainWindow.cs`, `HashcatKernels.cs`, `HashcatRunner.cs`) now say
  "Tools > Dependencies".

## Structure

- **Core: dependencies (new, `src/RecoverKit.Core/Dependencies.cs` or a folder).**
  Check and install orchestration, no UI:
  - `DependencyCheck` returns a list of `DependencyItem { Id, Name, Version, Light,
    Reason, DownloadBytes, Installable, License (name, url)?, SkipKey }` from settings,
    the located hashcat, its version and devices.
  - Inputs that touch the machine (file system, bundle, `nvidia-smi`, `hashcat -I`,
    elevation, platform) are passed in as an interface or delegates so the decision
    table is unit-tested without a real machine.
  - `DependencyInstaller` runs the existing installers (bundle copy, `NvrtcRuntime`,
    `CpuRuntime`) in order and reports progress per item.
- **App: `DependenciesPage` (new file).** The control shown in the main pane, using
  `Palette` brushes (`GoodBrush`, `WarnBrush`, `BadTextBrush` and their soft variants)
  and `Layout` helpers like the rest of the app, light and dark theme.

## Constraints

- No network during the start check. NVRTC and CPU runtime URLs and SHA-256
  verification stay as they are; hashcat's archive is verified at build time.
- Elevated processes keep ignoring per-user runtimes (`CpuRuntime.IsElevatedProcess`);
  the page explains it instead of offering an install that would not be used.
- The user's own hashcat is never modified.
- Works in light and dark themes, on Windows, macOS and Linux source builds.
- Tests: decision table (every row x platform x situation), skip memory and its reset,
  install ordering and partial failure, Windows bundle discovery and stamp handling.
  Existing installer and `HashcatTool.Locate` tests stay green or are updated for the
  removed download.
- README, docs/DEVELOPERS.md, installer/README.md, NOTICE and CHANGELOG are updated.

## Risk to check

An antivirus product could flag hashcat as a "hack tool" (possible, not confirmed: no
report of Windows Defender flagging stock hashcat was found; monitoring rules such as
Sigma's alert on running it). With hashcat inside the MSI and portable zip, a flag would
affect the RecoverKit download itself. Check the built MSI and zip with Windows
Defender (and, if possible, a VirusTotal scan the user runs) before release. Code
signing is out of scope: a certificate would carry the maintainer's legal name. The
fallback for a flag is a false-positive report to the vendor.

## Left to the builder

- Exact wording of row reasons and instructions, within the meanings above.
- How the pill and status bar read while setup is needed or skipped.
- Where the pinned hashcat URL/hash live so build script and code share them.
- Debug log lines for the check result and each install step.
