# RecoverKit for developers

How RecoverKit is built, tested and packaged. For using the program, see the [README](../README.md).

## How it works

RecoverKit reads a protected file, extracts the data needed to verify passwords, and drives the
open-source [hashcat](https://hashcat.net) engine for GPU work. Writing dozens of GPU kernels is
not practical: hashcat already implements every supported format with mature NVIDIA (CUDA/OpenCL),
AMD (HIP/OpenCL) and Intel Arc (OpenCL) backends. RecoverKit owns format parsing, the attack model,
scenarios, the wizard GUI and session management.

For formats where hashcat's CPU kernels are slow, a built-in CPU engine runs brute-force and mask
attacks when no GPU is used: managed .NET kernels plus a small native C library
(`native/rknative.c`, built with `zig cc`). See [benchmarks.md](benchmarks.md).

## Layout

```
src/RecoverKit.Core   format parsers, attack model, scenarios, hashcat integration (no UI)
src/RecoverKit.Cli    headless front-end (recoverkit-cli), also used for testing
src/RecoverKit.App    Avalonia GUI (net10.0; Windows x64 and macOS arm64)
tests/RecoverKit.Tests  xUnit tests for parsers, charsets, extractors
native/               native CPU kernels (C, built with zig)
docs/                 benchmarks, screenshots, this file
```

Everything is cross-platform .NET. The GUI is written in C# against Avalonia 12 (code only, no
XAML) and uses the system menu bar on macOS and an in-window menu elsewhere.

## Building

Requires the .NET 10 SDK, and [zig](https://ziglang.org) 0.15.2 for the native kernels.

```
sh native/build.sh          # rknative.dll (win-x64) and librknative.dylib (osx-arm64)
dotnet build RecoverKit.sln -c Release
dotnet test tests/RecoverKit.Tests
```

The Stay ZIP attack tests (`Category=Stay`) run full key searches and take many minutes, so
`dotnet test` skips them. Run them with `dotnet test tests/RecoverKit.Tests -p:RunStayTests=true`.
CI runs them in a separate workflow (`stay-tests.yml`) only when the attack's code or tests change.

The GUI:

```
dotnet publish src/RecoverKit.App -c Release -r win-x64 --self-contained false -o publish
dotnet run --project src/RecoverKit.App          # on any desktop, for development
```

Set `AVALONIA_TELEMETRY_OPTOUT=1` to keep Avalonia's build tooling from sending usage data. In
Debug builds `RECOVERKIT_SNAPSHOTS=<dir>` renders every window and wizard page to PNG and exits,
which makes layout changes quick to check. It also walks the main window through its states with
made-up data (empty, drag over, file loaded, running, paused by the GPU temperature guard, found),
and renders the wizard's attack cards and the password found dialog. `RECOVERKIT_SNAPSHOT_THEME=light`
or `dark` forces a theme, `RECOVERKIT_SNAPSHOT_ONLY=main` skips the other windows, and
`RECOVERKIT_SNAPSHOT_REAL=<file>` runs a real short attack on a test file and saves the live view.

The GUI draws its few custom pieces itself (`src/RecoverKit.App/Ui`): `ProgressRing`,
`Sparkline`, `ProgressStrip` (the bar with the moving sheen), `CheckMark`, `DropFrame`, the
monochrome `LineIcon`s and the wizard's `AttackCard`s. Colours come in light/dark pairs from
`Palette`. Animations are skipped when `Platform.ReduceMotion` is set (macOS "Reduce motion",
Windows "Animation effects" off, or `RECOVERKIT_REDUCE_MOTION=1`). The live attack view updates at
most 8 times a second from the newest hashcat status, whatever rate hashcat reports at.

hashcat is the GPU engine and is fetched on demand: the first time you start RecoverKit
without it, choose **Tools > Download hashcat** (also on the Preferences "Files and Paths"
tab, or run `recoverkit-cli install-hashcat`). It downloads the pinned release from
hashcat.net, checks its SHA-256, and unpacks it into a per-user `engines` folder that
RecoverKit then finds automatically. On Windows the small official `7zr.exe` extractor is
downloaded too when no 7-Zip is already installed.

You can still place hashcat in a `hashcat` folder next to `RecoverKit.exe`, or point at an
existing install in Options > Preferences > Files and Paths.

## macOS hashcat

hashcat.net publishes no macOS binary, so the macOS app bundles its own build. On an Apple
Silicon Mac with the Xcode command line tools:

```
macos/build-hashcat.sh            # add --force to rebuild, --jobs N to limit parallelism
```

It downloads the official hashcat 7.1.2 source tarball (SHA-256 pinned in the script), builds
an arm64-only binary with the Metal backend using hashcat's bundled dependencies (nothing from
Homebrew; `otool -L` is checked so that only system libraries and frameworks are linked) and
assembles a portable folder in `macos/out/hashcat/`: the executable, `modules/`, `bridges/`
(argon2, scrypt; the Python and Rust plugin bridges are left out), `OpenCL/` kernel sources,
`charsets/`, `layouts/`, `masks/`, `rules/`, `tunings/`, `hashcat.hcstat2`, the license texts
in `docs/` and a `RECOVERKIT_BUNDLE` stamp (`<hashcat version>-<bundle revision>`). The build
takes about a minute and the folder is about 200 MB. It is skipped when the folder already holds
the same stamp.

Portable mode: hashcat compares the folder of its resolved executable with the install folder
compiled in (`PREFIX/bin`, `/usr/local/bin`). When they differ, which is everywhere except
`/usr/local/bin`, it reads its data from and writes kernel caches, `hashcat.log`, dictstat and
pid files to the executable's own folder.

That folder goes into `RecoverKit.app/Contents/Resources/hashcat/`. Because hashcat writes into
its folder and the signed app bundle must stay unchanged (it may also be read-only), RecoverKit
never runs it there: `HashcatInstaller.TryInstallBundled()` copies it to
`~/Library/Application Support/RecoverKit/engines/hashcat-7.1.2` (keeping executable bits,
dropping the quarantine attribute) when that copy is missing or has another stamp, and
`HashcatTool.Locate` prefers that copy. `recoverkit-cli install-hashcat --from macos/out/hashcat`
installs a build by hand.

On Apple Silicon hashcat lists the GPU twice, as a Metal device and as an OpenCL alias, and by
default disables Metal while an OpenCL device exists (`-d <metal id>` forces Metal). There is no
CPU device, so the "Don't use GPU threads" strategy only works for formats the built-in CPU
engine supports. Some modes (for example 17200, PKZIP) are refused on the Apple GPU by hashcat;
when the built-in CPU engine supports such a mode, the attack step reruns on it automatically.

## macOS app

On an Apple Silicon Mac with the .NET 10 SDK, zig and the Xcode command line tools:

```
sh native/build.sh
pip install dmgbuild            # or PYTHON=/path/to/venv/bin/python
macos/package.sh 1.2.0          # -> macos/out/RecoverKit-1.2.0-macos-arm64.dmg
```

It builds hashcat if needed, publishes a self-contained osx-arm64 app, assembles
`RecoverKit.app` (Info.plist template and icon in `macos/`), signs every file ad hoc
(`codesign --sign -`; there is no Apple Developer ID, so the app is not notarized) and builds a
compressed disk image whose background explains the Gatekeeper steps. The background is
`macos/dmg/background.html`, rendered to PNG by `macos/dmg/render_background.sh` (headless
Chrome). The app needs macOS 15 or later, hashcat 7's own minimum. `assets/make-icons.sh` also
regenerates `macos/RecoverKit.icns`.

## Installer

A standard Windows Installer (.msi) is built with WiX v6. On Windows x64 with the .NET 10
SDK:

```powershell
powershell -ExecutionPolicy Bypass -File installer\build.ps1
```

It publishes the app and writes `installer\out\RecoverKit-1.0.0-x64.msi`, which installs
into `Program Files\RecoverKit` with Start Menu and desktop shortcuts and an Add/Remove
Programs entry. The default build is self-contained (no runtime prerequisite); pass
`-FrameworkDependent` for a smaller MSI that needs the .NET 10 Runtime. See
[installer/README.md](../installer/README.md) for details.

## Command line

```
recoverkit-cli install-hashcat                        # download + unpack the GPU engine
recoverkit-cli extract <file>                         # identify + print the extracted hash
recoverkit-cli extract database.kdbx --keyfile database.key # KeePass password + optional keyfile
recoverkit-cli crack <file> --brute sd --min 1 --max 6 # brute force (s=smalls c=caps d=digits e=specials)
recoverkit-cli crack <file> --dict words.txt --rules advanced
recoverkit-cli crack <file> --hcmask '?u?l?l?l?d?d'
recoverkit-cli crack <file> --scenario-file my.txt     # run a scenario file
recoverkit-cli crack vol.hc --volume vc --kdf sha512,ripemd160 --cascade 1,2,3
recoverkit-cli crack vol.hc --volume vc --keyfile "first key.bin" --keyfile second.bin --pim 7 --dict words.txt
recoverkit-cli crack vol.tc --volume tc --keyfile key.bin --dict words.txt
recoverkit-cli crack hash.txt --hash-mode 13000 --dict words.txt   # any hashcat mode
recoverkit-cli decrypt secret.docx <password> [out.docx]           # decrypt an MS Office file
```

`--new` ignores a saved session and starts over; `--no-potfile` disables the cache.
`--temp-limit 85 [--temp-hysteresis 10]` turns on the GPU temperature guard and `--gpu-duty 50`
the GPU load limit for one run, `--power-limit <watts>` the NVIDIA power limit (see GPU temperature
guard below; the CLI prints the explanation and asks y/n/c before the system prompt).

For TrueCrypt/VeraCrypt, repeat `--keyfile <path>` for each required keyfile. Files must be readable and nonempty; paths
containing commas are rejected because hashcat uses commas to separate keyfiles. Only the first
1 MiB of each keyfile is used, matching TrueCrypt/VeraCrypt. Keyfiles are unavailable with `--boot`.
`--pim N` sets a known VeraCrypt PIM: 0 (or omitted) uses the default, positive values test that exact
PIM. The maximum is 2147468 for normal/hidden volumes and 65535 for system encryption. TrueCrypt
has no custom PIM. Credential options require `--volume`; `extract --full` outputs only the header
hash, so the same keyfiles and PIM must also be supplied when using that hash directly with hashcat.

Credential-specific sessions and password caches are separate from other combinations of keyfiles
and PIM. Reopen a volume after changing its keyfiles. Recovery with keyfiles uses hashcat, including
on the CPU; the built-in TrueCrypt Whirlpool kernel handles password-only recovery. For a volume
protected by keyfiles with an empty password, use a dictionary containing an empty line.

For TrueCrypt/VeraCrypt, repeat `--keyfile <path>` for each required keyfile. Files must be readable and nonempty; paths
containing commas are rejected because hashcat uses commas to separate keyfiles. Only the first
1 MiB of each keyfile is used, matching TrueCrypt/VeraCrypt. Keyfiles are unavailable with `--boot`.
`--pim N` sets a known VeraCrypt PIM: 0 (or omitted) uses the default, positive values test that exact
PIM. The maximum is 2147468 for normal/hidden volumes and 65535 for system encryption. TrueCrypt
has no custom PIM. Credential options require `--volume`; `extract --full` outputs only the header
hash, so the same keyfiles and PIM must also be supplied when using that hash directly with hashcat.

Credential-specific sessions and password caches are separate from other combinations of keyfiles
and PIM. Reopen a volume after changing its keyfiles. Recovery with keyfiles uses hashcat, including
on the CPU; the built-in TrueCrypt Whirlpool kernel handles password-only recovery. For a volume
protected by keyfiles with an empty password, use a dictionary containing an empty line.

## Scenario file format

UTF-8 or UTF-16 text; blocks separated by a blank line:

```
Name of scenario
OF13 RAR5 WPAH          <- format ids this scenario is the default for (NONE = none)
/a:b /c:a /min:1 /max:4 <- attack 1
/a:r /r:*1s /d:*default <- attack 2
```

Switches: `/a:` b|m|d|r (brute / mask / dictionary as-is / dictionary+rules), `/c:` c|s|d|e|a
charset, `/u:` user charset, `/l:` national alphabet, `/m:` mask, `/ms:` mask symbol,
`/min:` `/max:` lengths, `/1:`..`/8:` custom mask charsets, `/r:` rules (`*1s *1a *1c *2s
*2a *3s` or a file), `/d:` dictionary (up to four; `*default` = configured default dictionary).


## GPU temperature guard and load limit

Optional, off by default (`Settings.GpuTempGuard`, `GpuTempLimit`, `GpuTempHysteresis`,
`GpuDutyPercent`), and only for hashcat runs that use a GPU; the built-in CPU engine is never
paused. The decisions live in `ThermalGuard` (pure, unit tested); `ThermalController` applies them
to the running hashcat process.

- Temperature: the hottest GPU from hashcat's `--status-json` (`temp`, NVML/ADL/sysfs). hashcat
  reports -1 on Apple Silicon, so on those Macs the die and GPU sensors are read through the IOKit
  HID event system (`AppleSiliconSensors`, no admin rights). With NVIDIA, `nvidia-smi` is used while
  hashcat is suspended. Without any reading while paused the guard resumes after 90 s and lets the
  next hashcat reading decide. Pause at `limit`, resume at `limit - hysteresis`. With the guard on,
  `--hwmon-temp-abort` is set to limit + 10 (max 100) as a safety net, unless the extra arguments
  already contain a `--hwmon` option.
- Pausing suspends the hashcat process (SIGSTOP/SIGCONT, `NtSuspendProcess` on Windows). Measured
  on an M1 Pro with a slow hash: GPU utilization (ioreg) fell from 99 % to about 10 % within 6 s,
  the die cooled 3.6 °C in 28 s, and after SIGCONT the attack went on with no loss. Alternatives
  that were tested and rejected: hashcat's `p` key works through a redirected stdin on macOS, but
  hashcat checks for a pause only between batches, so with PBKDF2 the GPU stayed at 100 % for the
  whole 90 s "pause"; on Windows `tty_getchar` uses `WaitForSingleObject`/`ReadConsoleInput`,
  which do not work on a pipe, and stdin-fed attacks have no key thread at all. A checkpoint stop
  plus `--restore` redoes the unfinished batch (minutes for slow hashes) and the kernel start-up.
  The GPU finishes work already queued, a few seconds, so this does not trip driver watchdogs
  (those limit a single kernel's run time). A user stop resumes the process first, then sends the
  usual Ctrl+C/SIGINT, so the restore file is written as before.
- Load limit: the GPU works `GpuDutyPercent` of every 60 s cycle and is suspended for the rest.
  Speeds are reported scaled by that share so the ETA stays right. It does not cap peak power
  (that needs administrator rights and vendor tools); the workload slider (`-w`) is separate.
- Status passed to the UI: thermal pause time is added to `TimeStart` so the average speed ignores
  it; after a resume the pre-pause speed is shown until hashcat's own averaged figure recovers.

## NVIDIA power limit

Optional (`Settings.GpuPowerLimit`, `GpuPowerWatts` by nvidia-smi GPU index), Windows and Linux
only, and shown only when nvidia-smi reports an adjustable limit
(`--query-gpu=index,name,power.min_limit,power.max_limit,power.default_limit,power.limit`, no admin
rights needed). Setting it (`nvidia-smi -i <gpu> -pl <watts>`) requires an administrator, and
RecoverKit must not run elevated (elevation breaks the Intel CPU OpenCL runtime), so:

- `RecoverySession.ConfirmElevation` is asked first with `PowerLimitRequest.Explanation`; the GUI
  shows `PowerLimitWindow`, the CLI asks on the console. Continue / run without / cancel.
- `PowerLimiter` starts the same executable as `power-helper --pid <RecoverKit pid> --gpu <i>
  --watts <w> ...` elevated: `runas` (UAC) on Windows, `/usr/bin/pkexec` on Linux. Declining
  falls back to running without the limit, with a log line.
- The helper (`PowerHelper.Run`) accepts only those integer options, uses only nvidia-smi from the
  driver's fixed locations (`System32`, `Program Files\NVIDIA Corporation\NVSMI`, `/usr/bin`,
  `/usr/local/bin`), checks every value against the range nvidia-smi reports, remembers the
  current limits, sets the new ones and waits for RecoverKit to exit or to ask it to stop
  (Windows: named events `Local\RecoverKit.PowerLimit.<pid>.*` created by RecoverKit; Linux:
  stdin closing). Then it restores the remembered limits. A limit set by nvidia-smi does not
  survive a reboot or driver reload either.
- Debug builds: `RECOVERKIT_POWER_SIMULATE=1` pretends there is a GPU and the helper (`--simulate`,
  refused by release builds) only logs the nvidia-smi calls to `%TEMP%\recoverkit-power-simulation.log`.
  The Windows flow (UAC launch, apply, restore at the end and after killing RecoverKit) was
  verified this way; pkexec on Linux and a real NVIDIA GPU were not available for testing.

## Continuous integration

`.github/workflows/build.yml` runs on every push and pull request. The `windows` job
(`windows-latest`) builds the native kernels, runs the tests and builds the MSI and a portable zip.
The `macos` job (`macos-15`, Apple Silicon) runs the tests on arm64, builds hashcat (cached by
the build script's hash) and the disk image. Both upload their files as workflow artifacts. Pushing
a tag such as `v1.2.0` makes the `release` job publish all three files as a GitHub release with
that version. Before tagging, add a `## [x.y.z] - date` section to `CHANGELOG.md`: the release
notes are taken from it, and the release job fails if the section is missing.

## Technical notes

- PDF revision 3 with a 40-bit RC4 key has format ID `P340` and uses hashcat 7.1.2
  [module 10510](https://github.com/hashcat/hashcat/blob/v7.1.2/src/modules/module_10510.c).
  It accepts V=1/2, 40 bits, 16/32-byte IDs and 32-byte /U and /O entries, with a
  32-byte password limit. Missing /Length defaults to 40; /EncryptMetadata is ignored
  before R4. Mode 10500 accepts only 128 bits, so R3 lengths other than 40/128 are
  rejected instead of producing an unusable hash. The existing PDF CPU kernel also
  handles 10510. The PDF filter, content detector and UI format listing already cover it.
  There is no guaranteed R3 key search in this hashcat release:
  [10410](https://github.com/hashcat/hashcat/blob/v7.1.2/src/modules/module_10410.c) and
  [10420](https://github.com/hashcat/hashcat/blob/v7.1.2/src/modules/module_10420.c)
  require R=2. Their kernels implement one RC4 pass over fixed padding and the R2 MD5
  derivation, respectively. The [10510 kernel](https://github.com/hashcat/hashcat/blob/v7.1.2/OpenCL/m10510-pure.cl)
  derives keys from candidate passwords with 50 extra MD5 rounds over five bytes, then
  checks 20 RC4 passes over MD5(padding + ID). Mode 25400 is a 128-bit owner/user
  password mode, not an R3 key enumerator. P340 therefore uses password attacks only;
  no key recovery or equivalent-password stage is offered. The embedded one-page V=1/2
  fixtures in `PdfExtractorTests` were created with pypdf 7.0.1's encryption constructor
  using explicit (V, R=3, Length=40) options, then reopened with pypdf and pikepdf 10.18.0.
  Hash fields match John's pdf2john.py after normalizing unsigned permissions to signed
  32-bit values; no extractor code was copied. The public pypdf `RC4-40` option selects
  R2, so it is insufficient by itself for creating these R3 fixtures.
  End-to-end checks used the CLI and bundled hashcat 7.1.2 mode 10510 with a three-word
  dictionary on an Apple M1 Pro. Both fixtures recovered `r3-test-42` and reopened with
  pikepdf; V=1/32-byte ID took 14.74 s and V=2/16-byte ID took 4.42 s including startup.
- Access database recovery uses `InstantUnlock` with a password and no save action or hashcat
  target. Jet 3/4 header bytes at 0x18 use fixed-key RC4 (key c7da396b); the password is at
  0x42 (20 code-page bytes for Jet 3, 40 UTF-16LE bytes for Jet 4). Jet 4 additionally XORs
  the password with the repeating little-endian int32 obtained by truncating the decoded
  creation-date double at 0x72. Layout references: [mdbtools HACKING.md](https://github.com/mdbtools/mdbtools/blob/dev/HACKING.md)
  and Jackcess `JetFormat` / `DatabaseImpl.getDatabasePassword`. Tests use Apache-licensed
  header excerpts plus independent synthetic vectors. Full Jackcess Encrypt `pwd-set.mdb`
  was checked with the CLI, Jackcess 4.0.7 and an independent Python reader: all recovered
  `testpassword`. No hashcat mode or attack scenario applies. Password clearing is omitted:
  Jet 4 also requires re-masking stored security identifiers, so changing the header alone
  does not produce a valid Access file. Workgroup (.mdw) user-level security is unsupported.
  ACE (.accdb) encryption is recognized via the header encoding key and remains unsupported.
  Its encryption descriptor starts after a two-byte length at 0x299 and can use Office
  RC4, CryptoAPI, standard AES or agile encryption. Supporting it needs a bounded descriptor
  parser and verified password-verifier extraction; the existing Office entry point expects
  compound-file streams and cannot be used directly. ACE page decryption also differs from
  OOXML package decryption. Never send ACE password fields through the reversible Jet path.
- Word restrictions use `InstantUnlock`, with no hashcat target or scenario. `WordRestrictions`
  removes `documentProtection` and `writeProtection` from `word/settings.xml` in unencrypted
  OOXML packages, including Strict namespaces. Other ZIP entries are left untouched.
  `BinaryWordRestrictions` reads the FIB, DopBase/Dop2003 and SttbfAssoc entry 17 in Word
  97-2003 files. It clears form/comment/revision locks, style/enforcement flags, the editing
  verifier, FIB write reservation/read-only recommendation and the associated reservation
  password. `CompoundFile.WriteStreamRange` patches regular and mini streams without changing
  their sizes or allocation. Ordinary revision recording and VBA protection flags are preserved.
  Associated-string passwords can be shown directly; four-digit legacy `w:password` verifiers
  get an equivalent 15-character password, never a claim to the original. Binary Word's 32-bit
  editing verifiers and modern SHA password hashes are not recovered. Their restrictions can
  still be removed. Other binary Word generations and file-sharing variants are not supported.
  ODT support covers `text:section` protection and LibreOffice's `LoadReadonly` setting, not
  change-recording passwords or protected tables. Restriction XML is limited to 4 MiB per part;
  binary property ranges must fit in the first 32 MiB of the table stream.
  `RestrictionCopy` writes a temporary sibling, checks source/output aliases and moves it into
  place only after a successful update. Package signatures become invalid after XML changes.
  The tiny Word fixtures were generated from synthetic content with LibreOffice 26.2.4.2;
  the reservation variant adds a synthetic SttbfAssoc password (`kit42`). Tests need no Office
  installation. Manual checks used python-docx 1.2.0 packages with added protection settings,
  an Apache POI protected sample kept in scratch only, and LibreOffice reopening saved copies.
  Field definitions: [MS-DOC DopBase](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/f885b87a-15b3-460e-aecc-213bd17f960e),
  [Dop2003](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/8783a51d-da22-4e5f-a8f0-d98ae25215c5)
  and [SttbfAssoc](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/f6f1030e-2e5e-46ff-92f0-b228c5585308).
- `SpreadsheetProtection` handles editing restrictions through `Detection.Unlocks` before the
  existing encrypted Office/ZIP extractors. It creates no hashcat target, mode or attack scenario:
  removing restrictions needs no attack, including SHA-512 sheet/workbook verifiers. Each finding
  saves only its selected restriction; reopen the saved copy to remove another. ZIP update mode
  preserves untouched compressed payloads; only changed XML entries are serialized. BIFF8 uses
  `CompoundFile.WriteStreamSameLength` to patch the existing regular or mini-sector allocation.
  Copies are edited in a temporary file beside the output and renamed only after success.
  XML parts are capped at 32 MiB and BIFF streams at 64 MiB. Oversized BIFF streams still go
  through the existing Office encryption detector. A FILEPASS prefix keeps encrypted BIFF files
  on the existing Office prefix-only read path. FILEPASS and encrypted ODS manifests prevent
  inspection of editing restrictions until a decrypted copy is opened. Legacy 16-bit passwords
  use a bounded printable collision search, checked independently against openpyxl verifiers.
  Spreadsheet fixtures include Apache POI SHA-512 samples and an openpyxl workbook exported
  to BIFF8 by LibreOffice; origins and the Apache license are recorded in NOTICE.

- 7-Zip extraction follows the [7z format description](https://github.com/ip7z/7zip/blob/main/DOC/7zFormat.txt)
  and [hashcat 7.1.2 module 11600](https://github.com/hashcat/hashcat/blob/v7.1.2/src/modules/module_11600.c).
  Encrypted metadata is used directly; unencrypted Copy/LZMA1 metadata is decoded locally with
  a 16 MiB output limit and a bounded decoder adapted from the public-domain LZMA SDK 23.01.
  No installed 7-Zip or new package is needed. Folder bindings and substream CRCs select the
  smallest compatible encrypted stream (or a prefix of a solid folder). LZMA solid prefixes
  combine adjacent substream CRCs until hashcat's CRC-length-based estimate decrypts the full
  encrypted stream, avoiding silent verification failures from under-reading compressed input.
  Prefixes that cannot meet that condition are skipped. Hashcat
  accepts Copy, LZMA1, LZMA2 and Deflate without filters, with an empty AES salt. Encrypted data
  is limited to 8 MiB and decompressed CRC input to 9,999,999 bytes; compressed hashes also need
  space for their suffix within the module's input limit. NumCyclesPower above 24 is refused,
  matching the reference extractor's practical limit. Split volumes must be joined manually;
  SFX signature searches cover the first 4 MiB. Real fixtures were created with 7zz 26.03 and
  p7zip 17.05 using password `kit7`; extraction was compared with 7z2john and verified with
  bundled hashcat 7.1.2. The default tests perform no KDF or cracking work.
- KeePass extraction implements hashcat 7.1.2 modes 13400 (KDB, KDBX 2/3) and 34300
  (KDBX 4 Argon2d/Argon2id). Mode 34300 hard-codes a 253-byte header in both its tokenizer
  and HMAC kernel; headers of other lengths and AES-KDF are rejected. Header SHA-256 is
  checked before extracting the stored HMAC. Argon2 secret/associated data, rounds over
  99999, lanes over 32, and memory of 4 GiB or more are unsupported by this module.
  Keyfiles are normalized into the hash's `*1*64*<key>` suffix, so existing session keys
  distinguish credentials without new hashcat arguments. The GUI prompts after content
  detection; the CLI reuses `--keyfile` without `--volume`. XML v2 checksums are validated;
  KDB uses the legacy raw/hex/SHA-256 rules. KDB ciphertext is limited to 8 MiB and a
  32-byte password-only ciphertext is rejected because hashcat mistakes it for a keyfile.
  Small fixtures in `tests/RecoverKit.Tests/Fixtures/KeePass` use the synthetic password
  `rk-test-42` and, where required, key bytes 00 through 1f. KDBX fixtures were generated
  and reopened with pykeepass 4.2.0; KDB fixtures use a minimal group serialized in Python.
  Reference hash strings follow keepass2john's field order and hashcat's module limits.
  All supported fixture variants were checked with a three-word hashcat dictionary.
- Android backup extraction reads only the bounded ASCII header of standard adb / Helium `.ab`
  files, versions 1-5 (hashcat 18900). It preserves the version and checksum salt. Hashcat 7.1.2
  verifies the encrypted master key blob's padding rather than recomputing its checksum. The
  embedded v1/v5 fixtures were generated with Python cryptography, including the signed Java
  byte-to-char checksum conversion followed by UTF-8 encoding for v2+. Both were cracked through
  the CLI; a physical Android device and Helium were not available. Legacy v1 non-ASCII passwords
  can require an 8-bit encoded dictionary. Only password recovery is implemented, not unpacking.
- JSON wallets (implementation limits):
  - Wallet recovery needs the wallet file from your own device, not a wallet address or public key.
    Wallets are identified by content, including extensionless `UTC--*` and `default_wallet` files.
    Ethereum v3 supports PBKDF2-SHA256 and scrypt (32-byte salt; N must be a power of two, at least 1024).
    scrypt and MetaMask's newer 600,000-iteration vaults can be very slow.
  - MetaMask accepts extracted vault JSON, nested/escaped vault strings, or a chosen `.ldb`/`.log`
    file up to 32 MiB containing a complete vault record. Compressed, split or deleted LevelDB
    records require extracting the vault first. If several vaults exist, the first complete
    supported record is selected; it may be an older vault with a different password.
  - Electrum supports encrypted seeds, BIP32/private keys and BIE1 full-file encryption. Large
    Electrum wallets and MetaMask vaults use partial plaintext checks; verify found passwords in
    the original wallet. Large Electrum wallets (mode 21800) need a compatible GPU or OpenCL CPU
    runtime; hashcat disables this mode on Apple GPUs. Hardware-encrypted BIE2 files are unsupported. Legacy Electrum 1.x
    Python dictionaries support string keys, strings, numbers, booleans and null values.
  - Blockchain.com recovery handles the main password (legacy base64 with 10 PBKDF2 iterations,
    or version 2-4 JSON backups with explicit iterations), not the second spending password.
    Legacy base64 has no unique signature; confirm the backup's origin before recovery.
  - Exodus `seed.seco` files are recognized but not extracted: the SECO binary layout has not
    been verified against mode 28200. Use an independently verified extractor and Open As for hashes.
- RAR 3.x recovery covers encrypted file names (`-hp`, hashcat 12500) and visible file names
  (`-p`, hashcat 23700 for stored files or 23800 for compressed files). Data-only extraction
  prefers entries with at least eight unpacked bytes, then stored entries, then smaller entries.
  Shorter entries can produce false password matches and are flagged for verification. Split files
  and entries depending on earlier solid files are skipped. The first file in a solid archive
  can be used. The pinned hashcat version
  accepts at most 327,520 encrypted bytes and 655,360 unpacked bytes per selected file.
  Data-only recovery uses hashcat on both CPU and GPU; the built-in RAR kernel handles `-hp` only.
  Only the selected file's password is recovered; other entries can have different passwords.
- The per-user CPU runtime is not used when RecoverKit runs as administrator: the OpenCL loader
  ignores per-process driver lists in elevated processes on purpose, and RecoverKit does not register
  a user-writable DLL system-wide.
- The debug log (`%APPDATA%\RecoverKit\logs`, `~/Library/Logs/RecoverKit` on macOS) records environment, settings, every hashcat command
  with output and exit code, detection results, wizard choices and crashes. Recovered passwords are
  never written to it, and the profile path and account name are replaced by `%USERPROFILE%` / `%USERNAME%`.
- The built-in downloader pins hashcat 7.1.2. hashcat 8 changed `--restore` and `-w` handling, which
  the resume and workload features rely on.
- Apple iOS backup extraction follows the documented keybag format and reproduces hashcat's example
  hashes, but has not been verified against a real backup. Automatic decryption is implemented for MS
  Office OOXML only.

### Wallet fixtures and extraction

`WalletExtractor` bounds JSON/database inputs to 32 MiB and never derives keys during detection.
Format IDs are ETH3 (Ethereum v3), ELCT (Electrum), MTMK (MetaMask) and BLCH (Blockchain.com).
Hash syntax and limits follow hashcat 7.1.2 modules 12700, 15200, 15600, 15700, 16600, 21700,
21800, 26600 and 26610. The reference *2john tools were read for field selection; their code
is not embedded. SECO is recognized only because module 28200 does not specify container offsets.

The tiny `Fixtures/Wallets` corpus uses the synthetic password `wallet-test-42`. Ethereum files
were generated with eth-keyfile 0.10.0 (PBKDF2 with a 16-byte salt and scrypt N=1024 with a 32-byte salt). Python cryptography 50.0.2
produced AES-GCM MetaMask vaults and AES-CBC Blockchain.com backups, plus Electrum encryption
reproduced from Electrum 4.5.8 crypto/storage/ecc sources (double SHA256 for individual keys;
PBKDF2-SHA512, secp256k1 ECIES, zlib, AES-CBC and HMAC-SHA256 for full files). Fixtures include
expected hash lines and are parsed without KDF work in the default test suite.

Full Electrum hashes authenticate `BIE1 || ephemeral public key || ciphertext`, including the
header. Above hashcat's 16384-byte authenticated-data limit, mode 21800 instead takes the first
1024 ciphertext bytes. MetaMask mode 26600 checks the GCM tag for ciphertext sizes 30-3136;
larger vaults use mode 26610 with exactly 64 ciphertext bytes and a printable-text check.
Neither truncated mode verifies the MAC, so their Notes tell users to verify recovered passwords.
Blockchain.com modes inspect the initial JSON blocks; backups larger than 32768 bytes use only
the first 80 bytes (IV and four ciphertext blocks). Legacy base64 has no identifying magic.

The corpus also roundtrips six published `hashcat -m MODE --example-hashes --machine-readable`
hashes (12700, 15200, 15600, 15700, 16600, 26600). The Electrum mode-21700 example authenticates
synthetic ciphertext without a BIE1 header; actual wallet extraction follows Electrum's complete
container MAC instead. Low-N scrypt fixtures require `--self-test-disable` during attacks because
hashcat's fixed scrypt self-test uses N=262144; normal Ethereum parameters keep self-tests enabled.

End-to-end validation used the CLI and bundled hashcat 7.1.2 on an Apple M1 Pro, with a
three-word dictionary recovering `wallet-test-42` for all generated wallets except mode 21800:
Ethereum 15600/15700, Electrum salt types 1-3 (16600) and full HMAC (21700), MetaMask
10000/600000 iterations (26600) and large vaults (26610), Blockchain.com v1/v2 (12700/15200).
Mode 21800 extraction matches the reference electrum2john output, but hashcat disables this
mode on Apple GPUs because of Metal/OpenCL runtime limitations. Its cracking check remains
unverified on a compatible device. No live funds or personal wallets were used.
