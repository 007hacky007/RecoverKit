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

The GUI:

```
dotnet publish src/RecoverKit.App -c Release -r win-x64 --self-contained false -o publish
dotnet run --project src/RecoverKit.App          # on any desktop, for development
```

Set `AVALONIA_TELEMETRY_OPTOUT=1` to keep Avalonia's build tooling from sending usage data. In
Debug builds `RECOVERKIT_SNAPSHOTS=<dir>` renders every window and wizard page to PNG and exits,
which makes layout changes quick to check.

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

Repeat `--keyfile <path>` for each required keyfile. Files must be readable and nonempty; paths
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


## Continuous integration

`.github/workflows/build.yml` runs on every push and pull request. The `windows` job
(`windows-latest`) builds the native kernels, runs the tests and builds the MSI and a portable zip.
The `macos` job (`macos-15`, Apple Silicon) runs the tests on arm64, builds hashcat (cached by
the build script's hash) and the disk image. Both upload their files as workflow artifacts. Pushing
a tag such as `v1.2.0` makes the `release` job publish all three files as a GitHub release with
that version.

## Technical notes

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
