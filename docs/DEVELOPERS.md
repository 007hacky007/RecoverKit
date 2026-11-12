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
src/RecoverKit.App    WinForms GUI (net10.0-windows, win-x64)
tests/RecoverKit.Tests  xUnit tests for parsers, charsets, extractors
native/               native CPU kernels (C, built with zig)
docs/                 benchmarks, screenshots, this file
```

`RecoverKit.Core` is plain cross-platform .NET; only `RecoverKit.App` requires Windows.

## Building

Requires the .NET 10 SDK, and [zig](https://ziglang.org) 0.15.2 for the native kernels.

```
sh native/build.sh          # rknative.dll (win-x64) and librknative.dylib (osx-arm64)
dotnet build RecoverKit.sln -c Release
dotnet test tests/RecoverKit.Tests
```

The Windows GUI:

```
dotnet publish src/RecoverKit.App -c Release -r win-x64 --self-contained false -o publish
```

hashcat is the GPU engine and is fetched on demand: the first time you start RecoverKit
without it, choose **Tools > Download hashcat** (also on the Preferences "Files and Paths"
tab, or run `recoverkit-cli install-hashcat`). It downloads the pinned release from
hashcat.net, checks its SHA-256, and unpacks it into a per-user `engines` folder that
RecoverKit then finds automatically. On Windows the small official `7zr.exe` extractor is
downloaded too when no 7-Zip is already installed.

You can still place hashcat in a `hashcat` folder next to `RecoverKit.exe`, or point at an
existing install in Options > Preferences > Files and Paths.

## Installer

A standard Windows Installer (.msi) is built with WiX v6. On Windows x64 with the .NET 10
SDK:

```powershell
powershell -ExecutionPolicy Bypass -File installer\build.ps1
```

It publishes the app and writes `installer\out\RecoverKit-1.0.0-x64.msi`, which installs
into `Program Files\RecoverKit` with Start Menu and desktop shortcuts and an Add/Remove
Programs entry. The default build is self-contained (no runtime prerequisite); pass
`-FrameworkDependent` for a smaller MSI that needs the .NET 10 Desktop Runtime. See
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
recoverkit-cli crack hash.txt --hash-mode 13000 --dict words.txt   # any hashcat mode
recoverkit-cli decrypt secret.docx <password> [out.docx]           # decrypt an MS Office file
```

`--new` ignores a saved session and starts over; `--no-potfile` disables the cache.

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

`.github/workflows/build.yml` runs on every push and pull request on `windows-latest`: it builds
the native kernels, runs the tests, builds the MSI and a portable zip, and uploads both as workflow
artifacts. Pushing a tag such as `v1.2.0` also publishes them as a GitHub release with that version.

## Technical notes

- RAR 3.x recovery covers archives with encrypted file names (`-hp`, hashcat 12500). Archives
  with encrypted data only need an external `$RAR3$*1*` extraction.
- The per-user CPU runtime is not used when RecoverKit runs as administrator: the OpenCL loader
  ignores per-process driver lists in elevated processes on purpose, and RecoverKit does not register
  a user-writable DLL system-wide.
- The debug log (`%APPDATA%\RecoverKit\logs`) records environment, settings, every hashcat command
  with output and exit code, detection results, wizard choices and crashes. Recovered passwords are
  never written to it, and the profile path and account name are replaced by `%USERPROFILE%` / `%USERNAME%`.
- The built-in downloader pins hashcat 7.1.2. hashcat 8 changed `--restore` and `-w` handling, which
  the resume and workload features rely on.
- Apple iOS backup extraction follows the documented keybag format and reproduces hashcat's example
  hashes, but has not been verified against a real backup. Automatic decryption is implemented for MS
  Office OOXML only.
