# RecoverKit for developers

How RecoverKit is built, tested and packaged. For using the program, see the [README](../README.md).

## How it works

RecoverKit reads a protected file, extracts the data needed to verify passwords, and drives the
open-source [hashcat](https://hashcat.net) engine for GPU work. Writing dozens of GPU kernels is
not practical: hashcat already implements every supported format with mature NVIDIA (CUDA/OpenCL),
AMD (HIP/OpenCL) and Intel Arc (OpenCL) backends. RecoverKit owns format parsing, the attack model,
scenarios, the wizard GUI and session management.

For formats where hashcat's CPU kernels are slow, a built-in CPU engine runs brute-force and mask
attacks: managed .NET kernels plus a small native C library (`native/rknative.c`, built with
`zig cc`). Without a GPU it runs them alone; with a GPU it runs next to hashcat on another part of
the keyspace (hybrid CPU + GPU, below). See [benchmarks.md](benchmarks.md).

The one exception on the GPU side is classic ZIP (ZipCrypto, modes 17200/17210): RecoverKit ships
its own versions of those two hashcat kernel sources and installs them into hashcat's `OpenCL/`
folder (see [ZIP kernels for hashcat](#zip-kernels-for-hashcat)).

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

## Detailed performance diagnostics

`recoverkit-cli bench-full --out report.html` runs the same Core diagnostics as **Tools >
Benchmark > Detailed performance test**. `--sections system,cpu,gpu,zip,hybrid` selects sections.
The quick benchmark keeps its existing speed-cache behavior. Detailed measurements use synthetic
targets, isolate hashcat work, retain partial results on cancellation, and write a self-contained
HTML report with embedded JSON. Compare only rows with the same target and candidate length;
hashcat's built-in benchmark and the native microbenchmarks are separate workloads.

The performance profile lives beside settings under `RECOVERKIT_HOME` when set. Its decisions
require correctness and repeated measurements with at least a 5% margin; explicit user settings
win. CPU and GPU fingerprints allow driver changes to invalidate GPU choices without discarding
CPU path measurements. The default has 115 seconds of work plus 5 seconds reserved for cleanup:
system/setup 8, CPU 28, GPU 45, ZIP kernels 24, finite hybrid checks 10. The full step list is planned
before running. Each step and section has an enforced timeout; omitted or timed-out work is listed
as "not measured, run the thorough test". All CPU paths get correctness gates first, then selectable
paths get one one-second timing at the logical-thread count. Representative backend probes cover
PDF R3 and RAR 5; an alternative must win both by 10% to apply across other modes. Main-format GPU
rates use that backend only. Stored/deflated kernel probes and predicted-worker finite hybrid checks
follow. Short CPU samples exclude a half-second warmup within their two-second slots. Unconfirmed
CPU choices stay eligible for the six-second lazy calibration; GPU/kernel/execution choices retain
their current defaults until a confirmed detailed measurement.
One isolated engine directory and kernel cache serve the whole test. Progress uses planned budgets
and actual durations. `--thorough` / **Thorough (slower)** retains the full repeated sweep, including
all eleven modes on each backend, pure kernels, repeats, worker sweeps and integrated-GPU comparisons.
Preferences exposes automatic calibration and profile reset.

Comparison targets come from `BenchmarkTestFiles`: deterministic real ZipCrypto archives (stored
17/453/4096 bytes with one/two-byte checks, deflated 1024/16384 bytes with/without descriptors),
WinZip AES-256 AE-2, PDF R3/R6 and encrypted OOXML Office 2007/2013 documents. The generators use
only the standard library and existing cryptographic helpers. Their passwords are outside the
lowercase-plus-digits length-seven comparison mask. Export passwords appear only in readme.txt;
HTML/JSON contains metadata and rates, never file bytes, hashes or passwords. Rates are matched
by exact synthetic file, attack and length, not by format alone. The report permits only a fixed
list of synthetic export names through its filename scrubber. RAR 3/5 remain hashes only and are
called out in the readme. `--export-tests <folder>` and the GUI Save test files action use the
same catalog. Existing export files are never overwritten.

Automatic calibration currently measures CPU variants and worker counts, with a six-second budget,
only for masks of up to ten characters whose estimated duration is at least twelve seconds. It
keeps the engine strategy until a detailed finite comparison is available. Detailed whole-job
engine comparisons cover RAR 5 and stored ZipCrypto; other formats retain their existing engine
strategy. GPU backend choices are measured per physical device, never by adding aliases. The finite jobs
compare the current backend with any repeatable backend winner found earlier in the test.
ZIP GPU source variants are applied when a single physical GPU runs the job; a mixed-device
process keeps the replacement default because it shares one kernel source tree and kernel flag.
If a temperature or duty guard is active, the raw hashcat benchmark and ZIP comparison are skipped;
the finite jobs use the normal guarded runner. A requested power cap must already be active.
All skipped or unavailable cases remain visible in the report. Native CPU checks and timings
run in short-lived child processes; a native fault is recorded and remaining steps continue.

## Building

Requires the .NET 10 SDK, and [zig](https://ziglang.org) 0.15.2 for the native kernels.

```
sh native/build.sh          # rknative.dll (win-x64) and librknative.dylib (osx-arm64)
dotnet build RecoverKit.sln -c Release
dotnet test tests/RecoverKit.Tests
```

Stay ZIP tests that search key spaces (`Category=Stay`) take many minutes, so `dotnet test`
skips them. Run them with `dotnet test tests/RecoverKit.Tests -p:RunStayTests=true --filter Category=Stay`.
Fast payload extraction, archive generation, decryption, filter and key verification tests run
in the normal suite, even when their files are under `Stay/`.
Tests that run hashcat on the GPU (`Category=Slow`, for example `ZipGpuKernelSlowTests`) are skipped
as well; run them with `-p:RunSlowTests=true` or an explicit `--filter`.
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

It downloads the official hashcat 8.0.0 source tarball (SHA-256 pinned in the script), builds
an arm64-only binary with the Metal backend (`SHARED=0`: no libhashcat.dylib; nothing from
Homebrew; `otool -L` is checked so that only system libraries and frameworks are linked) and
assembles a portable folder in `macos/out/hashcat/`: the executable, `modules/`, `bridges/`
(argon2, scrypt; the Python, Rust and FPGA bridges are left out), `feeds/` (candidate generators:
stdin and wordlists go through them in hashcat 8), `OpenCL/` kernel sources, `charsets/`, `tables/`
(keyboard layouts, formerly `layouts/`), `masks/`, `rules/`, `tunings/`, `pcfg/`,
`hashcat.hcstat2`, the license texts in `docs/` and a `RECOVERKIT_BUNDLE` stamp
(`<hashcat version>-<bundle revision>`). hashcat 8 loads liblzma (every mask attack reads the
LZMA2-compressed `hashcat.hcstat2`) and zlib at run time; macOS has both in `/usr/lib`. The build
takes about four minutes and the folder is about 130 MB. It is skipped when the folder already
holds the same stamp.

Portable mode: hashcat compares the folder of its resolved executable with the install folder
compiled in (`PREFIX/bin`, `/usr/local/bin`). When they differ, which is everywhere except
`/usr/local/bin`, it reads its data from and writes kernel caches, `hashcat.log`, dictstat and
pid files to the executable's own folder (hashcat 8: kernel caches in `cache/kernels/`).

That folder goes into `RecoverKit.app/Contents/Resources/hashcat/`. Because hashcat writes into
its folder and the signed app bundle must stay unchanged (it may also be read-only), RecoverKit
never runs it there: `HashcatInstaller.TryInstallBundled()` copies it to
`~/Library/Application Support/RecoverKit/engines/hashcat-8.0.0` (keeping executable bits,
dropping the quarantine attribute) when that copy is missing or has another stamp, and
`HashcatTool.Locate` prefers that copy. `recoverkit-cli install-hashcat --from macos/out/hashcat`
installs a build by hand.

On Apple Silicon hashcat lists the GPU twice, as a Metal device and as an OpenCL alias, and by
default disables Metal while an OpenCL device exists (`-d <metal id>` forces Metal). There is no
CPU device, so the "Don't use GPU threads" strategy only works for formats the built-in CPU
engine supports. hashcat 7 refused some modes on the Apple GPU (17200 PKZIP: its inflate code used
`goto`, which Metal rejects, and Apple's OpenCL compiler never finished it); hashcat 8 runs them on
Metal and OpenCL. Should a mode still be refused and the built-in CPU engine support it, the attack
step reruns on the CPU automatically.

## ZIP kernels for hashcat

hashcat compiles its kernels at run time from the `.cl` sources in its `OpenCL/` folder, and the
same source serves CUDA, HIP, OpenCL and Metal. RecoverKit therefore speeds up classic ZIP
(ZipCrypto) on the GPU by replacing two source files, without GPU host code of its own:
`src/RecoverKit.Core/Hashcat/Kernels/` holds the brute-force/mask (`_a3`) and dictionary/rules
(`_a0`) kernels for `m17210` (stored entries) and `m17200` (deflated entries), the shared
`inc_rk_zipcrypto.cl` and the kernel bodies `inc_rk_zip_a3.cl` and `inc_rk_zip_a0.cl`, embedded
in RecoverKit.Core. `HashcatKernels.EnsureFor` writes them into hashcat's `OpenCL/` folder before a
mode 17200/17210 run or benchmark, keeping hashcat's file as `<name>.hashcat`. It only replaces a
file whose content is exactly hashcat 8.0.0's (line endings ignored; the Windows release uses
CRLF), or an earlier RecoverKit kernel with that original saved beside it, so another hashcat
version is left alone. hashcat 8 keys its kernel cache on the kernel
source and on every non-kernel file in `OpenCL/`, so the new kernel is compiled on first use.
`RECOVERKIT_HASHCAT_ZIP_KERNELS=0` keeps hashcat's kernels. Combinator and hybrid attacks
(`-a 1/6/7`, hashcat's `_a1` kernels), multi-file hashes (17220/17225) and checksum-only hashes
(17230) still run hashcat's kernels; RecoverKit's ZIP targets use none of them.

Why hashcat's kernels are slow: each candidate runs the key schedule and decrypts the 12-byte
encryption header; when the check byte matches (1 in 128 with the CRC and time check bytes,
1 in 256 with one), the same thread decrypts the whole entry and computes its CRC-32 (17210) or
inflates it (17200) inside the candidate loop. The other threads of the SIMD group wait for it,
and with 32 threads one of them hits a check byte in about every fourth step, so the cost grows
with the entry size: on the M1 Pro a 1 KB stored entry ran 13 times slower than a 17-byte one.

The replacement kernels:

- The candidate loop does only the key schedule and the header. A candidate that passes the check
  byte is queued in local memory (one 32-bit word: thread and `il_pos`); after a round of
  candidates the whole work-group verifies the queue together, one candidate per thread, with the
  keys computed again. The rounds are sized for about 512 queued candidates (`RK_QUEUE` 1024). When
  the queue is full a thread starts its next round at the first candidate it could not queue, so
  nothing is lost; verifying inline instead put the long verification loop into the candidate
  loop, and that alone halved the speed on the Apple GPU (register pressure).
- The kernel bodies are plain code included into each kernel function (`#include` inside the
  function, once per `_sxx`/`_mxx`), not one big macro: Apple's OpenCL compiler ran the identical
  code at less than half the speed when it came from a macro. The candidate loop is not unrolled
  (`#pragma unroll 1`).
- hashcat's mask attack varies the first one to four characters fastest (the "amplifier" in
  `words_buf_r`), so the key schedule cannot be shared between candidates the way a CPU loop over
  the last character shares it. `RK_AMP_CACHE 1` computes the key state after the amplifier's
  characters once per work-group into 12 KB of local memory; it brought nothing on the M1 Pro, so
  it is off, and `bench-zip` measures it on other GPUs.
- Dictionary attacks (`-a 0`) apply the rule to the word as hashcat's kernel does and use the same
  queue; association attacks (`-a 9`) keep hashcat's one-candidate-per-hash logic.
- Verification is the same as hashcat's: CRC-32 of the stored data, or for deflate hashcat's
  block-type and Huffman-table pre-checks and its inflate (`inc_zip_inflate.cl`).

Correctness: `ZipGpuKernelSlowTests` builds random archives (`ZipCryptoSample`: stored and deflated
entries, 1-3 files, with and without data descriptors, passwords of 1 to 64 characters), attacks
them with masks of a few thousand candidates on every GPU device (`--keep-guessing`) and requires
exactly the passwords the built-in CPU engine accepts among the same candidates; a dictionary
test does the same with rules (keep, append, delete last). A third test installs the include with
a two-entry queue so that the retry path runs all the time. On the M1 Pro all three pass on Metal
and OpenCL (and the random-archive test also with `RK_AMP_CACHE 1`).

`recoverkit-cli bench-zip [--device N] [--seconds S]` measures hashcat's kernels against
RecoverKit's on every device (CUDA, OpenCL and Metal aliases separately) for entries of 17 bytes to
16 KB; see [benchmarks.md](benchmarks.md#zip-on-the-gpu).

### Large entries

If every usable encrypted entry exceeds hashcat's 320 KiB limit, `ZipExtractor` emits a type 1
`$pkzip2$` hash with the first 256 KiB (including the encryption header). Full entries still take
priority, with the selection rules below. The prefix crosses several stored deflate block headers;
a short prefix ending inside the first block would admit too many wrong passwords. The unmodified
module passes `data_type_enum == 1` to RecoverKit's kernels. They check the header, first deflate
block and available inflate data without requiring end-of-stream or the full length. Full hashes
retain the original inflate/CRC checks.

`HashTarget.ZipPartial` keeps the archive path, entry offset, lengths, method and CRC, and the other
ZipCrypto entries' header checks (`Siblings`, from `ZipPasswordConfirmer`). CPU `Verify` decrypts from
that file through bounded streams and checks the entire output length, deflate end and CRC-32,
without the old 64 MiB embedded-data limit. That costs as much as thousands of candidates (about
170 us for a deflated 1.3 MB entry, 24 ms for a stored one), and 1 candidate in 256 passes the
header check. For deflate, survivors first pass `DeflateStartIsPlausible` on the first decrypted
bytes, then inflate at most 4 KiB of encrypted input in memory. Full embedded targets use the same
staged check before decrypting the whole body. For partial targets, the session confirmer's own
sibling header checks run before the inflate stage or archive read. Early rejection cannot change
the result because the confirmer rejects the same candidates. Stored partial targets without
siblings have no cheap body check.
`ConfirmPassword` also runs the existing other-entry checks. Partial GPU runs always use outfile
confirmation and keep guessing.

The GPU kernels need hashcat 8.0.0's kernel files (`HashcatKernels.Originals`). An older hashcat (one
left by an earlier RecoverKit in `engines/hashcat-7.1.2`, or the user's own) makes `Inspect` return
`Unsupported`, which used to send ZIP attacks to the CPU without a word; `HashcatKernels.UnavailableReason`
now names the cause in the log. At start the main window compares the version hashcat reports with
`HashcatInstaller.Version` (`HashcatTool.IsOlderThanPinned`, not the folder name) and offers the pinned
version (`OfferHashcatUpgradeAsync`): once per start for a copy RecoverKit installed, and for the user's
own copy until they decline it (`Settings.DeclinedHashcatUpgrade`, keyed by path and version). `Locate`
prefers the pinned copy over any other `engines/hashcat-*` (`IsUnpinnedManagedCopy`).

Stored partials have only the header check (1 in 128 or 256 candidates), which overwhelms
hashcat's one-hit-per-launch result buffer and can hide the real password. Recovery therefore
uses the CPU for these entries. If replacement kernels are unavailable, partial deflated targets
also use the CPU. Masks/brute-force and plain dictionaries are supported; CPU dictionary fallback
does not interpret hashcat rule files or extra options and explains that limit before starting.
The CLI and GUI Notes describe partial targets. GPU tests are opt-in through `RunSlowTests`.

### False positives

The hash covers one entry. For a stored entry a wrong password passes the check byte and the CRC-32
about once in 5 * 10^11 candidates, a few minutes of GPU work; deflated entries must also inflate to
the stored length, so they are far safer. `ZipExtractor` therefore attacks the smallest deflated
entry unless a stored one is at least 8 times smaller (entries within hashcat's 320 KB limit first),
and when the archive has other classic ZipCrypto entries it sets `HashTarget.ConfirmPassword`
(`ZipPasswordConfirmer`): up to 16 other entries, each checked by its header's check byte and, for
stored or deflated entries up to 1 MB (4 MB in all), by decrypting, inflating and comparing the
CRC-32. A single stored entry gets a note to confirm the password by opening the archive.

With a confirmation check:

- Built-in engine and hybrid CPU side: a hit must pass `kernel.Verify` and the check. A rejected hit
  is logged ("False positive rejected", length only, the first three per session) and the search
  continues right after it in the same kernel call (`NativeEngine.SearchFrom`), so nothing is skipped.
- hashcat: runs with `--keep-guessing --potfile-disable`. `HashcatRunner` reads the outfile while it
  runs (every 0.5 s; hashcat writes it once per kernel launch), checks each plaintext ($HEX[...]
  decoded) and stops hashcat gracefully at the first confirmed one, which counts as cracked. Without
  one the step is exhausted, whatever hashcat's exit code. On macOS these runs use each GPU's Metal
  device instead of the OpenCL alias hashcat picks: with Apple's OpenCL, hashcat 8 never clears a
  hash's "shown" flag after a hit (the `clEnqueueFillBuffer` reset has no effect), so with
  `--keep-guessing` it reports nothing after the first hit. On the M1 Pro a run that hit a false
  positive at 1% missed the real password at 38% on OpenCL, with hashcat's kernel and with
  RecoverKit's; on Metal both were reported.
- Password cache: a confirmed password is written as `hash:$HEX[...]` by RecoverKit itself. On
  reading, hashcat's `--show` (which prints one plaintext per hash, the last matching line) plus
  RecoverKit's own lines for the hash are each checked again; false positives are dropped.

Limitation: hashcat reports at most one hit per hash per kernel launch (the kernel's `hashes_shown`
gate and a one-slot result buffer; `--keep-guessing` only resets the gate after the launch). When a
false positive and the real password fall into the same launch, either may be the one reported, so
the real password can be missed in that run. hashcat sizes a launch to about 0.1 s of GPU work, so
for a stored entry this happens in roughly 1 run in 4,000 at 3 billion candidates per second (M1 Pro)
and 1 in 400 at 30 billion; deflated entries are far less affected, the built-in engine not at all.

`ZipFalsePositiveTests` uses a stored entry built so that a known wrong password passes its check byte
and CRC-32 (header bytes and four content bytes searched, about 2^32 trials), checks the confirmation,
the engine's continuation within a batch, hashcat's outfile handling (a Python stand-in for hashcat)
and the cache filter; `HybridTests` checks the CPU side of a hybrid run.

## CUDA on NVIDIA (NVRTC)

hashcat drives NVIDIA GPUs through CUDA or OpenCL. The OpenCL compiler is part of the driver, but
CUDA needs NVIDIA's run-time compiler NVRTC (`nvrtc64_*.dll` and `nvrtc-builtins64_*.dll`), which
comes with the CUDA Toolkit and not with the driver; without it hashcat uses OpenCL and lists no
CUDA device. hashcat 8 (`src/ext_nvrtc.c`) loads `nvrtc.dll`, or else the newest `nvrtc64_*.dll`
in `%CUDA_PATH%\bin`, `%CUDA_PATH%\bin\x64` or any `PATH` folder, and the matching builtins DLL
next to it; it needs CUDA 12.0 or later for both the driver and NVRTC.

NVIDIA publishes NVRTC on its own as the `nvidia-cuda-nvrtc-cu12` package on PyPI (CUDA EULA,
which lists these DLLs as redistributable). **Tools > Download NVIDIA CUDA compiler (NVRTC)**
(Windows) downloads the wheel after the user accepts NVIDIA's license, checks its SHA-256,
unpacks the two DLLs and the license text into `engines/nvrtc-<version>` and puts that folder on
the `PATH` of every hashcat process (`NvrtcRuntime.ApplyTo`; not when RecoverKit runs elevated,
as with the CPU runtime). hashcat hands the driver PTX from NVRTC, and a driver only accepts PTX
from an NVRTC no newer than itself, so the package is chosen by the CUDA version in
`nvidia-smi`'s banner: 12.8.93 for drivers with CUDA 12.8 or later (also the first that knows the
RTX 50 series), 12.4.127 for CUDA 12.4 to 12.7; older drivers are asked to update. The start page
says when an NVIDIA GPU runs through OpenCL. Installing the CUDA Toolkit works as well. Whether
CUDA is faster than OpenCL for a given mode shows in `recoverkit-cli bench-zip`, which measures
both. The download and the CUDA path were not tested on real NVIDIA hardware.

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
recoverkit-cli crack file.pdf --hcmask '?l?l?l?l?l' --no-hybrid    # hashcat alone on the GPUs
recoverkit-cli decrypt secret.docx <password> [out.docx]           # decrypt an MS Office file
```

`--new` ignores a saved session and starts over; `--no-potfile` disables the cache.
`--strategy GpuOnly|FastGpu|GpuAndCpu|CpuOnly` picks the CPU/GPU strategy, `--no-hybrid` turns the
hybrid CPU + GPU mode off, `--hashcat-cpu` adds hashcat's CPU device next to the GPUs for formats
without a built-in kernel and `--threads N` limits the CPU threads, all for one run. The status
lines list each device's speed in hybrid runs.
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


## Devices

hashcat runs on every GPU it can use: discrete and integrated, each physical device once (a GPU
seen through CUDA or HIP and again through OpenCL is used through CUDA/HIP, the OpenCL alias is
skipped, as hashcat does; on Apple silicon the OpenCL device is used and the Metal one skipped).
`hashcat -I` prints no `Type` for CUDA and HIP devices; they are GPUs, and before this was handled
a GPU used through CUDA or HIP counted as "no GPU" (its OpenCL alias being skipped), so the GPU list
stayed empty and the built-in engine ran alone. Devices the user unchecks are remembered by backend,
name and position (`Settings.DisabledDeviceKeys`), not only by hashcat's id, which shifts when a
driver adds or removes a backend. `Memory.Unified` marks integrated GPUs.

## Native kernels

`native/rknative.c` is plain C with intrinsics; `build.sh` compiles it with zig for win-x64 and
osx-arm64. Every vector path has a per-function target attribute and is chosen at run time from
`rk_features()` (cpuid / xgetbv on x64, sysctl on macOS), so the library loads on any CPU of the
architecture. `rk_set_features(mask)` (`RkNative.LimitFeatures`) turns paths off for tests and
benchmarks. `RK_API_VERSION` must match `RkNative.RequiredVersion`; bump both when an export
changes, and add a bit to both feature enums for a new instruction set (AVX-512 is bit 512: CPUID
leaf 7 AVX512F plus the opmask and ZMM state enabled in XCR0).

PBKDF2-HMAC-SHA256 (`pbkdf2_sha256()`, for RAR 5 now and meant to be reused by later kernels):
per candidate, scalar code computes the HMAC inner and outer states (key xor ipad / opad, keys
over 64 bytes hashed first) and U1. The remaining iterations are two SHA-256 compressions of a
32-byte message, one lane per candidate. `native/sha256_lanes.h` holds that loop once, in generic
clang vector arithmetic, and is included per width: 16 lanes with AVX-512 (the rotates become
VPROLD and the boolean trees VPTERNLOGD), 8 with AVX2, 8 on NEON register pairs, and 1 (scalar
fallback). The first round of each compression depends on the message only through W0, so it is
computed once per call; message words 8-15 are constant padding and fold into the schedule. On
arm64 with the SHA-256 instructions, 8 interleaved streams of SHA256H/H2 are used instead
(2.4 times the NEON path on an M1 Pro, 730 against 308 candidates per second per core). The
`rk_pbkdf2_sha256` export takes candidates of different lengths and any salt, iteration count
and output length; `Pbkdf2Sha256Tests` checks it against .NET on every path the CPU has.

RAR 5 (`Rar5Kernel`, mode 13000): the hash line is `$rar5$16$salt$lg2$iv$8$check`. WinRAR's key
is PBKDF2 with 2^lg2 iterations; the password check value continues to 2^lg2 + 32 iterations and
folds the 32 bytes to 8 (byte i xored into byte i % 8), exactly as hashcat's m13000 kernel. The
iteration count comes from the hash (lg2 1-24); hits are confirmed with .NET's PBKDF2. The kernel
is offered when the library has a vector path (AVX2 or NEON).

ZipCrypto (`ZipCryptoKernel`, modes 17200/17210): API version 9 adds `rk_zip_search_batch`
alongside `rk_zip_search` and `rk_zip_path`. The managed worker keeps its prefix-key cache and
passes the three keys after the prefix plus the final-position charset. The C filter returns all header survivors in candidate
order, then the existing managed `Verify` checks the entry. It deliberately filters only the last
header byte, including for two-check-byte archives; `Verify` handles the other byte. No password
packing, heap allocation or prefix re-hashing is needed in the native loop.

Small final charsets request multiple prefixes with `RkNative.BatchFor`. The worker fills lanes
across prefixes with three arrays of per-candidate prefix keys and a final-character array. Native
paths share their rounds with single-prefix search; managed AVX2 and NEON load the same keys.
Charsets of 48 or more keep the single-prefix path, including the 95-character benchmark.
`ZipCryptoNativeTests.CpuMaskRatesCompareLaneFillWithOnePrefixAtATime` (category `Slow`) prints
three paired CPU-only rates for literal, digit, lowercase and all-printable mask endings.

`native/zip_lanes.h` supplies the same rounds for AVX-512 (three groups of 16), AVX2 (three groups
of 8), NEON (four groups of 4, nibble-table lookups), and scalar (four interleaved candidates).
AVX2 and AVX-512 use the same source with width-specific gathers from the 1 KB CRC table and
32-bit multiplies. On ARM with CRC32 instructions (feature bit 1024), eight independent scalar
candidates use `CRC32B` for both key updates. The last header byte needs no following key update.
ARM CRC is the measured automatic choice on the M1 Pro, with native NEON as the ARM fallback.
x86 CPUs keep managed search by default; native x86 and scalar are opt-in for comparison. AVX2 and
AVX-512 were cross-compiled but not executed here. Rosetta exposed only scalar on this Mac.

For testing and comparison, set `RECOVERKIT_ZIP_PATH` to `managed`, `managed-scalar`, `scalar`,
`neon`, `arm-crc`, `avx2`, or `avx512` (`auto` or unset restores the default). Unsupported native
requests fall back to managed search. `RECOVERKIT_NO_NATIVE_LIB=1` still disables the entire
library. `bench-native --mode 17210` labels the selected path and adds a separate native comparison
row when automatic selection stays managed. Use a Release build for throughput measurements.
`ZipCryptoNativeTests` checks every native path available on the host against a bitwise CRC
reference and managed scalar search, including partial groups, ordered hits, feature masking,
prefix changes, 64-byte passwords, stored/deflated entries and one/two-check-byte hashes.
`native/tests/zip_test.c` is an independent standalone differential test suitable for sanitizer
builds; its first comment gives build commands.

## Hybrid CPU + GPU

With a GPU, brute-force and mask attacks on formats with a built-in kernel run on both engines at
once (`HybridRunner`; on by default, Preferences > Performance, `--no-hybrid`): hashcat on the GPUs
(`-D 2`, never on the CPU) and the built-in engine on the CPU, on disjoint parts of the keyspace.
Strategies "Keep one CPU thread free for each GPU" (default) and "Use all CPU threads" use it; the
first leaves one thread per active GPU to hashcat's host thread, and Preferences' thread limit is
respected. "Avoid the CPU" and "CPU only" do not.

Numbering. In a mask attack hashcat counts base words, not candidates (`HashcatOrder`): the first
positions of the mask form the amplifier, which the kernel runs through for every base word, and the
rest form the base word, numbered as a mixed-radix number whose least significant digit is the
first base position. `--skip`, `--limit` (a count when `--skip` is given) and restore points use
that number. Each position's characters are ordered by hashcat's Markov table, so RecoverKit passes
its own table (`--markov-hcstat2`, `Native/Resources/ordered.hcstat2`, made by the script next to
it) in which every count differs and the order is ascending byte value. How many positions form the
amplifier depends on the mode and mask; it is derived from `hashcat --keyspace` for each length (the
base word count is the product of the base positions). For any range of base words,
`HashcatOrder.Boxes` gives mask spaces for the built-in engine that hold exactly its candidates:
one digit runs over a sub-range, the lower digits and the amplifier are free, the higher ones fixed.
`HybridHashcatTests` (category `Slow`) checks the numbering against a real hashcat for a fast mode
with one and three amplifier positions, a UTF-16 mode and an iterated mode.

Split. Lengths run one after another (hashcat refuses `--skip` with `--increment`). hashcat takes
base words from the bottom, the CPU takes batches of about 3 s from the top, so what is left is
always one interval plus at most one unfinished CPU batch. The last character is hashcat's most
significant digit, while the built-in kernels run through the last character themselves and are
fastest with all of it (RAR 3: 4,600/s with ten last characters, 2,200/s with one, M1 Pro); so when
one value of the last character is at most a minute of CPU work, batches and the split point fall
on whole values of it. Until hashcat reports its first speed the CPU uses half its threads, because
hashcat's self-test and autotune need the processor. The first split makes both sides finish
together, counting hashcat's start-up (self-test, autotune; measured per run and remembered per
mode, about 25-75 s on an M1 Pro), from the speeds remembered from the last hybrid attack or the
Benchmark (`GpuSpeedByMode`, `CpuSpeedByMode`). A length the CPU finishes in less than two hashcat
start-ups stays on the CPU. Rebalancing: when the CPU runs out of work while hashcat still needs
more than three start-ups, or once hashcat's speed is known it would finish more than five start-ups
after the CPU, hashcat is stopped, its restore point read from its `.restore` file
(`restore_data_t.words_cur`, offset 272) and the rest split again. When hashcat finishes first it
starts again on what the CPU has not taken. If hashcat fails (or quits on its own), the CPU takes
everything left and later lengths stay on the CPU; if the CPU engine fails, its unfinished batch
goes back to hashcat. A find on either side stops both and is reported once; a CPU find is written
to the password cache in hashcat's format.

Resume. `<session>.hybrid.json` holds the length, hashcat's restore point, the CPU batch and the
box and prefix inside it. Nothing is skipped; work that was in flight at the stop is redone, as
hashcat and the built-in engine each do on their own.

Status. One status per second: summed speed, progress and time left for the length, hashcat's
device rows plus a "CPU (built-in engine)" row. While the temperature guard pauses hashcat the CPU
keeps working. The Benchmark window and the wizard's speed measurement run hashcat's benchmark on
the GPUs and the built-in benchmark on the CPU at the same time and add them.

Integrated GPU only (Apple silicon): the CPU and GPU share one power budget and memory, so a busy
CPU slows the GPU. RAR 3 on an M1 Pro: the GPU ran 8,000-11,000/s next to the CPU engine instead of
11,500-14,000/s alone, and the CPU added about 1,700/s. When every GPU in use is integrated and the
last hybrid attack on a mode measured the CPU below a quarter of hashcat's speed, later attacks on
that mode run hashcat alone (logged; `HybridRunner.CpuAddsTooLittle`). PDF R6, where the CPU is
five times faster than this GPU, keeps both.

Integrated GPU next to a discrete one: it ties up a CPU thread (hashcat's host thread) and shares
the processor's power budget. Once hashcat reports its speed, an integrated GPU slower than one CPU
thread of the built-in engine is left out of the next hashcat runs of that attack and its thread
goes back to the CPU engine (logged). Faster integrated GPUs, and Apple silicon's only GPU, stay in.

Other formats: Preferences "For other formats, also give hashcat the CPU next to the GPUs" (off;
`HashcatCpuWithGpu`, `--hashcat-cpu`) adds `-D 1,2` when hashcat sees a CPU device. hashcat's CPU
kernels are far slower than a GPU and compete with the threads that feed the GPUs, so expect a few
percent at best; it was not measured (the Mac used for this work has no OpenCL CPU device).

Priority on macOS: a niced process, and "Idle" is nice 19, runs on the efficiency cores, and an
unprivileged process cannot raise its priority again; lowered thread priorities do the same as
soon as anything else runs. Measured on an M1 Pro: PDF R6 at "Idle" 10,000-16,000/s instead of
55,000/s, RAR 3 at "below normal" 1,800/s instead of 4,400/s, and a niced hashcat next to the CPU
engine fed the GPU at 2,500 instead of 9,600/s. So on macOS neither the built-in engine nor hashcat
lowers its priority; the setting applies on Windows.

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

- `OfficeKnownPasswords` checks default/empty passwords using only encryption verifiers;
  detection never reads `EncryptedPackage`. Standard and Agile reuse `OfficeDecryptor`'s
  KDF and AES routines; Agile derives its iterated password hash once per candidate for both
  verifier blocks. The KDF reuses buffers and hash state, and detection skips Agile spin counts
  above 1,000,000 to bound work on untrusted headers (reported in detection info). OOXML unlocks
  decrypt to a temporary file beside the destination and rename it atomically. Legacy RC4
  unlocks report the password only: BIFF record exclusions, block rekeying and OLE stream
  rewriting need a separate decryptor. CryptoAPI 128-bit hashes use type 4 and hashcat, since
  the built-in CPU kernel implements only 40-bit keys. Hashcat does not support all Agile
  key/hash combinations; their default/empty password unlocks still work without an attack
  target. Fixtures use msoffcrypto-tool, LibreOffice and Apache POI 5.4.1 (sources in NOTICE).
  Extraction was compared with `office2john.py` and hashcat 7.1.2 modules 9400-9800. Saved
  `.xlsx`, `.xlsm` and `.xlsb` packages were reopened through LibreOffice headless without
  supplying a password.
- Office XOR recovery lives in `Formats/OfficeXor.cs`, with one dispatch hook in `OfficeExtractor`.
  It recognizes Word FIB versions 0x65-0x69 (including the 0xA5DC signature), Word 97+ fObfuscated,
  BIFF5 four-byte FILEPASS and BIFF8 encryption-type-zero FILEPASS. It implements
  [MS-OFFCRYPTO 2.3.7](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/06494548-8c5c-4697-bce1-e2a9fe1c4de4)
  array reversal using WRITEACCESS space padding, common BIFF bytes, and Word font/text data.
  ASCII candidates of 1-15 characters must match the array evidence, key and verifier. Matching
  the key/verifier alone is insufficient because the array also contains the password bytes.
  Recovery reads at most 1 MiB per stream; files with insufficient evidence remain inconclusive.
  Results are password-only `InstantUnlock` entries, with no hashcat mode, target or attack scenario.
  No CFB writer or deobfuscated-copy action is added. The small fixtures include an original POI
  XOR workbook and independently obfuscated real Word/BIFF5 files. Headless LibreOffice 26.2.4.2
  reopened the recovered passwords and checked document text and worksheet cells against the sources.
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
    the original wallet. hashcat 7 refused large Electrum wallets (mode 21800) on Apple GPUs;
    hashcat 8 runs them. Hardware-encrypted BIE2 files are unsupported. Legacy Electrum 1.x
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
  Data-only recovery uses hashcat on both CPU and GPU; the built-in RAR 3 kernel handles `-hp` only.
  Only the selected file's password is recovered; other entries can have different passwords.
- The per-user CPU runtime is not used when RecoverKit runs as administrator: the OpenCL loader
  ignores per-process driver lists in elevated processes on purpose, and RecoverKit does not register
  a user-writable DLL system-wide.
- The debug log (`%APPDATA%\RecoverKit\logs`, `~/Library/Logs/RecoverKit` on macOS) records environment, settings, every hashcat command
  with output and exit code, detection results, wizard choices and crashes. Recovered passwords are
  never written to it, and the profile path and account name are replaced by `%USERPROFILE%` / `%USERNAME%`.
- The built-in downloader and the macOS build pin hashcat 8.0.0. Resuming: hashcat 8 no longer runs
  the command line stored in a `.restore` file (CVE-2026-68766, `--restore` only prints it), so
  `HashcatRunner` gives the same command line again with `--restore-position`, which takes only the
  position from the file; with an older hashcat (`--version` below 8) it still uses `--restore`.
  hashcat 8 accepts `-w` but always uses the former workload 3, so the Workload setting no longer
  changes anything; the GPU load limit (duty cycle) still works. An existing per-user
  `engines/hashcat-7.1.2` copy keeps working until hashcat 8.0.0 is installed next to it, which
  `HashcatTool.Locate` then prefers; the app shows a notice meanwhile. Every hash mode RecoverKit
  produces was checked against hashcat 8.0.0 with the module's example hash and password on the
  M1 Pro (OpenCL); notes below that name hashcat 7.1.2 describe how the format was validated at
  the time.
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
Mode 21800 extraction matches the reference electrum2john output. hashcat 7.1.2 disabled this
mode on Apple GPUs; with hashcat 8.0.0 the CLI recovered `wallet-test-42` from the
`electrum-large` fixture on the M1 Pro (OpenCL), and the module's example also cracks on Metal.
No live funds or personal wallets were used.

### PDF permission removal

PDFs with an empty document-open password use `Detection.Unlocks` instead of starting an
attack. Nonempty-password detection keeps the existing hash extraction path; the stricter
rewrite parser runs only after an empty-password check. `PdfDecryptor` reuses the full R2-R4 and R6 password checks (R5 uses SHA-256), derives
the file key and authenticates AES-256 `/Perms`. `PdfSyntax` and `PdfDocument` read the active
classic, stream or hybrid xrefs, follow incremental updates, resolve indirect stream lengths,
and decode each object stream once. Compressed-object strings are not decrypted twice.
`PdfWriter` expands compressed objects and emits a new classic xref table, preserving the PDF
version, catalog, document information and file IDs. Saving uses a temporary file beside the
output and an atomic move, with source path and symlink-alias checks.

RC4 40-128, AES-128 and AES-256 are supported, including separate string/stream/embedded-file
crypt filters, `/Identity`, explicit `/Crypt` filters and cleartext metadata. Structural streams
support Flate and ASCIIHex with 8-bit TIFF/PNG predictors; other content filters are preserved
without decoding. Signed/certified PDFs, external streams, other structural codecs, mismatched
crypt-filter key lengths, cyclic or invalid structures are refused with an explanation.
Limits are 256 MiB for input, decoded structural data and output, one million object numbers,
64 levels of nesting/dependencies and 128 xref revisions. These bounds keep malformed input
from exhausting the parser. Larger encrypted files retain the existing password-attack path.

The small `Fixtures/Pdf` files were generated with pypdf and qpdf, without external content.
They cover R2-R6, object streams, cleartext metadata, selective and explicit Identity filters,
and an embedded-file filter. Independent validation used pypdf and qpdf 12.4.2, including
qpdf-encrypted copies of the W3C dummy PDF, PDFObject sample and Mozilla pdf.js TraceMonkey
paper. Source PDFs and tooling remain in the task scratch directory. pypdf currently cannot
read explicit named Crypt filters and mishandles cleartext encrypted-document metadata;
qpdf supplies the source-side oracle for those cases. Every saved copy is read by pypdf and
passes `qpdf --check`.

Validation recovered the synthetic user password with bundled hashcat 7.1.2 in modes 10400,
10500 (RC4 and AES), 10600 and 10700. The independent permission-removal matrix contains
36 files, including six encrypted copies of the three public source PDFs.
