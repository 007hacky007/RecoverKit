# Changelog

All notable changes to RecoverKit. Downloads are on the
[releases page](https://github.com/007hacky007/RecoverKit/releases).

## [Unreleased]

### Added
- Exportable synthetic benchmark files with matched comparison rates, exact attack instructions
  and a results template, available from Save test files and `bench-full --export-tests`.
- Two-minute detailed performance test with enforced section/step budgets, short samples, shared
  GPU kernel cache and a Thorough option for the full sweep.
- Detailed performance test with selectable sections, live progress, partial reports and a
  privacy-scrubbed HTML/JSON report; measured performance profiles and automatic calibration.
- Native ZipCrypto CPU header filters, with measured ARM CRC acceleration on Apple silicon and
  selectable AVX-512, AVX2, NEON and scalar paths for testing and benchmarks.
- 7-Zip archives (.7z), with visible or encrypted file names, solid or not, and self-extracting.
- KeePass databases: KeePass 1 (.kdb) and KeePass 2 / KeePassXC (.kdbx, including KDBX 4 with
  Argon2), with an optional keyfile.
- Cryptocurrency wallets: Ethereum keystore files, Electrum, MetaMask vaults and Blockchain.com
  wallet backups.
- Encrypted Android backups (.ab) made with adb or Helium.
- Instant unlocks, no attack needed:
  - Access 97-2003 database passwords are shown right away.
  - Word 6/95, Excel 5/95 and Office 97-2003 "XOR" passwords are shown right away.
  - Excel files encrypted with Excel's built-in default password ("VelvetSweatshop") or an empty
    password are recognized, and .xlsx copies can be saved without it.
  - Excel sheet and workbook protection, Word editing restrictions and "password to modify" are
    removed into a saved copy (.xlsx, .xls, .ods, .docx, .doc, .odt); old-style Excel and Word
    protection also shows a password the program accepts.
  - PDF printing and copying restrictions are removed into a saved copy when the PDF opens without
    a password.
  - A file with several restrictions can be saved once without all of them.
- PDF files encrypted with 40-bit RC4 at revision 3 get their own, faster password search.
- Hybrid CPU + GPU: brute-force and mask attacks on formats with a built-in kernel run hashcat on
  every GPU and the built-in CPU engine at the same time, on separate parts of the passwords, with
  rebalancing and exact resume (on by default, Preferences > Performance, CLI `--no-hybrid`).
  Optional: hashcat's CPU device next to the GPUs for other formats (`--hashcat-cpu`).
- Built-in CPU engine for RAR 5 archives: brute-force and mask attacks run on the CPU (16 passwords
  at once with AVX-512, 8 with AVX2 or on Apple silicon), and next to hashcat on the GPU in hybrid
  runs. On an Apple M1 Pro a hybrid run reached about 13,000 passwords per second against 11,000 on
  the GPU alone.
- Faster classic ZIP (ZipCrypto) recovery on GPUs: RecoverKit's own hashcat kernels for brute-force,
  mask and dictionary attacks no longer slow down with the size of the attacked file. `recoverkit-cli bench-zip`
  compares them with hashcat's on each device.
- Windows: Tools > Download NVIDIA CUDA compiler (NVRTC) lets hashcat use CUDA on NVIDIA GPUs
  without installing the CUDA Toolkit.

### Changed
- hashcat 8.0.0 instead of 7.1.2. On Macs, ZIP archives with compressed files and large Electrum
  wallets now run on the GPU.
  hashcat 8 ignores the Workload setting (it always uses the former level 3).

### Fixed
- Large classic ZIP entries now use a bounded GPU prefix and streamed whole-file password checks.
  Uncompressed large entries and installations without the ZIP GPU kernels use the built-in CPU engine.
- Optional HIP/CUDA startup advice no longer obscures hashcat's actual failure; NVIDIA OpenCL fallback
  points to the CUDA compiler download in Tools.
- GPU runtime failures resume the current attack from its checkpoint, with up to three retries
  without progress, including the GPU side of hybrid attacks.
- Resumed hashcat attacks keep their original optimized-kernel choice, even after Preferences change.
- Optimized kernels use hashcat's reported limit for each mode and attack, avoiding skipped long masks.
  Unknown limits, dictionaries and rule attacks use pure kernels; benchmarks share the same decision.
- "CPU only" on Windows PCs without a CPU OpenCL runtime failed with "Failed to initialize AMD HIP
  RTC library" (or no devices). hashcat now skips the GPU-only CUDA and HIP interfaces in that mode,
  and RecoverKit explains the missing CPU runtime and offers to download it.
- GPUs that hashcat uses through CUDA or HIP were not recognized as GPUs.
- Resuming a built-in CPU engine attack could skip candidates the threads had in hand at the stop.
- On macOS the built-in engine ran on the efficiency cores at the default priority (up to four times
  slower).
- Classic ZIP (ZipCrypto): a wrong password that happened to pass the check of the one attacked file
  (with fast GPUs, about every few minutes for a stored file) stopped the attack and was reported as
  the password. Every hit is now checked against the archive's other encrypted files, and the search
  goes on when it fails; cached passwords are checked the same way. For an archive with a single
  stored file the information pane says to confirm the password by opening the archive.

## [1.3.0] - 2026-11-12

### Added
- Redesigned main window: drop zone for files, labelled toolbar icons, a file card with the
  format and protection, and a status bar with what is being tried, speed, time left and progress.
- Live attack view: a progress ring for the current step, the steps of the plan as chips, and a
  speed graph for the last minute. The text log is under "Show details".
- Wizard: recovery methods are cards with a time estimate for the opened file, a step trail, and a
  quick "Measure speed" button with a countdown when no speed has been measured yet.
- New "Password found" dialog with Hide/Show and a copy confirmation.
- GPU temperature guard (optional): pauses the attack when the GPU reaches a set temperature and
  resumes after it cools by a set amount. Works on Apple silicon (built-in sensors) and on GPUs that
  report temperature. hashcat's own over-temperature abort is set 10 °C above the limit as a backup.
- GPU load choice (optional): let the GPU work all the time, 75%, half or 25% of the time.
- NVIDIA power limit (optional, Windows and Linux): sets a real power limit with `nvidia-smi`
  during an attack and restores it afterwards. RecoverKit explains why administrator rights are
  needed before Windows asks; RecoverKit itself keeps running without them.
- Fast key search for classic ZIP archives made by WinZip 8 and older and other Info-ZIP-based
  zippers on Windows (Stay's attack): with five or more encrypted files it recovers the archive's
  keys in minutes without guessing the password and writes a password-free copy. It runs first in
  the ZIP plan and can be turned off in Preferences > Key search.
- CLI options `--temp-limit`, `--temp-hysteresis`, `--gpu-duty` and `--power-limit`.

### Changed
- The Benchmark window and the wizard use the same speed measurement, so both feed the time
  estimates.

## [1.2.0] - 2026-11-12

### Added
- macOS version for Apple silicon (arm64), as a .dmg. Uses the Apple GPU through Metal and a CPU
  engine tuned for the chip's NEON and crypto instructions. Requires macOS 15 or later.
- New cross-platform interface (Avalonia) on Windows and macOS.
- TrueCrypt and VeraCrypt: keyfiles and a custom VeraCrypt PIM in File > Open As.
- RAR 3 archives whose file names are visible (only the file contents are encrypted).

### Fixed
- RAR 3 archives with encrypted file names could never be cracked: the wrong header was used.
- A failing hashcat check of the password cache could be reported as a found password.
- A shortened hash could appear in the debug log even with hashes masked.

## [1.1.0] - 2026-11-12

### Added
- Built-in CPU engine for TrueCrypt volumes protected with Whirlpool, about 2.3 times faster than
  hashcat on the processor.

## [1.0.0] - 2026-11-12

First release, for Windows.

- Opens Microsoft Office (97 to Microsoft 365), PDF, ZIP (classic and WinZip AES), RAR 3 and RAR 5,
  OpenDocument, TrueCrypt and VeraCrypt volumes, encrypted iPhone/iPad backups and WPA/WPA2
  handshakes, plus any hash hashcat supports through File > Open As.
- Brute-force, mask and dictionary attacks with word-variation rules, ready-made plans, pause and
  resume, and a cache of found passwords.
- GPU acceleration through hashcat, and a built-in CPU engine for ZIP, Office 97-2003, PDF and RAR 3.
- Guaranteed 40-bit key search for Office 97-2003 and early PDF files.
- Benchmark with an HTML report, word list and Wi-Fi table generators, and update checks on request.

[1.3.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.3.0
[1.2.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.2.0
[1.1.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.1.0
[1.0.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.0.0
