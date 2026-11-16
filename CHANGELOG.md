# Changelog

All notable changes to RecoverKit. Downloads are on the
[releases page](https://github.com/007hacky007/RecoverKit/releases).

## [Unreleased]

### Added
- Split ZIP archives (.z01, .z02, ..., .zip and .zip.001, .zip.002, ...) open directly,
  including ZIP64: RecoverKit reads the parts in place without joining them. Open any part
  with all the others in the same folder; a missing part is named. ZipCrypto and WinZip AES
  password recovery work across parts. Stay fast key search is unavailable for split ZIPs.

## [1.7.2] - 2026-11-16

### Fixed
- A downloaded word list now shows by its name in the dictionary field instead of its full path.
- Preferences now offers the word list library for the default dictionary, including built-in lists.
- Data-folder lists show by file name in the wizard. Deleted library selections are cleared with a note.
- Dictionary and WPA-PMK generation work without a GPU driver for plain lists and masks without rules.
  Combined lists use hashcat when it can run, or a local fallback when no compute backend exists.

## [1.7.1] - 2026-11-16

### Fixed
- The Dictionary Generator and WPA-PMK Generator no longer report an empty file as saved when
  hashcat cannot run, for example on a computer without a GPU driver or CPU runtime. They now
  stop with hashcat's reason and point to Tools > Dependencies.
- Wordlist library: plain messages when the drive is too small for a list or fills up while it
  unpacks, sizes in MB and GB instead of bytes, and the list name no longer appears twice.

## [1.7.0] - 2026-11-16

### Added
- A wordlist library. The "..." button next to each dictionary now opens a window with four tabs:
  the built-in lists, lists you downloaded, the weakpass.com catalog and files on disk. The
  weakpass.com tab lists about 1,700 password lists with search and filters, and shows for each
  one its rank, success rate, size, password lengths, character mix, common patterns, sample
  passwords and how long it would take on your file. Downloads resume after an interruption, are
  checked against weakpass.com's checksums, unpacked once and then work offline. Downloaded lists
  also appear in the dictionary drop-downs.

## [1.6.2] - 2026-11-15

### Added
- 7-Zip archives whose encrypted files are all too large for hashcat (about 8 MB) are no longer
  refused. 7-Zip stores a checksum only for each whole file, so RecoverKit checks such archives
  itself on the processor, without the graphics card: wrong passwords are rejected from the first
  bytes, and the few that pass are confirmed by unpacking the whole file. This is much slower than
  hashcat (on an Apple M1 Pro about 1,000 passwords per second for LZMA and LZMA2, a few hundred
  for uncompressed files); the file's details say why and how fast. Copy, LZMA, LZMA2 and Deflate
  are supported; PPMd, BZip2, filter chains and archives with salted encryption are not.
- An experimental AVX-512 path for TrueCrypt volumes protected with Whirlpool when the processor
  checks passwords (Preferences), off by default until measured on more CPUs. The previous
  processor path remains the default. On supported CPUs the quick benchmark and detailed CPU report
  compare both paths and report any self-test failure.
- RAR 3 archives whose encrypted files are all too large for hashcat are no longer refused (file
  data encrypted with -p; archives with encrypted file names were never limited). RAR 3 stores a
  checksum only for each whole file, so RecoverKit checks such archives itself on the processor,
  without the graphics card: wrong passwords are rejected from the first bytes, and the few that
  pass are confirmed by unpacking the whole file. This is much slower than hashcat (on an Apple M1
  Pro about 2,500 passwords per second for compressed files, 1,600 for stored ones); the file's
  details say why and how fast. A password that passes every check but cannot be confirmed is
  listed as a possible password to try by hand, never as found.
- A built-in processor engine for WPA/WPA2 (including SHA-256 PMKID lines) and WinZip AES. It runs
  only where the detailed performance test measured it faster, alone or next to the graphics card.
  Otherwise hashcat alone stays the default for these formats, because sharing the work with the
  processor made attacks slower.

### Changed
- Repair (when hashcat does not start) first lists what it will do, with the folders involved, and
  starts only when you agree. If the fresh copy still does not start, it explains why and asks
  before putting hashcat in another folder; after such a move it offers to remove the old, unused
  copy. Declining any step leaves everything as it was.
- The speed in the status bar shows every digit ("1 382 456 789 p/s") instead of "1.38 G p/s".
- The Benchmark measures RAR 3 with 4-character passwords instead of 7. RAR 3 hashes the
  password again in each of its 262,144 rounds, so it gets slower as passwords get longer
  (1.32x from 4 to 7 characters); 4 characters is the length other recovery tools' RAR 3 figures
  match. Other formats hash the password once and cost the same at any test length.
- Each Benchmark result names the test password length, and for formats where the GPU and the
  processor work together, what each side measured.
- The detailed performance test measures RAR 3 on the GPU alone, the processor alone and both
  together, as it does for RAR 5 and ZIP.
- Benchmark results name the GPU backend that ran, CUDA, OpenCL or Metal: "Engine: hashcat, GPU
  (CUDA)". An NVIDIA GPU running through OpenCL after a failed CUDA kernel build is listed as
  OpenCL with the reason.
- When the processor and the GPU share an attack, processor threads wait less at the end of each
  batch.

### Fixed
- Dictionary attacks with rules skipped passwords made from words outside a format's length
  limits: hashcat drops such words before it applies the rules. For WPA, which needs at least 8
  characters, "hashcat" with the rule "add !" never became "hashcat!"; in the default WPA scenario
  about a quarter of the rule step's passwords were skipped. RecoverKit now runs these words through
  the rules in an extra pass and tests every result of a valid length, for words up to 256 bytes.
- 7-Zip archives whose encrypted data block is larger than 8 MiB (a solid archive with large files,
  without encrypted file names) were refused with "encrypted streams larger than hashcat's 8 MiB
  limit". The password is now checked against the first files of the block, so only the beginning
  of the block is needed.
- 7-Zip archives whose only checkable data was shorter than 8 bytes (for example a tiny file stored
  without compression) were checked by hashcat with a checksum over those few bytes, which wrong
  passwords can match; RecoverKit only warned that false positives were possible. Such checks now
  cover at least 8 bytes or run on the processor, and every password hashcat reports for a 7-Zip
  archive is confirmed by RecoverKit before it is shown.
- Attacks that RecoverKit feeds to hashcat itself (dictionaries converted on the fly, word
  combinations, national characters) showed "0s" left and a full progress bar. They now show the
  progress and time left from the number of candidates RecoverKit sends.
- On PCs with an AMD integrated GPU, the details log no longer shows hashcat's notes that the AMD HIP
  runtime is missing. They were harmless: such GPUs run through OpenCL. The notes stay in the debug
  log.
- NVIDIA: RecoverKit now asks the driver itself for its CUDA version and uses nvidia-smi only as a
  fallback. Where nvidia-smi gave no version, a CUDA Toolkit newer than the driver was not hidden
  from hashcat, every CUDA kernel build failed and the GPU ran through OpenCL; the dependencies page
  then called the driver "too old or unknown" and offered no CUDA compiler.
- A stopped and resumed processor attack no longer tests again work it had already finished.

## [1.6.1] - 2026-11-14

### Added
- Split 7-Zip archives (.7z.001, .7z.002, ...) open directly: RecoverKit reads the parts as one
  archive, without joining them on disk. Open any part; a missing part is named.
- When hashcat does not start at all, the dependencies page offers Repair: it stops hashcat
  processes left from earlier attempts, copies hashcat again and checks that it starts. If the
  copy still does not start while the hashcat that came with RecoverKit does, antivirus software
  is holding that folder, and Repair moves hashcat to a RecoverKit folder in your user folder
  (`C:\Users\<you>\RecoverKit`) and uses it from there. If hashcat starts nowhere, it says where to allow it.

### Fixed
- NVIDIA GPUs: with a CUDA Toolkit newer than the graphics driver installed (for example toolkit 13.5
  with a driver for CUDA 13.3), every attack stopped with "hashcat could not compile the attack
  kernel": hashcat used the toolkit's compiler, whose code the driver rejects. hashcat no longer sees
  compilers newer than the driver, and uses RecoverKit's own CUDA compiler when it is installed. The
  dependencies page names such a toolkit and offers RecoverKit's compiler.
- If a CUDA kernel still fails to build, the attack no longer stops: RecoverKit switches that GPU to
  OpenCL, says so in the log with hashcat's reason, and starts the step again. CUDA stays off on that
  PC until the NVIDIA driver or RecoverKit changes, or RecoverKit's CUDA compiler is installed.

## [1.6.0] - 2026-11-14

### Changed
- The Windows portable version is now fully portable: it runs the hashcat in its own folder
  instead of copying it to `%APPDATA%`, and keeps settings, recovered passwords, sessions and logs
  in a `userdata` folder next to `RecoverKit.exe`.

### Fixed
- When hashcat did not answer at start, the dependencies page only said "hashcat did not finish in
  time". It now says whether hashcat did not start at all (usually antivirus software holding or
  blocking it, with the folder to allow) or started but hung while listing the graphics cards (a
  driver), and what to do.
- On a Mac, a password search on an OpenOffice 1.x-3.x document (ODF 1.1, Blowfish) could end
  without finding a password that was in the list or mask: 1.5.0 ran it through Metal, where
  hashcat skips such candidates. It runs on OpenCL again, as in 1.4.1.

## [1.5.0] - 2026-11-14

### Added
- One dependencies page (Tools > Dependencies) shows hashcat, NVIDIA's CUDA compiler and Intel's CPU
  runtime as green, yellow or red lights and installs what is missing with one "Install all" button
  after you accept the licenses. It appears at start only when something needs attention and stays
  hidden otherwise; optional items you skip are remembered. It replaces the separate download prompts.
- hashcat 8.0.0 is now included in the Windows installer and portable zip, as it already was on the
  Mac, and is set up silently at first start. The Windows build downloads and verifies the official
  archive (7-Zip is needed on the build machine; `-HashcatArchive` allows an offline build).
- Help > Check for updates now installs a newer version from here: the release file is downloaded,
  checked against its published SHA-256 and installed (the installer on Windows, the app bundle on
  Macs, the folder of a portable copy), and RecoverKit starts again. The download page remains the
  fallback for installations it cannot update in place.
- RecoverKit checks for a newer version when it starts, at most once an hour. When one is out, an
  Update button appears in the toolbar: one click downloads, verifies and installs it. The check can
  be turned off in Preferences > Other.
- The processor now helps the graphics card in dictionary attacks too, not only in brute force:
  RAR 5, RAR 3, PDF 1.7 level 8 and TrueCrypt (Whirlpool) dictionaries, with or without rules, are
  shared between hashcat on the GPU and the built-in CPU engine. On an M1 Pro a RAR 5 dictionary job
  of 9.6 million candidates finished in 10 to 11 minutes instead of 14 to 16.
- Classic ZIP archives with eight or more encrypted files are searched about three times faster on
  the GPU: the graphics card checks only each file's check byte and the processor confirms the few
  candidates that pass (measured on an M1 Pro with an archive of 25 large photos). RecoverKit
  measures both methods before the first ZIP attack and keeps the faster one.
- Dictionary attacks on RAR 3, 7-Zip and PDF 1.7 level 8 use hashcat's faster "optimized" kernels,
  about twice the speed for RAR 3 and 7-Zip. Words too long for those kernels are tested in a second
  pass, so nothing is skipped.
- Classic ZIP on the processor is 2 to 7 times faster when it works next to the GPU, and faster for
  masks whose last position has few characters (M1 Pro).
- RAR 3 on the processor is about twice as fast for masks that end in fixed characters, for example
  `?l?l?l?l2024`.
- RAR 3 has a wider code path for processors with AVX-512. It checks itself against known answers
  when it is first used and runs only when they match. The detailed performance test reports the
  AVX2 and AVX-512 rates side by side ("Wide vector paths"), and the Benchmark shows which processor
  path ran.

### Removed
- The run-time hashcat download and the 7-Zip extractor (7zr.exe) download. The "Download hashcat",
  "Download CPU runtime" and "Download NVIDIA CUDA compiler" items in the Tools menu are replaced by
  Tools > Dependencies, and "Install hashcat" in `recoverkit-cli` only copies the bundled build or
  `--from <folder>`. In Preferences the hashcat "Download/Install" button is now "Default".

### Fixed
- Classic ZIP archives whose encrypted files are all larger than 320 KB (for example photos) were
  searched by the built-in CPU engine at about 16 million passwords per second instead of hundreds
  of millions: every candidate that passed the 12-byte header check (1 in 256) was confirmed by
  decrypting the whole file. Such candidates are now rejected by the other files' headers and by
  the beginning of the compressed data first, which takes a fraction of a microsecond.
- After upgrading from an earlier RecoverKit, the hashcat 7.1.2 it had installed stayed in use.
  RecoverKit's fast ZIP GPU kernels need hashcat 8.0.0, so ZIP attacks silently ran on the CPU.
  The copy an earlier RecoverKit installed now gives way to the bundled hashcat 8.0.0. When the hashcat
  in use is your own and older (a path set in Preferences, Homebrew, PATH), the dependencies page
  shows it as a yellow light with a switch to the bundled copy, and the attack log says why the GPU
  kernels are not used. Your own hashcat is left in place, and skipping the switch on the start page
  is remembered until that hashcat changes.
- An attack step that a large ZIP file cannot run on the CPU (rules, extra hashcat options) ended
  the whole recovery with an error. The step is skipped with the reason and the other steps run.
- On a Mac, a RAR 3 or PDF 1.7 Level 8 dictionary attack could end without finding a password that
  was in the list: hashcat skipped candidates on Apple's OpenCL without reporting an error. Every
  format now runs through Metal, which found the password in every test run.
- The Benchmark showed 7-Zip and Electrum wallets as "not supported on this device" with hashcat 8.

## [1.4.1] - 2026-11-13

### Fixed
- The fast key search for classic ZIP archives (Stay's attack) could include a damaged (cut off) or
  very large file of the archive and then fail. Such files are skipped again, as in 1.3.0.

## [1.4.0] - 2026-11-13

### Added
- Detailed performance test (Tools > Benchmark): measures every engine and device on this computer in
  about two minutes, saves a report to send to the developers, and can save test files for comparing
  RecoverKit with another program. "Thorough" runs the full, much slower measurement.
- RecoverKit learns the fastest method for each format on this computer (GPU, CPU or both, number of
  CPU workers, GPU interface) from the detailed test, or by measuring for a few seconds before the
  first attack on a format. Preferences shows this performance profile and can reset it; your own
  settings always win.
- Faster classic ZIP (ZipCrypto) recovery on the CPU of Apple silicon Macs: about 44% faster on an
  M1 Pro.
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
- Classic ZIP archives whose encrypted files are all larger than 320 KB (for example camera photos)
  failed every GPU attack with "Token length exception" and "No hashes loaded". The GPU now checks the
  beginning of the file and every hit is checked against the whole file; large uncompressed files are
  searched by the built-in CPU engine.
- hashcat's notes about a missing AMD HIP or CUDA installation were shown as the error instead of the
  real cause. The real cause is now shown in plain words, and NVIDIA GPUs that fall back to OpenCL get
  a pointer to Tools > Download NVIDIA CUDA compiler.
- A GPU error in the middle of an attack (seen on Macs while another program used the GPU) ended the
  attack. RecoverKit now resumes from the last checkpoint, up to three times in a row.
- A resumed attack ran without hashcat's optimized kernel (RAR 3 about 1.8 times slower).
- Masks longer than the optimized kernel allows for a format (for example 21 or more characters for
  RAR 3) were skipped by hashcat without being searched. RecoverKit now uses the slower kernel for them.
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

[1.7.2]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.7.2
[1.7.1]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.7.1
[1.7.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.7.0
[1.6.2]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.6.2
[1.6.1]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.6.1
[1.6.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.6.0
[1.5.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.5.0
[1.4.1]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.4.1
[1.4.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.4.0
[1.3.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.3.0
[1.2.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.2.0
[1.1.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.1.0
[1.0.0]: https://github.com/007hacky007/RecoverKit/releases/tag/v1.0.0
