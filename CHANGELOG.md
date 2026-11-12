# Changelog

All notable changes to RecoverKit. Downloads are on the
[releases page](https://github.com/007hacky007/RecoverKit/releases).

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
