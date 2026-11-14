# Performance plan

Written 2026-11-14, updated the same day after the first round of work. A ranked list of
performance work for RecoverKit, with the GPU as the main target and one commercial product as
the reference to compare with. Items are sorted from cheap and rewarding to expensive with
diminishing returns.

How the findings were made: reading the hashcat integration, the hybrid scheduler, the ZIP GPU
kernels and the built-in CPU engine; published speed figures for the commercial product and for
hashcat; measurements on an Apple M1 Pro (16-core GPU, hashcat 8.0.0) with an isolated copy of the
bundled hashcat; and CPU measurements on a Windows VM (Xeon E5-2620 v4, 8 vCPU, AVX2, no GPU).

What is still unmeasured: everything on NVIDIA or AMD GPUs, and everything on a CPU with AVX-512
or SHA-NI. Every gain below is marked as measured, read from code, or estimated.

Related: [benchmarks.md](benchmarks.md) and [DEVELOPERS.md](DEVELOPERS.md). An earlier research
note on the unmerged `research/perf` branch (`docs/performance-research.md`) covers the Ryzen 7
9800X3D + RTX 4060 comparison and has a tester script for that machine.

## Status

| # | Item | Status |
|---|---|---|
| 1 | Measure on a real NVIDIA card | Open. Needs the tester's machine |
| 2 | Benchmark flags (`-B` with `-O`) | Done |
| 3 | `-O` for dictionary and rules attacks | Done. Measured on M1 |
| 4 | Volumes: run only the widest cascade mode | Open |
| 5 | RAR 3 CPU: lift the 8-prefix cap | Done. Measured on NEON and AVX2 |
| 6 | ZIP CPU: cheaper survivor checks | Done for deflated entries. Measured on M1 |
| 7 | ZIP entry choice by speed | Done. Constants from M1, retune on NVIDIA |
| 8 | Stop piping candidates through stdin | Open |
| 9 | ZIP CPU in hybrid: fill lanes across prefixes | Done. Measured on M1; x86 paths compiled only |
| 10 | Deflated ZIP on the GPU | Check-byte path done for 8 or more entries. Filter kernel for small archives open |
| 11 | ZIP kernel that varies the last characters | Open |
| 12 | More CPU kernels for hybrid | Open |
| 13 | AVX-512 and SHA-NI | RAR 3 AVX-512 written, never executed. PDF R6 and SHA-NI open |
| 14 | Fewer hashcat starts in hybrid | Open for masks. The wordlist hybrid starts hashcat once |
| 15 | Small CPU items | Open |
| 16 | CPU engine next to the GPU in wordlist attacks | Done. Measured on M1 |

## Where the commercial product stands

From the product's own published figures against public hashcat benchmarks. The hashcat numbers
are from versions 6.1.1 to 7.0.0, before the gains hashcat 8.0.0 reports. The product's Office and
RAR 5 GPU ratings are calculated from the GPU's architecture, not measured per card. Treat ratios
across different cards as rough.

| Format | Commercial product | hashcat | Product / hashcat |
|---|---|---|---|
| ZIP classic, RTX 4060 | about 10 G/s published | about 1.5 G/s in single-file mode 17210 | 6.5x |
| ZIP classic, RX 6800 | 20.1 G/s | RX 6800 XT: 3.66 G/s (17210), 23.7 G/s (17230, header only) | 5.5x and 0.85x |
| RAR 3, RTX 4060 | about 105,000/s | 72,012/s (6.2.6, OpenCL) | 1.46x |
| RAR 5, RTX 4060 | about 53,000/s | 50,323/s | 1.05x |
| PDF R3/R4, RTX 5090 | "up to 228 M/s" | 166.4 M/s | 1.37x |
| Office 2007, same cards | calculated | measured | 0.96x to 1.02x |
| Office 2013, NVIDIA | calculated | measured | 0.86x to 0.91x |
| WPA, RTX 3070 | 542,133/s | 645,700/s | 0.84x |
| Office 97-2003 password | CPU only, about 95 M/s on a Ryzen 9 9950X | RTX 4090: 2.7 to 3.6 G/s | 0.03x |
| PDF R6 | CPU only, 28,157/s on a Ryzen 9 9950X | RTX 4090: 427,200/s | 0.07x |
| 7-Zip, KeePass, VeraCrypt | not supported | supported | - |

A tester ran both programs' benchmarks on one machine (Ryzen 7 9800X3D, RTX 4060, 2026-11-12).
RecoverKit was version 1.3.0 with the RTX 4060 as an OpenCL device, before hashcat 8, the
replacement ZIP kernels and the work below, and its rows are GPU only.

| Format | Commercial product | RecoverKit 1.3.0 | Gap |
|---|---:|---:|---:|
| ZIP classic | 13,389 M/s | 1,357 M/s | 9.9x |
| RAR 3 | 98,014/s | 61,758/s | 1.59x |
| RAR 5 | 50,812/s | 43,904/s | 1.16x |
| RAR 5, wordlist with rules, live attack | 51,451/s | 47,900/s | 1.07x |

RecoverKit led on Word 97/2003 (about 10x), PDF R6 (4x) and TrueCrypt RIPEMD-160.

What this means:

- The product is clearly ahead of hashcat on the GPU in one place: classic ZIP against hashcat's
  single-file modes (17200, 17210). Against hashcat's header-only multi-file mode (17230) it is
  about level.
- RAR 3 and PDF R3/R4 show a 1.2x to 1.5x lead against old hashcat versions. hashcat 8.0.0 reports
  1.9x for the optimized RAR 3 kernel on an RTX 4090 and +21% for PDF R3.
- The PBKDF2 formats (Office 2007/2013, RAR 5, WPA, WinZip AES) are within about 15% either way.
  hashcat has only a pure kernel for RAR 5, and its 8.0.0 change log has no speed change for it,
  so the remaining lever is the CPU working next to the GPU (items 12 and 16).
- How the product does ZIP, from its manuals: the GPU is used only for plain brute force, not for
  dictionaries, positional masks, or a mask whose last character is fixed. The CPU prepares chunks
  and verifies the GPU's survivors by unpacking. The "last character" restriction suggests that
  its GPU kernel enumerates the trailing characters from a cached key state of the prefix. That is
  an inference, not something the vendor states.

Sources: the vendor's product pages, knowledge base and manual; for hashcat, the public benchmark
gists for RTX 4090, RTX 5090, RTX 3080 and RX 6800 XT, the hashcat forum threads for RTX 4060 and
RTX 3070, and `docs/changes.txt` of hashcat 8.0.0.

## Ranked plan

| # | Item | Gain | Effort | Evidence |
|---|---|---|---|---|
| 1 | Measure on a real NVIDIA card (`bench-zip`, `bench-full`) | Decides items 10 and 11 | Hours | Nothing NVIDIA is measured |
| 2 | Fix the benchmark flags: `-B` with `-O` is rejected | Benchmark rows that returned 0 | Done | Reproduced, then fixed |
| 3 | Use `-O` for dictionary and rules attacks | RAR 3 1.9x, 7-Zip 2.0x, PDF R6 1.14x on the kernel; less with long words | Done | Measured on M1 |
| 4 | Volumes: run only the widest cascade mode | 1.5x to 2.1x when several cipher types are selected | Hours | Kernel source read, gain estimated |
| 5 | RAR 3 CPU: lift the 8-prefix cap | 1.8x to 2.1x for masks ending in a literal | Done | Measured on NEON and AVX2 |
| 6 | ZIP CPU: inflate a bounded prefix before decrypting everything | 4x to 50x per survivor check, by entry size | Done | Measured on M1 |
| 7 | Prefer a small stored ZIP entry when other entries can confirm | Up to 3.2x | Done | Measured on M1 |
| 8 | Stop piping candidates through stdin on fast formats | 10x to 100x for those attacks | 2 to 5 days | Estimated |
| 9 | ZIP CPU in hybrid: fill lanes across prefixes | About 2x to 7x CPU share in hybrid | Done | Measured on M1 |
| 10 | Deflated ZIP on the GPU: check bytes on the GPU, CPU confirms | About 3x to exhaust a mask with 8 or more entries | Done for 8 or more entries; 1 to 2 weeks for fewer | Measured on M1 |
| 11 | ZIP kernel that varies the last characters in the inner loop | 1.35x to 1.7x by operation count | Weeks | Estimated |
| 12 | CPU kernels for hybrid: Office 2007-2013, WPA, WinZip AES, VeraCrypt, KeePass | 10% to 30% on a mid-range GPU | Days per family | Estimated |
| 13 | AVX-512 for RAR 3 and PDF R6, SHA-NI for RAR 5 | 1.3x to 3.5x on CPUs that have them | RAR 3 written; 2 to 5 days each for the rest | Arithmetic only |
| 14 | Fewer hashcat starts in hybrid; warm the kernel cache when a file is opened | Short jobs only | Days | Start-up measured at 12 s on M1 |
| 15 | Small CPU items | 2% to 15% each | Hours each | Estimated |
| 16 | CPU engine next to the GPU in wordlist attacks | 20% to 31% less time on M1; more on a discrete GPU | Done | Measured on M1 |

Suggested order for what is open: item 1 first, because it decides whether item 10's filter
kernel or item 11 is needed for small ZIP archives; then items 4 and 8.

## What the tester's machine has to show

Nothing below has run on the Ryzen 7 9800X3D + RTX 4060 machine.

- **AVX-512.** Tools > Benchmark > Detailed performance test, only "Built-in CPU engine and
  correctness", "Thorough" ticked, about 5 to 10 minutes, then "Save report...". In the report's
  "Wide vector paths" table the RAR 3 and RAR 5 rows must say PASS with self-test "passed"; the
  ratio columns give AVX-512 against AVX2 at one thread and at all threads. A requested AVX-512
  run that fell back to AVX2 is reported as a failure. Without the GUI:
  `recoverkit-cli bench-full --sections system,cpu --thorough --out report.html`.
- **ZIP on the GPU.** `recoverkit-cli bench-zip` prints hashcat's kernels, RecoverKit's
  replacement kernels and the check-byte path side by side. The check-byte row is the ceiling of
  that approach on the card.
- **Wordlist attacks.** The commands in DEVELOPERS.md time a fixed RAR 5 job (the first two
  million words of a large wordlist with a rule file) with and without the CPU engine, and count
  hashcat starts.
- **RAR 3.** The same wordlist job on a RAR 3 archive, pure kernel against the default.

## Notes on the items

### 1. Measure on NVIDIA first

- The replacement ZIP kernels, the amplifier cache default, the queue size and the CUDA path were
  all tuned or tested on Apple silicon only.
- hashcat 8.0.0 reports 13.8x for its own deflated ZIP kernel (17200) on an RTX 4090, and 2.5x for
  PKZIP from limiting kernels with 8 KiB or more of private memory to one warp. RecoverKit's
  replacement may not win on NVIDIA at all.
- `recoverkit-cli bench-zip` compares hashcat's kernels with RecoverKit's on every device and
  backend; `bench-full` writes the whole report.
- The Windows VM has no GPU, so this needs the tester's RTX 4060 or a rented GPU machine.

### 2. Benchmark flags (done)

- `HashcatTool.BenchmarkAsync` sent `-B` (benchmark the pure kernel) together with `-O` (use the
  optimized kernel) for every mode that has an optimized kernel. hashcat 8.0.0 exits with
  "--benchmark-pure cannot be combined with --optimized-kernel-enable" and the speed came back as 0.
- Tools > Benchmark shows a speed of 0 as "not supported on this device". With default settings
  this hit 7-Zip (11600) and Electrum seed (16600).
- Fix: `-b` when the optimized kernel is chosen, `-B` otherwise; a caller's own `-O` is dropped.
  Against hashcat 8.0.0 on the M1 Pro, 7-Zip measured 0 before the fix and 111,309 to 120,650/s
  after it; with optimized kernels turned off it gives the pure kernel's 63,347/s.

### 3. Optimized kernels for dictionary attacks (done)

- Kernel rates on the M1 Pro, pure against optimized: RAR 3 (12500) 7,881 against 14,962/s; 7-Zip
  (11600) 63,924 against 129,048/s; PDF R6 (10700) 9,807 against 11,226/s. RAR 5 has only a pure
  kernel.
- The optimized kernel cannot test candidates over its limit (20 bytes for RAR 3 and 7-Zip, 16
  for PDF R6). Under `-O` hashcat drops an over-long word, and it tests a truncated candidate
  when a rule pushes a word past the limit, without counting a rejection.
- So a wordlist attack runs as two passes: the whole list with `-O`, then only the words that
  could exceed the limit (after the largest growth the rule files allow) with the pure kernel.
  The passes are ordinary session steps, so progress and resume work in either.
- With the shipped best66 rules every word longer than 10 bytes repeats in the second pass, so
  the gain on a real list is below the kernel ratio.
- The list is scanned once for word lengths: 0.3 to 0.5 s for 130 MiB, about 4 s for 2 GiB, then
  cached per file.
- Measured on the M1 Pro, RAR 3, 480,004 candidates, complete runs with start-up: pure 112 to
  262 s, two passes 49 to 86 s (five pairs on a shared machine).
- Combination and hybrid-mask wordlist attacks (`-a 1`, `-a 6`, `-a 7`) use `-O` only when every
  candidate fits. Stdin-fed attacks stay pure.

### 4. Volume cascades

- `CryptVolume.Modes` (`src/RecoverKit.Core/Formats/CryptVolume.cs`) adds one hashcat mode per
  selected cipher type (single, double, triple) and the session runs them one after another.
- hashcat's triple-cascade kernel already checks all three groups: `m13723-pure.cl` calls the
  single-cipher header checks, then the two-cipher ones, then the three-cipher ones. The 294xx
  modes reuse the 137xx kernels and the 293xx modes the 62xx kernels.
- Work in PBKDF2 output blocks: SHA-512 and Whirlpool need 1, 2 and 3 blocks for the three key
  sizes, so running only the widest costs 3 instead of 6 (2x). RIPEMD-160 needs 4, 7 and 10, so
  10 instead of 21 (2.1x). Single plus double: 1.5x.
- Check before shipping: boot-volume modes and keyfiles behave the same way.

### 5. RAR 3 lane fill on the CPU (done)

- `Rar3Kernel.PrefixBatch` took at most 8 prefixes per call, so a mask ending in a literal, and
  every hybrid box with the last character fixed, filled half the lanes.
- It now searches up to the native lane count, which the library reports.
- Mask `?l?l?l?l2024`, CPU only: 1,144 to 2,094/s on NEON (M1 Pro, 8 threads) and 1,660 to
  3,438/s on AVX2 (Xeon E5-2620 v4, 8 threads). A mask ending in `?d` is unchanged (3,324 against
  3,299/s on AVX2).

### 6. ZIP survivor checks on the CPU (done for deflated entries)

- A candidate that passes the check byte (1 in 256) went to a full decrypt of the entry. Now a
  deflated survivor first inflates at most 4 KiB of the entry.
- Per header survivor on the M1 Pro: 9.1 to 12.0 us before and 1.1 to 2.3 us after at 1 KiB;
  33.1 to 60.9 us before and 1.10 to 1.15 us after at 16 KiB.
- The other entries' header checks still run only for large "partial" targets, where they are the
  confirmer's own checks: 0.18 us per survivor with 16 siblings, against a full read of the entry
  (123 ms for a 1.26 MB stored entry) without them.

### 7. Which ZIP entry to attack (done)

- `ZipExtractor` attacked the smallest deflated entry unless a stored entry was at least 8 times
  smaller. With the replacement kernels a small stored entry is much faster on the GPU: 2,484 M/s
  for a 453-byte stored entry against 781 M/s for a deflated one on the M1 Pro.
- When the archive has other entries to confirm a hit, the entry is now chosen by estimated speed.
  The constants come from the M1 Pro and need retuning once NVIDIA rates exist. Sessions saved
  before the change resume on their old entry.

### 8. Attacks fed through stdin

- `AttackPlanner` sends these to hashcat as `-a 0` with candidates written to stdin by
  `Generators.Pump`, one thread, one line per candidate: brute force with national characters,
  two-word "advanced" and three-word attacks, length-filtered dictionaries, and dictionaries that
  are not UTF-8.
- hashcat cannot amplify stdin on the GPU, so a ZIP attack that could run at billions per second
  is limited to what one thread can write to a pipe. Slow formats do not care.
- Replacements that keep the work on the GPU:
  - two words with variants: one `-a 1` run over two temp wordlists that already contain the
    capitalized and separator variants;
  - three words: the first two through stdin and the third as generated append rules;
  - national brute force: the prefix through stdin and the last one or two characters as generated
    append rules;
  - non-UTF-8 dictionaries: convert once to a temp UTF-8 file, which also restores resume and
    `-O`.
- The pump's rate was not measured; the 10x to 100x range is an estimate for fast formats.

### 9. ZIP on the CPU in hybrid mode (done)

- In hybrid mode hashcat's most significant digit is the last character, so the built-in engine
  gets boxes with the last characters fixed, and each call filled 1 of its 8 (ARM) or 24 (x86)
  lanes. The kernel now fills lanes across prefixes with per-lane key states.
- CPU row in hybrid on the M1 Pro: 1.81 to 3.84 M/s before, 8.30 to 25.31 M/s after.
- CPU only, million candidates per second, before and after: mask ending in a literal 2.59 to
  3.40 and 6.77 to 13.19; ending in `?d` 9.55 to 13.37 and 12.72 to 18.96; ending in `?l` 10.39
  to 10.73 and 13.89 to 16.38. A mask ending in `?a` was inconclusive on a shared machine (4.71
  to 19.23 before, 3.88 to 26.69 after).
- The AVX2 and AVX-512 paths were compiled but not executed.

### 10. Deflated ZIP entries on the GPU (check-byte path done)

- Measured on the M1 Pro with `hashcat -b`: header-only multi-file mode 17230 runs at 3,026 M/s,
  the replacement kernel on a deflated entry (17200) at 781 M/s, on a 453-byte stored entry
  (17210) at 2,484 M/s.
- Built: for archives with 8 or more encrypted entries (4 when entries carry two check bytes),
  hashcat gets a check-byte hash of 8 entries (mode 17230) and every hit is confirmed against the
  real entries on the CPU. Eight entries give 56 effective bits, because each entry accepts two
  possible check bytes. A rejected hit triggers a recheck of that range on the original entry.
- The first ZIP attack measures both paths for the active GPUs and uses the faster one.
- On a real archive of 25 multi-megabyte entries, M1 Pro, 34.3 billion candidates, seconds with
  start-up: GPU only 47.6 to 77.0 before and 13.6 to 25.3 after; hybrid 53.7 to 170.6 before and
  19.2 to 41.8 after (three pairs on a shared machine).
- Open: archives with fewer entries. The kernel needs a bounded inflate (the first kilobyte, a
  small window, no CRC) as a filter, with the CPU doing the full check. Upstream hashcat master
  has a new mode 17240 ("PKZIP streaming") with this split; it is not in 8.0.0. Adopting it when
  it is released may be better than building it.

### 11. Varying the last characters in the ZIP kernel

- hashcat's mask attack varies the first characters fastest, so the kernel runs the whole key
  schedule for every candidate: for 8 characters, 8 password updates plus 12 header bytes.
- With the varying characters at the end, the key state after the prefix is computed once per
  thread and each candidate costs about 1 password update plus the header: 20 updates become
  about 13. By update count that is 1.35x at 6 characters and 1.7x at 10.
- It can be done inside hashcat's interface by giving hashcat the mask with the last positions
  moved to the front and letting the kernel put them back, but it changes candidate numbering,
  the decoding of found passwords, hashcat's self-test and the hybrid split. The amplifier cache
  that brought nothing on the M1 Pro saved only 1 of 20 updates; this saves 7.
- This is the item that would go past the commercial product's ZIP rate rather than match it.

### 12. More built-in kernels for hybrid

- Hybrid exists only for ZIP, Office 97/2003, PDF, RAR 3, RAR 5 and TrueCrypt Whirlpool.
- Candidates, by the code they could reuse: PBKDF2-SHA256 formats on the existing lanes
  (VeraCrypt SHA-256, MetaMask, Ethereum, iOS 10.2+ backups); SHA-512 loops from the PDF R6 code
  (Office 2013, TrueCrypt/VeraCrypt SHA-512, Electrum); a new PBKDF2-SHA1 lane file (WPA, WinZip
  AES, Android backup, ODF); KeePass AES-KDF with AES-NI.
- Also small: Office 2003 files with a key size other than 40 bits (`$oldoffice$4`) fall to
  hashcat although the existing key schedule covers them (2 to 3 hours); VeraCrypt Whirlpool and
  the TrueCrypt cascades need only the iteration count and key length as parameters (1 day).
- The cheap experiment before writing kernels: Preferences already has "also give hashcat the
  CPU next to the GPUs" (off, never measured).

### 13. Wider instruction sets (RAR 3 AVX-512 written)

- RAR 3 now has an AVX-512 path (32 candidates per batch): estimated 1.75x on Zen 4, 2.5x to 3.5x
  on Zen 5. It was compiled and inspected, never executed.
- Because it cannot run on the development machines, the path is guarded: its first use in a
  process runs a known-answer test over every batch position at four password lengths and falls
  back to AVX2 on any mismatch. The RAR 5 AVX-512 path, which was on by default without ever
  having run, got the same guard. `RECOVERKIT_RAR3_AVX512=0` and `RECOVERKIT_RAR5_AVX512=0` turn
  them off.
- The RAR 3 vector code is now one source for NEON, AVX2 and AVX-512. The existing paths did not
  get slower: 3,693 against 3,693/s on NEON and 3,575 against 3,573/s on AVX2 (8 threads, four
  alternating rounds each).
- Open: PDF R6 has no AVX-512 or VAES path (estimated 2x to 3x, then another 1.3x), and SHA-NI is
  detected but never used (estimated 1.3x to 2x for RAR 5 on CPUs with AVX2 only).

### 14. hashcat starts in hybrid

- Mask hybrid runs one hashcat process per password length and one more per rebalance. On the M1
  Pro a ZIP start takes about 12 s, all of it kernel loading; the documentation records 25 to 75 s
  under CPU load.
- hashcat 8 reuses its autotune results across increments inside one process, which per-length
  runs give up.
- The speed and start-up caches are keyed by mode only, not by device, password length or cost
  parameters, so a stale estimate can split the work badly.
- Starting the kernel build in the background when a file is opened would hide the first-use
  compile.

### 15. Small CPU items

- ZIP: the search path is looked up through a native call on every search, and lane characters
  are loaded by a scalar loop (3% to 15%).
- Whirlpool: the constant padding block needs far fewer table lookups in its first two rounds
  (about 6%).
- Hybrid: 3 s batches with a new thread pool per box (2% to 7% of the CPU share).
- RC4 key schedule on arm64 is plain C (possibly 8% to 20% on Apple silicon; uncertain).

### 16. CPU engine in wordlist attacks (done)

- Hybrid existed only for masks, so a wordlist attack ran on the GPU alone. The tester's live
  RAR 5 run with a wordlist and rules was 7% behind the commercial product, which uses CPU and GPU.
- Now hashcat takes words from the bottom of the list and the built-in engine takes them from the
  top, fed by `hashcat --stdout`, so rules behave exactly as on the GPU. When the CPU reaches
  hashcat's range it keeps working downwards into it, so hashcat is started once and the tail
  needs no restart. Words the CPU kernel cannot take are kept aside for hashcat.
- Formats: RAR 5, RAR 3, PDF R6 and TrueCrypt Whirlpool, plain `-a 0` with or without rule files.
- Measured on the M1 Pro, RAR 5, 9.6 million candidates, complete jobs in seconds, GPU only
  against hybrid: 840.5 / 673.8, 857.0 / 622.3, 935.1 / 640.9. That is 20% to 31% less time. The
  CPU hashed at 5,579/s, against 5,762 to 5,958/s for the same kernel in a mask attack.
- The integrated GPU shares its power budget with the CPU, so a discrete GPU should gain more:
  the estimate for the built-in RAR 5 kernel on a Ryzen 7 9800X3D is about 20,000/s next to
  roughly 48,000/s from an RTX 4060. Neither that CPU rate nor the AVX-512 path behind it has
  been measured.
- The optimized kernel numbers words differently, so the CPU engine can only join the pure
  kernel. Where both apply (RAR 3, PDF R6), the planner compares the expected time of the two
  optimized passes with the pure kernel plus the CPU and takes the shorter.

### Candidate order in hybrid (not a throughput item)

Hybrid passes hashcat an ordered Markov table so both engines number candidates the same way.
Candidates then run in byte order instead of hashcat's likely-characters-first order. Throughput
is the same, but a typical human password is found later. Worth weighing against the CPU's share
on formats where a discrete GPU does almost all the work.

## Every format on macOS runs through Metal

hashcat 8.0.0 on the M1 Pro can end a RAR 3 (12500) wordlist attack without the password and
without an error when it runs on Apple's OpenCL device. Measured on an idle machine with hashcat
alone, one run at a time: the example hash, a mask, and wordlists with the password first, in the
middle, last, in a 10-word list, in a 200,000-word list and reached through a rule; five runs each
(three for the large list).

| Device | Kernel | Password found | Benchmark rate |
|---|---|---|---:|
| Metal | pure | 33 of 33 | 5,360/s |
| Metal | optimized | 33 of 33 | 15,630/s |
| OpenCL | pure | 30 of 33 | 8,350/s |
| OpenCL | optimized | 33 of 33 | 15,220/s |

- The three misses were wordlist runs (password first, in the middle, and through a rule). An
  earlier session also saw misses with the optimized kernel on OpenCL.
- A device that can skip a password is not used: on macOS the RAR 3 modes (12500, 23700, 23800)
  run with every GPU replaced by its Metal device and with `--backend-ignore-opencl`, so a GPU
  without a Metal device makes hashcat stop with an error
  (`HashcatRunner.MetalOnlyArguments`). Ten wordlist attacks through the application afterwards
  all found the password.
- Cost: the pure kernel is 36% slower on Metal; the optimized kernel is the same speed. Metal also
  starts in about 4 s where OpenCL took about 47 s in these runs.

The same check for every format the application hands to hashcat (46 modes, hashcat's example
hashes, a mask, the password first and in the middle of a wordlist, and through a rule; both
kernels where the mode has them) found a second format that OpenCL skips: PDF 1.7 Level 8 (10700)
with the pure kernel missed the password in 6 of 17 runs. Metal found it in every run of the 13
modes measured on both devices.

- Every format on macOS now runs Metal only (`HashcatRunner.MustAvoidAppleOpenCl`), the ZIP
  header filter and its calibration included. Formats measured only on Metal were moved before
  their runs finished; a mode where Metal misses goes into `HashcatRunner.MetalMisses` and is
  decided on its own measurements.
- Cost, Metal rate against OpenCL rate: 0.88 to 1.00 for most formats; RAR 3 pure 0.63 (and
  RAR 3 compressed 0.96), Office 2003 0.67 to 0.83, PDF 1.1-1.3 0.68, PDF R6 optimized 0.79,
  7-Zip pure 0.88, ZIP 0.96. PDF R6 pure is faster on Metal (1.31).

## Checked, not worth doing

- **Workload setting (`-w`).** hashcat 8 ignores it. Measured on a ZIP mask attack: 2,351 M/s
  with `-w 3`, 2,314 M/s with `-w 4`.
- **`--self-test-disable`.** Saves under 1 s of a 12 s start (first speed after 12.2 s against
  12.9 s).
- **Metal instead of OpenCL for ZIP on Apple silicon (for speed).** 2,258 against 2,351 M/s. ZIP
  runs on Metal anyway, because OpenCL can skip passwords.
- **Manual `-n`, `-u`, `-T` tuning.** The earlier research note found no gain on Office 2007, and
  hashcat 8 refuses these options without `--force`.
- **Engine counters and locks.** Touched once per chunk of about 20 ms; no contention.
- **Thread scheduling and affinity.** Work is pulled dynamically, so performance and efficiency
  cores balance on their own.
- **.NET build settings (ReadyToRun, server GC, tiered PGO).** They do not touch the hot loops.
- **Native build flags.** Already `-O3` with per-function targets; one translation unit, so LTO
  changes nothing.
- **AVX-512 MD5/SHA-1 for Office 97/2003 and PDF R3.** The RC4 key schedule dominates: 6% to 25%.
- **Status polling and restore writes.** One JSON line every two seconds; not a compute cost.

## Before measuring from a checkout

- `native/bin` can hold a stale library. The code requires API version 11; an older library is
  ignored silently and the managed kernels run instead. Run `sh native/build.sh` first, and check
  the path that `bench-native` prints. CI builds the library fresh, so releases are not affected.
- hashcat's example hash for mode 17210 has a false positive about 2 s into an 8-character `?a`
  mask at 2.3 billion per second. Use `--keep-guessing` for speed runs.
- A freshly copied hashcat took over 3 minutes to answer `--version` on macOS while the system
  validated its 728 modules; later starts took 0.01 s. Seen once in a scratch copy, not confirmed
  for the installed app.

## Kernel measurements behind the plan

Apple M1 Pro, 16-core GPU, hashcat 8.0.0 from the bundled build, OpenCL device, 2026-11-14. One
run each unless noted; the machine was not isolated.

| Measurement | Result |
|---|---|
| `-b -m 17210`, replacement kernel, 453-byte stored entry | 2,484 M/s |
| `-b -m 17200`, replacement kernel, deflated entry | 781 M/s |
| `-b -m 17225`, hashcat kernel, mixed multi-file | 1,463 M/s |
| `-b -m 17230`, hashcat kernel, checksum only | 3,026 M/s |
| RAR 3 (12500), pure / optimized | 7,881 / 14,962 per second |
| 7-Zip (11600), pure / optimized | 63,924 / 129,048 per second |
| PDF R6 (10700), pure / optimized | 9,807 / 11,226 per second |
| RAR 3 -p compressed (23800), pure | 7,909 per second |
| Live 17210 mask, 8 x `?a`, `-w 3` | 2,351 M/s, first speed after 12.9 s |
| Same, `-w 4` | 2,314 M/s |
| Same, Metal device | 2,258 M/s |
| Same, `--self-test-disable` | 2,329 M/s, first speed after 12.2 s |
| `BenchmarkAsync` for 7-Zip before the fix, optimized kernels on / off | 0 / 64,255 per second |
