# Benchmarks and performance findings

Measured on 2026-11-12 on a Windows 11 VM: Intel Xeon E5-2620 v4 @ 2.10 GHz, 8 vCPU,
AVX2 + AES-NI, no GPU. RecoverKit was compared with a commercial password-recovery product
whose CPU path is hand-written assembly, both run on the same VM, CPU only, each with its own
built-in benchmark.

RecoverKit's raw report: [benchmarks/xeon-e5-2620v4-recoverkit.html](benchmarks/xeon-e5-2620v4-recoverkit.html)

## Results (passwords per second)

| Format | Commercial | RecoverKit | Engine | Ratio |
|---|---:|---:|---|---:|
| PDF R6 (AES-256) | 5,079 | **19,045** | built-in | **3.75x** |
| ZIP (ZipCrypto) | 190.1 M | **408.2 M** | built-in | **2.15x** |
| TrueCrypt RIPEMD-160 | 6,278 | **9,346** | hashcat | 1.49x |
| Word 2007 | 4,784 | **6,691** | hashcat | 1.40x |
| Word 2003 (RC4/SHA-1) | 16.36 M | **21.58 M** | built-in | 1.32x |
| PowerPoint 2013+ | 403 | **518** | hashcat | 1.29x |
| RAR 5 | 1,586 | **2,028** | hashcat | 1.28x |
| RAR 3 (-hp) | 3,802 | **4,799** | built-in | 1.26x |
| Word 97 (RC4/MD5) | 13.97 M | **17.27 M** | built-in | 1.24x |
| PDF R3 (RC4) | 1.128 M | **1.293 M** | built-in | 1.15x |
| WPA | 18,418 | **20,266** | hashcat | 1.10x |
| WinZip AES | 149,752 | **153,617** | hashcat | 1.03x |
| TrueCrypt SHA-512 | 21,132 | 21,039 | hashcat | 1.00x |
| TrueCrypt Whirlpool | 2,806 | 1,794 | hashcat | 0.64x |

The built-in rows use a 7-character mask (`?u?d?s` charset), except RAR 3, which uses 4 characters
like the commercial product's RAR 3 figure. They were measured with `recoverkit-cli bench-native`
after the native kernel library (`native/rknative.c`) was added; the other rows come from the GUI
benchmark report.

### Same inputs, live attacks

Built-in benchmarks can differ in password length, and for RAR 3 and PDF R6 the cost per password
depends on it. These were checked with live brute-force attacks on the same test files in both
programs, at a fixed length:

| Format | Length | Commercial | RecoverKit | hashcat | Ratio |
|---|---:|---:|---:|---:|---:|
| RAR 3 (-hp) | 4 | 3,947 | 4,656 | - | 1.18x |
| RAR 3 (-hp) | 7 | 3,019 | 3,483 | - | 1.15x |
| PDF R6 | 4 | 5,271 | 18,861 | 3,482 | 3.58x |
| PDF R6 | 7 | 5,017 | 18,705 | 3,263 | 3.73x |

The commercial benchmark's RAR 3 figure matches a 4-character password and its PDF R6 figure a
7-character one, and so does hashcat's `-b` figure for PDF R6 (3,303).

## hashcat 7.1.2 baseline (same VM, CPU, Intel OpenCL runtime)

These are the formats where plain hashcat was far behind the commercial product, which is why the
built-in engine exists:

| Format | hashcat mode | hashcat | Built-in engine | Gain |
|---|---|---:|---:|---:|
| ZIP (ZipCrypto) | 17210 | 42.7 M | 408.2 M | 9.6x |
| Word 97 | 9700 | 3.45 M | 17.27 M | 5.0x |
| Word 2003 | 9800 | 5.55 M | 21.58 M | 3.9x |
| PDF R3 | 10500 | 287 K | 1.293 M | 4.5x |
| RAR 3 -hp | 12500 | 240 (465 with -O) | 4,799 | 10.3x vs -O |
| PDF R6 | 10700 | 2,882 (3,149 with -O) | 19,045 | 6.0x vs -O |
| TrueCrypt Whirlpool | 29331 | 1,783 | - | - |

On every other format hashcat on CPU already beats it, so those stay on hashcat.

## When the built-in engine runs

`NativeRunner.Plan()` picks it only when all of these hold:

- the format has a built-in kernel (ZIP, Word/Excel 97, Word/Excel 2003, PDF R2-R4, PDF R6, RAR 3 -hp);
- for PDF R6 and the fast RAR 3 path, the native library is present and the CPU has AVX2 (PDF R6 also AES-NI);
- the attack is brute-force or mask (`-a 3`), not dictionary or stdin generators;
- no GPU will be used (no GPU present, or strategy "CPU only");
- Preferences > Performance "Use the built-in CPU engine" is on (default).

Otherwise hashcat runs. With a GPU, hashcat runs everything.

## Findings

- **ZipCrypto.** AVX2, three interleaved vectors per thread, CRC-32 table lookups done as
  `vpermd` on a 3+3+2-bit split instead of gathers, allocation-free streaming verification of
  candidates that pass the check byte. A real attack on `cputest.zip` ran at 355 M/s.
- **Native kernel library.** `native/rknative.c` (plain C with intrinsics and some inline asm,
  built with `zig cc`) holds the kernels where the .NET JIT could not keep up: two interleaved
  8-lane groups need all 16 vector registers without spills. The managed kernels remain as the
  fallback when the library is missing (or with `RECOVERKIT_NO_NATIVE_LIB=1`).
- **Word 97 / Word 2003 / PDF R3.** 16-lane MD5 and SHA-1 (two AVX2 groups) and an
  eight-way interleaved RC4 key schedule in assembly. RC4 key scheduling is serial within one key
  (data-dependent swaps), so the speed comes from running eight keys side by side.
- **RAR 3.** 262,144 SHA-1 rounds per candidate. Bytes shared by all candidates of a batch are
  kept in a template, the message schedule is split into shared and per-lane parts, and constants
  are pre-added for the first 16 rounds.
- **PDF R6.** Each candidate runs at least 64 rounds of AES-128-CBC over 64 copies of
  (password || K), then SHA-256, -384 or -512 chosen by the data, so candidates diverge after the
  first round. Each thread keeps a pool of 64 candidates and runs whichever (hash, key length)
  group has eight ready. The AES blocks of eight independent CBC chains are interleaved (AES-NI
  latency hidden) and fed straight into an 8-lane SHA-256 or two 4-lane SHA-384/512 compressions,
  without storing E. hashcat's OpenCL kernel loses most of its vector width to that divergence.
- **TrueCrypt Whirlpool.** hashcat only.
- **Vector kernels** (Word 97/2003, PDF, RAR 3) are offered only when
  `Vector256.IsHardwareAccelerated`. Without hardware 256-bit vectors those formats go to
  hashcat, because emulated `Vector256` would be slower. ZipCrypto has a non-vector path and
  is always built in.
- **Bugs found while benchmarking:**
  - engine thread-join race (`First()` after `Any()`) that could crash about 1 in 10 runs at the end;
  - `guess_mask_length` 4294967295 overflowed `HashcatStatus` and broke progress for every
    dictionary attack;
  - after resuming, the resumed part was counted into the average speed (`ResumedFrom` now excluded).

## Reproducing

- GUI: Tools > Benchmark, then "Save as HTML".
- CLI: `RecoverKit.Cli bench-native` (built-in kernels) and `RecoverKit.Cli bench-prims`
  (MD5/SHA-1/RC4 primitives).
- To compare machines, compare the saved HTML files row by row; the report shows which engine
  produced each row. Enable the debug log (Preferences > Other) if numbers look wrong.
