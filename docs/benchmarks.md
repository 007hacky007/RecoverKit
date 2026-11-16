# Benchmarks and performance findings

Measured on 2026-11-12 on a Windows 11 VM: Intel Xeon E5-2620 v4 @ 2.10 GHz, 8 vCPU,
AVX2 + AES-NI, no GPU. RecoverKit was compared with a commercial password-recovery product
whose CPU path is hand-written assembly, both run on the same VM, CPU only, each with its own
built-in benchmark.

Original GUI report (before the Whirlpool optimization): [benchmarks/xeon-e5-2620v4-recoverkit.html](benchmarks/xeon-e5-2620v4-recoverkit.html)

## Results (passwords per second)

| Format | Commercial | RecoverKit | Engine | Ratio |
|---|---:|---:|---|---:|
| PDF R6 (AES-256) | 5,079 | **19,045** | built-in | **3.75x** |
| ZIP (ZipCrypto) | 190.1 M | **408.2 M** | built-in | **2.15x** |
| TrueCrypt RIPEMD-160 | 6,278 | **9,346** | hashcat | 1.49x |
| TrueCrypt Whirlpool | 2,806 | **4,038** | built-in | **1.44x** |
| Word 2007 | 4,784 | **6,691** | hashcat | 1.40x |
| Word 2003 (RC4/SHA-1) | 16.36 M | **21.58 M** | built-in | 1.32x |
| RAR 5 | 1,586 | **2,089** | built-in | 1.32x |
| PowerPoint 2013+ | 403 | **518** | hashcat | 1.29x |
| RAR 3 (-hp) | 3,802 | **4,799** | built-in | 1.26x |
| Word 97 (RC4/MD5) | 13.97 M | **17.27 M** | built-in | 1.24x |
| PDF R3 (RC4) | 1.128 M | **1.293 M** | built-in | 1.15x |
| WPA | 18,418 | **20,266** | hashcat | 1.10x |
| WinZip AES | 149,752 | **153,617** | hashcat | 1.03x |
| TrueCrypt SHA-512 | 21,132 | 21,039 | hashcat | 1.00x |

The built-in rows use a 7-character mask (`?u?d?s` charset), except RAR 3, which uses 4 characters
like the commercial product's RAR 3 figure. They were measured with `recoverkit-cli bench-native`
after the native kernel library (`native/rknative.c`) was added; the other rows come from the GUI
benchmark report. Whirlpool uses the follow-up measurement below.

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

ZIP classic was checked the same way on 2026-11-15 (live brute force in the commercial product, 96
characters, fixed length, 8 threads, stored single-file archives). Its speed does not depend on the
password length; it depends on the file:

| Archive | Length 5 | Length 6 | Length 7 |
|---|---:|---:|---:|
| one stored file of 28 bytes | 195.8 M | 193.5 M | 196.0 M |
| one stored file of 4,053 bytes | 34.9 M | 34.7 M | 34.6 M |

Its benchmark figure (190.1 M) matches the tiny file. RecoverKit's ZIP benchmark also uses one
stored file of 29 bytes, so the two ZIP figures compare like with like. On larger files most of the
time goes into checking the candidates that pass the one-byte header test against the file, which
is why a real archive is slower in both programs. The other formats in the comparison cost the same
at any test length: their key derivation hashes the password once.

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
| TrueCrypt Whirlpool | 29331 | 1,723 | 4,038 | 2.34x |
| RAR 5 | 13000 | 2,028 | 2,089 | 1.03x |

On every other format hashcat on CPU already beats the commercial result, so those stay on hashcat.
RAR 5 is the exception: hashcat's CPU result was already ahead, and the built-in kernel matches it
on this CPU (see below); it exists to run on the CPU next to hashcat on the GPU.

## Whirlpool follow-up (same winbench VM)

Three consecutive 12-second `bench-native` runs, eight threads, mode 29331, gave 4,121,
4,011 and 4,038 passwords/s (median 4,038). The native benchmark uses a seven-byte mask
from `?u?d?s`, with a one-second warm-up excluded. A one-thread run measured 554 passwords/s.
Three hashcat 7.1.2 CPU benchmarks (`-b -m 29331 -D 1 -w 3 --machine-readable`) gave
1,794, 1,723 and 1,678 passwords/s (median 1,723). The median gain is 2.34x over hashcat
and 1.44x over the earlier commercial benchmark. These are separate sequential runs on a VM,
so allow for scheduling variation.

Raw output: [hashcat](benchmarks/xeon-e5-2620v4-whirlpool-hashcat.txt),
[built-in engine](benchmarks/xeon-e5-2620v4-whirlpool-native.txt).

A live hashcat attack on the same published example and the same seven-byte `?u?d?s` mask
measured 1,756 passwords/s. The CLI's normal recovery flow recovered that example's password.
hashcat independently recovered the AES, Serpent and Twofish headers generated by the tests.
The Windows test suite also checks native derivation against Bouncy Castle at password lengths
0, 1, 7, 31, 32, 63 and 64 with binary inputs, recovery for all three single ciphers, and
rejection of corrupted headers. All 88 tests passed on Windows and macOS.

Reproduce the built-in measurement:

```powershell
recoverkit-cli bench-native --mode 29331 --threads 8 --seconds 12
```

## Native ZipCrypto CPU follow-up (Apple M1 Pro)

Measured on 2026-11-13 with .NET 10.0.401 Release, mode 17210, the same seven-character
`?u?d?s` charset as the earlier CPU results. Three six-second runs per path and thread count,
alternating paths, one-second warm-up excluded. Other recovery work ran on the same host. Throughput varied: the initial
managed NEON runs were 304.1, 314.2 and 343.5 M/s; the final alternating comparison below had a
lower managed baseline. Use the paired measurements to compare implementations.

| Search path | 1 thread, M/s | 10 threads, M/s | vs managed NEON, 10 threads |
|---|---:|---:|---:|
| Managed scalar | 8.80 | 66.7 | 0.63x |
| Native scalar, four streams | 10.27 | 82.4 | 0.77x |
| Managed NEON (before) | 14.17 | 106.6 | 1.00x |
| Native NEON, four groups of four | 16.12 | 128.4 | 1.20x |
| Native ARM CRC, eight streams (after) | **19.60** | **155.2** | **1.46x** |

ARM CRC is the default on Apple silicon with CRC32 instructions; native NEON is the ARM fallback.
x86 stays managed. Native AVX2 and AVX-512 share their round source and use CRC gathers and 32-bit
multiplies. On the Windows VM (Xeon E5-2620 v4, 8 vCPU, `bench-native --mode 17210 --seconds 8`,
two alternating runs each) native AVX2 lost to the managed AVX2 kernel: 341 and 345 M/s against
425 and 406 M/s (native scalar: 164 M/s); a brute-force run with the native AVX2 path forced found
the password. AVX-512 compiles into the Windows DLL but has not run on real hardware; it is opt-in
(`RECOVERKIT_ZIP_PATH=avx512`) until measured on an AVX-512 CPU.

The native loop receives keys after the shared prefix from the existing managed cache. Several
independent candidates hide the CRC/key-update dependency chain. The final header byte needs no
following key update. A precomputed table of keys after the last password character lost: median
23.6 M/s versus 32.2 M/s for the direct loop in three short one-thread tuning runs. It adds table
construction and loads without reusing those states across candidates. Six ARM CRC streams were
within 2% of eight on repeated checks; four, twelve and sixteen were slower in the initial sweep.
On NEON, scalar per-lane table loads measured 13.69 M/s versus 14.89 M/s for nibble-table `TBL`
lookups. The keystream depends on key2's low 16 bits, but the CRC chains need their higher bytes
for subsequent updates, and a one-byte check cannot reject a candidate before header byte 11.
Verification and native-engine hit handling are unchanged.

Reproduce with a Release build (PowerShell: set `$env:RECOVERKIT_ZIP_PATH` instead of an inline
environment assignment):

```sh
recoverkit-cli bench-native --mode 17210 --threads 10 --seconds 6
RECOVERKIT_ZIP_PATH=managed recoverkit-cli bench-native --mode 17210 --threads 10 --seconds 6
RECOVERKIT_ZIP_PATH=avx2 recoverkit-cli bench-native --mode 17210 --threads 8 --seconds 6
RECOVERKIT_ZIP_PATH=avx512 recoverkit-cli bench-native --mode 17210 --threads 16 --seconds 6
```

Each ZIP row names the path actually used. With the default x86 selection, the command prints
both managed and native rows; forcing an unsupported native path prints the managed fallback.
Other selectors: `managed-scalar`, `scalar`, `neon`, `arm-crc`, `auto`.
The requested Debug CLI also ran three times before and after: median 27.66 M/s managed,
197.3 M/s native ARM CRC. Debug penalizes the managed hot loop, so the Release comparisons above
are the useful optimization result.
Raw timings and tuning results: [Mac CPU measurements](benchmarks/apple-m1-pro-zip-native.txt).

A real Info-ZIP `zip -0 -e` archive (17-byte stored entry, generated six-character password) was
recovered with a fresh app home and no password cache, mask `--brute sd --min 6 --max 6`.
CPU-only, ten threads, found it in 4.3 seconds, with a 207.8 M/s status sample. The hybrid
visibility check used four total threads (three CPU workers after GPU startup), hashcat 8.0.0
OpenCL, workload 1 and a 10% GPU duty cycle so its small ranges lasted long enough to print a
combined status: GPU 316.7 M/s plus CPU 11.75 M/s (328.4 M/s total). hashcat found the fixture
password after 67.8 seconds. The lower GPU duty cycle is for observing both engine rows, not a
throughput recommendation. The returned password matched the generated fixture in both runs;
password and archive hash are redacted in the [hybrid evidence](benchmarks/apple-m1-pro-zip-hybrid.txt).


## ZIP: Stay fast key search

For ZipCrypto archives whose encryption headers come from Microsoft Visual C `rand()`,
Michael Stay's 2001 attack ("ZIP Attacks with Reduced Known Plaintext", FSE 2001) recovers the
three internal cipher keys without guessing the password: about 2^39 cipher-byte operations,
independent of the password's length. RecoverKit then writes a password-free decrypted copy and
continues with the normal password attacks. It runs as the first step of the default ZIP scenario;
incompatible archives are rejected within seconds.

| Machine | Archive | Time to keys |
|---|---|---:|
| Apple M1 Pro, 10 cores | 5 encrypted files, WinZip-style MSVC headers (test archive) | 42 s |

Requirements: ZipCrypto (not AES), at least 5 encrypted files added in the same run of the
zipping program. Archives with 2 to 4 files would need Stay's 2020 lattice attack (not implemented).

| Software | Vulnerable |
|---|---|
| WinZip 8.0 and earlier (until about 2001) | Yes (WinZip 8.0's variant without the LCG increment is handled) |
| WinZip 8.1 and later | Believed fixed; WinZip 9 (2003) also added AES |
| Info-ZIP `zip.exe` built for Windows (MSVC) | Yes, never fixed (last release Zip 3.0, 2008); still bundled with many scripts and tools |
| Other Info-ZIP-based Windows tools (for example NetZip) | Yes |
| Info-ZIP on Linux and macOS | No (different `rand()`; reported as not compatible) |
| 7-Zip, PKZIP | No (different, stronger generators) |
| WinRAR (ZIP output) | Not known to be vulnerable; RAR archives are unrelated |
| Windows Explorer (XP-era password option) | Unknown, treated as not compatible |

## ZIP on the GPU

Large-entry recovery, outfile hit rates and the concurrent Metal comparison are recorded in
[large ZIP measurements](benchmarks/apple-m1-pro-zip-large.txt).

The starting point: on an NVIDIA RTX 4060 a commercial product reports 13.4 billion ZipCrypto
passwords per second, while RecoverKit's benchmark (hashcat 7.1.2 `-b -m 17210`, OpenCL) reported
1.4 to 1.6 billion. That hashcat figure depends on the archive: `-b` attacks hashcat's built-in
example, a 453-byte stored file, and hashcat's PKZIP kernels decrypt and check the whole file in
the candidate loop for the 1 in 128 candidates whose check byte matches, while the other threads of
the SIMD group wait. The cost grows with the entry size, which is why the replacement kernels exist
(see [DEVELOPERS.md](DEVELOPERS.md#zip-kernels-for-hashcat)).

### Apple M1 Pro (16-core GPU), hashcat 7.1.2 vs 8.0.0 vs RecoverKit's kernels

Live brute-force attacks, mask `?a?a?a?a?a?a?a?a`, median of the status updates of 6-second runs,
millions of passwords per second, average of two runs each (they agreed within 5%). Entries made with
Info-ZIP `zip` (data descriptor, so two check bytes are accepted: 1 in 128). hashcat 7.1.2 refuses
deflated entries on the Apple GPU (Metal and OpenCL).

| Entry | Backend | hashcat 7.1.2 | hashcat 8.0.0 | RecoverKit kernel | vs 8.0.0 |
|---|---|---:|---:|---:|---:|
| stored, 17 bytes | OpenCL | 3,545 | 3,183 | 3,002 | 0.94x |
| stored, 453 bytes (hashcat `-b`) | OpenCL | 528 | 548 | 2,425 | **4.4x** |
| stored, 1,000 bytes | OpenCL | 156 | 266 | 1,913 | **7.2x** |
| deflated, 1,000 bytes (588 compressed) | OpenCL | refused | 913 | 920 | 1.0x |
| deflated, 4,000 bytes (2,239 compressed) | OpenCL | refused | 873 | 890 | 1.0x |
| stored, 17 bytes | Metal | 1,639 | 2,960 | 2,582 | 0.87x |
| stored, 453 bytes (hashcat `-b`) | Metal | 17 | 444 | 2,112 | **4.8x** |
| stored, 1,000 bytes | Metal | 26 | 220 | 1,629 | **7.4x** |
| deflated, 1,000 bytes | Metal | refused | 254 | 642 | **2.5x** |
| deflated, 4,000 bytes | Metal | refused | 194 | 742 | **3.8x** |

hashcat selects the OpenCL device on Apple Silicon by default (the Metal device is an alias).

hashcat's own benchmark (`hashcat -b`, its example hashes: a 453-byte stored and a deflated
entry), million passwords per second:

| Mode | Backend | hashcat 7.1.2 | hashcat 8.0.0 | RecoverKit kernel |
|---|---|---:|---:|---:|
| 17210 stored | OpenCL | 569 | 551 | 2,478 |
| 17210 stored | Metal | 105 | 519 | 2,407 |
| 17200 deflated | OpenCL | refused | 944 | 1,015 |
| 17200 deflated | Metal | refused | 42 | 808 |

Findings:

- With the verification out of the candidate loop the speed hardly depends on the entry size any
  more (stored: 3.0 billion at 17 bytes, 1.9 billion at 1,000 bytes; it falls by the 1/128 share of
  candidates that still need the full check).
- Tiny entries lose 6 to 13%: the queue and the barriers between rounds cost a little, and the
  original kernel's inline check is cheap when there are only a few bytes to check.
- Deflated entries on OpenCL do not gain. hashcat 8 already rejects most survivors with a quick
  look at the first Huffman block, and the inflate code (77 KB of private memory per work item, and
  hashcat runs this mode with 32 threads per work-group) is what limits both kernels: without it the
  same kernel ran at 1,470 million, and at 2,600 million with 64 threads. A full inflate cannot be
  moved out of the kernel without a writable buffer for its 32 KB window, which hashcat's kernel
  interface does not give a mode without changing the module.
- Things tried that did not help on this GPU: caching the key state after the amplifier
  characters in local memory (`RK_AMP_CACHE`), and two candidates per thread for more
  instruction-level parallelism. Writing the kernel body as one macro instead of included code
  halved the speed, and so did verifying inline.
- hashcat 8.0.0 against 7.1.2 on this Mac: Metal became usable for ZIP (17 to 444 million for the
  453-byte entry), deflated entries run on the GPU at all, OpenCL with stored entries is within 10%.

`recoverkit-cli bench-zip --seconds 6` on the same Mac (its generated entries have one check byte,
so one candidate in 256 needs the full check; the GPU was shared with other jobs at times, so
single rows can be off):

```
Device #1: Apple M1 Pro (Metal 382.5.3)
  entry                                       hashcat     RecoverKit    gain      amp cache
  stored, 17 bytes                       3,355.4 MH/s   2,826.2 MH/s   0.84x   2,730.8 MH/s
  stored, 453 bytes (as hashcat -b)        771.3 MH/s   2,172.8 MH/s   2.82x   2,352.2 MH/s
  stored, 4 KB                              94.0 MH/s   1,098.5 MH/s  11.69x   1,082.6 MH/s
  deflated, 1 KB text                      557.8 MH/s     954.6 MH/s   1.71x     944.5 MH/s
  deflated, 16 KB text                     563.9 MH/s     918.5 MH/s   1.63x     881.9 MH/s
Device #2: Apple M1 Pro (OpenCL OpenCL 1.2)
  entry                                       hashcat     RecoverKit    gain      amp cache
  stored, 17 bytes                       3,391.7 MH/s   3,056.1 MH/s   0.90x   2,549.8 MH/s
  stored, 453 bytes (as hashcat -b)        884.7 MH/s   2,707.8 MH/s   3.06x     667.4 MH/s
  stored, 4 KB                             114.0 MH/s   1,331.3 MH/s  11.67x         failed
  deflated, 1 KB text                    1,207.0 MH/s   1,129.2 MH/s   0.94x     862.6 MH/s
  deflated, 16 KB text                   1,145.6 MH/s   1,096.5 MH/s   0.96x     829.1 MH/s
```

The "failed" run found a false positive and stopped (bench-zip now passes `--keep-guessing`).
False positives are real with stored entries: a wrong password passes the check byte (1 in 128 or
256) and the CRC-32 (1 in 2^32) about once in 5 * 10^11 candidates, so a brute-force run over
billions of candidates per second reports one every few minutes. The 1,000-byte stored test entry
above (password `ab1`) also opens with `TSHJNTER`: hashcat 8's own kernel, RecoverKit's kernel and
an independent Python check agree. hashcat stops at the first such hit. Deflated entries are much
safer, because the data must also inflate to the stored length.

### NVIDIA and other GPUs

Not measured here (no NVIDIA GPU). To measure on a PC with the GPU driver installed:

```
recoverkit-cli install-hashcat
recoverkit-cli bench-zip
```

`bench-zip` lists the devices, then runs every entry size on every device (CUDA, OpenCL and
Metal aliases separately) with hashcat's kernel, RecoverKit's kernel and RecoverKit's kernel with
the amplifier cache, 10 seconds each, and prints a table per device. `--device 1`
limits it to one device, `--seconds 20` makes the runs longer, `--quick` leaves out the
amplifier-cache column. The GUI's Tools > Benchmark row "ZIP/Classic" (`hashcat -b -m 17210`) uses
RecoverKit's kernel too. On Windows, an NVIDIA GPU appears as a CUDA device only after
Tools > Dependencies (or with the CUDA Toolkit installed); run
`bench-zip` before and after to compare OpenCL and CUDA.

## When the built-in engine runs

`NativeRunner.Plan()` and `HybridRunner.Plan()` use it when all of these hold:

- the format has a built-in kernel (ZIP, Word/Excel 97, Word/Excel 2003, PDF R2-R4, PDF R6, RAR 3 -hp, RAR 5, TrueCrypt Whirlpool with a single cipher);
- for PDF R6, RAR 5 and the fast RAR 3 path, the native library is present and the CPU has AVX2 (PDF R6 also AES-NI) or NEON;
- the attack is brute-force or mask (`-a 3`), not dictionary or stdin generators;
- no extra hashcat arguments are configured (they can change candidate interpretation);
- for TrueCrypt Whirlpool, the native library is present;
- Preferences > Performance "Use the built-in CPU engine" is on (default).

Without a GPU (no GPU present, every GPU unchecked, or strategy "CPU only") it runs alone. With a
GPU it runs next to hashcat on part of the keyspace (hybrid, see below) when "Run it next to the
GPUs" is on (default) and the strategy is "Keep one CPU thread free for each GPU" (default) or "Use
all CPU threads"; with "Avoid the CPU" or hybrid off, hashcat runs alone as before.

## Hybrid CPU + GPU (Apple M1 Pro)

Measured on 2026-11-13 on an Apple M1 Pro (8 performance + 2 efficiency cores, 16-core GPU),
hashcat 7.1.2 on the GPU through OpenCL, built-in engine with the native NEON library, 9 CPU threads
next to hashcat (one left for hashcat's GPU thread), RecoverKit's CLI with default settings. Another
program used the GPU at times during this session; rows marked * overlapped with it.

| Format, mask | GPU only | CPU only | Hybrid |
|---|---:|---:|---:|
| PDF R6, `?u?u?u?u?u` (steady speed) | 7,700-9,600/s | 55,000-60,000/s | 63,000-67,000/s (GPU 6,700, CPU 58,000) |
| PDF R6, same, second hybrid run * | | | 33,000-35,000/s (GPU 6,600, CPU 27,600) |
| RAR 3 -hp, `?1?1?1?1?d`, `?1`=a-p, whole run | 48 s (11,500-14,000/s) | 147-186 s (3,500-4,800/s) | 142-191 s * |

What this machine shows:

- **PDF R6**: the CPU engine is about six times faster than this integrated GPU, and hybrid adds the
  GPU on top: about +15-20 % over CPU only and seven times GPU only.
- **RAR 3**: here the GPU is three times faster than the CPU, and the two share one power budget
  and memory: with the CPU engine busy the GPU fell to 7,000-11,000/s while the CPU added about
  1,700/s, and hashcat's start-up grew from a few seconds to about a minute. Hybrid lost to GPU only.
  This is why, when every GPU is integrated and the last hybrid attack measured the CPU below a
  quarter of hashcat's speed, later attacks on that mode run hashcat alone.
- On a desktop with a discrete GPU the GPU does not share the processor's power budget, so the CPU's
  share adds almost fully: on a Ryzen 7 9800X3D with an RTX 4060 the RAR 3 benchmark measured GPU
  76,271/s and CPU 36,052/s (see the Ryzen section above).

Before this work two things cost the built-in engine most of its speed on macOS: the default
"Idle" priority niced the process, which macOS runs on the efficiency cores (PDF R6 10,000-16,000/s
instead of 55,000/s; RAR 3 at "below normal" 1,800/s instead of 4,400/s), and a niced hashcat next to
the engine fed the GPU at 2,500/s instead of 9,600/s. On macOS neither is lowered any more.

Reproduce: `recoverkit-cli crack <file> --hcmask '?u?u?u?u?u'` with and without `--no-hybrid`, and
`--strategy CpuOnly`; the status lines list each device's speed.

## Ryzen 7 9800X3D + RTX 4060 against a commercial product

Measured on the tester's Windows PC: AMD Ryzen 7 9800X3D (Zen 5, 8 cores, 16 threads, AVX-512),
NVIDIA GeForce RTX 4060, the processor's integrated Radeon unticked. Each program's own built-in
benchmark: the commercial product on 2026-11-12, RecoverKit 1.6.1 on 2026-11-14 and 1.7.2 on
2026-11-16. Passwords per second; the commercial product uses the processor next to the GPU for
every format. The ratio compares 1.7.2 with the commercial product.

RecoverKit 1.7.2 report: [benchmarks/ryzen-9800x3d-rtx4060-recoverkit-1.7.2.html](benchmarks/ryzen-9800x3d-rtx4060-recoverkit-1.7.2.html)

| Format | Commercial | RecoverKit 1.6.1 | RecoverKit 1.7.2 | Ratio | RecoverKit engine (1.7.2) |
|---|---:|---:|---:|---:|---|
| Word 97 (RC4/MD5) | 43.4 M | 558.8 M | **529.1 M** | **12.2x** | hashcat + built-in CPU engine |
| Word 2003 (RC4/SHA-1) | 56.3 M | 634.1 M | **591.4 M** | **10.5x** | hashcat + built-in CPU engine |
| PDF R6 (AES-256) | 23,158 | 159,061 | **144,859** | **6.3x** | hashcat + built-in CPU engine |
| RAR 5 | 50,812 | 68,383 | **66,539** | **1.31x** | hashcat + built-in CPU engine (AVX2, AVX-512) |
| TrueCrypt RIPEMD-160 | 260,444 | 332,109 | **305,730** | **1.17x** | hashcat |
| RAR 3 | 98,014 | 87,951 (7 chars) | **112,323** (4 chars) | **1.15x** | hashcat + built-in CPU engine (AVX-512) |
| ZIP classic | 13.39 G | 14.68 G | **14.51 G** | **1.08x** | hashcat + built-in CPU engine (managed AVX2) |
| PowerPoint 2013+ | 12,704 | 12,392 | 11,830 | 0.93x | hashcat |
| Word 2007 | 181,756 | 154,338 | 156,984 | 0.86x | hashcat |
| WPA | 531,252 | 456,779 | 448,144 | 0.84x | hashcat |
| WinZip AES | 4.15 M | 3.26 M | 3.30 M | 0.79x | hashcat |
| TrueCrypt SHA-512 | 590,736 | 507,259 | 447,447 | 0.76x | hashcat |
| PDF R3 (128-bit) | 34.6 M | 28.8 M | 25.6 M | 0.74x | hashcat + built-in CPU engine |
| TrueCrypt Whirlpool | 87,438 | 71,267 | failed | - | hashcat + built-in CPU engine |

What each side measured in the 1.7.2 hybrid rows (GPU + CPU): Word 97 478.0 M + 51.1 M, Word 2003
531.1 M + 60.4 M, PDF R6 90,971 + 53,888, RAR 5 48,227 + 18,312, RAR 3 76,271 + 36,052, ZIP
12.79 G + 1.72 G, PDF R3 21.9 M + 3.7 M.

- 1.7.2 leads on 7 of the 13 measured formats. It leads where the built-in CPU engine carries
  the work (Office 97-2003, PDF R6) or adds a large share to hashcat (RAR 5 +38%, RAR 3 +47%). On
  ZIP the GPU alone (12.79 G) is 5% behind and the CPU's 1.72 G puts it ahead.
- RAR 3 moved from 0.90x to 1.15x because 1.7.x measures it at 4 characters, the length the
  commercial figure matches (see "Same inputs, live attacks"). 1.6.1 measured 7 characters, which
  costs 1.32x more per password; 87,951 x 1.32 = 116,000 is close to the new figure. This is a
  like-for-like correction, not a speed-up.
- The formats that run on hashcat alone are 7% to 24% behind; the commercial product adds the
  processor there. WPA and WinZip AES have had a CPU engine since 1.6.2, but it runs next to the
  GPU only after the performance profile has measured a whole-job win, so the benchmark used
  hashcat alone. PDF R3 runs hybrid and is still 26% behind: hashcat's GPU share alone
  (21.9 M) is 37% below the commercial figure.
- The GPU backend differs between the two runs. On this PC 1.6.1 could not build hashcat's CUDA
  kernels (a CUDA Toolkit newer than the driver was not hidden from hashcat, fixed after 1.6.1),
  so hashcat ran the RTX 4060 through OpenCL, although the 1.6.1 report listed the device as CUDA.
  1.7.2 ran it through CUDA. Rows on hashcat alone moved by -12% to +2% (TrueCrypt SHA-512 -12%,
  TrueCrypt RIPEMD-160 -8%, PowerPoint -5%, WPA -2%, WinZip AES +1%, Word 2007 +2%). Both runs used
  hashcat 8.0.0. The short detailed performance test on the same day compared the two backends
  only for RAR 5 (mode 13000, GPU alone, synthetic fixture, 7 characters): CUDA 46,983/s, OpenCL
  47,713/s, within 2%. The other CUDA probes did not fit the short test's time budget, so the
  formats that dropped most (TrueCrypt SHA-512 and RIPEMD-160, PDF) still need the thorough test.
- The same detailed test measured the CPU engines that 1.7.2 keeps off next to the GPU (AVX-512,
  16 threads): WinZip AES 1,120,784/s and WPA 140,217/s (8 characters). Added to the GPU's
  3,301,783/s and 448,144/s from the benchmark, that would be about 4.4 M and 588,000/s, ahead of
  the commercial 4.15 M and 531,252/s, if the GPU keeps its speed with the CPU busy. Not measured
  as a combined run.
- TrueCrypt Whirlpool returned no rate in 1.7.2 ("not supported on this device"): the matched
  hybrid probe got a zero from the GPU or the CPU side and returned 0. 1.6.1 measured 71,267 on the
  same PC. The separate CPU path measurement in the same report ran: 11,891/s for the scalar path
  and 8,901/s for the AVX-512 path (0.75x, 15 threads, 3 pairs). The AVX-512 Whirlpool path is
  slower on Zen 5 and stays off by default.
- The RAR 5 CPU share (18,312/s with 15 threads) is close to the 20,000/s estimated below for this
  CPU before it was measured.
- The commercial report prints a second figure in brackets (RAR 3: 98,014 (92,947)); the first
  one is compared. Its Word 2007 test file uses 256-bit AES, RecoverKit's 128-bit AES, so that row
  is approximate. PDF R6 and RAR 3 costs depend on password length (see "Same inputs, live
  attacks" above).
- RecoverKit 1.3.0 on the same PC: ZIP classic 1.36 G, RAR 3 61,758, RAR 5 43,904.
- The 1.7.2 report also covers formats without a commercial figure: 7-Zip 506,600, KeePass
  AES-KDF 54,858, KeePass Argon2 637, Android backup 184,512, Word 2010 77,102, OpenDocument
  19,110, PDF R2 769.7 M, PDF R5 3.65 G, VeraCrypt SHA-512 1,159, and the wallet formats.

## Version 1.5.0 performance work

Measured on 2026-11-14 on the Apple M1 Pro (16-core GPU, hashcat 8.0.0) and on the Xeon VM above,
on a machine that was not isolated unless noted. The method and the open items are in
[performance-plan.md](performance-plan.md).

| Change | Measurement | Before | After |
|---|---|---:|---:|
| RAR 3 CPU fills every vector lane | mask `?l?l?l?l2024`, CPU only, M1 Pro (NEON, 8 threads) | 1,144/s | 2,094/s |
| | same, Xeon VM (AVX2, 8 threads) | 1,660/s | 3,438/s |
| ZIP CPU fills every lane next to the GPU | CPU share of a hybrid ZIP attack, M1 Pro | 1.8-3.8 M/s | 8.3-25.3 M/s |
| ZIP GPU checks only check bytes (8+ encrypted files) | archive of 25 large photos, 34.3 billion candidates, GPU only, whole job | 47.6-77.0 s | 13.6-25.3 s |
| | same, hybrid | 53.7-170.6 s | 19.2-41.8 s |
| Optimized kernels for dictionaries, long words in a second pass | RAR 3, 480,004 candidates, whole job | 112-262 s | 49-86 s |
| CPU joins the GPU in dictionary attacks | RAR 5 word list, 9.6 million candidates, whole job | 840-935 s | 622-674 s |

- The dictionary rows are complete jobs with start-up, three to five alternating pairs. In the
  RAR 5 hybrid job the CPU hashed at 5,579/s, close to its 5,762-5,958/s in a mask attack.
- The integrated GPU of the M1 Pro shares its power budget with the CPU, so a desktop with a
  discrete GPU gains more from the CPU's share (see the Ryzen section above).
- RAR 3 also has an AVX-512 path. It checks itself against known answers before first use; it
  first ran on a Ryzen 7 9800X3D in the 1.6.1 benchmark and passed. The AVX2 and NEON rates were unchanged by it (3,575 against
  3,573/s and 3,693 against 3,693/s).

### Metal instead of OpenCL on macOS

hashcat 8.0.0 on Apple's OpenCL device ended some wordlist attacks without the password and
without an error: RAR 3 with the pure kernel in 3 of 33 runs, PDF 1.7 Level 8 in 6 of 17. The
Metal device found the password in every run, so RecoverKit 1.5.0 runs every format through Metal
on a Mac. Each format was checked with a mask, the password first and in the middle of a word
list, and through a rule, one hashcat at a time.

| Format (hashcat mode) | Kernel | OpenCL | Metal | Metal / OpenCL |
|---|---|---:|---:|---:|
| RAR 5 (13000) | pure | 11,545/s | 11,556/s | 1.00 |
| RAR 3 -p (23700) | pure | 8,365/s | 5,309/s | 0.63 |
| RAR 3 -p (23700) | optimized | 16,545/s | 15,068/s | 0.91 |
| PDF 1.7 Level 8 (10700) | pure | 2,190/s | 2,860/s | 1.31 |
| PDF 1.7 Level 8 (10700) | optimized | 11,572/s | 9,097/s | 0.79 |
| PDF 1.4-1.6 (10500) | pure | 4.83 M/s | 5.29 M/s | 1.10 |
| PDF 1.1-1.3 (10400) | optimized | 119.7 M/s | 81.1 M/s | 0.68 |
| Office 2007 (9400) | pure | 42,398/s | 42,590/s | 1.00 |
| Office 2013 (9600) | pure | 1,845/s | 1,780/s | 0.96 |
| Office 2003 SHA-1 (9800) | optimized | 87.0 M/s | 58.6 M/s | 0.67 |
| 7-Zip (11600) | optimized | 133,625/s | 130,665/s | 0.98 |

Metal also starts faster: about 4 s against about 47 s for RAR 3 in these runs.

## RAR 5 (PBKDF2-HMAC-SHA256)

RAR 5 costs 32,800 PBKDF2-HMAC-SHA256 iterations per password (2^15 for the key plus 32 for the
password check value), each two SHA-256 compressions. The built-in kernel runs one candidate per
lane: 16 lanes with AVX-512, 8 with AVX2, 8 interleaved streams of the ARMv8 SHA-256 instructions
on Apple silicon (see DEVELOPERS.md, Native kernels).

| Machine | Path | Built-in, 1 thread | Built-in, all threads | hashcat |
|---|---|---:|---:|---:|
| Xeon E5-2620 v4 VM, 8 vCPU | AVX2 | 276/s | 2,089/s (2,110, 2,082, 2,089) | 2,028/s (CPU, OpenCL) |
| Apple M1 Pro, 8P + 2E | ARMv8 SHA-256 | 730/s (NEON 308/s) | 6,134/s (10 threads) | GPU: 10,600-11,000/s live, 9,028/s `-b` |

Windows VM: three 12-second `bench-native --mode 13000 --threads 8` runs, median 2,089/s, 3 %
above hashcat's CPU figure from the same VM. On this Broadwell CPU every vector shift and rotate
goes through one execution port, and SHA-256 needs about 1,200 of them per 8-lane compression; both
programs hit that limit, so there is little to gain here. A CPU-only attack on a RAR 5 test archive
on the VM found the password.

Apple M1 Pro, hybrid (`crack <file> --brute sd --min 1 --max 4`, fresh `RECOVERKIT_HOME`, 9 CPU
threads next to hashcat): during length 4 the status showed 12,500-13,600/s, GPU 7,500-7,900 and
CPU 5,000-5,800. The same attack with `--no-hybrid` ran length 4 at 10,600-11,000/s, so hybrid is
about 1.2 times GPU only on this machine: the integrated GPU loses about 30 % to the busy CPU (one
power budget), and the CPU more than makes up for it. Lengths 1-3 stayed on the CPU (less than two
hashcat start-ups of work); with GPU only, hashcat started once per length and spent most of the
run on lengths 1-2. Two test archives (copies of r5.rar with the check value replaced for a
4-character password) checked both shares: `ab1z` (last character at the top of hashcat's order,
the CPU's first batch) was found by the built-in engine after 31 s, `ab10` (the bottom, hashcat's
first range) by hashcat after 137 s; GPU only found `ab10` after 448 s. Another program used the
GPU at times during these runs. Unlike RAR 3, the CPU here stays above a quarter of the integrated
GPU's speed, so both keep running. On a discrete GPU the CPU's share should add almost fully.

Estimate for a Ryzen 7 9800X3D (8 Zen 5 cores, full-width AVX-512) next to an RTX 4060, made
before it was measured: the AVX-512 loop is about 3,250 vector operations per iteration for 16
lanes (1,112 VPROLD, 812 VPTERNLOGD, 1,154 VPADDD, 172 shifts). With Zen 5's four vector ALUs and
rotates on two of them that is roughly 800-850 cycles, about 53 cycles per candidate and
iteration, or 1.7 million cycles per candidate. At about 5 GHz all-core that is 2,900/s per core
and, with one thread left to hashcat's GPU thread, about 20,000/s for the CPU. The 1.7.2 benchmark
on that PC measured 18,312/s for the CPU next to 48,227/s for hashcat on the GPU, 66,539/s
together: 1.31x the commercial product's 50,812/s.

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
- **RAR 5.** Multi-lane PBKDF2-HMAC-SHA256 from one generic C source per vector width; the first
  SHA-256 round of the fixed HMAC states and the constant padding words are folded out of the
  loop. On arm64 the SHA-256 instructions beat the NEON lanes 2.4 times.
- **TrueCrypt Whirlpool.** Native scalar 64-bit table rounds, with the inner and outer HMAC
  states and their Whirlpool round keys cached across all 1,000 PBKDF2 iterations. Bouncy Castle
  provides independent reference derivation and AES, Serpent and Twofish checks. Candidates must
  pass the decrypted header signature, key-area CRC and, for header version 4+, header CRC.
  Mode 29331 runs built in for CPU masks; cascades, dictionary attacks and GPU work stay on hashcat.
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
- CLI: `RecoverKit.Cli bench-native` (built-in kernels), `RecoverKit.Cli bench-prims`
  (MD5/SHA-1/RC4 primitives) and `RecoverKit.Cli bench-zip` (ZIP GPU kernels, hashcat's against
  RecoverKit's, per device).
- To compare machines, compare the saved HTML files row by row; the report shows which engine
  produced each row. Enable the debug log (Preferences > Other) if numbers look wrong.
