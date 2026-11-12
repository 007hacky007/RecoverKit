# Stay's ZIP Attack - Design

Date: 2026-11-12
Status: approved

## Intent and why

RecoverKit recovers ZipCrypto (`ZIPC`, hashcat 17200/17210) archives only by searching
passwords. For archives created by Info-ZIP-derived zippers - WinZip 8.0 and earlier,
NetZip, Windows builds of Info-ZIP itself - the 12-byte encryption header is generated
from a weak PRNG (MSVC `rand()`), and Michael Stay's 2001 attack
("ZIP Attacks with Reduced Known Plaintext", FSE 2001; math.ucr.edu/~mike/zipattacks.pdf)
recovers the internal cipher keys directly, with no plaintext and no password guessing:
about 2^39 cipher-byte encryptions of work - minutes on a modern CPU, "under two hours
on a 500 MHz Pentium II" in 2001. No open-source implementation exists (bkcrack and
pkcrack implement only Biham-Kocher known-plaintext, which needs 12+ known plaintext
bytes; ARCHPR is the only known living implementation).

Goal: add this attack to RecoverKit as an **optional, automatically-included first step**
for compatible archives, so that:

1. If the user's password is reachable by their configured attacks, they get the
   **password** (the session continues with their normal steps after the keys are found).
2. If the password is unreachable (long/random - the common case where the current
   product fails), the user still gets their files back: the step writes a
   **decrypted copy of the archive** using the recovered keys.

## Ground truth the implementation follows

Verified against the real Info-ZIP `crypt.c` (crypthead), Stay's paper, and the
February 2003 Full Disclosure post ("Yet another plaintext attack to ZIP encryption
scheme", dufresne; credits Mike Stevens, Elisa Flanders). All equations below were
validated numerically against a faithful Python simulation of crypthead.

### The cipher (ZipCrypto)

Keys `(k0, k1, k2)`, initialized from the password (unknown initial state `K0=(X,Y,Z)`).
Per plaintext byte `c`:

```
k0' = (k0 >> 8) ^ T[(k0 ^ c) & 0xff]           T = CRC-32 table (poly 0xEDB88320)
k1' = (k1 + LSB(k0')) * 0x08088405 + 1          M = 0x08088405 = 134775813
k2' = (k2 >> 8) ^ T[(k2 ^ MSB(k1')) & 0xff]
keystream byte = ((t * (t^1)) >> 8) & 0xff,  t = (k2 & 0xffff) | 2
```

The keystream byte depends only on bits 2..15 of `k2` (bit 0 cancels in `t*(t^1)`);
define `f14(v)` for a 14-bit value `v`: `t = (v << 2) | 2` (even), keystream
`= ((t * (t+1)) >> 8) & 0xff`. `T` is linear over GF(2): `T[x^y] = T[x] ^ T[y]`.

### Header generation (Info-ZIP crypthead, WinZip ≤ 8)

Per process run: `srand(time ^ pid)` **once**. Per encrypted file, in archive
(local-header) order, 10 calls to `rand()`, keeping the high 8 bits of the 15-bit
output (`(rand() >> 7) & 0xff` = bits 23..30 of the 31 observable state bits):

1. `init_keys(password)`; encrypt the 10 random bytes `r[0..9]` → intermediate
   ciphertext `c1[0..9]` (pass 1, "less skew" step in the original code).
2. `init_keys(password)` again (same initial state!); encrypt the 12-byte header
   `[c1[0..9], (crc>>16)&0xff, (crc>>24)&0xff]` (pass 2) and write it; the entry's
   compressed data continues in the same pass-2 key stream.

Consequences:
- **`stored[0] == r[0]`**: both passes encrypt byte 0 from the same key state, so the
  keystream cancels - every file's first header byte is in the clear.
- The data-decryption key state is `K0` evolved over `c1[0..9]` + the two check bytes.
- `crc` is the entry CRC-32 from the central directory (known). Entries with flag bit 3
  (data descriptor) may carry time-based check bytes instead - treat bytes 10..11 as
  unknown for those entries and verify only bytes 0..9.

### RNG variants

- **MSVC**: `s = s * 214013 + 2531011 (mod 2^32)`, output `(s >> 16) & 0x7fff`
  (Info-ZIP on Windows, WinZip per Stay's paper).
- **WinZip 8**: IBDL32.dll dropped the increment: `s = s * 214013` (FD 2003).

State bit 31 is never observable and never influences bits 0..30 (odd multiplier), so
the effective state is 31 bits. The seed *value* is irrelevant - the state at the first
observed output is recovered by enumeration.

## The attack (per-file data: `r[i][0..9]`, `stored[i][0..11]`, all known after stages 0-1)

Notation: `A0 = crc32(X, 0)`, `C = crc32(Z, 0)`, `K = f14(bits 2..15 of Z)` = the
position-0 keystream (identical for both passes and every file),
`bY = MSB(Y*M)`, `bY2 = MSB(Y*M²)`, `M² = 0xD4652819 mod 2^32` (verified).
`LSB/MSB` = low/high byte. `l1 = LSB(k0 after byte 0)` for a pass.

### Stage 0 - RNG state recovery (seconds)

The first encrypted entry's `stored[0]` gives bits 23..30 of the state `S1` after the
first `rand()` step. Enumerate the low 23 bits (2^23, bit 31 ignored), step the
composed every-10th-output LCG (`S_{10(i-1)+1} = S1 * A10 + C10 mod 2^31`,
`A10 = 214013^10`, `C10 = 2531011·(A10−1)/214013` for MSVC, `0` for WinZip), and match
each subsequent file's `stored[0]`. Score by the longest matching prefix of files
(handles archives appended in later sessions: only a prefix matches). Proceed when at
least 5 files are explained and the candidate count is small (≤ 8; typically 1).
Both RNG variants are tried.

### Stage 1 - 38-bit enumeration, position-1 filters (the dominant cost, ~2^38)

Guesses: `Cv` = bits 2..15 of `C` (14 bits), `K` (8), `a0` = bits 0..7 of `A0` (8),
`bY` (8). Per file `i`:

```
l1_E1 = a0 ^ LSB(T[r[i][0]])
l1_E2 = a0 ^ LSB(T[r[i][0] ^ K])              # pass-2 byte 0 is c1[0] = r[0] ^ K
g1 = MSB(l1_E1 * M + 1);  g2 = MSB(l1_E2 * M + 1)
filter: ∃ carries c1,c2 ∈ {0,1}:        # MSB((Y+l1)*M+1) = bY ^ g ^ carry
  f14(Cv ^ bits2..15(T[bY ^ g1 ^ c1])) ^ f14(Cv ^ bits2..15(T[bY ^ g2 ^ c2]))
    == stored[i][1] ^ r[i][1]
```

Each file passes with probability ≈ 4/256 (net 6 bits). With 5 files, ~2^8 survivors
total (~1 per K value). For every survivor, record the carry choices that passed -
each gives an interval constraint on Y:
`Y ∈ [((m1<<24) − 1)·M⁻¹ − l1, +2^24) mod 2^32` where `m1` is the MSB value.

Implementation: AVX2 (Vector256) over the `bY`/`a0` inner dimensions with arithmetic
`f14` (no table gather needed) and `T` lookups via the 3+3+2-bit split-table
`vpermd` trick already used in `ZipCryptoKernel`; scalar fallback; `Parallel` over
outer (K, Cv) chunks; progress + cancellation. Estimated ~10-60 s on a modern CPU;
worst case a few minutes.

### Stage 2 - 26-bit enumeration per stage-1 survivor, position-2 filters (~2^36 total)

New guesses per survivor: `a1` = bits 8..15 of `A0` (8), `bY2` (8), `Ch` = bits 16..23
of `C` (8), `Cl` = bits 0..1 of `C` (2). Per file and pass (pass-1 byte 1 is `r[i][1]`;
pass-2 byte 1 is `c1[i][1] = r[i][1] ^ s_E1` where `s_E1` = the pass-1 position-1
keystream, known from the stage-1 survivor):

```
k0_1 = A0 ^ T[byte0];  l1 = LSB(k0_1)
k1_1 = (Y + l1)·M + 1  (MSB from stage-1 record: m1 = bY ^ g ^ carry)
k2_1 = C ^ T[m1]
l2 = LSB(crc32(k0_1, byte1))     # needs a0, a1
m2 = MSB(k1_2) = bY2 ^ MSB(l1·M² + (l2+1)·M + 1) ^ carry2   (carry2 ∈ {0,1}, 4 combos)
k2_2 = crc32(k2_1, m2);  bits 2..15 need C bits 0..23 (Cv ∪ Ch ∪ Cl) and T[m1]
filter: f14(k2_2_E1) ^ f14(k2_2_E2) == stored[i][2] ^ r[i][2]
```

~2^6 survivors expected. Record carry2 choices → further Y intervals.

### Stage 3 - recover Z and Y (cheap)

- **Z**: for each of the 2^8 values of `LSB(Z)`: `Z = ((C ^ T[LSB(Z)]) & 0xffffff) << 8
  | LSB(Z)` using C bits 0..23; keep candidates with `f14(bits 2..15 of Z) == K`
  (typically 1-3 survive). With full Z, C is fully known.
- **Y**: intersect the recorded interval constraints (each is a 2^24-length interval
  mod 2^32); the intersection is a small set (~2^8-2^13 candidates, as ranges).
- Guess `a2` = bits 16..23 of `A0` (8 bits); for each (Y-candidate, a2) compute
  position-3 keystreams exactly (no carry guesses remain) and filter on
  `stored[i][3] ^ r[i][3]` across all files → unique (Y, a2).
- Guess `a3` = bits 24..31 of `A0` (8 bits) → full `A0`; recover `X` by CRC inversion:
  find `z` with `(A0 ^ T[z]) >> 24 == 0`, then `X = ((A0 ^ T[z]) << 8) | z` (unique in
  practice; verified).

### Verification (exact, cryptographic)

From `(X, Y, Z)`, re-simulate crypthead for every explained file (pass 1 over `r`,
pass 2 over `[c1, checks]`) and require all 12 stored bytes to match (bytes 10..11
skipped for data-descriptor entries). Then decrypt each classic encrypted entry's data
and verify CRC-32 after decompression for methods 0/8. Only a verified key set is
reported. Keys recovered from the explained files decrypt *all* entries encrypted with
the same password, including files added in later sessions (same password → same
initial state); those are verified per-entry via check bytes/CRC and included if they
pass.

## What the user gets

1. **Keys**: `X, Y, Z` reported (hex), like the existing 40-bit RC4 key search.
2. **Decrypted copy of the archive** written next to the original
   (`<name><DecryptSuffix>.zip`): a minimal ZIP writer re-emits every classic encrypted
   entry with the encryption flag cleared and the 12-byte header dropped (data is
   decrypted with the recovered keys; ZipCrypto is length-preserving, compression
   method and raw compressed bytes are preserved). AES or strong-encryption entries
   are copied through untouched with a note. (AutoDecrypt today is Office-only; this
   feature adds ZIP decryption through the keys path.)
3. **Password, if reachable**: after the Stay step succeeds, the session continues
   with the user's remaining steps unchanged (hashcat 17200/17210 or the built-in CPU
   engine) - if the password is in range it is found and reported as usual. If the
   steps exhaust, the final outcome is `KeyRecovered` (keys + already-delivered
   decrypted copy). No separate equivalent-password search is added: it is exactly as
   expensive as the existing password path and would duplicate it.

## Integration

Calls settled after the builder review (marked **[call]** - maintainer can veto any of them):

- **[call]** The Stay payload includes **every** ZipCrypto entry regardless of compression
  method (the attack only needs the 12 stored header bytes); CRC verification after
  decryption applies to methods 0/8 only, other methods verify by header match alone
  (5 files × 10 bytes is conclusive). The compatibility gate (≥ 5 explained entries)
  counts all ZipCrypto entries.
- **[call]** The archive-level target keeps today's creation rules: a `ZIPC` target still
  requires at least one method-0/8 entry with `CompSize > 12` (the hashcat-verifiable
  entry), and PKWARE strong-encryption entries still abort extraction as today.
  Archives with *zero* 0/8 entries are rare in practice (WinZip ≤ 8 wrote deflate or
  stored; exotic methods arrived with the AES era) - supporting a Stay-only target
  for them is future work, noted below.
- **[call]** Recovered `(X, Y, Z)` are stored in the existing key cache
  (`KeyCache`, keyed by the stable per-archive ZIPC hash line) exactly like RC4 keys -
  the "never in the debug log" policy applies to logs, not the cache. Re-running the
  session hits the cache, skips the D&C, rewrites the decrypted copy if missing, and
  continues to the password steps. Mid-search interruption restarts the Stay step
  from scratch (≈ 1 minute; no checkpoint plumbing).
- **[call]** The decrypted copy is written **unconditionally** when keys are recovered
  (this is the headline deliverable the maintainer asked for: "decrypt too"), not
  gated on the Office-oriented `AutoDecrypt` preference. Naming follows the existing
  pattern (`<name><DecryptSuffix>.zip`); on collision or unwritable directory: skip
  with a log line (never overwrite, never fail the session).
- **[call]** `/a:s` is a first-class, authorable scenario step, and the built-in default
  scenario for `ZIPC` gains it as its first line. There is **no** hidden runtime
  injection beyond that: an explicitly chosen scenario behaves exactly as authored
  (matching the product's scenario philosophy). CLI default step list includes the
  step for compatible targets; `--no-stay` drops it. Wizard offers it as a choice like
  the RC4 key search.

- `AttackKind.StayZip` (scenario switch `/a:s`), mirroring `AttackKind.KeySearch`:
  - `ZipExtractor` additionally collects every classic encrypted entry's 12-byte stored
    header, CRC, flags, method, sizes, name, and local offset (in archive order) into
    a new typed `HashTarget` payload (e.g. `target.StayZip`). The regular `ZIPC` hash
    line is unchanged, so sessions, caching, and the existing attack path keep working.
  - `RecoverySession` special-cases the step (like `KeySearchStepAsync`):
    probe compatibility (stage 0, seconds) → if compatible, run the D&C with progress,
    logging, and cancellation → on success, verify, write the decrypted copy, report
    keys, and continue to the next step (password search). If incompatible or failed,
    log why and continue with the remaining steps - the attack never blocks the
    existing flow.
  - Auto-included as the **first step** of the default scenario for `ZIPC` targets
    with ≥ 5 classic encrypted entries, and offered as a wizard choice
    ("Fast key search - WinZip-style archives") like the RC4 key search. Controlled by
    a Preferences toggle (`TryStayZipAttack`, default on) and excludable per scenario.
  - CLI: `recoverkit-cli attack` includes the step automatically for compatible
    targets; `--no-stay` skips it. Keys print as `KEY: <hex x12>`; the decrypted copy
    path is logged.
- Requirements to run: ≥ 5 classic encrypted entries explained by one RNG chain
  (the paper's requirement; 5 files determine the 31-bit state and filter the D&C).
  Fewer files, non-Info-ZIP RNGs (PKZIP proper, glibc rand, modern tools), or
  archives whose encrypted files came from many sessions → clean "not compatible"
  message, existing attacks continue.

## Non-goals / anti-goals

- No Stay 2020 lattice attack (2-file archives) - out of scope.
- No glibc `rand()`, PKZIP-native RNG, or other PRNG families.
- No Biham-Kocher known-plaintext attack (bkcrack territory; different feature).
- No WinZip AES, no PKWARE strong encryption.
- No GPU kernel for the D&C (CPU + SIMD is fast enough at 2^38).
- No equivalent-password collider step (redundant with the existing 17200 path).
- Never weakens or changes the existing ZIPC attack path; the step is purely additive
  and skippable.
- No Stay-only target for archives with zero method-0/8 entries (see Integration
  calls) - future work if a real archive ever needs it.

## Testing

- A faithful WinZip-8/Info-ZIP archive generator for tests (no public one exists):
  implements crypthead exactly (both RNG variants, chosen seed, chosen session
  splits) + ZipCrypto encryption of stored/deflate entries, producing real ZIP files
  via the existing parsing path.
- Unit tests, per stage, against known intermediates computed from the generator's
  password: cancellation, stage-0 recovery (both variants, appended-session archives,
  wrong-RNG rejection), stage-1/2 filter equations (true values pass; random values
  filtered at the expected rate), Z/Y/X recovery, full verification, decrypted-copy
  writer output (re-openable by System.IO.Compression and content-identical).
- One end-to-end test: 5+ file archive, strong password, full D&C to keys + decrypted
  copy. Budget: < 2 min on CI (Windows/x64 AVX2) and on developer machines; keep the
  suite's total runtime acceptable. If scalar/ARM runs too slow, guard the e2e test on
  SIMD availability (stage-level tests still run everywhere).
- Negative tests: 4-file archive (insufficient), modern-zip archive (Info-ZIP with
  glibc-style headers - mismatched first bytes → no state found), mixed classic+AES.

## Performance notes

Stage 1 dominates at 2^38 candidate-evaluations with early exit after the first file;
AVX2-interleaved like `ZipCryptoKernel.SearchAvx2x3` with multithreading lands in the
tens of seconds; scalar fallback exists for correctness and non-x86 hosts. Stage 2 is
2^36 total; stages 3-4 are negligible. A paper-style optimization (fix K once a
survivor passes stage 2, expected ~¼ of the keyspace) is available if needed but not
required for the budget.

## Constraints

- Windows 10/11 64-bit product; `RecoverKit.Core` is cross-platform .NET 10 (tests run
  on macOS arm64 too - scalar/Vector128 paths must exist even if slow).
- No new NuGet dependencies.
- Recovered keys must never be written to the debug log (repo policy, see NOTICE).
- The UI refactor (Forms → Avalonia Views) is committed on `main` (`04f3ea3`, “Add
  macOS arm64 build with Avalonia GUI”); the feature worktree is cut from updated
  `main` and App-side integration targets the Views UI. The App now builds on
  macOS arm64 as well - SIMD fallbacks must exist for that host.
