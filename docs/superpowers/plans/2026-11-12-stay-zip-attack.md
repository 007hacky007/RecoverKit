# Stay's ZipCrypto Header-RNG Attack — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Stay's 2001 header-RNG attack as an optional, automatically-included first step that recovers ZipCrypto internal keys (and a decrypted archive copy) for WinZip-8/Info-ZIP-style archives, then falls through to the user's normal password steps.

**Architecture:** New `RecoverKit.Core.Attacks.Stay` pipeline: stage 0 recovers the MSVC/WinZip `rand()` state from the clear first header bytes of ≥5 encrypted entries; stages 1–3 are Stay's parallel divide-and-conquer over the doubly-encrypted 12-byte headers (SIMD + multithreaded); exact re-simulation verifies the keys; a minimal ZIP writer emits a decrypted copy. `ZipExtractor` additionally collects every classic entry's stored header into `HashTarget.StayZip`; `RecoverySession` special-cases the new `AttackKind.StayZip` step like the RC4 key search.

**Tech Stack:** .NET 10, C# with `System.Runtime.Intrinsics.X86` AVX2 (scalar fallback for arm64), xUnit. No new NuGet packages.

**Spec:** `docs/superpowers/specs/2026-11-12-stay-zip-attack-design.md` — the attack equations there were validated numerically against a faithful Python simulation of Info-ZIP `crypthead`; implement them verbatim. Executor must read the spec's "The attack" section before Tasks 4–6.

## Global Constraints

- No new NuGet dependencies; `RecoverKit.Core` stays plain cross-platform .NET 10.
- Recovered keys must never be written to the debug log (repo policy, `NOTICE`); the key cache is allowed.
- Cipher constants, exactly: `M = 0x08088405`, CRC-32 table poly `0xEDB88320`, keystream `t=(k2&0xffff)|2; ((t*(t^1))>>8)&0xff`, RNG `214013 (+2531011 for MSVC variant)`, `M² = 0xD4652819`, MSVC output `(s>>16)&0x7fff`, header byte `(rand()>>7)&0xff`.
- Attack requires ≥ 5 ZipCrypto entries explained by one RNG chain; proceed only when stage-0 yields ≤ 8 candidate states.
- The existing ZIPC hashcat path must not change behavior; the Stay step is purely additive, skippable, and logs-and-continues on any incompatibility.
- Work happens in `worktrees/stay-zip-attack` (branch `feat/stay-zip-attack`); every task ends with a commit there.
- Baseline before Task 1: `sh native/build.sh && dotnet build RecoverKit.sln -c Release && dotnet test tests/RecoverKit.Tests -c Release` (currently 176/176 passing).

## Review Focus

Each line names an input class the spec implies but no ordinary test exercises; the owning task's test pins it.

1. **Archives appended across sessions** (only a prefix of entries shares the RNG chain; later entries may even use a different password) — attack must explain the prefix, and the decrypted copy must carry entries that verify and pass through (still encrypted) entries that don't. → Task 7 test `Decryptor_skips_entries_that_fail_verification`.
2. **Data-descriptor entries (flag bit 3)** — check bytes are time-based/unknown: header verification uses bytes 0–9 only; the decrypted copy clears flag bit 3 and drops the trailing descriptor. → Task 7 test `Decryptor_handles_data_descriptor_entries`.
3. **Non-0/8 compression methods in the payload** (e.g. method 12) — participate in stage 0 and header verification, skip CRC verification, still decrypt into the copy. → Task 2 test `Payload_includes_exotic_method_entries` and Task 7 assertion in the mixed-methods test.
4. **Corrupt/truncated entries** (`CompSize < 12`, truncated data) — payload collection skips them; if < 5 usable entries remain, the attack reports incompatible without throwing. → Task 2 test `Payload_skips_entries_with_short_headers` and Task 6 test `Run_returns_null_for_truncated_archive`.
5. **Correlated filters** (two files whose first RNG byte coincides) — filters share `r[i][0]`-derived constants and must not reject the true guess. → Task 4 test `Filter_accepts_true_guess_when_files_share_first_byte`.

---

### Task 1: Faithful WinZip-8/Info-ZIP test-archive generator

**Files:**
- Create: `tests/RecoverKit.Tests/Stay/ZipStayArchive.cs` (generator + independent decrypt oracle, test-internal)

**Interfaces:**
- Produces: `static GeneratedZip Generate(IReadOnlyList<GeneratedEntry> entries, string password, ZipRngVariant variant, uint seed, int filesInFirstSession = int.MaxValue)`
  with `GeneratedEntry { string Name; byte[] Content; int Method; bool DataDescriptor; bool Classic = true }` (method 0 or 8; `DataDescriptor` sets flag bit 3),
  `GeneratedZip { byte[] Archive; uint X, Y, Z; byte[][] R; byte[][] StoredHeaders; string[] Names; int SessionFileCount; ZipRngVariant Variant; uint Seed }`.
  `ZipRngVariant` comes from Task 3 — until then declare it locally as `public enum TestRngVariant { Msvc, WinZip }` and switch Task 3 to consume it (move the enum into Core in Task 3, keep the test alias).
- The generator writes a minimal ZIP by hand (local header, data, optional 8-byte data descriptor, central directory, EOCD), following Info-ZIP `crypthead` exactly: `srand(seed)` once, 10 `rand()` calls per file in archive order (only for files in the first session — later-session entries get bytes from a second, independently seeded sequence), pass 1 over the 10 random bytes, keys reset, pass 2 over `[c1, (crc>>16)&0xff, (crc>>24)&0xff]` (time bytes for `DataDescriptor` entries), then the compressed data in the pass-2 stream. Deflate via `DeflateStream` (raw compressed bytes computed before encryption).
- The decrypt oracle is an independent 25-line cipher implementation in the test file (from the spec pseudocode), used by later tasks to verify production code.

- [ ] **Step 1: Write failing tests** in `tests/RecoverKit.Tests/Stay/ZipStayArchiveTests.cs`:
  - `Generated_archive_round_trips_through_oracle`: 5 stored entries, MSVC variant, fixed seed/password; oracle-decrypt each entry (drop 12-byte header, inflate when method 8) → contents equal; CRCs match central directory values the generator wrote.
  - `First_stored_byte_equals_first_random_byte`: for every file `StoredHeaders[i][0] == R[i][0]` (the double-encryption cancellation).
  - `Random_bytes_match_direct_lcg_computation`: recompute `r` from `seed` with the spec's LCG formulas in the test → equals `R`.
  - `WinZip_variant_differs_from_msvc`: same seed, both variants → different `R`.
- [ ] **Step 2: Run** `dotnet test tests/RecoverKit.Tests -c Release --filter Stay` → fails, types missing.
- [ ] **Step 3: Implement** the generator + oracle in `ZipStayArchive.cs`.
- [ ] **Step 4: Run** → all Stay tests pass; full suite still 176 + new passing.
- [ ] **Step 5: Commit** `feat: add faithful WinZip-8-style encrypted ZIP generator for tests`.

### Task 2: Stay payload collected by ZipExtractor

**Files:**
- Create: `src/RecoverKit.Core/Formats/ZipStayTarget.cs`
- Modify: `src/RecoverKit.Core/Formats/HashTarget.cs` (add `public ZipStayTarget? StayZip { get; init; }`)
- Modify: `src/RecoverKit.Core/Formats/ZipExtractor.cs` (populate in `Extract`/`Pkzip`)
- Test: `tests/RecoverKit.Tests/Stay/ZipStayTargetTests.cs`

**Interfaces:**
- `ZipStayTarget { public required IReadOnlyList<ZipStayEntry> Entries { get; init; } }`
  (archive/local-offset order, every entry with flag bit 0 set, no AES extra field, `CompSize >= 12`, method any).
- `ZipStayEntry { required string Name; required byte[] StoredHeader (12); uint Crc; ushort Flags; ushort Method; long CompSize; long UncompSize; long LocalOffset; }`
  plus `bool HasCrcCheckBytes => (Flags & 8) == 0`.
- Populate on every `ZIPC` target (also keep a payload when the archive has ≥ 2 such entries even if the single hashcat entry is chosen as today; do not create a target where none exists today).
- Consumes: Task 1's `GeneratedZip` for test inputs (write to temp file, `ZipExtractor.Extract`).

- [ ] **Step 1: Failing tests**: `Payload_matches_generator_records` (entry order, names, stored headers, crc, flags, sizes for a mixed stored/deflate 5-file archive); `Payload_includes_exotic_method_entries` (one entry with method 12 and garbage compressed bytes — payload includes it; note the ZIPC hash line is built from a 0/8 entry as today); `Payload_skips_entries_with_short_headers` (an entry with `CompSize < 12` excluded; if ≥ 1 valid 0/8 entry remains, target still exists); `Payload_absent_for_odf_and_aes_archives`.
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement** (private helpers in ZipExtractor; reuse `ReadEntryData` to fetch the 12 header bytes).
- [ ] **Step 4: Run** → pass, suite green.
- [ ] **Step 5: Commit** `feat: collect ZipCrypto header data for the Stay attack`.

### Task 3: RNG state recovery (stage 0)

**Files:**
- Create: `src/RecoverKit.Core/Attacks/Stay/ZipRng.cs`
- Move/adjust Task 1's local variant enum to `RecoverKit.Core.Attacks.Stay.ZipRngVariant { Msvc, WinZip }` (test file aliases or switches to it).
- Test: `tests/RecoverKit.Tests/Stay/ZipRngTests.cs`

**Interfaces:**
- `public static class ZipRng`:
  - `public const int CallsPerFile = 10;`
  - `public static byte NextByte(ref uint state, ZipRngVariant v)` (advances one `rand()` step, returns `(s>>23)&0xff`, arithmetic mod 2^31 — bit 31 unobservable).
  - `public static List<ZipRngSolution> RecoverStates(IReadOnlyList<byte> firstBytes, ZipRngVariant v, int minMatched)` — enumerates the 2^23 low bits (bits 23..30 fixed by `firstBytes[0]`), composed 10-step LCG (`A10 = 214013^10`, `C10 = 2531011*(A10-1)/214013` for MSVC, 0 for WinZip, all mod 2^31), returns every state whose matched **prefix** length ≥ `minMatched`, ordered by matched length desc.
  - `public static byte[][] RandomHeaders(uint state, ZipRngVariant v, int fileCount)` — `r[i][0..9]` for consecutive files.
  - `public sealed record ZipRngSolution(ZipRngVariant Variant, uint State, int MatchedFiles);`
- Perf: the enumeration must early-exit per state after the first mismatch; 2^23 × ~2 steps ≈ well under a second. If too slow in tests, compute file-1 and file-2 constraints in a first pass (filter 2^23 → ~2^15) before full prefix matching.

- [ ] **Step 1: Failing tests**: `Recovers_unique_state_for_msvc` (5 files → exactly the generator's post-first-step state; assert also via `RandomHeaders` == generator `R`); `Recovers_winzip_variant`; `Explains_prefix_of_appended_archive` (7 files, 5 in first session → one solution with `MatchedFiles == 5`); `Returns_none_for_random_headers` (uniform random first bytes → empty at `minMatched: 5`); `Four_files_leave_candidates` (4 files, MSVC → more than 8 solutions at `minMatched: 4`, documenting why 5 is the gate).
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → pass.
- [ ] **Step 5: Commit** `feat: add MSVC/WinZip rand state recovery for Stay attack`.

### Task 4: Stage 1 — position-1 filter and 38-bit search

**Files:**
- Create: `src/RecoverKit.Core/Attacks/Stay/StaySearch.cs` (data types + filter + scalar and AVX2 searches)
- Test: `tests/RecoverKit.Tests/Stay/StayStage1Tests.cs`

**Interfaces:**
- `internal sealed class StayFileData { required byte[] R (10); required byte[] Stored (12); }` (internal, same assembly — tests use `InternalsVisibleTo` if present; if not, add `[assembly: InternalsVisibleTo("RecoverKit.Tests")]` to `RecoverKit.Core` — check whether it already exists for the native engine tests and follow that pattern).
- `internal static class StayStage1`:
  - `public static bool FilterPasses(in StayFileData f, uint cv, byte k, byte a0, byte bY)` — spec stage-1 equation: `∃ carries c1,c2 ∈ {0,1}` with `f14(cv ^ bits2_15(T[bY ^ g1 ^ c1])) ^ f14(cv ^ bits2_15(T[bY ^ g2 ^ c2])) == f.Stored[1] ^ f.R[1]`, `l1_E1 = a0 ^ LSB(T[R[0]])`, `l1_E2 = a0 ^ LSB(T[R[0] ^ k])`, `g = MSB(l*M + 1)`.
  - `public static List<Stage1Survivor> Search(IReadOnlyList<StayFileData> files, CancellationToken ct, Action<double, long>? progress)` — full 2^38 enumeration (`cv` 14 bits, `k` 8, `a0` 8, `bY` 8), early exit per file, AVX2 over `bY` lanes when `Avx2.IsSupported`, scalar otherwise, `Parallel` over `(k, cv)` chunks ordered so progress is meaningful; returns survivors (~2^8 expected with 5 files).
  - `internal sealed class Stage1Survivor { uint Cv; byte K; byte A0; byte BY; per-file chosen (m1e1, m1e2) pairs incl. all passing carry combos; Y-interval constraints }` — exact internal shape is the implementer's; later tasks consume it only through Task 5's stage-2 entry point.
- Produces for Task 5: `Search` result consumed by `StayStage2.Search(survivors, files, ct, progress)`.

- [ ] **Step 1: Failing tests** (true intermediates computed in-test from the generator's password via the Task 1 oracle: `A0 = crc32(X,0)`, `C = crc32(Z,0)`, `cv = (C>>2)&0x3fff`, `k = keystream(Z)`, `a0 = A0&0xff`, `bY = MSB(Y*M)`):
  - `Filter_accepts_true_guess_all_files` (all 5 files pass).
  - `Filter_rejects_random_guesses` (10k random guesses → pass count consistent with ~4/256 per file; assert < 1% pass file 1 alone and 0 pass all 5).
  - `Filter_accepts_true_guess_when_files_share_first_byte` (scan seeds until two files share `R[i][0]`, regenerate, true guess still passes all files).
  - `Scalar_and_avx2_agree_on_subrange` (restrict both searches to a fixed `(k, cv)` window containing the truth plus 2^16 random windows — expose an optional range parameter on `Search` for this; survivor sets identical; skip AVX2 part on non-x86).
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement** (scalar first, then AVX2 following `ZipCryptoKernel` idioms: split-table `vpermd` CRC lookups, arithmetic `f14`).
- [ ] **Step 4: Run** → pass. Also run one full `Search` on the 5-file generator archive inside `Search_finds_true_guess_in_full_keyspace` and assert the true `(cv, k, a0, bY)` is among the survivors and total survivors ≤ 2^10 — this is the plan's stage-1 integration test; budget ~2 min scalar / ~30 s AVX2 locally. If it blows the budget, keep it but mark `[Trait("Category","Slow")]` and confirm CI time stays acceptable.
- [ ] **Step 5: Commit** `feat: add Stay attack stage-1 parallel divide-and-conquer search`.

### Task 5: Stage 2 — position-2 filter, per-survivor refinement

**Files:**
- Modify: `src/RecoverKit.Core/Attacks/Stay/StaySearch.cs`
- Test: `tests/RecoverKit.Tests/Stay/StayStage2Tests.cs`

**Interfaces:**
- `internal static class StayStage2`:
  - `public static List<Stage2Survivor> Search(IReadOnlyList<Stage1Survivor> stage1, IReadOnlyList<StayFileData> files, CancellationToken ct, Action<double, long>? progress)` — per survivor, 26-bit enumeration (`a1` bits 8–15 of `A0`, `bY2 = MSB(Y*M²)`, `Ch` bits 16–23 of `C`, `Cl` bits 0–1 of `C`), spec stage-2 equations with 4 carry combos per file, early exit; appends Y-interval constraints from chosen carries.
  - `Stage2Survivor` carries everything Task 6 needs: full `A0` bits 0–15, `C` bits 0–23, `K`, per-file `m1`/`m2` records, Y-intervals.
- Consumes: `Stage1Survivor` from Task 4.

- [ ] **Step 1: Failing tests** (true values: `a1 = (A0>>8)&0xff`, `bY2 = MSB(Y*M²)`, `Ch = (C>>16)&0xff`, `Cl = C&3`; construct a `Stage1Survivor` directly from true values):
  - `Filter_accepts_true_guess_all_files` (spec equations, both passes, pass-2 byte 1 = `R[1] ^ s_E1` with `s_E1` the pass-1 position-1 keystream).
  - `Y_intervals_contain_true_value` (intersection of the survivor's interval constraints contains `Y` and has < 2^16 measure).
  - `Search_refines_true_stage1_survivor` (single true stage-1 survivor → the true 26-bit guess is among stage-2 survivors; expected count ≤ 2^8).
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement** (scalar is fine — 2^36 total with early exits; vectorize only if the e2e budget demands it).
- [ ] **Step 4: Run** → pass.
- [ ] **Step 5: Commit** `feat: add Stay attack stage-2 refinement`.

### Task 6: Stage 3, verification, and the public attack entry point

**Files:**
- Create: `src/RecoverKit.Core/Attacks/Stay/StayAttack.cs`
- Modify: `src/RecoverKit.Core/Attacks/Stay/StaySearch.cs` (add stage 3 next to stages 1–2, or a `StayStage3` class in the same file)
- Test: `tests/RecoverKit.Tests/Stay/StayAttackTests.cs`

**Interfaces:**
- `public sealed record ZipStayKeys(uint X, uint Y, uint Z) { public string Hex => $"{X:x8}{Y:x8}{Z:x8}"; }`
- `public sealed record StayResult(ZipStayKeys Keys, ZipRngVariant Variant, int ExplainedFiles);`
- `public static class StayAttack`:
  - `public const int MinimumFiles = 5;`
  - `public static bool Supports(HashTarget t)` → `t.FormatId == "ZIPC" && t.StayZip?.Entries.Count >= MinimumFiles`.
  - `public static ZipRngSolution? Probe(ZipStayTarget t)` — both variants, `minMatched: 5`, ≤ 8 candidates, best first.
  - `public static Task<StayResult?> RunAsync(ZipStayTarget t, CancellationToken ct, Action<LogKind, string>? log = null, Action<double, long>? progress = null)` — probe → `r` bytes → stages 1–3 → `VerifyKeys` → result; null (with log lines) when incompatible or nothing verified.
  - `public static bool VerifyKeys(ZipStayTarget t, ZipStayKeys keys, byte[][] r, int[] fileIndices)` — exact re-simulation of crypthead per file, all 12 stored bytes (bytes 10–11 skipped for `!HasCrcCheckBytes`); then decrypt + CRC-32 check for method 0/8 entries (inflate via `DeflateStream`); all indexed files must pass.
  - Stage 3 internals: Z candidates from `C` bits 0–23 + `k` (256 `LSB(Z)` guesses, keep `keystream(Z)==k`); Y from interval intersection (as ranges mod 2^32, expanded lazily); `a2` (bits 16–23 of `A0`) + position-3 exact filters; `a3` (bits 24–31) + position-4/check-byte filters; `X` by CRC inversion (`z` with `(A0^T[z])>>24 == 0`, `X = ((A0^T[z])<<8)|z`).

- [ ] **Step 1: Failing tests**:
  - `Stage3_recovers_exact_keys_from_true_survivor` (construct true `Stage2Survivor` → keys equal generator's `X, Y, Z`).
  - `VerifyKeys_accepts_true_and_rejects_corrupted` (flip one stored byte → false; wrong check-byte entry with flag 3 → still true when bytes 0–9 match).
  - `Run_recovers_keys_end_to_end` (5-file archive, password `"&THPOL101%ISLAME@|1"`-style strong password, MSVC variant → `StayResult` keys equal generator's; full pipeline; budget ≤ ~3 min local — this is the headline e2e test).
  - `Run_recovers_keys_winzip_variant` (WinZip variant archive).
  - `Run_explains_prefix_and_verifies_all_matched` (7-file, 5-session archive → `ExplainedFiles == 5`, keys still correct).
  - `Run_returns_null_for_incompatible` (4 files; random-header archive; `Run_returns_null_for_truncated_archive` — archive with < 5 valid entries).
  - `Run_reports_progress_and_cancels` (progress callback receives increasing fractions; cancelling the token mid-stage-1 makes `RunAsync` return null or throw `OperationCanceledException` — pick one and assert it; the session maps it to "stopped").
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement** (wire stages; log stage transitions and throttled speed lines via `log`).
- [ ] **Step 4: Run** → pass, full suite green; note total suite time (keep the two full-D&C e2e tests under ~6 min combined on this machine; optimize stage 1 AVX2 if needed).
- [ ] **Step 5: Commit** `feat: add complete Stay attack with verification`.

### Task 7: Decryption and the password-free archive copy

**Files:**
- Create: `src/RecoverKit.Core/Formats/ZipStayDecryptor.cs`
- Test: `tests/RecoverKit.Tests/Stay/ZipStayDecryptorTests.cs`

**Interfaces:**
- `public static class ZipStayDecryptor`:
  - `public static byte[] DecryptEntry(byte[] dataWithHeader, ZipStayKeys keys)` — init from keys, drop the 12-byte header, decrypt the body (used for verification too, if convenient).
  - `public static string WriteDecryptedCopy(string archivePath, ZipStayTarget target, ZipStayKeys keys, string outputPath)` — reads the original file stream, writes a new ZIP: every classic encrypted entry re-emitted with flag bit 0 cleared (and bit 3 cleared + trailing data descriptor dropped when present), the 12-byte header removed, raw decrypted compressed bytes and method preserved, local offsets rebuilt, central directory + EOCD rebuilt; AES or non-classic encrypted entries copied through untouched (still encrypted); entries whose decrypted check byte/CRC fail are copied through still encrypted (Review Focus 1). Returns `outputPath`; throws `IOException`/`FormatException` on hard failures (caller logs).
- Consumes: `ZipStayKeys`, `ZipStayTarget`/`ZipStayEntry` (Task 2), `GeneratedZip` (Task 1) for tests.

- [ ] **Step 1: Failing tests**:
  - `Copy_opens_without_password_and_contents_match` (mixed stored/deflate/method-12 archive → `System.IO.Compression.ZipFile.OpenRead` reads all entries, 0/8 contents equal generator inputs, method-12 entry's bytes equal the generator's raw compressed input).
  - `Decryptor_skips_entries_that_fail_verification` (appended-session file with a different password → present in the copy but still encrypted, flag bit set).
  - `Decryptor_handles_data_descriptor_entries` (flag-3 entry: copy clears bit 3, drops descriptor, data correct; `ZipFile.OpenRead` accepts it).
  - `Decryptor_passes_aes_entries_through` (classic + AES-entry archive → AES entry byte-identical and still flagged encrypted).
  - `Copy_rejects_existing_output_file` (calling with an existing `outputPath` overwrites — assert the caller-side existence check instead: document via a `ComputeOutputPath`-style helper `public static string OutputPathFor(string archivePath, Settings s)`; test it).
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement** (reuse `ZipExtractor`'s parsing via the `ZipStayTarget` records + `Bin.ReadAt`; write local headers 30 + name + data, central dir, EOCD — mirror the generator's structure).
- [ ] **Step 4: Run** → pass.
- [ ] **Step 5: Commit** `feat: decrypt ZipCrypto archives with recovered keys`.

### Task 8: Attack kind, planner, scenarios, settings

**Files:**
- Modify: `src/RecoverKit.Core/Attacks/AttackSpec.cs` (`AttackKind.StayZip`, `Describe` line "Fast key search: Stay attack on ZipCrypto headers (WinZip-style archives, 5+ files)")
- Modify: `src/RecoverKit.Core/Attacks/AttackPlanner.cs` (`AttackKind.StayZip => StayZipPlanner.Prepare(a, target)`)
- Create: `src/RecoverKit.Core/Attacks/Stay/StayZipPlanner.cs` (`Prepare` throws `AttackPlanException("The fast key search applies only to ZIP archives with five or more ZipCrypto-encrypted files.")` unless `StayAttack.Supports(target)`; returns `PreparedAttack { Description = a.Describe(), Keyspace = 1L<<38 }`)
- Modify: `src/RecoverKit.Core/Attacks/Scenarios.cs` (`"s" => AttackKind.StayZip` in the `/a:` switch + doc comment)
- Modify: `src/RecoverKit.Core/Attacks/DefaultScenarios.txt` (new first-class block `ZIP archives (ZipCrypto)` with `DefaultFor: ZIPC`, first line `/a:s`, then the exact step list currently in "Fast formats: ZipCrypto, PDF R2-R5"; remove `ZIPC` from that block's format line)
- Modify: `src/RecoverKit.Core/Settings.cs` (`public bool TryStayZipAttack { get; set; } = true;`)
- Test: extend `tests/RecoverKit.Tests/GapFeatureTests.cs` (or new `StayZipFeatureTests.cs`)

- [ ] **Step 1: Failing tests**: `/a:s` parses to `AttackKind.StayZip`; planner throws for a `PDF2` target and for a `ZIPC` target with 3 entries, prepares for a 5-entry `ZIPC` target with `StayZip` payload; the default-scenario list has a `DefaultFor: ZIPC` block whose first step is `StayZip`; `Describe()` returns the copy above; `new Settings().TryStayZipAttack` is true.
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → pass.
- [ ] **Step 5: Commit** `feat: add StayZip attack kind, scenario switch, and default scenario`.

### Task 9: Session integration, key cache, CLI

**Files:**
- Create: `src/RecoverKit.Core/Attacks/Stay/StayZipStep.cs` (hashcat-free core of the step, unit-testable)
- Modify: `src/RecoverKit.Core/RecoverySession.cs` (special-case `AttackKind.StayZip` in `RunAsync`, like `KeySearchStepAsync`; carry stay keys to the final result)
- Modify: `src/RecoverKit.Cli/Program.cs` (`--no-stay` filters `StayZip` steps out of any built list; result printing already emits `KEY:`; decrypted-copy path arrives via session log lines)
- Test: `tests/RecoverKit.Tests/Stay/StayZipStepTests.cs`

**Interfaces:**
- `public sealed class StayZipStep` (static):
  - `public static StayStepOutcome Run(HashTarget target, string filePath, Settings settings, Action<LogKind, string> log, CancellationToken ct)` where `StayStepOutcome { ZipStayKeys? Keys; string? DecryptedCopy; bool Incompatible; }`: key-cache lookup on the ZIPC hash line → `StayAttack.RunAsync` → `KeyCache.Store` → existence-checked `ZipStayDecryptor.WriteDecryptedCopy` to `ZipStayDecryptor.OutputPathFor(filePath, settings)` (skip + log when the file exists; log the path on success; never write keys to `DebugLog`).
- `RecoverySession`: `StayZipStepAsync`-equivalent inline — on success logs keys recovered (not the key value itself into DebugLog), keeps `string? stayKeysHex` for the session result, continues to the next step; final `NotFound` becomes `SessionOutcome.KeyRecovered { Key = stayKeysHex, ... }` when set; `Found` results carry `Key` too. Steps are skipped with an info log when `!settings.TryStayZipAttack`. Cancellation maps to `SessionOutcome.Stopped`.
- `SessionResult`: add `public string? DecryptedCopy { get; init; }`.

- [ ] **Step 1: Failing tests** (run `StayZipStep.Run` directly on temp-file archives — no hashcat involved; use `Settings` with a temp `AppDataDir`… follow how existing tests isolate settings, e.g. `ScenarioTests`):
  - `Step_recovers_caches_and_decrypts` (5-file archive → keys + copy path exists and opens; second run hits the key cache — assert via log line and no progress callbacks).
  - `Step_incompatible_archive_continues` (`Incompatible == true`, no exception, log contains "not compatible").
  - `Step_skips_copy_when_output_exists` (pre-create the output path → no overwrite, `DecryptedCopy == null`, log mentions it).
  - `Step_respects_disabled_setting` is a RecoverySession concern — assert instead via the `RunAsync` skip logic with a minimal stub: if constructing `RecoverySession` without hashcat proves impossible, cover the toggle in the App/CLI smoke (Task 10) and note it here.
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → pass; `dotnet build RecoverKit.sln -c Release` clean.
- [ ] **Step 5: Commit** `feat: wire Stay attack into recovery sessions and CLI`.

### Task 10: App integration, docs, final verification

**Files:**
- Modify: `src/RecoverKit.App/Views/WizardWindow.cs` (`Choice.Stay`; radio "Fast key search (recovers keys without the password — WinZip-style ZIPs)" when `StayAttack.Supports(_target)`; `NextAsync` case adds the step)
- Modify: `src/RecoverKit.App/Views/PreferencesWindow.cs` (Key search tab checkbox "Try the fast ZIP key search (WinZip-style archives)" → `TryStayZipAttack`)
- Modify: `src/RecoverKit.App/Views/MainWindow.cs` (`KeyRecovered` case: when `result.DecryptedCopy` is set show "Archive decrypted to: <path>" with the existing link pattern, and ZIP-specific copy for the keys line; keep the Office text for RC4)
- Modify: `README.md` (ZIP row / features: one sentence about the fast key search for WinZip-style archives) and `NOTICE` (credit Stay's paper, the 2003 Full Disclosure post, Info-ZIP crypt.c as the reference for header generation)

**Interfaces:** consumes `StayAttack.Supports`, `SessionResult.DecryptedCopy`, `Settings.TryStayZipAttack`. No new logic in the App layer.

- [ ] **Step 1: Build check** `dotnet build RecoverKit.sln -c Release` → clean (App compiles on macOS arm64).
- [ ] **Step 2: CLI smoke** — `dotnet run --project src/RecoverKit.Cli -c Release -- attack <generated 5-file archive> --default-scenario` with a temp settings dir (no hashcat present is fine if a dictionary-free path exists — otherwise use `--scenario "ZIP archives (ZipCrypto)"` and confirm the Stay step's log lines and `KEY:` output appear before any hashcat-dependent step fails cleanly).
- [ ] **Step 3: Full suite** `dotnet test tests/RecoverKit.Tests -c Release` → all green; note the new total and suite duration.
- [ ] **Step 4: Commit** `feat: expose Stay attack in the GUI and docs`.

## Self-review notes

- Spec coverage: stages 0–3 (Tasks 3–6), verification (6), decrypted copy (7), optionality surface — scenario/planner/settings (8), session/cache/CLI (9), GUI (10), testing strategy incl. faithful generator (1) — all spec sections map to tasks. Deliverable "password if possible" = unchanged continuation of remaining steps (Task 9 wiring), keys + decrypted copy on exhaust (Task 9).
- The two full-D&C e2e tests (Tasks 4 and 6) dominate suite time; they are the feature's proof and stay, with `[Trait("Category","Slow")]` available if CI needs filtering.
- Attack-internal record shapes (`Stage1Survivor`, `Stage2Survivor`) are deliberately left to the implementer — the spec's equations plus the test-constructed "true survivor" fixtures pin their required content.
