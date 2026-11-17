# Office Agile CPU implementation plan

**Goal:** Built-in CPU recovery for Office Agile modes 9500 and 9600 alongside a discrete GPU.

**Architecture:** Share the existing Office 2007 SHA-1 lane functions with a configurable spin count. Reuse the SHA-512 compression for the 68-byte Agile chain. A managed Agile kernel parses hashcat lines, encodes passwords identically to Office 2007, checks AES-CBC verifiers, and independently confirms every native hit.

**Tech stack:** .NET 10, C11, zig cc, existing SIMD and cryptographic primitives.

**Spec:** User request in this session.

## Global constraints

- Work only in this worktree. No commits, pushes or external publication.
- API version 19 in C, managed loading and tests.
- Full 100000-spin known answers guard every accelerated path; failure falls back to scalar.
- Preserve raw candidate bytes and complete hybrid coverage, including resume and dictionaries.
- Unsupported hashcat variants remain eligible for hashcat; default CPU-only execution requires a measured choice.
- ASCII hyphen-minus only in generated text.

## Review focus

- UTF-8 supplementary and hashcat F4 edge encodings, empty and maximum passwords.
- SHA-1 key padding and AES-CBC IV; 16-byte versus 32-byte verifier comparisons.
- Partial SIMD batches, path guards and Office 2007 regressions after sharing spin code.
- GPU hits and potfile hits retain candidate bytes and use independent confirmation.
- Integrated GPU, CPU-only and unsupported format gates never silently remove candidates.

## Tasks

### 1. Native Agile chains

- [x] Add independent Python full-spin known answers before implementing native code.
- [x] Parameterize Office 2007 SHA-1 iteration functions without copying their lane code.
- [x] Add Agile SHA-1/SHA-512 spin, path, lane, guard and observed-path exports, mode argument 9500/9600.
- [x] Reuse existing SHA-512 compression for scalar, AVX2, AVX-512, NEON and ARM SHA-512.
- [x] Build both targets and compare native output with Python known answers.

### 2. Managed Agile kernel

- [x] Add failing registration/known-answer tests.
- [x] Share Office 2007 UTF-8 encoder; implement OfficeAgileKernel.TryParse, Verify, SpinManaged and native filter.
- [x] Bind native exports in RkNative and register both modes, benchmark hashes and diagnostic state.
- [x] Compare all locally executable native paths to independent .NET reference, including partial batches.

### 3. Hybrid and diagnostic plumbing

- [x] Extend Office 2007 gates to Agile in planning, probing, profile application and detailed benchmarks.
- [x] Extend byte preservation and independent confirmation to CPU/GPU recovery and caches.
- [x] Register diagnostic path selectors, workers, wide checks and CLI bench-native output.
- [x] Update preferences, README, developer documentation and changelog.
- [x] Exercise hybrid partition, dictionary and resume behavior using existing Office test patterns.

### 4. Fixtures, integration and verification

- [x] Generate deterministic hashlib/cryptography vectors and obtain independent encrypted fixtures.
- [x] Test examples, Unicode, boundaries, malformed lines, supported variants and opt-in hashcat recovery.
- [x] Run native/build.sh, release solution build and full test suite; record failures and skips.
- [x] Measure both modes for each available path/thread count, three runs with medians; GPU context.
- [x] Record measurements and PowerShell reproduction commands in docs/benchmarks/office-agile-cpu.txt.
- [x] Review full diff against the request and leave all changes uncommitted.
