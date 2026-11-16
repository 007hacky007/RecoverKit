using System.Collections.Concurrent;
using System.IO.Compression;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Attacks.Stay;

/// <summary>The three internal cipher keys of a ZipCrypto stream (as initialized by the password).</summary>
public readonly record struct ZipStayKeys(uint X, uint Y, uint Z);

/// <summary>Outcome of Stay's header-RNG attack on a ZIP archive.</summary>
public sealed record StayResult(ZipStayKeys Keys, ZipRngVariant Variant, int ExplainedFiles);

/// <summary>
/// Stay's attack on weak-RNG ZipCrypto encryption headers ("ZIP Attacks with Reduced Known Plaintext",
/// FSE 2001). For archives whose zipper seeded the 12-byte headers with MSVC rand() (WinZip ≤ 8 and
/// other Info-ZIP-derived zippers), the internal keys (X, Y, Z) are recovered without any plaintext
/// or password guessing: stage 0 recovers the RNG state, then a divide-and-conquer search over the
/// carry structure of the cipher recovers the keys. Requires ≥ 5 entries encrypted in one process.
/// </summary>
public static class StayAttack
{
    private const int MinFiles = 5;
    private const int HeaderLength = 12;

    /// <summary>The design's stage-0 gate: proceed only when few RNG chains explain the headers.</summary>
    private const int MaxRngCandidates = 8;

    /// <summary>Whether the payload has enough entries for the attack to apply at all.</summary>
    public static bool Supports(ZipStayTarget target) => target.Entries.Count >= MinFiles;

    /// <summary>
    /// Runs the full attack. Returns the first key set that survives exact verification, or null
    /// when no variant's RNG chain explains the headers. When <paramref name="archivePath"/> is
    /// given, candidates are also verified against the decrypted entry data and CRC.
    /// The progress callback is invoked serialized (under a lock) with a non-decreasing value in [0, 1].
    /// </summary>
    public static async Task<StayResult?> RunAsync(ZipStayTarget target, CancellationToken ct,
        Action<double, long>? progress = null, string? archivePath = null)
    {
        if (!Supports(target)) return null;

        double reported = 0;
        object progressGate = new();
        void Report(double fraction, long work)
        {
            if (progress is null) return;
            lock (progressGate)
            {
                reported = Math.Max(reported, fraction);
                progress.Invoke(reported, work);
            }
        }

        foreach (var variant in Enum.GetValues<ZipRngVariant>())
        {
            foreach (var (solution, r) in Probe(target, variant))
            {
            var indices = Enumerable.Range(0, solution.MatchedFiles).ToArray();
            var files = indices.Select(i => new StayFileData { R = r[i], Stored = target.Entries[i].StoredHeader }).ToList();

            var stage1 = StayStage1.Search(files, ct, (f, w) => Report(0.50 * f, w));
            var stage2 = StayStage2.Search(stage1, files, ct, (f, w) => Report(0.50 + 0.25 * f, w));

            Report(0.75, 0);
            var candidates = new ConcurrentQueue<ZipStayKeys>();
            try
            {
                Parallel.ForEach(stage2, new ParallelOptions { CancellationToken = ct },
                    s2 =>
                    {
                        foreach (var keys in StayStage3.RecoverKeys(s2, files, ct))
                            candidates.Enqueue(keys);
                    });
            }
            catch (AggregateException agg) when (agg.InnerExceptions.All(e => e is OperationCanceledException))
            {
                throw new OperationCanceledException(ct);
            }

            foreach (var keys in candidates)
            {
                ct.ThrowIfCancellationRequested();
                if (VerifyKeys(target, keys, r, indices, archivePath))
                    return new StayResult(keys, variant, solution.MatchedFiles);
            }
            }
        }

        Report(1.0, 0);
        return null;
    }

    /// <summary>
    /// Stage 0: every RNG chain of this variant that explains the stored headers' first bytes,
    /// each with the full list of implied random headers in archive order. Empty when no chain
    /// matches; more than <see cref="MaxRngCandidates"/> co-equal chains is treated as no match
    /// (the design's gate against wasting the search on a well-distributed RNG).
    /// </summary>
    public static IReadOnlyList<(ZipRngSolution Solution, byte[][] Headers)> Probe(ZipStayTarget target, ZipRngVariant variant)
    {
        var firstBytes = target.Entries.Select(e => e.StoredHeader[0]).ToList();
        var solutions = ZipRng.RecoverStates(firstBytes, variant, MinFiles);
        if (solutions.Count == 0 || solutions.Count > MaxRngCandidates) return [];
        return solutions.Select(s => (s, ZipRng.RandomHeaders(s.State, variant, target.Entries.Count))).ToList();
    }

    /// <summary>
    /// Exact verification: the keys must decrypt each explained entry's stored header to the pass-1
    /// ciphertext of the RNG-implied random bytes, and (for entries with a CRC in the local flags)
    /// to the two CRC check bytes; with an archive path, the decrypted data must inflate to the
    /// entry's content with a matching CRC-32.
    /// </summary>
    public static bool VerifyKeys(ZipStayTarget target, ZipStayKeys keys, byte[][] r, int[] fileIndices,
        string? archivePath)
    {
        try
        {
            foreach (var i in fileIndices)
                if (!VerifyEntry(target.Entries[i], keys, r[i], archivePath))
                    return false;
            return true;
        }
        catch (Exception e) when (e is IOException or FormatException or InvalidDataException or ObjectDisposedException)
        {
            return false;
        }
    }

    private static bool VerifyEntry(ZipStayEntry e, ZipStayKeys keys, byte[] r, string? archivePath)
    {
        // pass 1: the zipper encrypted the 10 random bytes with the password keys; recover the ciphertext
        var (k0, k1, k2) = (keys.X, keys.Y, keys.Z);
        var c1 = new byte[10];
        for (int i = 0; i < 10; i++)
        {
            c1[i] = (byte)(r[i] ^ Keystream(k2));
            Update(ref k0, ref k1, ref k2, r[i]);          // keys absorb the plaintext (zencode)
        }

        // pass 2: the stored header decrypts (with the same initial keys) back to c1 + check bytes
        (k0, k1, k2) = (keys.X, keys.Y, keys.Z);
        var p = new byte[HeaderLength];
        for (int i = 0; i < HeaderLength; i++)
        {
            p[i] = (byte)(e.StoredHeader[i] ^ Keystream(k2));
            Update(ref k0, ref k1, ref k2, p[i]);          // keys absorb the plaintext (zdecode)
        }

        for (int i = 0; i < 10; i++)
            if (p[i] != c1[i]) return false;
        if (e.HasCrcCheckBytes)
        {
            if (p[10] != (byte)(e.Crc >> 16) || p[11] != (byte)(e.Crc >> 24)) return false;
        }
        // exotic compression methods cannot be CRC-verified here; the header match (and check
        // bytes, when present) is the verification, per the design
        if (e.Method is not (0 or 8)) return true;
        if (e.CompSize < HeaderLength || archivePath is null) return true;
        if (e.CompSize - HeaderLength > int.MaxValue) return true;   // zip64-sized body: header match suffices

        // the pass-2 cipher state continues straight into the entry data
        using var fs = ZipArchiveSource.Open(archivePath);
        fs.Seek(e.DataOffset + HeaderLength, SeekOrigin.Begin);
        var len = (int)(e.CompSize - HeaderLength);
        var enc = new byte[len];
        fs.ReadExactly(enc);
        var plain = new byte[len];
        for (int i = 0; i < len; i++)
        {
            plain[i] = (byte)(enc[i] ^ Keystream(k2));
            Update(ref k0, ref k1, ref k2, plain[i]);      // keys absorb the plaintext
        }

        var content = e.Method == 0 ? plain : Inflate(plain);
        return Crc32(content) == e.Crc;
    }

    private static byte Keystream(uint k2)
    {
        uint t = (k2 & 0xffff) | 2;
        return (byte)((t * (t ^ 1)) >> 8);
    }

    private static void Update(ref uint k0, ref uint k1, ref uint k2, byte c)
    {
        k0 = (k0 >> 8) ^ StayTables.T[(k0 ^ c) & 0xff];
        k1 = unchecked((k1 + (k0 & 0xff)) * StayTables.M + 1);
        k2 = (k2 >> 8) ^ StayTables.T[(k2 ^ (k1 >> 24)) & 0xff];
    }

    private static byte[] Inflate(byte[] deflated)
    {
        using var ds = new DeflateStream(new MemoryStream(deflated), CompressionMode.Decompress);
        using var ms = new MemoryStream();
        ds.CopyTo(ms);
        return ms.ToArray();
    }

    private static uint Crc32(byte[] data)
    {
        uint crc = 0xffffffff;
        foreach (var b in data)
            crc = (crc >> 8) ^ StayTables.T[(crc ^ b) & 0xff];
        return crc ^ 0xffffffff;
    }
}
