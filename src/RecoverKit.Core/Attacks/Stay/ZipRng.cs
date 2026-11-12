namespace RecoverKit.Core.Attacks.Stay;

/// <summary>The PRNG family used for the 12-byte encryption header. State bit 31 is never observable.</summary>
public enum ZipRngVariant
{
    /// <summary>MSVC / Info-ZIP on Windows: s = s*214013 + 2531011 (WinZip per Stay's paper).</summary>
    Msvc,
    /// <summary>WinZip 8 (IBDL32.dll) dropped the increment: s = s*214013.</summary>
    WinZip,
}

public sealed record ZipRngSolution(ZipRngVariant Variant, uint State, int MatchedFiles);

/// <summary>
/// Recovery of the header RNG state (stage 0 of Stay's attack). The first stored header byte of
/// every file is in the clear (double-encryption cancellation), and equals the high 8 bits of one
/// rand() output per file. The 31-bit state at the first observed output is found by enumeration.
/// </summary>
public static class ZipRng
{
    public const int CallsPerFile = 10;
    private const uint Mult = 214013;
    private const uint Inc = 2531011;

    /// <summary>Advances one rand() step and returns the header byte it would produce ((rand()>>7)&amp;0xff).</summary>
    public static byte NextByte(ref uint state, ZipRngVariant v)
    {
        state = unchecked(state * Mult + (v == ZipRngVariant.Msvc ? Inc : 0));
        return (byte)((state >> 23) & 0xff);
    }

    /// <summary>
    /// Enumerates all states whose generated first bytes match a prefix of <paramref name="firstBytes"/>
    /// of at least <paramref name="minMatched"/> files (bits 23..30 of the state are fixed by file 0's byte;
    /// the low 23 bits are enumerated, bit 31 is unobservable). Returns solutions ordered by matched length.
    /// </summary>
    public static List<ZipRngSolution> RecoverStates(IReadOnlyList<byte> firstBytes, ZipRngVariant v, int minMatched)
    {
        var solutions = new List<ZipRngSolution>();
        int files = firstBytes.Count;
        if (files == 0 || minMatched > files) return solutions;

        // composed 10-step LCG over the observable 31 bits: S_{10(i-1)+1} = S1 * A10 + C10 (mod 2^31)
        (uint a10, uint c10) = ComposeTen(v);
        uint b0 = firstBytes[0];

        for (uint low = 0; low < (1u << 23); low++)
        {
            uint s = (b0 << 23) | low;                    // state after file 0's first rand() step, bit 31 clear
            int matched = 1;
            uint t = s;
            for (int i = 1; i < files; i++)
            {
                t = StepTen(t, a10, c10);
                if (((t >> 23) & 0xff) != firstBytes[i]) break;
                matched++;
            }
            if (matched >= minMatched)
                solutions.Add(new ZipRngSolution(v, s, matched));
        }

        solutions.Sort((x, y) => y.MatchedFiles.CompareTo(x.MatchedFiles));
        return solutions;
    }

    /// <summary>
    /// Regenerates every file's 10 clear random header bytes from the state recovered for file 0's
    /// first byte (the state after that first rand() step): file 0's first byte is the state's own
    /// top bits, every later byte costs one more rand() step.
    /// </summary>
    public static byte[][] RandomHeaders(uint state, ZipRngVariant v, int fileCount)
    {
        var r = new byte[fileCount][];
        for (int i = 0; i < fileCount; i++)
        {
            var ri = new byte[CallsPerFile];
            for (int j = 0; j < CallsPerFile; j++)
            {
                if (i == 0 && j == 0) ri[0] = (byte)((state >> 23) & 0xff);   // already stepped
                else ri[j] = NextByte(ref state, v);
            }
            r[i] = ri;
        }
        return r;
    }

    private static (uint A10, uint C10) ComposeTen(ZipRngVariant v)
    {
        uint inc = v == ZipRngVariant.Msvc ? Inc : 0;
        uint a = 1, c = 0;
        for (int k = 0; k < CallsPerFile; k++)
        {
            c = unchecked((a * inc + c) & 0x7fffffff);
            a = unchecked((a * Mult) & 0x7fffffff);
        }
        return (a, c);
    }

    private static uint StepTen(uint s, uint a10, uint c10)
        => unchecked((s * a10 + c10) & 0x7fffffff);
}
