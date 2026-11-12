namespace RecoverKit.Core.Native;

/// <summary>
/// A built-in CPU implementation of one hash format. A kernel is created once per attack from the
/// hash line; each worker thread gets its own <see cref="KernelWorker"/> with private scratch state.
/// </summary>
public abstract class NativeKernel
{
    /// <summary>Human-readable algorithm, for logs and the benchmark.</summary>
    public abstract string Name { get; }

    /// <summary>Longest password the kernel supports (matching hashcat's limit for the mode).</summary>
    public virtual int MaxPasswordLength => 64;

    /// <summary>Approximate candidates per second per thread, used to size work chunks.</summary>
    public abstract double SpeedHint { get; }

    public abstract KernelWorker CreateWorker();

    /// <summary>
    /// How many prefixes the engine should hand to <see cref="KernelWorker.SearchBatch"/> at once, for a
    /// last position of <paramref name="lastCount"/> characters. Kernels that test candidates in fixed-size
    /// vector groups use this to keep every lane busy.
    /// </summary>
    public virtual int PrefixBatch(int lastCount) => 1;

    /// <summary>
    /// Full check of one password, independent of the fast search path. Used by tests and to
    /// re-confirm a hit before it is reported.
    /// </summary>
    public abstract bool Verify(ReadOnlySpan<byte> password);
}

public abstract class KernelWorker
{
    /// <summary>
    /// Tests every candidate <c>prefix + last[i]</c>. Returns the index <c>i</c> of a candidate that
    /// passed the kernel's complete check, or -1. Consecutive calls usually share all but the last
    /// byte of <paramref name="prefix"/>, which kernels may exploit by caching intermediate state.
    /// </summary>
    public abstract int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last);

    /// <summary>
    /// Tests <c>prefix[k] + last[i]</c> for <paramref name="count"/> prefixes packed in
    /// <paramref name="prefixes"/>. Returns <c>k * last.Length + i</c> of a candidate that passed the
    /// complete check, or -1.
    /// </summary>
    public virtual int SearchBatch(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
    {
        int plen = count == 0 ? 0 : prefixes.Length / count;
        for (int k = 0; k < count; k++)
        {
            int hit = Search(prefixes.Slice(k * plen, plen), last);
            if (hit >= 0) return k * last.Length + hit;
        }
        return -1;
    }
}
