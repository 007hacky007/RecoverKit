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

    /// <summary>Lets streaming workers stop unfinished checks when the engine stops or finds a password.</summary>
    public virtual KernelWorker CreateWorker(CancellationToken stop) => CreateWorker();

    /// <summary>
    /// True when a worker can return from a search before testing every candidate it was given, because
    /// the engine stopped (streaming checks of large files). The engine then does not count that batch.
    /// </summary>
    public virtual bool StopsInsideBatch => false;

    /// <summary>Whether dictionary bytes can be verified without a different encoding or longer kernel layout.</summary>
    public virtual bool SupportsDictionaryPassword(ReadOnlySpan<byte> password) => password.Length <= MaxPasswordLength;

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
    /// <summary>Tests unrelated passwords packed at a positive fixed byte length; returns the first hit or -1.</summary>
    public virtual int SearchPasswords(ReadOnlySpan<byte> passwords, int length, int count)
    {
        for (int i = 0; i < count; i++)
        {
            var pw = passwords.Slice(i * length, length);
            if (Search(pw[..^1], pw[^1..]) >= 0) return i;
        }
        return -1;
    }

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
