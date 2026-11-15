using System.Diagnostics;

namespace RecoverKit.Core.Native;

/// <summary>Where a native attack stopped, so it can continue later.</summary>
public sealed class NativeResumePoint
{
    public int Length { get; set; }
    public long PrefixIndex { get; set; }
}

public sealed class NativeProgress
{
    public int Length { get; init; }
    public long Done { get; init; }          // candidates tested for this length
    public long Total { get; init; }         // candidates for this length
    public double Speed { get; init; }       // candidates per second (recent)
    public DateTime Started { get; init; }
    public long ResumedFrom { get; init; }   // candidates of this length done before this run (resume)
}

public enum NativeOutcome { Found, Exhausted, Stopped }

public sealed class NativeResult
{
    public NativeOutcome Outcome { get; init; }
    public byte[]? Password { get; init; }
    public NativeResumePoint? ResumeAt { get; init; }
    public long Tested { get; init; }
}

/// <summary>
/// Runs a <see cref="NativeKernel"/> over a <see cref="MaskSpace"/> on all requested CPU threads.
/// The last mask position is iterated by the kernel; the positions before it ("prefixes") are
/// enumerated here in hashcat's order and handed out to threads in chunks.
/// </summary>
public sealed class NativeEngine(NativeKernel kernel, MaskSpace space)
{
    public int Threads { get; init; } = Environment.ProcessorCount;
    public ThreadPriority Priority { get; init; } = ThreadPriority.Lowest;
    public event Action<NativeProgress>? Progress;
    public TimeSpan ProgressInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Second check a hit must pass besides the kernel's own (<see cref="Formats.HashTarget.ConfirmPassword"/>).</summary>
    public Func<byte[], bool>? Confirm { get; init; }

    /// <summary>A hit passed the kernel but not <see cref="Confirm"/>; the search went on. Called on worker threads.</summary>
    public Action<byte[]>? Rejected { get; init; }

    public NativeResult Run(NativeResumePoint? resume, CancellationToken ct)
    {
        long testedTotal = 0;
        int startLen = Math.Max(space.MinLength, resume?.Length ?? space.MinLength);
        for (int len = startLen; len <= space.MaxLength; len++)
        {
            if (len > kernel.MaxPasswordLength) break;
            long startPrefix = resume is not null && len == resume.Length ? resume.PrefixIndex : 0;
            var r = RunLength(len, startPrefix, ct, out long tested);
            testedTotal += tested;
            if (r is not null) return new NativeResult { Outcome = r.Outcome, Password = r.Password, ResumeAt = r.ResumeAt, Tested = testedTotal };
        }
        return new NativeResult { Outcome = NativeOutcome.Exhausted, Tested = testedTotal };
    }

    /// <summary>
    /// Searches the packed prefixes from flat candidate index <paramref name="from"/> (prefix * last.Length + last
    /// index) on; returns the flat index of the first hit or -1.
    /// </summary>
    internal static int SearchFrom(KernelWorker worker, byte[] packed, int prefixLen, int count, ReadOnlySpan<byte> last, int from)
    {
        int n = last.Length;
        int k = from / n, i = from % n;
        if (i > 0)
        {
            int h = worker.Search(packed.AsSpan(k * prefixLen, prefixLen), last[i..]);
            if (h >= 0) return k * n + i + h;
            k++;
        }
        if (k >= count) return -1;
        int rest = count - k;
        int hit = rest == 1 ? worker.Search(packed.AsSpan(k * prefixLen, prefixLen), last)
                            : worker.SearchBatch(packed.AsSpan(k * prefixLen, prefixLen * rest), rest, last);
        return hit < 0 ? -1 : k * n + hit;
    }

    private NativeResult? RunLength(int len, long startPrefix, CancellationToken ct, out long tested)
    {
        var pos = space.Positions;
        byte[] last = pos[len - 1];
        int prefixLen = len - 1;
        long prefixCount = 1;
        for (int i = 0; i < prefixLen; i++)
            prefixCount = checked(prefixCount * pos[i].Length);
        long total = checked(prefixCount * last.Length);

        // Chunks of about 20 ms of work per thread keep scheduling overhead negligible and make
        // stopping responsive.
        int batch = Math.Max(1, kernel.PrefixBatch(last.Length));
        long chunk = Math.Max(batch, (long)(kernel.SpeedHint * 0.02 / last.Length));
        long next = startPrefix;
        long done = startPrefix * last.Length;
        int threads = Math.Max(1, Threads);
        var inFlight = new long[threads];
        Array.Fill(inFlight, long.MaxValue);
        byte[]? found = null;
        Exception? failure = null;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var started = DateTime.Now;

        void Worker(int t)
        {
            var worker = kernel.CreateWorker(stop.Token);
            var digits = new int[prefixLen];
            var prefix = new byte[prefixLen];
            var packed = new byte[prefixLen * batch];
            while (!stop.IsCancellationRequested)
            {
                long s = Interlocked.Add(ref next, chunk) - chunk;
                if (s >= prefixCount) break;
                Volatile.Write(ref inFlight[t], s);
                long e = Math.Min(s + chunk, prefixCount);

                // Decode the first prefix of the chunk (last prefix position varies fastest).
                long rem = s;
                for (int i = prefixLen - 1; i >= 0; i--)
                {
                    int n = pos[i].Length;
                    digits[i] = (int)(rem % n);
                    rem /= n;
                    prefix[i] = pos[i][digits[i]];
                }

                long p = s;
                while (p < e)
                {
                    // Pack up to `batch` consecutive prefixes.
                    int count = (int)Math.Min(batch, e - p);
                    for (int k = 0; k < count; k++)
                    {
                        prefix.CopyTo(packed, k * prefixLen);
                        // Advance the odometer.
                        for (int i = prefixLen - 1; i >= 0; i--)
                        {
                            if (++digits[i] < pos[i].Length) { prefix[i] = pos[i][digits[i]]; break; }
                            digits[i] = 0;
                            prefix[i] = pos[i][0];
                        }
                    }
                    // A rejected hit (a false positive) does not end the batch: the search goes on right after it.
                    int from = 0;
                    while (from < count * last.Length)
                    {
                        int hit = SearchFrom(worker, packed, prefixLen, count, last, from);
                        if (hit < 0) break;
                        var pw = new byte[len];
                        packed.AsSpan(hit / last.Length * prefixLen, prefixLen).CopyTo(pw);
                        pw[len - 1] = last[hit % last.Length];
                        if (worker is Kernels.SevenZipKernel.Worker sevenZip && sevenZip.VerifiedBy(kernel) || kernel.Verify(pw))
                        {
                            if (Confirm is null || Confirm(pw))
                            {
                                Interlocked.CompareExchange(ref found, pw, null);
                                stop.Cancel();
                                return;
                            }
                            Rejected?.Invoke(pw);
                        }
                        from = hit + 1;
                    }
                    // A cancellable kernel can return before finishing the last-character loop.
                    if (stop.IsCancellationRequested) return;
                    long before = p;
                    p += count;
                    if ((before >> 6) != (p >> 6) && stop.IsCancellationRequested) break;
                }
                // A chunk left early (stop) stays marked in flight, so the resume point does not pass it.
                if (p < e) return;
                Interlocked.Add(ref done, (e - s) * last.Length);
                Volatile.Write(ref inFlight[t], long.MaxValue);
            }
        }

        // A kernel exception on a worker thread would end the process; stop the others and rethrow it here.
        void Guarded(int t)
        {
            try { Worker(t); }
            catch (Exception ex)
            {
                Interlocked.CompareExchange(ref failure, ex, null);
                stop.Cancel();
            }
        }

        var threadObjs = Enumerable.Range(0, threads).Select(t => new Thread(() => Guarded(t))
        {
            IsBackground = true, Priority = Priority, Name = $"RecoverKit CPU {t}",
        }).ToArray();
        foreach (var th in threadObjs) th.Start();

        var sw = Stopwatch.StartNew();
        long lastDone = Volatile.Read(ref done);
        var lastTime = sw.Elapsed;
        double speed = 0;
        while (true)
        {
            // Take one snapshot: a thread may finish between "any alive?" and "which one?".
            var alive = Array.Find(threadObjs, th => th.IsAlive);
            if (alive is null) break;
            alive.Join(ProgressInterval);
            var now = sw.Elapsed;
            long d = Volatile.Read(ref done);
            // Very short intervals (threads finishing after a stop) give meaningless rates: keep the last one.
            if ((now - lastTime).TotalSeconds >= 0.5)
            {
                speed = (d - lastDone) / (now - lastTime).TotalSeconds;
                lastDone = d;
                lastTime = now;
            }
            Progress?.Invoke(new NativeProgress { Length = len, Done = Math.Min(d, total), Total = total, Speed = speed, Started = started, ResumedFrom = startPrefix * last.Length });
        }
        tested = Volatile.Read(ref done) - startPrefix * last.Length;
        if (failure is not null) throw new InvalidOperationException("Built-in engine kernel failed: " + failure.Message, failure);

        if (found is not null) return new NativeResult { Outcome = NativeOutcome.Found, Password = found };
        if (ct.IsCancellationRequested)
        {
            long resumeAt = Math.Min(Volatile.Read(ref next), inFlight.Min());
            return new NativeResult { Outcome = NativeOutcome.Stopped, ResumeAt = new NativeResumePoint { Length = len, PrefixIndex = Math.Min(resumeAt, prefixCount) } };
        }
        return null; // this length exhausted
    }
}
