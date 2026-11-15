using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native.Kernels;

namespace RecoverKit.Core.Native;

/// <summary>Bounded parallel batches of plain words; an interrupted batch is replayed on resume.</summary>
internal sealed class SevenZipDictionaryRunner
{
    internal Action<HashcatStatus>? Status { get; init; }
    internal TimeSpan ProgressInterval { get; init; } = TimeSpan.FromSeconds(2);
    internal static string RestoreFile(string dir, string session) => Path.Combine(dir, session + ".7z-dictionary.json");
    private sealed record Checkpoint(long Done, string Fingerprint);

    internal async Task<RunResult> RunAsync(HashTarget target, RunRequest request, AttackSpec spec, PlannerContext context, CancellationToken ct)
    {
        string restore = RestoreFile(request.SessionDir, request.SessionName);
        using var fingerprint = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        fingerprint.AppendData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(spec)));
        foreach (string source in spec.Dictionaries.OfType<string>().Where(p => p.Length > 0))
        {
            string path = AttackPlanner.ResolveDictionary(source, context) ?? throw new IOException("The dictionary could not be found.");
            using var file = File.OpenRead(path);
            fingerprint.AppendData(await SHA256.HashDataAsync(file, ct));
        }
        string stamp = Convert.ToHexString(fingerprint.GetHashAndReset());
        long done = 0;
        if (request.Restore && File.Exists(restore))
        {
            Checkpoint? saved;
            try { saved = JsonSerializer.Deserialize<Checkpoint>(await File.ReadAllTextAsync(restore, ct)); }
            catch (JsonException) { saved = null; }
            if (saved is null || saved.Fingerprint != stamp || saved.Done < 0)
                return new RunResult { Outcome = RunOutcome.Error, Error = "The dictionary changed or its saved progress is damaged. Start a new attack instead of resuming." };
            done = saved.Done;
        }
        long resumed = done;
        int threads = request.Settings.MaxCpuThreads > 0 ? Math.Min(request.Settings.MaxCpuThreads, Environment.ProcessorCount) : Environment.ProcessorCount;
        var watch = Stopwatch.StartNew();
        long started = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        HashcatStatus? last = null;
        void Report(int status)
        {
            last = new HashcatStatus
            {
                Status = status, ProgressDone = done, ResumedFrom = resumed,
                ProgressTotal = (long)System.Numerics.BigInteger.Min(request.Attack.Keyspace, long.MaxValue),
                TotalHashes = 1, TimeStart = started,
                Devices = [new DeviceSpeed { Id = 0, Type = "CPU", Name = "CPU (built-in engine)",
                    Speed = (done - resumed) / Math.Max(watch.Elapsed.TotalSeconds, .001) }],
            };
            Status?.Invoke(last);
        }
        return await Task.Run(async () =>
        {
            var words = request.Attack.Stdin?.Invoke() ?? Wordlists.ReadWords(request.Attack.Args[2]);
            using var iterator = words.GetEnumerator();
            for (long i = 0; i < resumed; i++)
                if (!iterator.MoveNext()) return new RunResult { Outcome = RunOutcome.Error, Error = "The dictionary is shorter than its saved progress." };
            var kernel = new SevenZipKernel(target.SevenZipCpu!, ct);
            using var workersStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var workers = Enumerable.Range(0, threads).Select(_ => kernel.CreatePasswordWorker(workersStop.Token)).ToArray();
            double nextReport = ProgressInterval.TotalSeconds;
            while (true)
            {
                if (ct.IsCancellationRequested)
                {
                    await File.WriteAllTextAsync(restore, JsonSerializer.Serialize(new Checkpoint(done, stamp)), CancellationToken.None);
                    Report(7);
                    return new RunResult { Outcome = RunOutcome.Aborted, LastStatus = last };
                }
                var batch = new List<byte[]>(threads * 2);
                while (batch.Count < threads * 2 && iterator.MoveNext()) batch.Add(PasswordConfirmation.PlainBytes(iterator.Current));
                if (batch.Count == 0)
                { File.Delete(restore); Report(5); return new RunResult { Outcome = RunOutcome.Exhausted, LastStatus = last }; }
                byte[]? found = null;
                Parallel.For(0, threads, new ParallelOptions { MaxDegreeOfParallelism = threads }, worker =>
                {
                    for (int i = worker; i < batch.Count && Volatile.Read(ref found) is null; i += threads)
                        if (workers[worker].Verify(batch[i]))
                        {
                            Interlocked.CompareExchange(ref found, batch[i], null);
                            workersStop.Cancel();
                            break;
                        }
                });
                if (found is not null)
                {
                    string password = await NativeRunner.RecordFoundAsync(request.Settings, target.HashLines, found, request.Settings.PotfilePath);
                    File.Delete(restore); Report(6);
                    return new RunResult { Outcome = RunOutcome.Cracked, Passwords = [password], LastStatus = last };
                }
                if (!ct.IsCancellationRequested) done += batch.Count;
                // A cancelled batch may contain untested words. Keep its starting position.
                if (watch.Elapsed.TotalSeconds >= nextReport) { Report(3); nextReport += ProgressInterval.TotalSeconds; }
            }
        }, CancellationToken.None);
    }
}
