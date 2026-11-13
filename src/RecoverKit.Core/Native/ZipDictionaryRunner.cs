using System.Diagnostics;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.Core.Native;

/// <summary>Streams plain dictionary candidates through a partial ZIP target's whole-file confirmation.</summary>
internal sealed class ZipDictionaryRunner
{
    internal Action<HashcatStatus>? Status { get; init; }
    internal static string RestoreFile(string dir, string session) => Path.Combine(dir, session + ".dictionary.txt");

    internal static bool CanRun(PreparedAttack attack)
        => attack.Args is ["-a", "0", _] || attack.Args is ["-a", "0"] && attack.Stdin is not null;

    internal async Task<RunResult> RunAsync(HashTarget target, RunRequest request, CancellationToken ct)
    {
        string restore = RestoreFile(request.SessionDir, request.SessionName);
        long done = 0, resumed = 0;
        if (request.Restore && File.Exists(restore))
            long.TryParse(await File.ReadAllTextAsync(restore, ct), out resumed);
        resumed = Math.Max(0, resumed);
        var watch = Stopwatch.StartNew();
        long start = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        HashcatStatus? last = null;
        void Report(int status)
        {
            last = new HashcatStatus
            {
                Status = status, ProgressDone = done, ResumedFrom = resumed,
                ProgressTotal = (long)System.Numerics.BigInteger.Min(request.Attack.Keyspace, long.MaxValue),
                TotalHashes = 1, TimeStart = start,
                Devices = [new DeviceSpeed { Id = 0, Type = "CPU", Name = "CPU (built-in engine)",
                    Speed = (done - resumed) / Math.Max(watch.Elapsed.TotalSeconds, .001) }],
            };
            Status?.Invoke(last);
        }
        try
        {
            return await Task.Run(async () =>
            {
                var words = request.Attack.Stdin?.Invoke() ?? Wordlists.ReadWords(request.Attack.Args[2]);
                double nextReport = 2;
                foreach (string word in words)
                {
                    if (ct.IsCancellationRequested)
                    {
                        await File.WriteAllTextAsync(restore, done.ToString(System.Globalization.CultureInfo.InvariantCulture), CancellationToken.None);
                        Report(7);
                        return new RunResult { Outcome = RunOutcome.Aborted, LastStatus = last };
                    }
                    if (done++ < resumed) continue;
                    var password = PasswordConfirmation.PlainBytes(word);
                    if (target.ConfirmPassword!(password))
                    {
                        string found = await NativeRunner.RecordFoundAsync(request.Settings, target.HashLines, password,
                            request.PasswordCachePath ?? request.Settings.PotfilePath);
                        File.Delete(restore);
                        Report(6);
                        return new RunResult { Outcome = RunOutcome.Cracked, Passwords = [found], LastStatus = last };
                    }
                    if (watch.Elapsed.TotalSeconds >= nextReport) { Report(3); nextReport += 2; }
                }
                File.Delete(restore);
                Report(5);
                return new RunResult { Outcome = RunOutcome.Exhausted, LastStatus = last };
            }, CancellationToken.None);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new RunResult { Outcome = RunOutcome.Error, Error = "The CPU could not read the dictionary or ZIP file: " + ex.Message, LastStatus = last };
        }
    }
}
