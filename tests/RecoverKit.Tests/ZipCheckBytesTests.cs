using System.Text;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class ZipCheckBytesTests
{
    internal static HashTarget Target(int count, bool twoBytes = false, bool descriptor = true, bool descriptorUsesCrc = false)
    {
        var rng = new Random(91);
        return ZipCryptoSample.Extract(ZipCryptoSample.Archive(Enumerable.Range(0, count)
            .Select(i => new ZipCryptoSample.Entry($"file{i}.dat", ZipCryptoSample.Text(2000, rng), true, descriptor, TwoCheckBytes: twoBytes, DescriptorUsesCrc: descriptorUsesCrc)).ToArray(), "test42"u8, rng));
    }

    [Theory]
    [InlineData(7, false, true, false)]
    [InlineData(8, false, true, true)]
    [InlineData(12, false, false, true)]
    [InlineData(3, true, false, false)]
    [InlineData(4, true, false, true)]
    [InlineData(4, true, true, false)]
    public void RequiresEnoughIndependentCheckBytes(int count, bool twoBytes, bool descriptor, bool eligible)
    {
        var t = Target(count, twoBytes, descriptor);
        Assert.Equal(eligible, t.ZipCheckBytes is not null);
        if (t.ZipCheckBytes is not { } filter) return;
        var fields = filter.HashLines.Split('*');
        Assert.InRange(int.Parse(fields[0][8..]), 4, 8);
        Assert.Equal(twoBytes && !descriptor ? "2" : "1", fields[1]);
        Assert.True(filter.ConfirmPassword("test42"u8.ToArray()));
        Assert.False(filter.ConfirmPassword("wrong"u8.ToArray()));
        Assert.NotNull(ZipCryptoKernel.TryParse(t.HashLines));
        Assert.Equal(ZipCryptoKernel.TryParse(t.HashLines)!.Verify("test42"u8), filter.ConfirmPassword("test42"u8.ToArray()));
    }

    [Fact]
    public void DuplicateHeadersDoNotCountAsIndependentEvidence()
    {
        var e = new ZipCryptoSample.Entry("same.dat", "same content"u8.ToArray(), false, Header: new byte[10]);
        var t = ZipCryptoSample.Extract(ZipCryptoSample.Archive(Enumerable.Repeat(e, 8).ToArray(), "test42"u8, new Random(1)));
        Assert.Null(t.ZipCheckBytes);
    }

    [Fact]
    public void CheckBytesRequireAMeasuredGainOnEveryActiveDevice()
    {
        var device = new BackendDevice { Id = 1, Key = "gpu", Type = "GPU" };
        var settings = new RecoverKit.Core.Settings();
        var profile = new PerformanceProfile();
        Assert.False(ZipCheckBytesTarget.IsFaster(profile, settings, [device], 17200));
        profile.Decisions.Add(new() { Domain = "zip", Mode = 17200, DeviceKeys = ["gpu"], Speed = 100 });
        profile.Decisions.Add(new() { Domain = "zip", Mode = 17230, DeviceKeys = ["gpu"], Speed = 90 });
        Assert.False(ZipCheckBytesTarget.IsFaster(profile, settings, [device], 17200));
        profile.Decisions[1].Speed = 120;
        Assert.True(ZipCheckBytesTarget.IsFaster(profile, settings, [device], 17200));
        Assert.False(ZipCheckBytesTarget.IsFaster(profile, settings, [device, new() { Id = 2, Key = "unknown", Type = "GPU" }], 17200));
        var integrated = new BackendDevice { Id = 2, Key = "integrated", Type = "GPU" };
        profile.Decisions.Add(new() { Domain = "zip", Mode = 17200, DeviceKeys = ["gpu", "integrated"], Speed = 150 });
        profile.Decisions.Add(new() { Domain = "zip", Mode = 17230, DeviceKeys = ["integrated", "gpu"], Speed = 200 });
        Assert.True(ZipCheckBytesTarget.IsFaster(profile, settings, [device, integrated], 17200));
        Assert.False(ZipCheckBytesTarget.IsFaster(profile, settings, [device, new() { Id = 3, Key = "third", Type = "GPU" }], 17200));
        foreach (var decision in profile.Decisions) decision.Policy = PerformanceProfiles.PolicyFingerprint(settings, "zip");
        settings.HybridCpuGpu = false;
        Assert.True(ZipCheckBytesTarget.IsFaster(profile, settings, [device], 17200));
        settings.GpuDutyPercent = 50;
        Assert.False(ZipCheckBytesTarget.IsFaster(profile, settings, [device], 17200));
    }

    [Fact]
    public async Task AutomaticCalibrationMeasuresAndCachesBothModesForTheCompleteGpuSet()
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-zip-calibration-").FullName;
        string profileFile = Path.Combine(RecoverKit.Core.Settings.AppDataDir, "performance-profile.json");
        byte[]? saved = File.Exists(profileFile) ? File.ReadAllBytes(profileFile) : null;
        try
        {
            string executable = Path.Combine(dir, "hashcat");
            File.WriteAllText(executable, """
                #!/usr/bin/env python3
                import sys, json
                args = sys.argv[1:]
                if '--version' in args:
                    print('v8.0.0')
                    sys.exit(0)
                with open('probes.jsonl', 'a') as f: f.write(json.dumps(args) + '\n')
                speed = 200 if args[args.index('-m') + 1] == '17230' else 100
                for i in range(4): print(json.dumps({'status':3, 'devices':[{'speed':speed}]}))
                sys.exit(4)
                """);
            File.SetUnixFileMode(executable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var tool = HashcatTool.Locate(executable)!;
            await tool.VersionAsync();
            var settings = new RecoverKit.Core.Settings();
            BackendDevice[] devices = [new() { Id = 1, Type = "GPU", Key = "discrete" }, new() { Id = 2, Type = "GPU", Key = "integrated" }];
            var target = Target(8);
            File.Delete(profileFile);
            var profile = await PerformanceCalibration.EnsureZipAsync(tool, settings, devices, 17200,
                target.HashLines, target.ZipCheckBytes!, _ => { }, CancellationToken.None);
            Assert.True(ZipCheckBytesTarget.IsFaster(profile, settings, devices, 17200));
            var calls = File.ReadAllLines(Path.Combine(dir, "probes.jsonl"))
                .Select(line => System.Text.Json.JsonSerializer.Deserialize<string[]>(line)!).ToList();
            Assert.Equal(4, calls.Count);
            Assert.Equal(["17200", "17230", "17200", "17230"], calls.Select(args => args[Array.IndexOf(args, "-m") + 1]));
            Assert.All(calls, args =>
            {
                int selection = Array.IndexOf(args, "-d");
                if (selection >= 0) Assert.Equal("1,2", args[selection + 1]);
                else Assert.Equal("2", args[Array.IndexOf(args, "-D") + 1]);
            });
            await PerformanceCalibration.EnsureZipAsync(tool, settings, devices, 17200,
                target.HashLines, target.ZipCheckBytes!, _ => { }, CancellationToken.None);
            Assert.Equal(4, File.ReadAllLines(Path.Combine(dir, "probes.jsonl")).Length);
            settings.DisabledDevices.Add(2);
            profile = await PerformanceCalibration.EnsureZipAsync(tool, settings, devices, 17200,
                target.HashLines, target.ZipCheckBytes!, _ => { }, CancellationToken.None);
            calls = File.ReadAllLines(Path.Combine(dir, "probes.jsonl"))
                .Select(line => System.Text.Json.JsonSerializer.Deserialize<string[]>(line)!).ToList();
            Assert.Equal(8, calls.Count);
            Assert.All(calls.Skip(4), args => Assert.Equal("1", args[Array.IndexOf(args, "-d") + 1]));
            Assert.True(ZipCheckBytesTarget.IsFaster(profile, settings, devices, 17200));
        }
        finally
        {
            if (saved is null) File.Delete(profileFile); else File.WriteAllBytes(profileFile, saved);
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void FilterDoesNotIncludeEntriesThatTheExistingConfirmerDoesNotCheck()
    {
        var rng = new Random(191);
        var entries = Enumerable.Range(0, 27).Select(i => new ZipCryptoSample.Entry($"file{i}.dat",
            ZipCryptoSample.Text(1000, rng), false)).ToArray();
        var archive = ZipCryptoSample.Archive(entries, "test42"u8, new Random(92));
        var different = ZipCryptoSample.Archive(entries, "other42"u8, new Random(92));
        using (var stream = new MemoryStream(archive))
        {
            var parsed = ZipExtractor.ReadCentralDirectory(stream, out _, out long centralOffset, out _);
            long central = centralOffset;
            for (int i = 0; i < parsed.Count; i++)
            {
                var entry = parsed[i];
                int nameLength = Encoding.UTF8.GetByteCount(entry.Name);
                if (i < 8)
                {
                    int offset = checked((int)entry.LocalOffset);
                    int dataOffset = offset + 30 + nameLength;
                    different.AsSpan(dataOffset, (int)entry.CompSize).CopyTo(archive.AsSpan(dataOffset));
                    BitConverter.TryWriteBytes(archive.AsSpan(offset + 8, 2), (ushort)12);
                    BitConverter.TryWriteBytes(archive.AsSpan((int)central + 10, 2), (ushort)12);
                }
                central += 46 + nameLength;
            }
        }
        var target = ZipCryptoSample.Extract(archive);
        Assert.True(target.ConfirmPassword!("test42"u8.ToArray()));
        Assert.True(target.ZipCheckBytes!.ConfirmPassword("test42"u8.ToArray()));
        var fields = target.ZipCheckBytes.HashLines.Split('*');
        for (int i = 2; i < fields.Length - 1; i += 7)
        {
            byte check = ZipCryptoKernel.HeaderCheckByte("test42"u8, Convert.FromHexString(fields[i + 6]));
            Assert.True(check == Convert.ToUInt16(fields[i + 4], 16) >> 8 || check == Convert.ToUInt16(fields[i + 5], 16) >> 8);
        }
    }

    [Fact]
    public void BenchmarkHasASeparateHeaderOnlyRow()
        => Assert.Contains(ZipKernelBenchmark.DefaultSamples(), s => s.Mode == 17230);

    [Fact]
    public void LegacySelectionKeepsItsSavedSessionIdentity()
    {
        var rng = new Random(12);
        var target = ZipCryptoSample.Extract(ZipCryptoSample.Archive([
            new("stored.dat", new byte[200], false),
            new("deflated.dat", ZipCryptoSample.Text(4000, rng), true)], "test42"u8, rng));
        Assert.Equal(17210, target.Modes[0]);
        Assert.NotNull(target.LegacyZipTarget);
        Assert.Equal(17200, target.LegacyZipTarget.Modes[0]);
        string dir = Directory.CreateTempSubdirectory("rk-legacy-session-").FullName;
        try
        {
            var settings = new RecoverKit.Core.Settings { SessionsDir = dir };
            string key = RecoverKit.Core.SessionState.KeyFor(target.LegacyZipTarget);
            new RecoverKit.Core.SessionState { Key = key, Modes = [17200] }.Save(settings);
            Assert.Equal(key, RecoverKit.Core.SessionState.Load(settings, target)!.Key);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SavedSessionRunsWithItsSavedHashAndMode(bool filterResume)
    {
        if (OperatingSystem.IsWindows()) return;
        var rng = new Random(12);
        var target = ZipCryptoSample.Extract(ZipCryptoSample.Archive([
            new("stored.dat", new byte[200], false),
            new("deflated.dat", ZipCryptoSample.Text(4000, rng), true)], "test42"u8, rng));
        var old = target.LegacyZipTarget!;
        if (filterResume) target = old = Target(8);
        string dir = Directory.CreateTempSubdirectory("rk-legacy-run-").FullName;
        try
        {
            string executable = Path.Combine(dir, "hashcat");
            File.WriteAllText(executable, """
                #!/usr/bin/env python3
                import sys, json
                args = sys.argv[1:]
                if '--version' in args:
                    print('v8.0.0')
                    sys.exit(0)
                if '-o' in args:
                    with open('args.json', 'w') as f: json.dump(args, f)
                    with open(args[args.index('-o') + 1], 'w') as f: f.write('test42\n')
                sys.exit(0)
                """);
            File.SetUnixFileMode(executable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var tool = HashcatTool.Locate(executable)!;
            await tool.VersionAsync();
            var settings = new RecoverKit.Core.Settings { SessionsDir = dir, UseNativeCpuEngine = false,
                HybridCpuGpu = false, DontUsePasswordCache = true, AutomaticPerformanceCalibration = false };
            var spec = new RecoverKit.Core.Attacks.AttackSpec { Kind = RecoverKit.Core.Attacks.AttackKind.Mask, HashcatMask = "test?d?d" };
            string key = RecoverKit.Core.SessionState.KeyFor(old);
            var state = new RecoverKit.Core.SessionState { Key = key, Modes = old.Modes.ToList(),
                Steps = [spec], HashcatSession = "legacy", Restorable = true };
            state.Save(settings);
            File.WriteAllBytes(HashcatRunner.RestoreFile(dir, "legacy"), new byte[280]);
            if (filterResume)
                File.WriteAllText(HashcatRunner.ZipFilterStateFile(dir, "legacy"),
                    System.Text.Json.JsonSerializer.Serialize(new { Phase = "headers", HashLines = old.ZipCheckBytes!.HashLines }));
            var session = new RecoverKit.Core.RecoverySession(tool, settings)
            { Devices = [new() { Id = 1, Type = "GPU", Key = "synthetic" }] };
            var result = await session.RunAsync(target, "sample.zip", [spec], state, CancellationToken.None);
            Assert.Equal(RecoverKit.Core.SessionOutcome.Found, result.Outcome);
            var args = System.Text.Json.JsonSerializer.Deserialize<string[]>(File.ReadAllText(Path.Combine(dir, "args.json")))!;
            Assert.Equal(filterResume ? "17230" : "17200", args[Array.IndexOf(args, "-m") + 1]);
            Assert.Contains("--restore-position", args);
            Assert.Equal(old.HashLines.Trim(), File.ReadAllText(Path.Combine(dir, key + ".hash")).Trim());
        }
        finally { Directory.Delete(dir, true); }
    }

    internal static byte[] MixedArchive()
    {
        var rng = new Random(51);
        var entries = Enumerable.Range(0, 8).Select(i => new ZipCryptoSample.Entry($"file{i}.dat",
            ZipCryptoSample.Text(i == 0 ? 50 : 2000, rng), true, true)).ToArray();
        var archive = ZipCryptoSample.Archive(entries, "test42"u8, new Random(21));
        var other = ZipCryptoSample.Archive(entries, "other42"u8, new Random(21));
        using (var stream = new MemoryStream(archive))
        {
            var parsed = ZipExtractor.ReadCentralDirectory(stream, out _, out _, out _);
            foreach (var e in parsed.Skip(1))
            {
                int offset = checked((int)e.LocalOffset + 30 + Encoding.UTF8.GetByteCount(e.Name));
                other.AsSpan(offset, (int)e.CompSize).CopyTo(archive.AsSpan(offset));
            }
        }
        return archive;
    }

    [Fact]
    public void MixedPasswordsRetainTheExistingAllEntriesPolicy()
    {
        var target = ZipCryptoSample.Extract(MixedArchive());
        Assert.False(target.ConfirmPassword!("test42"u8.ToArray()));
        Assert.False(target.ZipCheckBytes!.ConfirmPassword("test42"u8.ToArray()));
        Assert.True(ZipCryptoKernel.TryParse(target.HashLines)!.Verify("test42"u8));
    }

    internal static byte[] CollidingArchive()
    {
        var rng = new Random(312);
        var entries = new List<ZipCryptoSample.Entry>();
        for (int i = 0; i < 8; i++)
        {
            var content = ZipCryptoSample.Text(2000, rng);
            while (true)
            {
                var header = new byte[10];
                rng.NextBytes(header);
                var entry = new ZipCryptoSample.Entry($"file{i}.dat", content, true, true, header);
                var one = ZipCryptoSample.Archive([entry], "test42"u8, rng);
                int offset = 30 + Encoding.UTF8.GetByteCount(entry.Name);
                if (ZipCryptoKernel.HeaderCheckByte("test00"u8, one.AsSpan(offset, 12)) != 0x6d) continue;
                entries.Add(entry);
                break;
            }
        }
        return ZipCryptoSample.Archive(entries, "test42"u8, rng);
    }

    [Fact]
    public void SyntheticWrongPasswordPassesAllHeadersButFailsFullConfirmation()
    {
        var target = ZipCryptoSample.Extract(CollidingArchive());
        var fields = target.ZipCheckBytes!.HashLines.Split('*');
        for (int i = 2; i < fields.Length - 1; i += 7)
            Assert.Equal(0x6d, ZipCryptoKernel.HeaderCheckByte("test00"u8, Convert.FromHexString(fields[i + 6])));
        Assert.False(target.ZipCheckBytes.ConfirmPassword("test00"u8.ToArray()));
        Assert.True(target.ZipCheckBytes.ConfirmPassword("test42"u8.ToArray()));
    }

    [Fact]
    public async Task CancellingAChangedDeviceSetComparisonReturnsAnAbortedRange()
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-header-cancel-calibration-").FullName;
        try
        {
            string executable = Path.Combine(dir, "hashcat"), hash = Path.Combine(dir, "original.hash");
            File.WriteAllText(executable, "#!/usr/bin/env python3\nraise SystemExit(1)\n");
            File.SetUnixFileMode(executable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var target = Target(8);
            File.WriteAllText(hash, target.HashLines);
            var attack = new RecoverKit.Core.Attacks.PreparedAttack { Description = "cancel calibration" };
            attack.Args.AddRange(["-a", "3", "test?d?d"]);
            using var stop = new CancellationTokenSource();
            stop.Cancel();
            var runner = new HashcatRunner(HashcatTool.Locate(executable)!)
            { KnownDevices = [new() { Id = 1, Key = "first", Type = "GPU" }, new() { Id = 2, Key = "second", Type = "GPU" }] };
            var result = await runner.RunAsync(new() { Mode = target.Modes[0], HashFile = hash, SessionName = "cancel",
                SessionDir = dir, Attack = attack, ZipCheckBytes = target.ZipCheckBytes, GpuOnly = true, ExcludeDevices = [2] }, stop.Token);
            Assert.Equal(RunOutcome.Aborted, result.Outcome);
            Assert.Equal(0, result.LastStatus!.RestorePoint);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancelledFilterKeepsItsCheckpointAndResumesInTheSameMode(bool rejected)
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-header-resume-").FullName;
        try
        {
            string toolPath = Path.Combine(dir, "hashcat"), hash = Path.Combine(dir, "original.hash");
            var target = ZipCryptoSample.Extract(CollidingArchive());
            File.WriteAllText(hash, target.HashLines + "\n");
            File.WriteAllText(toolPath, $$"""
                #!/usr/bin/env python3
                import sys, struct, os, json
                args = sys.argv[1:]
                previous = os.path.exists('calls.jsonl')
                with open('calls.jsonl', 'a') as f: f.write(json.dumps(args) + '\n')
                restore = args[args.index('--restore-file-path') + 1]
                if not previous:
                    data = bytearray(280)
                    struct.pack_into('<Q', data, 272, 12345)
                    with open(restore, 'wb') as f: f.write(data)
                    print('{"status":3,"restore_point":12345,"progress":[123450,200000]}', flush=True)
                    if {{(rejected ? "True" : "False")}}:
                        with open(args[args.index('-o') + 1], 'a') as f: f.write('test00\n')
                    sys.exit(2)
                with open(args[args.index('-o') + 1], 'a') as f: f.write('test42\n')
                sys.exit(1)
                """);
            File.SetUnixFileMode(toolPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var attack = new RecoverKit.Core.Attacks.PreparedAttack { Description = "resume" };
            attack.Args.AddRange(["-a", "3", "test?d?d"]);
            var runner = new HashcatRunner(HashcatTool.Locate(toolPath)!) { HashcatMajorVersion = 8 };
            var request = new RunRequest { Mode = target.Modes[0], HashFile = hash, SessionName = "test", SessionDir = dir,
                Attack = attack, ZipCheckBytes = target.ZipCheckBytes, ConfirmPassword = target.ConfirmPassword,
                Settings = new() { DontUsePasswordCache = true } };
            var stopped = await runner.RunAsync(request, CancellationToken.None);
            Assert.Equal(RunOutcome.Aborted, stopped.Outcome);
            Assert.Equal(rejected ? 0 : 12345, stopped.LastStatus!.RestorePoint);
            Assert.Equal(rejected, stopped.RecheckFromStart);
            Assert.True(File.Exists(HashcatRunner.ZipFilterStateFile(dir, "test")));
            var resumed = await runner.RunAsync(request with { Restore = true }, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, resumed.Outcome);
            Assert.Equal(["test42"], resumed.Passwords);
            var calls = File.ReadAllLines(Path.Combine(dir, "calls.jsonl"))
                .Select(line => System.Text.Json.JsonSerializer.Deserialize<string[]>(line)!).ToArray();
            Assert.Equal(2, calls.Length);
            Assert.Equal("17230", calls[0][Array.IndexOf(calls[0], "-m") + 1]);
            Assert.Equal(rejected ? "17200" : "17230", calls[1][Array.IndexOf(calls[1], "-m") + 1]);
            Assert.Equal(!rejected, calls[1].Contains("--restore-position"));
            Assert.False(File.Exists(HashcatRunner.ZipFilterStateFile(dir, "test")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task MissingOrHiddenHeaderHitReplaysTheWholeAssignedRange(bool falsePositive, bool mismatchedKeyspace)
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-header-replay-").FullName;
        try
        {
            var target = ZipCryptoSample.Extract(CollidingArchive());
            string toolPath = Path.Combine(dir, "hashcat"), hash = Path.Combine(dir, "original.hash");
            File.WriteAllText(hash, target.HashLines + "\n");
            File.WriteAllText(toolPath, $$"""
                #!/usr/bin/env python3
                import sys
                args = sys.argv[1:]
                mode = args[args.index('-m') + 1]
                if '--keyspace' in args:
                    print(3 if mode == '17230' and {{(mismatchedKeyspace ? "True" : "False")}} else 2)
                    sys.exit(0)
                with open('calls.txt', 'a') as f: f.write(' '.join(args) + '\n')
                hit = ('test00' if {{(falsePositive ? "True" : "False")}} else '') if mode == '17230' else 'test42'
                if hit:
                    with open(args[args.index('-o') + 1], 'a') as f: f.write(hit + '\n')
                sys.exit(1)
                """);
            File.SetUnixFileMode(toolPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var attack = new RecoverKit.Core.Attacks.PreparedAttack { Description = "synthetic range" };
            attack.Args.AddRange(["-a", "3", "test?d?d", "--skip", "2", "--limit", "7"]);
            string cache = Path.Combine(dir, "cache.potfile");
            var request = new RunRequest { Mode = target.Modes[0], HashFile = hash, Attack = attack,
                SessionName = "test", SessionDir = dir, ZipCheckBytes = target.ZipCheckBytes,
                ConfirmPassword = target.ConfirmPassword, PasswordCachePath = cache, GpuOnly = mismatchedKeyspace };
            var result = await new HashcatRunner(HashcatTool.Locate(toolPath)!).RunAsync(request, CancellationToken.None);
            bool found = falsePositive || mismatchedKeyspace;
            Assert.Equal(found ? RunOutcome.Cracked : RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(found ? new[] { "test42" } : [], result.Passwords);
            var calls = File.ReadAllLines(Path.Combine(dir, "calls.txt"));
            Assert.Equal(falsePositive && !mismatchedKeyspace ? 2 : 1, calls.Length);
            if (!mismatchedKeyspace) Assert.Contains("-m 17230", calls[0]);
            if (found) Assert.Contains("-m " + target.Modes[0], calls[^1]);
            Assert.All(calls, c => Assert.Contains("--skip 2 --limit 7", c));
            Assert.All(calls, c => Assert.DoesNotContain("--restore-position", c));
            if (found) Assert.StartsWith(target.HashLines + ":", File.ReadAllText(cache));
            else Assert.False(File.Exists(cache));
            Assert.Equal(target.HashLines + "\n", File.ReadAllText(hash));
        }
        finally { Directory.Delete(dir, true); }
    }
}

[Trait("Category", "Slow")]
[Collection("NativeFeatures")]
public class ZipCheckBytesSlowTests
{
    [Fact]
    public async Task HybridBaseWordCountsAgreeWithTheOriginalModes()
    {
        var tool = HashcatTool.Locate(Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT"));
        Assert.NotNull(tool);
        foreach (string mask in new[] { "?l?l?l?l", "?l?l?l?l?l?l4242", "?a?a?a?a?a?a?a?a" })
        {
            string[] args = ["-a", "3", mask, "--skip", "2", "--limit", "7"];
            var headers = await tool.KeyspaceAsync(17230, args);
            Assert.NotNull(headers);
            Assert.Equal(await tool.KeyspaceAsync(17200, args), headers);
            Assert.Equal(await tool.KeyspaceAsync(17210, args), headers);
        }
    }

    [Fact]
    public async Task MaskAndDictionaryConfirmAgainstTheOriginalEntryOnEveryGpuBackend()
    {
        var tool = HashcatTool.Locate(Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT"));
        Assert.NotNull(tool);
        var devices = (await tool.DevicesAsync()).Where(d => d.IsGpu).ToList();
        Assert.NotEmpty(devices);
        string dir = Directory.CreateTempSubdirectory("rk-header-gpu-").FullName;
        try
        {
            string hash = Path.Combine(dir, "original.hash"), dict = Path.Combine(dir, "words.txt");
            foreach (var target in new[] { ZipCryptoSample.Extract(ZipCheckBytesTests.CollidingArchive()),
                ZipCryptoSample.Extract(ZipCheckBytesTests.MixedArchive()), ZipCheckBytesTests.Target(4, twoBytes: true, descriptor: false),
                ZipCheckBytesTests.Target(8, descriptorUsesCrc: true) })
            {
                File.WriteAllText(hash, target.HashLines + "\n");
                foreach (var device in devices)
                foreach (bool dictionary in new[] { false, true })
                {
                    var attack = new RecoverKit.Core.Attacks.PreparedAttack { Description = "synthetic header collision" };
                    if (dictionary)
                    {
                        File.WriteAllLines(dict, ["test00", "unrelated", "test42"]);
                        attack.Args.AddRange(["-a", "0", dict]);
                    }
                    else attack.Args.AddRange(["-a", "3", "test?d?d"]);
                    var settings = new RecoverKit.Core.Settings { DontUsePasswordCache = true,
                        GpuPerformanceChoice = new() { DeviceKeys = [device.Key] } };
                    var request = new RunRequest { Mode = target.Modes[0], HashFile = hash, SessionName = "headers",
                        SessionDir = dir, Attack = attack, Settings = settings, ZipCheckBytes = target.ZipCheckBytes, GpuOnly = !dictionary,
                        ConfirmPassword = target.ConfirmPassword };
                    var result = await new HashcatRunner(tool) { KnownDevices = devices }.RunAsync(request, CancellationToken.None);
                    bool accepted = target.ConfirmPassword!("test42"u8.ToArray());
                    Assert.Equal(accepted ? RunOutcome.Cracked : RunOutcome.Exhausted, result.Outcome);
                    Assert.Equal(accepted ? new[] { "test42" } : [], result.Passwords);
                    if (accepted) Assert.True(ZipCryptoKernel.TryParse(target.HashLines)!.Verify(Encoding.ASCII.GetBytes(result.Passwords[0])));
                }
            }
            foreach (var device in devices)
                Assert.True(await GpuZipCorrectness.CheckAsync(tool, device, ZipKernelBenchmark.CheckBytesSample(), "replacement", CancellationToken.None));
        }
        finally { Directory.Delete(dir, true); }
    }
}
