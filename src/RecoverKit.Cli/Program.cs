using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

// recoverkit-cli: headless front-end for the same engine the GUI uses.
//   recoverkit-cli extract <file> [--volume tc|vc --kdf sha512,ripemd160 --cascade 1,2,3 --hidden --boot --keyfile path --pim N]
//   recoverkit-cli crack <file> <attack...> [--hashcat path]
//     attacks: --scenario "Name" | --brute csde --min 1 --max 6 [--mask "pass????"] |
//              --hcmask "?u?l?l?d" [-1 chars ..] | --dict file [--rules simple|advanced|complex|two|two-adv|three|file.rule]
//   recoverkit-cli scenario-line "/a:b /c:d /min:1 /max:4"
//   recoverkit-cli bench-zip [--hashcat path] [--device N[,N]] [--seconds S] [--quick]   ZipCrypto GPU kernels, hashcat's vs RecoverKit's

var argv = args.ToList();
if (argv.Count < 1) return Usage();
// The elevated NVIDIA power limit helper (started by RecoverKit itself, see PowerLimiter).
if (argv[0] == PowerHelper.Command) return PowerHelper.Run(args);
string cmd = argv[0];

try
{
    switch (cmd)
    {
        case "extract":
        {
            if (argv.Count < 2) return Usage();
            var d = Open(argv[1], argv);
            if (argv.Contains("--full")) { if (d.Target is not null) Console.WriteLine(d.Target.HashLines); }
            else Print(d);
            return d.Target is null ? 2 : 0;
        }
        case "bench-prims":
        {
            foreach (var (name, ps) in RecoverKit.Core.Native.NativeKernels.BenchmarkPrimitives())
                Console.WriteLine($"{name,-34}: {ps:N0}/s  ({2.1e9 / ps:N0} cycles @2.1GHz)");
            if (RecoverKit.Core.Native.RkNative.Available)
                foreach (var (w, name) in new[] { (0, "native RC4 KSA16 x4"), (1, "native RC4 KSA16 x8"), (2, "native RC4 KSA5 x4"), (3, "native RC4 KSA16 x8 C"), (4, "native RC4 KSA16 x8 asm"), (5, "native RC4 KSA16z5 x8 asm") })
                    Console.WriteLine($"{name,-34}: {RecoverKit.Core.Native.RkNative.Bench(w, 400_000):N0} TSC ticks each");
            return 0;
        }
        case "bench-native":
        {
            // recoverkit-cli bench-native [--threads N] [--seconds S] [--mode M] [--length L] [--managed] [--force-vector]
            int threads = int.TryParse(Opt(argv, "--threads"), out var th) ? th : Environment.ProcessorCount;
            int seconds = int.TryParse(Opt(argv, "--seconds"), out var se) ? se : 6;
            int length = int.TryParse(Opt(argv, "--length"), out var le) ? le : 0;
            var modes = Opt(argv, "--mode") is { } m ? [int.Parse(m)] : RecoverKit.Core.Native.NativeKernels.BenchmarkHashes.Keys.ToArray();
            // --managed: skip the native library; --force-vector: run the managed vector kernels even without hardware Vector256.
            if (argv.Contains("--managed")) RecoverKit.Core.Native.RkNative.Disabled = true;
            if (argv.Contains("--force-vector")) RecoverKit.Core.Native.NativeKernels.ForceVectorKernels = true;
            Console.WriteLine($"Built-in CPU engine, {threads} threads, {RecoverKit.Core.Native.NativeKernels.CpuFeatures()}");
            foreach (var mode in modes)
                Console.WriteLine($"mode {mode,6}: {RecoverKit.Core.Native.NativeKernels.Benchmark(mode, threads, TimeSpan.FromSeconds(seconds), default, length):N0} p/s");
            return 0;
        }
        case "bench-zip":
        {
            // recoverkit-cli bench-zip [--hashcat path] [--device N[,N]] [--seconds S] [--quick]
            // hashcat's ZipCrypto kernels against RecoverKit's replacements, per device.
            var settings = Settings.Load();
            if (HashcatInstaller.BundledDirectory is not null) HashcatInstaller.TryInstallBundled();
            var tool = HashcatTool.Locate(Opt(argv, "--hashcat") ?? settings.HashcatPath)
                ?? throw new InvalidOperationException("hashcat not found. Run 'recoverkit-cli install-hashcat' first, or pass --hashcat <path>.");
            Console.WriteLine($"Using {tool.Exe} ({await tool.VersionAsync()})");
            if (HashcatKernels.Inspect(tool.Directory) == HashcatKernels.State.Unsupported)
            {
                Console.WriteLine($"This hashcat's PKZIP kernels are not hashcat {HashcatInstaller.Version}'s, so RecoverKit's kernels cannot be used with it.");
                return 2;
            }
            var devices = await tool.DevicesAsync();
            var only = Opt(argv, "--device")?.Split(',').Select(int.Parse).ToHashSet();
            // Every backend device, aliases included: an NVIDIA GPU shows as CUDA and as OpenCL.
            var chosen = devices.Where(d => only?.Contains(d.Id) ?? true).ToList();
            foreach (var dev in devices)
                Console.WriteLine($"Device #{dev.Id}: {dev.Name} ({dev.Type}, {dev.Backend}{(dev.AliasOf is int a ? $", alias of #{a}" : "")}){(chosen.Contains(dev) ? "" : ", not measured")}");
            if (devices.Any(d => d.Vendor.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase) || d.Name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase))
                && !devices.Any(d => d.Backend == "CUDA"))
                Console.WriteLine("Note: no CUDA device. hashcat uses CUDA on NVIDIA GPUs only when it finds NVRTC (CUDA Toolkit); see docs/benchmarks.md.");
            var bench = new ZipKernelBenchmark(tool)
            {
                Seconds = int.TryParse(Opt(argv, "--seconds"), out var sec) ? sec : 10,
                WithAmpCache = !argv.Contains("--quick"),
            };
            bench.Progress += Console.WriteLine;
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
            var rows = await bench.RunAsync(chosen, ZipKernelBenchmark.DefaultSamples(), cts.Token);
            Console.WriteLine();
            Console.WriteLine($"ZipCrypto brute force, mask {bench.Mask}, {bench.Seconds} s per run, median speed:");
            Console.Write(ZipKernelBenchmark.Format(rows));
            return 0;
        }
        case "scenario-line":
        {
            var a = ScenarioParser.ParseLine(argv[1]);
            Console.WriteLine(a.Describe());
            return 0;
        }
        case "decrypt":
        {
            if (argv.Count < 3) { Console.Error.WriteLine("usage: recoverkit-cli decrypt <office-file> <password> [output]"); return 64; }
            var inp = argv[1];
            var pwd = argv[2];
            var outPath = argv.Count > 3 && !argv[3].StartsWith('-')
                ? argv[3]
                : Path.Combine(Path.GetDirectoryName(Path.GetFullPath(inp))!, Path.GetFileNameWithoutExtension(inp) + "_decrypted" + Path.GetExtension(inp));
            try
            {
                OfficeDecryptor.DecryptToFile(inp, pwd, outPath);
                Console.WriteLine("Decrypted: " + outPath);
                return 0;
            }
            catch (Exception ex) when (ex is UnsupportedFormatException or IOException or FormatException or System.Security.Cryptography.CryptographicException)
            {
                Console.Error.WriteLine("Decrypt failed: " + ex.Message);
                return 3;
            }
        }
        case "unlock":
        {
            // Applies an instant unlock found by detection (default password, removable restriction...).
            if (argv.Count < 2) { Console.Error.WriteLine("usage: recoverkit-cli unlock <file> [--index N] [--out path]"); return 64; }
            var det = Open(argv[1], argv);
            Print(det);
            if (det.Unlocks.Count == 0) { Console.Error.WriteLine("Nothing to unlock instantly."); return 2; }
            InstantUnlock u;
            if (Opt(argv, "--index") is "all")
            {
                if (InstantUnlock.All(det.Unlocks) is not { } all) { Console.Error.WriteLine("Fewer than two restrictions can be saved; use --index N."); return 64; }
                u = all;
            }
            else
            {
                int index = int.Parse(Opt(argv, "--index") ?? "1", System.Globalization.CultureInfo.InvariantCulture);
                if (index < 1 || index > det.Unlocks.Count) { Console.Error.WriteLine($"--index must be 1 to {det.Unlocks.Count} or all."); return 64; }
                u = det.Unlocks[index - 1];
            }
            if (u.SaveCopyAsync is null) return 0;
            var outPath = Opt(argv, "--out") ?? u.SuggestedPath(argv[1]);
            await u.SaveAsync(argv[1], outPath);
            Console.WriteLine("Saved: " + outPath);
            return 0;
        }
        case "install-hashcat":
        {
            var inst = new HashcatInstaller(Opt(argv, "--into"));
            Console.WriteLine($"Installing hashcat {HashcatInstaller.Version} into {inst.InstallRoot}");
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
            string lastStage = ""; DateTime last = DateTime.MinValue;
            var prog = new Progress<InstallProgress>(p =>
            {
                if (p.Stage != lastStage) { if (lastStage.Length > 0) Console.WriteLine(); lastStage = p.Stage; }
                if (p.BytesTotal > 0 && (DateTime.Now - last).TotalMilliseconds >= 200)
                {
                    last = DateTime.Now;
                    Console.Write($"\r  {p.Stage}: {p.BytesDone / 1_000_000.0:N1}/{p.BytesTotal / 1_000_000.0:N1} MB ({p.Fraction:P0})   ");
                }
                else if (p.Message.Length > 0) Console.WriteLine("  " + p.Message);
            });
            try
            {
                // --from <dir>: install a portable hashcat folder (for example macos/out/hashcat) instead.
                var res = Opt(argv, "--from") is { } from
                    ? await inst.InstallFromFolderAsync(from, prog, cts.Token)
                    : await inst.InstallAsync(prog, cts.Token);
                Console.WriteLine();
                Console.WriteLine($"Installed to: {res.Directory}");
                if (res.ExecutablePath is { } exe)
                {
                    var st = Settings.Load();
                    st.HashcatPath = exe;
                    st.Save();
                    Console.WriteLine($"hashcat ready: {exe}");
                    Console.WriteLine($"Saved as the default hashcat path.");
                }
                else
                {
                    Console.WriteLine("The release contains no binary for this OS (it ships hashcat.exe and hashcat.bin).");
                }
                return 0;
            }
            catch (InstallException ex)
            {
                Console.Error.WriteLine("Install failed: " + ex.Message);
                return 3;
            }
        }
        case "crack":
        {
            if (argv.Count < 2) return Usage();
            var settings = Settings.Load();
            settings.HashcatPath = Opt(argv, "--hashcat") ?? settings.HashcatPath;
            if (Opt(argv, "--workload") is { } w) settings.Workload = int.Parse(w);
            if (argv.Contains("--no-potfile")) settings.DontUsePasswordCache = true;
            // GPU temperature guard and load limit, e.g. --temp-limit 85 --temp-hysteresis 10 --gpu-duty 50
            if (Opt(argv, "--temp-limit") is { } tl) { settings.GpuTempGuard = true; settings.GpuTempLimit = int.Parse(tl); }
            if (Opt(argv, "--temp-hysteresis") is { } th) settings.GpuTempHysteresis = int.Parse(th);
            if (Opt(argv, "--gpu-duty") is { } gd) settings.GpuDutyPercent = int.Parse(gd);
            int? powerLimit = Opt(argv, "--power-limit") is { } pl ? int.Parse(pl) : null;
            if (Opt(argv, "--strategy") is { } strat) settings.Strategy = Enum.Parse<DeviceStrategy>(strat, ignoreCase: true);
            // macOS app: refresh the per-user copy of the hashcat bundled in RecoverKit.app (no-op elsewhere).
            if (HashcatInstaller.BundledDirectory is not null && HashcatInstaller.TryInstallBundled())
                Console.WriteLine($"Bundled hashcat {HashcatInstaller.BundledStamp} is installed.");
            var tool = HashcatTool.Locate(settings.HashcatPath)
                ?? throw new InvalidOperationException("hashcat not found. Run 'recoverkit-cli install-hashcat' to download it, or pass --hashcat <path>.");
            Console.WriteLine($"Using {tool.Exe} ({await tool.VersionAsync()})");

            var d = Open(argv[1], argv);
            Print(d);
            if (d.Target is null) return 2;

            var steps = BuildSteps(argv, d.Target);
            if (argv.Contains("--no-stay")) steps = steps.Where(s => s.Kind != AttackKind.StayZip).ToList();
            // Same device detection as the GUI, so the CPU/GPU strategy and built-in engine decisions match.
            var devices = await tool.DevicesAsync();
            foreach (var dev in devices)
                Console.WriteLine($"Device #{dev.Id}: {dev.Name} ({dev.Type}, {dev.Backend}{(dev.IsSkippedAlias ? ", skipped by hashcat" : "")})");
            if (powerLimit is int watts)
            {
                var gpus = await PowerLimiter.QueryAsync();
                if (gpus.Count == 0) Console.WriteLine("No NVIDIA GPU with an adjustable power limit was found; --power-limit is ignored.");
                foreach (var g in gpus)
                {
                    Console.WriteLine($"GPU {g.Index}: {g.Name}, power limit {g.MinAllowed}-{g.MaxAllowed} W, default {PowerLimitRequest.Watts(g.DefaultWatts)}, now {PowerLimitRequest.Watts(g.CurrentWatts)}");
                    if (g.Allows(watts)) settings.GpuPowerWatts[g.Index] = watts;
                    else Console.WriteLine($"  {watts} W is outside the allowed range; this GPU keeps its limit.");
                }
                settings.GpuPowerLimit = gpus.Count > 0;
            }
            var session = new RecoverySession(tool, settings) { Devices = devices };
            session.ConfirmElevation = request =>
            {
                Console.WriteLine(request.Explanation);
                Console.Write("Continue? [y] yes, [n] run without the power limit, [c] cancel: ");
                string answer = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
                return Task.FromResult(answer switch
                {
                    "y" or "yes" => ElevationChoice.Continue,
                    "c" or "cancel" => ElevationChoice.Cancel,
                    _ => ElevationChoice.WithoutPowerLimit,
                });
            };
            session.Log += (k, m) => Console.WriteLine($"[{k}] {m}");
            session.Thermal += e => Console.WriteLine($"[Thermal] {e.State} at {e.Temperature} °C (limit {e.Limit} °C, resume at {e.ResumeBelow} °C)");
            DateTime lastPrint = DateTime.MinValue;
            session.Status += s =>
            {
                if ((DateTime.Now - lastPrint).TotalSeconds < 5 && s.Status == 3) return;
                lastPrint = DateTime.Now;
                int temp = ThermalGuard.Hottest(s.Devices);
                Console.WriteLine($"  {s.StatusText}: {s.ProgressDone:N0}/{s.ProgressTotal:N0} ({s.Fraction:P1}) {s.TotalSpeed:N0} H/s, base {s.GuessBase}" +
                                  (temp >= 0 ? $", GPU {temp} °C" : ""));
            };
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
            if (Opt(argv, "--stop-after") is { } sa) cts.CancelAfter(TimeSpan.FromSeconds(int.Parse(sa)));
            var resume = argv.Contains("--new") ? null : SessionState.Load(settings, d.Target);
            if (resume is not null) Console.WriteLine($"Resuming interrupted session from {resume.SavedUtc.ToLocalTime():g} (pass --new to start over).");
            var res = await session.RunAsync(d.Target, d.FilePath, steps, resume, cts.Token);
            var persisted = Settings.Load(); // command-line overrides are not persisted
            persisted.SpeedByMode = settings.SpeedByMode;
            persisted.Save();
            Console.WriteLine($"RESULT: {res.Outcome}");
            foreach (var p in res.Passwords) Console.WriteLine($"PASSWORD: {p}");
            if (res.Key is not null) Console.WriteLine($"KEY: {res.Key}");
            if (res.DecryptedCopy is not null) Console.WriteLine($"DECRYPTED: {res.DecryptedCopy}");
            if (res.Error is not null) Console.WriteLine($"ERROR: {res.Error}");
            return res.Outcome is SessionOutcome.Found or SessionOutcome.FoundInCache ? 0 : 1;
        }
        default:
            return Usage();
    }
}
catch (Exception ex) when (ex is AttackPlanException or InvalidOperationException or FormatException or ArgumentException or IOException or UnauthorizedAccessException or OverflowException)
{
    Console.Error.WriteLine("Error: " + ex.Message);
    return 3;
}

static Detection Open(string path, List<string> argv)
{
    var keyfiles = new List<string>();
    for (int i = 2; i < argv.Count; i++)
    {
        if (argv[i] is not ("--keyfile" or "--pim" or "--volume")) continue;
        string flag = argv[i];
        if (i + 1 >= argv.Count || argv[i + 1].StartsWith("--"))
            throw new ArgumentException($"{flag} requires a value.");
        if (flag == "--keyfile") keyfiles.Add(argv[i + 1]);
        i++;
    }
    if (Opt(argv, "--volume") is { } vol)
    {
        if (vol is not ("tc" or "vc")) throw new ArgumentException("--volume must be tc or vc.");
        var o = new VolumeOptions
        {
            Kind = vol == "tc" ? VolumeKind.TrueCrypt : VolumeKind.VeraCrypt,
            HeaderOffset = argv.Contains("--hidden") ? VolumeOptions.HiddenOffset : 0,
            BootVolume = argv.Contains("--boot"),
            Kdfs = VolumeKdf.None,
            Ciphers = VolumeCipher.None,
            Keyfiles = keyfiles,
            Pim = int.Parse(Opt(argv, "--pim") ?? "0", System.Globalization.CultureInfo.InvariantCulture),
        };
        foreach (var k in (Opt(argv, "--kdf") ?? "sha512").Split(','))
            o.Kdfs |= k switch { "ripemd160" => VolumeKdf.Ripemd160, "sha512" => VolumeKdf.Sha512, "whirlpool" => VolumeKdf.Whirlpool, "sha256" => VolumeKdf.Sha256, "streebog" => VolumeKdf.Streebog, _ => throw new ArgumentException("bad kdf " + k) };
        foreach (var c in (Opt(argv, "--cascade") ?? "1").Split(','))
            o.Ciphers |= c switch { "1" => VolumeCipher.Single, "2" => VolumeCipher.Double, "3" => VolumeCipher.Triple, _ => throw new ArgumentException("bad cascade " + c) };
        return CryptVolume.Open(path, o);
    }
    if (argv.Contains("--pim"))
        throw new ArgumentException("--pim requires --volume tc or vc.");
    if (keyfiles.Count > 1) throw new ArgumentException("KeePass accepts one --keyfile. Multiple keyfiles require --volume tc or vc.");
    if (keyfiles.Count == 1)
    {
        if (argv.Contains("--hash-mode")) throw new ArgumentException("KeePass --keyfile requires a database file, not --hash-mode.");
        return FormatDetector.Detect(path, keyfiles[0]);
    }
    if (Opt(argv, "--hash-mode") is { } hm) return FormatDetector.FromManualHash(path, int.Parse(hm), File.ReadAllText(path));
    return FormatDetector.Detect(path);
}

static List<AttackSpec> BuildSteps(List<string> argv, HashTarget t)
{
    if (Opt(argv, "--scenario") is { } name)
    {
        var sc = ScenarioParser.LoadDefault().FirstOrDefault(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                 ?? throw new ArgumentException("Unknown scenario: " + name);
        return sc.Steps;
    }
    if (Opt(argv, "--scenario-file") is { } sf)
    {
        var all = ScenarioParser.LoadFile(sf, out var errs);
        foreach (var e in errs) Console.Error.WriteLine("scenario: " + e);
        return (all.FirstOrDefault(s => s.DefaultFor.Contains(t.FormatId)) ?? all.First()).Steps;
    }
    if (Opt(argv, "--default-scenario") is not null)
    {
        var all = ScenarioParser.LoadDefault();
        return (all.FirstOrDefault(s => s.DefaultFor.Contains(t.FormatId)) ?? all[0]).Steps;
    }
    var a = new AttackSpec();
    if (Opt(argv, "--brute") is { } cs)
    {
        a.Kind = AttackKind.BruteForce;
        a.Caps = cs.Contains('c'); a.Smalls = cs.Contains('s'); a.Digits = cs.Contains('d'); a.Specials = cs.Contains('e');
        if (Opt(argv, "--user") is { } u) { a.UseUserCharset = true; a.UserCharset = u; }
        if (Opt(argv, "--alphabet") is { } al) a.Alphabet = al;
        a.MinLength = int.Parse(Opt(argv, "--min") ?? "1");
        a.MaxLength = int.Parse(Opt(argv, "--max") ?? "4");
        a.Mask = Opt(argv, "--mask") ?? "";
    }
    else if (Opt(argv, "--hcmask") is { } m)
    {
        a.Kind = AttackKind.Mask;
        a.HashcatMask = m;
        for (int i = 1; i <= 8; i++) a.CustomCharsets[i - 1] = Opt(argv, $"-{i}") ?? "";
        if (Opt(argv, "--min") is { } mn) { a.Increment = true; a.MinLength = int.Parse(mn); a.MaxLength = int.Parse(Opt(argv, "--max") ?? "64"); }
    }
    else if (Opt(argv, "--dict") is { } dict)
    {
        a.Kind = AttackKind.Dictionary;
        a.Dictionaries[0] = dict;
        a.Dictionaries[1] = Opt(argv, "--dict2");
        a.Dictionaries[2] = Opt(argv, "--dict3");
        string r = Opt(argv, "--rules") ?? "asis";
        a.Rules = r switch
        {
            "asis" => RulesPreset.AsIs, "simple" => RulesPreset.Simple, "advanced" => RulesPreset.Advanced, "complex" => RulesPreset.Complex,
            "two" => RulesPreset.TwoWords, "two-adv" => RulesPreset.TwoWordsAdvanced, "three" => RulesPreset.ThreeWords,
            _ => RulesPreset.CustomFile,
        };
        if (a.Rules == RulesPreset.CustomFile) a.RulesFile = r;
        a.SkipShorterThan = int.Parse(Opt(argv, "--skip-shorter") ?? "0");
        a.SkipLongerThan = int.Parse(Opt(argv, "--skip-longer") ?? "0");
    }
    else throw new ArgumentException("No attack given.");
    return [a];
}

static string? Opt(List<string> argv, string name)
{
    int i = argv.IndexOf(name);
    return i >= 0 && i + 1 < argv.Count ? argv[i + 1] : null;
}

static void Print(Detection d)
{
    Console.WriteLine($"File:       {d.FilePath}");
    Console.WriteLine($"Type:       {d.TypeName}");
    foreach (var kv in d.Info) Console.WriteLine($"  {kv.Key}: {kv.Value}");
    if (d.Target is { } t)
    {
        Console.WriteLine($"Protection: {t.Protection}");
        Console.WriteLine($"Format id:  {t.FormatId}");
        Console.WriteLine($"Modes:      {string.Join(", ", t.Modes)}");
        Console.WriteLine($"HASH:       {(t.HashLines.Length > 300 ? t.HashLines[..300] + $"... ({t.HashLines.Length} chars)" : t.HashLines)}");
    }
    if (d.Message is not null) Console.WriteLine($"Message:    {d.Message}");
    for (int i = 0; i < d.Unlocks.Count; i++)
    {
        var u = d.Unlocks[i];
        Console.WriteLine($"UNLOCK {i + 1}:   {u.Title}");
        Console.WriteLine($"            {u.Description}");
        if (u.Password is { } pw) Console.WriteLine($"PASSWORD:   {pw}");
        if (u.SaveCopyAsync is not null) Console.WriteLine($"            recoverkit-cli unlock <file> --index {i + 1} [--out <path>]");
    }
    if (InstantUnlock.All(d.Unlocks) is not null)
        Console.WriteLine("UNLOCK ALL: recoverkit-cli unlock <file> --index all [--out <path>] removes every restriction above in one copy");
}

static int Usage()
{
    Console.WriteLine("usage: recoverkit-cli extract <file> [--full] | crack <file> <attack options> | unlock <file> [--index N|all] [--out path] | scenario-line \"/a:b ...\" | install-hashcat [--into dir] [--from portable-hashcat-dir] | bench-zip [--device N] [--seconds S]");
    Console.WriteLine("volume options: --volume tc|vc [--keyfile <path> ...] [--pim N] (VeraCrypt only; 0 = default)");
    Console.WriteLine("KeePass options: --keyfile <path> (optional, one keyfile for a .kdbx or .kdb database)");
    Console.WriteLine("GPU options: --temp-limit <°C> [--temp-hysteresis <°C>] pause while the GPU is too hot; --gpu-duty <10-100> share of time the GPU works; --power-limit <watts> NVIDIA power limit (asks for administrator rights)");
    return 64;
}
