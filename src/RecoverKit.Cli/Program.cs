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

var argv = args.ToList();
if (argv.Count < 1) return Usage();
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
            var session = new RecoverySession(tool, settings) { Devices = devices };
            session.Log += (k, m) => Console.WriteLine($"[{k}] {m}");
            DateTime lastPrint = DateTime.MinValue;
            session.Status += s =>
            {
                if ((DateTime.Now - lastPrint).TotalSeconds < 5 && s.Status == 3) return;
                lastPrint = DateTime.Now;
                Console.WriteLine($"  {s.StatusText}: {s.ProgressDone:N0}/{s.ProgressTotal:N0} ({s.Fraction:P1}) {s.TotalSpeed:N0} H/s, base {s.GuessBase}");
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
    if (keyfiles.Count > 0 || argv.Contains("--pim"))
        throw new ArgumentException("--keyfile and --pim require --volume tc or vc.");
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
}

static int Usage()
{
    Console.WriteLine("usage: recoverkit-cli extract <file> [--full] | crack <file> <attack options> | scenario-line \"/a:b ...\" | install-hashcat [--into dir] [--from portable-hashcat-dir]");
    Console.WriteLine("volume options: --volume tc|vc [--keyfile <path> ...] [--pim N] (VeraCrypt only; 0 = default)");
    return 64;
}
