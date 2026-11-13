using System.Text;
using System.IO.Compression;
using RecoverKit.Core;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native.Kernels;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

/// <summary>
/// RecoverKit's hashcat ZIP kernels on the real GPU: random archives (stored and deflated entries,
/// 1-3 files, passwords of 1 to 64 characters, with and without data descriptors) are attacked with
/// masks of a few thousand candidates, and the passwords hashcat reports (--keep-guessing, so every
/// match) must be exactly those the built-in CPU engine accepts among the same candidates.
///
/// Needs hashcat 8.0.0: RECOVERKIT_TEST_HASHCAT, the configured path or the engines copy. Without it
/// the tests pass without doing anything. Excluded from the default run (Category=Slow):
///   dotnet test tests/RecoverKit.Tests --filter FullyQualifiedName~ZipGpuKernelSlowTests
/// </summary>
[Trait("Category", "Slow")]
public class ZipGpuKernelSlowTests(ITestOutputHelper output)
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";

    private static HashcatTool? Tool()
    {
        var tool = HashcatTool.Locate(Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT") ?? Settings.Load().HashcatPath);
        return tool is not null && HashcatKernels.Inspect(tool.Directory) != HashcatKernels.State.Unsupported ? tool : null;
    }

    private sealed record Case(string Password, string Mask, string Charset, HashTarget Target, string Description);

    /// <summary>A random archive, and a mask over the password with some positions open (always the first one).</summary>
    private static Case MakeCase(Random rng, int length)
    {
        var pw = new string(Enumerable.Range(0, length).Select(_ => Alphabet[rng.Next(Alphabet.Length)]).ToArray());
        int files = rng.Next(1, 4);
        var entries = new List<ZipCryptoSample.Entry>();
        for (int i = 0; i < files; i++)
        {
            bool deflate = rng.Next(2) == 0;
            int size = rng.Next(4) switch { 0 => rng.Next(1, 40), 1 => rng.Next(40, 600), 2 => rng.Next(600, 3000), _ => rng.Next(3000, 9000) };
            var content = deflate ? ZipCryptoSample.Text(size, rng) : Enumerable.Range(0, size).Select(_ => (byte)rng.Next(256)).ToArray();
            entries.Add(new ZipCryptoSample.Entry($"f{i}.dat", content, deflate, DataDescriptor: rng.Next(3) == 0));
        }
        var target = ZipCryptoSample.Extract(ZipCryptoSample.Archive(entries, Encoding.ASCII.GetBytes(pw), rng));

        // Custom charset ?1: the true characters plus random others, about 12 in all.
        var cs = new SortedSet<char>(pw.Distinct());
        while (cs.Count < 12) cs.Add(Alphabet[rng.Next(Alphabet.Length)]);
        // Open positions: the first (hashcat's amplifier, which varies fastest), plus up to two others.
        var open = new SortedSet<int> { 0 };
        for (int k = 0; k < Math.Min(2, length - 1); k++) open.Add(rng.Next(length));
        var mask = new StringBuilder();
        for (int i = 0; i < length; i++) mask.Append(open.Contains(i) ? "?1" : pw[i].ToString());
        string desc = $"pw {length} chars, {files} file(s), mode {target.Modes[0]}, entry {target.HashLines.Length / 2} hex bytes, mask {mask}";
        return new Case(pw, mask.ToString(), new string(cs.ToArray()), target, desc);
    }

    /// <summary>All candidates of the mask that the built-in CPU engine accepts.</summary>
    private static SortedSet<string> CpuMatches(Case c)
    {
        var k = ZipCryptoKernel.TryParse(c.Target.HashLines)!;
        var parts = new List<string>();
        for (int i = 0; i < c.Mask.Length;)
        {
            if (c.Mask[i] == '?') { parts.Add(c.Charset); i += 2; }
            else { parts.Add(c.Mask[i].ToString()); i++; }
        }
        var found = new SortedSet<string>(StringComparer.Ordinal);
        var idx = new int[parts.Count];
        var buf = new byte[parts.Count];
        while (true)
        {
            for (int i = 0; i < parts.Count; i++) buf[i] = (byte)parts[i][idx[i]];
            if (k.Verify(buf)) found.Add(Encoding.ASCII.GetString(buf));
            int p = 0;
            while (p < parts.Count && ++idx[p] == parts[p].Length) idx[p++] = 0;
            if (p == parts.Count) break;
        }
        return found;
    }

    private async Task<SortedSet<string>> GpuMatches(HashcatTool tool, Case c, int device, string dir)
    {
        var hash = Path.Combine(dir, "case.hash");
        var outFile = Path.Combine(dir, "case.out");
        File.WriteAllText(hash, c.Target.HashLines + "\n");
        if (File.Exists(outFile)) File.Delete(outFile);
        var (code, o, e) = await tool.RunAsync(
        [
            "-m", c.Target.Modes[0].ToString(), "-a", "3", hash, c.Mask, "-1", c.Charset, "-d", device.ToString(),
            "--keep-guessing", "--potfile-disable", "--session", "rk-zip-test", "--quiet",
            "-o", outFile, "--outfile-format", "2",
        ], TimeSpan.FromMinutes(10));
        Assert.True(code is 0 or 1, $"hashcat exit {code}: {o} {e}");
        return new SortedSet<string>(File.Exists(outFile) ? File.ReadAllLines(outFile).Where(l => l.Length > 0) : [], StringComparer.Ordinal);
    }

    private async Task RunCases(HashcatTool tool, int seed, int count)
    {
        var devices = (await tool.DevicesAsync()).Where(d => d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase)).ToList();
        var dir = Directory.CreateTempSubdirectory("rk-zip-gpu").FullName;
        try
        {
            var rng = new Random(seed);
            int[] lengths = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 15, 16, 17, 20, 24, 31, 33, 48, 64];
            for (int n = 0; n < count; n++)
            {
                var c = MakeCase(rng, lengths[n % lengths.Length]);
                var cpu = CpuMatches(c);
                Assert.Contains(c.Password, cpu);
                foreach (var dev in devices)
                {
                    var gpu = await GpuMatches(tool, c, dev.Id, dir);
                    output.WriteLine($"#{dev.Id} {dev.Backend}: {c.Description}: {gpu.Count} found");
                    Assert.True(cpu.SetEquals(gpu), $"device #{dev.Id} {dev.Backend}, {c.Description}: CPU [{string.Join(",", cpu)}] GPU [{string.Join(",", gpu)}]");
                }
            }
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task PartialDeflateAcceptsTruncatedDynamicAndStoredBlocks()
    {
        if (Tool() is not { } tool) { output.WriteLine("hashcat 8.0.0 not found, skipped"); return; }
        Assert.True(HashcatKernels.Install(tool.Directory));
        var devices = (await tool.DevicesAsync()).Where(d => d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.NotEmpty(devices);
        var dir = Directory.CreateTempSubdirectory("rk-zip-partial-gpu").FullName;
        try
        {
            var rng = new Random(417);
            var password = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
            foreach (bool text in new[] { true, false })
            {
                var content = new byte[4_000_000];
                if (text) content = ZipCryptoSample.Text(content.Length, rng);
                else rng.NextBytes(content);
                using var compressed = new MemoryStream();
                using (var deflater = new DeflateStream(compressed, CompressionLevel.Optimal, leaveOpen: true)) deflater.Write(content);
                int firstType = compressed.ToArray()[0] & 6;
                Assert.Equal(text ? 4 : 0, firstType);
                var archive = ZipCryptoSample.Archive([new("a.bin", content, true)], Encoding.ASCII.GetBytes(password), rng);
                const int prefixLength = 256 * 1024;
                Assert.True(BitConverter.ToUInt32(archive, 18) > prefixLength);
                var prefix = archive.AsSpan(35, prefixLength).ToArray();
                var check = BitConverter.ToUInt32(archive, 14) >> 16;
                var hash = Path.Combine(dir, "partial.hash");
                var dict = Path.Combine(dir, "partial.dict");
                File.WriteAllText(hash, $"$pkzip2$1*1*1*0*8*{prefixLength:x}*{check:x4}*{check:x4}*{Convert.ToHexString(prefix)}*$/pkzip2$\n");
                var candidates = Enumerable.Range(0, 4096).Select(i => $"{i:X3}{password[3..]}").ToArray();
                File.WriteAllLines(dict, candidates);
                foreach (var device in devices)
                {
                    foreach (int attack in new[] { 0, 3 })
                    {
                        var outFile = Path.Combine(dir, "partial.out");
                        File.Delete(outFile);
                        var args = new List<string>
                        {
                            "-m", "17200", "-a", attack.ToString(), hash, attack == 0 ? dict : "?1?1?1" + password[3..],
                            "-1", "0123456789ABCDEF", "--keep-guessing",
                            "-d", device.Id.ToString(), "--potfile-disable", "--logfile-disable", "--session", "rk-zip-partial-test", "--quiet",
                            "-o", outFile, "--outfile-format", "2",
                        };
                        var (code, stdout, stderr) = await tool.RunAsync(args, TimeSpan.FromSeconds(90));
                        output.WriteLine($"#{device.Id} {device.Backend}, partial {(text ? "dynamic" : "stored")} deflate, attack {attack}: exit {code}, {(File.Exists(outFile) ? File.ReadAllLines(outFile).Length : 0)} hits / 4096 candidates");
                        Assert.True(code is 0 or 1, $"hashcat exit {code}: {stdout} {stderr}");
                        Assert.True(File.Exists(outFile), "Correct password was rejected for a truncated deflate stream");
                        Assert.Equal(password, File.ReadAllText(outFile).Trim());
                        // The right header must not allow an invalid deflate block type through.
                        if (attack == 0)
                        {
                            var invalid = (byte[])prefix.Clone();
                            invalid[12] ^= (byte)(firstType ^ 6);
                            File.WriteAllText(hash, $"$pkzip2$1*1*1*0*8*{prefixLength:x}*{check:x4}*{check:x4}*{Convert.ToHexString(invalid)}*$/pkzip2$\n");
                            File.Delete(outFile);
                            var (invalidCode, invalidOut, invalidErr) = await tool.RunAsync(args, TimeSpan.FromSeconds(90));
                            Assert.True(invalidCode is 0 or 1, $"hashcat exit {invalidCode}: {invalidOut} {invalidErr}");
                            Assert.False(File.Exists(outFile) && File.ReadAllLines(outFile).Length > 0, "Malformed prefix accepted");
                            if (!text)
                            {
                                // Stored blocks have no Huffman precheck; corrupt NLEN inside the inflater.
                                invalid = (byte[])prefix.Clone();
                                invalid[15] ^= 1;
                                File.WriteAllText(hash, $"$pkzip2$1*1*1*0*8*{prefixLength:x}*{check:x4}*{check:x4}*{Convert.ToHexString(invalid)}*$/pkzip2$\n");
                                var (badCode, badOut, badErr) = await tool.RunAsync(args, TimeSpan.FromSeconds(90));
                                Assert.True(badCode is 0 or 1, $"hashcat exit {badCode}: {badOut} {badErr}");
                                Assert.False(File.Exists(outFile) && File.ReadAllLines(outFile).Length > 0, "Inflater error accepted");
                            }
                            // A stream ending before the rest of the prefix is also a false hit.
                            var shortArchive = ZipCryptoSample.Archive([new("a.bin", [42], true)], Encoding.ASCII.GetBytes(password), rng);
                            var shortBody = shortArchive.AsSpan(35, (int)BitConverter.ToUInt32(shortArchive, 18));
                            shortBody.CopyTo(invalid);
                            var shortCheck = BitConverter.ToUInt32(shortArchive, 14) >> 16;
                            File.WriteAllText(hash, $"$pkzip2$1*1*1*0*8*{prefixLength:x}*{shortCheck:x4}*{shortCheck:x4}*{Convert.ToHexString(invalid)}*$/pkzip2$\n");
                            var (shortCode, shortOut, shortErr) = await tool.RunAsync(args, TimeSpan.FromSeconds(90));
                            Assert.True(shortCode is 0 or 1, $"hashcat exit {shortCode}: {shortOut} {shortErr}");
                            Assert.False(File.Exists(outFile) && File.ReadAllLines(outFile).Length > 0, "Early stream end accepted");
                            File.WriteAllText(hash, $"$pkzip2$1*1*1*0*8*{prefixLength:x}*{check:x4}*{check:x4}*{Convert.ToHexString(prefix)}*$/pkzip2$\n");
                        }
                    }
                }
            }
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task PartialStoredHeadersReachBothAttackKernels()
    {
        if (Tool() is not { } tool) { output.WriteLine("hashcat 8.0.0 not found, skipped"); return; }
        Assert.True(HashcatKernels.Install(tool.Directory));
        var devices = (await tool.DevicesAsync()).Where(d => d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.NotEmpty(devices);
        var dir = Directory.CreateTempSubdirectory("rk-zip-partial-stored-gpu").FullName;
        try
        {
            var rng = new Random(418);
            var password = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
            var content = new byte[400_000];
            rng.NextBytes(content);
            var archive = ZipCryptoSample.Archive([new("a.bin", content, false)], Encoding.ASCII.GetBytes(password), rng);
            const int prefixLength = 256 * 1024;
            var prefix = archive.AsSpan(35, prefixLength).ToArray();
            var check = BitConverter.ToUInt32(archive, 14) >> 16;
            string hashLine = $"$pkzip2$1*1*1*0*0*{prefixLength:x}*{check:x4}*{check:x4}*{Convert.ToHexString(prefix)}*$/pkzip2$";
            var hash = Path.Combine(dir, "stored.hash");
            var dict = Path.Combine(dir, "stored.dict");
            File.WriteAllText(hash, hashLine + "\n");
            File.WriteAllText(dict, password + "\n");
            foreach (var device in devices)
            foreach (int attack in new[] { 0, 3 })
            {
                var outFile = Path.Combine(dir, "stored.out");
                File.Delete(outFile);
                var (code, stdout, stderr) = await tool.RunAsync(
                [
                    "-m", "17210", "-a", attack.ToString(), hash, attack == 0 ? dict : password,
                    "-d", device.Id.ToString(), "--potfile-disable", "--logfile-disable", "--session", "rk-zip-partial-stored-test", "--quiet",
                    "-o", outFile, "--outfile-format", "2",
                ], TimeSpan.FromSeconds(90));
                Assert.True(code is 0 or 1, $"hashcat exit {code}: {stdout} {stderr}");
                Assert.True(File.Exists(outFile), "Partial stored header hit was rejected");
                Assert.Equal(password, File.ReadAllText(outFile).Trim());
                output.WriteLine($"#{device.Id} {device.Backend}, partial stored, attack {attack}: correct header reported");
            }
        }
        finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
    }

    [Fact]
    public async Task RandomArchivesGiveTheSamePasswordsAsTheCpuEngine()
    {
        if (Tool() is not { } tool) { output.WriteLine("hashcat 8.0.0 not found, skipped"); return; }
        Assert.True(HashcatKernels.Install(tool.Directory));
        await RunCases(tool, 1, 42);
    }

    /// <summary>
    /// Dictionary attack with rules (-a 0): words that differ from the password in the first and last
    /// character, rules that keep the word, append a character or delete the last one.
    /// </summary>
    [Fact]
    public async Task DictionaryWithRulesGivesTheSamePasswordsAsTheCpuEngine()
    {
        if (Tool() is not { } tool) { output.WriteLine("hashcat 8.0.0 not found, skipped"); return; }
        Assert.True(HashcatKernels.Install(tool.Directory));
        var devices = (await tool.DevicesAsync()).Where(d => d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase)).ToList();
        var dir = Directory.CreateTempSubdirectory("rk-zip-gpu").FullName;
        try
        {
            var rng = new Random(3);
            foreach (int length in new[] { 1, 3, 6, 8, 12, 17, 30 })
            {
                var c = MakeCase(rng, length);
                var stems = new SortedSet<string>(StringComparer.Ordinal);
                foreach (var a in c.Charset)
                    foreach (var b in c.Charset)
                        stems.Add(length == 1 ? a.ToString() : a + c.Password[1..^1] + b);
                // Words: full candidates, and the same without the last character for the append rules.
                var words = stems.Concat(stems.Where(w => w.Length > 1).Select(w => w[..^1])).Distinct().ToList();
                var rules = new List<string> { ":", "]" };
                rules.AddRange(c.Charset.Take(6).Append(c.Password[^1]).Distinct().Select(ch => "$" + ch));
                static string Apply(string rule, string w) => rule == ":" ? w : rule == "]" ? (w.Length > 0 ? w[..^1] : w) : w + rule[1];

                var k = ZipCryptoKernel.TryParse(c.Target.HashLines)!;
                var cpu = new SortedSet<string>(StringComparer.Ordinal);
                foreach (var w in words)
                    foreach (var r in rules)
                    {
                        var cand = Apply(r, w);
                        if (k.Verify(Encoding.ASCII.GetBytes(cand))) cpu.Add(cand);
                    }
                Assert.Contains(c.Password, cpu);

                var hash = Path.Combine(dir, "d.hash");
                var dict = Path.Combine(dir, "d.dict");
                var rule = Path.Combine(dir, "d.rule");
                var outFile = Path.Combine(dir, "d.out");
                File.WriteAllText(hash, c.Target.HashLines + "\n");
                File.WriteAllText(dict, string.Join("\n", words) + "\n");
                File.WriteAllText(rule, string.Join("\n", rules) + "\n");
                foreach (var dev in devices)
                {
                    if (File.Exists(outFile)) File.Delete(outFile);
                    var (code, o, e) = await tool.RunAsync(
                    [
                        "-m", c.Target.Modes[0].ToString(), "-a", "0", hash, dict, "-r", rule, "-d", dev.Id.ToString(),
                        "--keep-guessing", "--potfile-disable", "--session", "rk-zip-test", "--quiet", "-o", outFile, "--outfile-format", "2",
                    ], TimeSpan.FromMinutes(10));
                    Assert.True(code is 0 or 1, $"hashcat exit {code}: {o} {e}");
                    var gpu = new SortedSet<string>(File.Exists(outFile) ? File.ReadAllLines(outFile).Where(l => l.Length > 0) : [], StringComparer.Ordinal);
                    output.WriteLine($"#{dev.Id} {dev.Backend}: -a 0, {c.Description}, {words.Count} words x {rules.Count} rules: {gpu.Count} found");
                    Assert.True(cpu.SetEquals(gpu), $"device #{dev.Id} {dev.Backend}, -a 0, {c.Description}: CPU [{string.Join(",", cpu)}] GPU [{string.Join(",", gpu)}]");
                }
            }
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }

    /// <summary>
    /// The same with a two-entry queue, so it overflows all the time and candidates are retried in the
    /// next round: none may be lost or reported under another candidate's position.
    /// </summary>
    [Fact]
    public async Task QueueOverflowLosesNoCandidate()
    {
        if (Tool() is not { } tool) { output.WriteLine("hashcat 8.0.0 not found, skipped"); return; }
        Assert.True(HashcatKernels.Install(tool.Directory));
        var include = Path.Combine(tool.Directory, "OpenCL", HashcatKernels.IncludeFile);
        var original = File.ReadAllText(include);
        Assert.Contains("#define RK_QUEUE ", original);
        try
        {
            File.WriteAllText(include, System.Text.RegularExpressions.Regex.Replace(original, @"#define RK_QUEUE \d+", "#define RK_QUEUE 2"));
            await RunCases(tool, 2, 14);
        }
        finally
        {
            File.WriteAllText(include, original);
        }
    }
}
