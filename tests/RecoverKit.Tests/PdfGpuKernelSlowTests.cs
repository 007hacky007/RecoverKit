using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using RecoverKit.Core.Native.Simd;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

/// <summary>Explicit opt-in real GPU checks. The supplied engine and its caches are never changed.</summary>
[Trait("Category", "Slow")]
[Collection("NativeFeatures")]
public class PdfGpuKernelSlowTests(ITestOutputHelper output)
{
    private sealed record Case(string Hash, byte[] Password);
    private sealed record Result(string[] Hits, HashcatStatus Status);
    private static string Hex(byte[] value) => Convert.ToHexString(value).ToLowerInvariant();

    private static Case Generate(int mode, byte[] password, int seed, bool metadata = true, int idLength = 16)
    {
        byte[] pad = Convert.FromHexString("28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a");
        var random = new Random(seed);
        byte[] owner = new byte[32], id = new byte[idLength];
        random.NextBytes(owner); random.NextBytes(id);
        byte[] padded = [.. password, .. pad.Take(32 - password.Length)];
        byte[] digest = MD5.HashData([.. padded, .. owner, 0xfc, 0xff, 0xff, 0xff, .. id, .. metadata ? Array.Empty<byte>() : new byte[] { 255, 255, 255, 255 }]);
        int keyLength = mode == 10510 ? 5 : 16;
        for (int i = 0; i < 50; i++) digest = MD5.HashData(digest.AsSpan(0, keyLength));
        byte[] key = digest[..keyLength], u = MD5.HashData([.. pad, .. id]);
        for (int i = 0; i < 20; i++) u = Rc4.Apply(key.Select(b => (byte)(b ^ i)).ToArray(), u);
        int revision = metadata ? 3 : 4, version = metadata ? 2 : 4;
        string hash = $"$pdf${version}*{revision}*{keyLength * 8}*-4*{(metadata ? 1 : 0)}*{id.Length}*{Hex(id)}*32*{Hex([.. u, .. new byte[16]])}*32*{Hex(owner)}";
        Assert.True(PdfRc4Kernel.TryParse(hash)!.Verify(password));
        return new(hash, password);
    }

    private static Case EmptyFixture(string name)
    {
        var pdf = new PdfDocument(PdfOwnerTests.Fixture(name));
        var security = Assert.IsType<PdfDictionary>(pdf.Resolve(pdf.Trailer.Get("Encrypt")));
        byte[] id = Assert.IsType<PdfString>(Assert.IsType<PdfArray>(pdf.Trailer.Get("ID")).Items[0]).Bytes;
        bool metadata = security.Get("EncryptMetadata") is not PdfKeyword { Text: "false" };
        string hash = $"$pdf${security.Int("V")}*{security.Int("R")}*128*{security.Int("P")}*{(metadata ? 1 : 0)}*{id.Length}*{Hex(id)}*32*{Hex(security.Bytes("U"))}*32*{Hex(security.Bytes("O"))}";
        Assert.True(PdfRc4Kernel.TryParse(hash)!.Verify([]));
        return new(hash, []);
    }

    private async Task<Result> Attack(HashcatTool tool, int mode, int device, string hash, string[] attack, string directory,
        bool restore = false, int? expectedCode = null)
    {
        string file = Path.Combine(directory, "target.hash"), outfile = Path.Combine(directory, "hits.txt");
        await File.WriteAllTextAsync(file, hash + "\n");
        File.Delete(outfile);
        var args = new List<string> { "-m", mode.ToString(), "-d", device.ToString(), file, "-o", outfile, "--outfile-format", "1,3",
            "--potfile-disable", "--logfile-disable", "--session", "rk-pdf-test", "--keep-guessing", "--markov-disable", "--status", "--status-json", "--status-timer", "1", "--quiet" };
        if (restore) args.AddRange(["--restore-position", "--restore-file-path", Path.Combine(directory, "position.restore")]);
        else args.Add("--restore-disable");
        args.AddRange(attack);
        var (code, stdout, stderr) = await tool.RunAsync(args, TimeSpan.FromMinutes(3));
        Assert.True(code is 0 or 1, $"exit {code}: {stdout}\n{stderr}");
        if (expectedCode is int expected) Assert.Equal(expected, code);
        var statuses = stdout.Split('\n').Select(l => HashcatStatus.TryParse(l.Trim())).OfType<HashcatStatus>().ToList();
        Assert.NotEmpty(statuses);
        var hits = File.Exists(outfile) ? File.ReadAllLines(outfile).Select(l => l.ToLowerInvariant()).Order(StringComparer.Ordinal).ToArray() : [];
        return new(hits, statuses[^1]);
    }

    private static void Same(Result stock, Result replacement)
    {
        Assert.Equal(stock.Hits, replacement.Hits);
        Assert.Equal(stock.Status.ProgressDone, replacement.Status.ProgressDone);
        Assert.Equal(stock.Status.ProgressTotal, replacement.Status.ProgressTotal);
        Assert.Equal(stock.Status.RestorePoint, replacement.Status.RestorePoint);
        Assert.Equal(stock.Status.Rejected, replacement.Status.Rejected);
    }

    [Fact]
    public async Task OriginalAndReplacementHaveIdenticalHitsAndPositionsOnEveryBackend()
    {
        string? configured = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        if (configured is null) { output.WriteLine("SKIPPED: set RECOVERKIT_TEST_HASHCAT to a hashcat 8.0.0 executable."); return; }
        var source = HashcatTool.Locate(configured)!;
        string directory = Directory.CreateTempSubdirectory("rk-pdf-gpu-test-").FullName;
        try
        {
            PdfKernelBenchmark.PrepareEngine(source.Directory, directory, default);
            var tool = HashcatTool.ForExe(Path.Combine(directory, Path.GetFileName(source.Exe)));
            Assert.True(PdfHashcatKernels.Supported(directory));
            Assert.True(HashcatKernels.EnsureFor(tool, 10500, 0));
            string? previous = Environment.GetEnvironmentVariable("RECOVERKIT_HASHCAT_PDF_KERNELS");
            try
            {
                Environment.SetEnvironmentVariable("RECOVERKIT_HASHCAT_PDF_KERNELS", "0");
                Assert.False(HashcatKernels.EnsureFor(tool, 10500));
                foreach (var (name, hash) in PdfHashcatKernels.Originals)
                    Assert.Equal(hash, HashcatKernels.Hash(File.ReadAllText(Path.Combine(directory, "OpenCL", name))));
            }
            finally { Environment.SetEnvironmentVariable("RECOVERKIT_HASHCAT_PDF_KERNELS", previous); }
            var devices = (await tool.DevicesAsync()).Where(d => d.IsGpu).ToArray();
            Assert.NotEmpty(devices);
            foreach (int mode in new[] { 10500, 10510 })
            {
                var info = await tool.ModeInfoAsync(mode, 3);
                Assert.NotNull(info);
                Assert.False(info.HasOptimizedKernel);
                Assert.Equal(32, info.PasswordLenMax);
                var cases = new List<Case>();
                int seed = 100;
                foreach (int length in new[] { 0, 1, 7, 15, 16, 31, 32 })
                    cases.Add(Generate(mode, Enumerable.Range(0, length).Select(i => (byte)('A' + i % 26)).ToArray(), seed++, idLength: seed % 2 == 0 ? 16 : 32));
                cases.Add(Generate(mode, [0x80, 0xff, 0, 0x7f, 0x41], seed++));
                if (mode == 10500)
                {
                    cases.Add(Generate(mode, "meta-off"u8.ToArray(), seed++, metadata: false));
                    cases.AddRange(new[] { "RC4-128", "AES-128", "metadata-128" }.Select(EmptyFixture));
                }
                else
                {
                    var target = PdfOwnerTests.Extract(PdfExtractorTests.Fixture()).Target!;
                    cases.Add(new(target.HashLines, "r3-test-42"u8.ToArray()));
                }
                var words = cases.Select(c => Hex(c.Password)).Concat(new[] { Hex("rule"u8.ToArray()), new string('a', 66), new string('a', 128), new string('a', 512) }).ToArray();
                cases.Add(Generate(mode, "rule1"u8.ToArray(), seed++));
                string dictionary = Path.Combine(directory, "words.txt"), rules = Path.Combine(directory, "rules.rule");
                await File.WriteAllLinesAsync(dictionary, words);
                await File.WriteAllTextAsync(rules, ":\n$1\n");
                foreach (var device in devices)
                {
                    Result? stock = null;
                    foreach (bool replacement in new[] { false, true })
                    {
                        if (replacement) Assert.True(PdfHashcatKernels.Install(directory)); else PdfHashcatKernels.Restore(directory);
                        var result = await Attack(tool, mode, device.Id, string.Join('\n', cases.Select(c => c.Hash)),
                            ["-a", "0", dictionary, "--hex-wordlist", "-r", rules], directory);
                        foreach (var c in cases) Assert.Contains(c.Hash.ToLowerInvariant() + ":" + Hex(c.Password), result.Hits);
                        Assert.Equal(cases.Count, result.Hits.Length);
                        Assert.True(result.Status.Rejected > 0); // 33, 64 and 256-byte inputs remain outside this module's 32-byte limit.
                        if (stock is null) stock = result; else Same(stock, result);
                    }

                    string example = NativeKernels.BenchmarkHashes[mode];
                    var maskCase = Generate(mode, "ba"u8.ToArray(), 500);
                    foreach (var (hash, attack, expectedHits) in new[]
                    {
                        (example, new[] { "-a", "3", "hashca?1", "-1", "tx" }, 1),
                        (maskCase.Hash, new[] { "-a", "3", "?1?1", "-1", "ab", "--skip", "0", "--limit", "1", "--force", "-u", "7" }, 1),
                        (maskCase.Hash, new[] { "-a", "3", "?1?1", "-1", "ab", "--skip", "1", "--limit", "1" }, 0),
                    })
                    {
                        stock = null;
                        long? keyspace = null;
                        foreach (bool replacement in new[] { false, true })
                        {
                            if (replacement) Assert.True(PdfHashcatKernels.Install(directory)); else PdfHashcatKernels.Restore(directory);
                            long? space = await tool.KeyspaceAsync(mode, attack);
                            Assert.NotNull(space);
                            if (keyspace is null) keyspace = space; else Assert.Equal(keyspace, space);
                            var result = await Attack(tool, mode, device.Id, hash, attack, directory);
                            Assert.Equal(expectedHits, result.Hits.Length);
                            if (stock is null) stock = result; else Same(stock, result);
                        }
                    }

                    // A real hashcat 8 restore-position read, with no saved argv to replace this attack.
                    stock = null;
                    foreach (bool replacement in new[] { false, true })
                    {
                        if (replacement) Assert.True(PdfHashcatKernels.Install(directory)); else PdfHashcatKernels.Restore(directory);
                        byte[] restore = new byte[296];
                        BinaryPrimitives.WriteInt32LittleEndian(restore, 720);
                        Encoding.UTF8.GetBytes(directory).CopyTo(restore, 4);
                        BinaryPrimitives.WriteUInt64LittleEndian(restore.AsSpan(272), 1);
                        await File.WriteAllBytesAsync(Path.Combine(directory, "position.restore"), restore);
                        var result = await Attack(tool, mode, device.Id, maskCase.Hash, ["-a", "3", "?1?1", "-1", "ab"], directory, restore: true, expectedCode: 1);
                        Assert.Empty(result.Hits);
                        Assert.Equal(2, result.Status.RestorePoint);
                        if (stock is null) stock = result; else Same(stock, result);
                    }
                    output.WriteLine($"{mode}, #{device.Id} {device.Backend}: byte/length/rules/metadata/fixtures/mask/skip/limit/restore checks passed.");
                }
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}
