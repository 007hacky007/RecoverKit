using System.Diagnostics;
using System.Text;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

[Trait("Category", "Slow")]
[Collection("NativeFeatures")]
public sealed class ExportCandidatesSlowTests(ITestOutputHelper output)
{
    [Fact]
    public void WindowsHashcatLayoutSelectsUcrt()
    {
        string? directory = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_WINDOWS_HASHCAT");
        if (string.IsNullOrEmpty(directory))
        {
            output.WriteLine("Not run: set RECOVERKIT_TEST_WINDOWS_HASHCAT to a Windows hashcat 8.0.0 folder.");
            return;
        }
        string exe = Path.Combine(directory, "hashcat.exe");
        Assert.True(File.Exists(exe));
        Assert.True(File.Exists(Path.Combine(directory, "hashcat.dll")));
        Assert.Equal("ucrtbase.dll", HashcatMaskOrder.ImportedCrt(exe));
    }

    [Fact]
    public async Task DictionariesMatchHashcatIncludingBytesAndLengthLimits()
    {
        var tool = Tool();
        if (tool is null) return;
        string dir = Directory.CreateTempSubdirectory("rk-export-dictionaries").FullName;
        try
        {
            var cases = new (string Name, byte[] Bytes)[]
            {
                ("line-endings", "alpha\r\nbeta\n\nlast"u8.ToArray()),
                ("carriage-returns", "\r\r\nleft\rright\r\r\n\r"u8.ToArray()),
                ("empty-lines", "\n\r\n\n"u8.ToArray()),
                ("bom", [0xef, 0xbb, 0xbf, .. "first\n\uFEFFsecond\n"u8.ToArray()]),
                ("hex", "$HEX[6162]\n$HEX[]\n$HEX[ff00c3a9]\n$HEX[xyz]\n$HEX[61]\r\n$HEX[244845585b36315d]\n"u8.ToArray()),
                ("binary", [0, 1, 0x7f, 0x80, 0xff, (byte)'\n', 0xc3, 0xa9, (byte)'\n', 0xc3, (byte)'\n']),
                ("lengths", LengthWords()),
            };
            foreach (var (name, bytes) in cases)
            {
                string words = Path.Combine(dir, name + ".txt");
                await File.WriteAllBytesAsync(words, bytes);
                foreach (bool optimized in new[] { false, true })
                {
                    var step = Step("-a", "0", words);
                    if (optimized) step.Args.Add("-O");
                    await Compare(tool, step, dir, name + (optimized ? "-optimized" : "-pure"));
                }
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task MasksMatchHashcatIncludingCharsetOrderAndIncrement()
    {
        var tool = Tool();
        if (tool is null) return;
        string dir = Directory.CreateTempSubdirectory("rk-export-masks").FullName;
        try
        {
            var cases = new (string Name, string[] Args)[]
            {
                ("lower", ["?l"]), ("upper", ["?u"]), ("digits", ["?d"]),
                ("specials", ["?s"]), ("printable", ["?a"]),
                ("hex-lower", ["?h"]), ("hex-upper", ["?H"]),
                ("bytes", ["?b"]), ("byte-pairs", ["?b?b"]),
                ("duplicates", ["-1", "cbacba", "?1?1"]),
                ("nested", ["-1", "ba", "-2", "?1dc", "?1?2"]),
                ("all-custom", ["-1", "ba", "-2", "dc", "-3", "fe", "-4", "hg", "-5", "ji", "-6", "lk", "-7", "nm", "-8", "po", "?1?2?3?4?5?6?7?8"]),
                ("utf8-custom", ["-1", "éa", "?1?1"]),
                ("utf8-literal", ["-1", "ba", "é?1"]),
                ("escaped-question", ["??a?d"]),
                ("hex-literals", ["--hex-charset", "-1", "6261000a0dff", "41?143"]),
                ("hex-mixed", ["--hex-charset", "-1", "61?d62", "?1?1"]),
                ("hex-nested", ["--hex-charset", "-1", "6261", "-2", "?163", "?2?1"]),
                ("hex-utf8", ["--hex-charset", "c3a9"]),
                ("hex-bom", ["--hex-charset", "efbbbf61"]),
                ("hex-looking-literal", ["$HEX[61]"]),
                ("increment", ["-1", "ba", "--increment", "--increment-min", "1", "--increment-max", "3", "X?1?1"]),
                ("increment-defaults", ["-1", "ba", "-i", "?1?1"]),
                ("increment-minimum", ["-1", "ba", "-i", "--increment-min", "2", "X?1?1"]),
                ("increment-maximum", ["-1", "ba", "-i", "--increment-max", "9", "?1?1"]),
                ("pure-boundary", [new string('a', 256)]),
                ("optimized-boundary", ["-O", new string('a', 55)]),
                ("optimized-increment-boundary", ["-O", "-i", "--increment-min", "54", "--increment-max", "56", new string('a', 56)]),
                ("increment-overlong-mask", ["-i", "--increment-min", "1", "--increment-max", "1", new string('a', 257)]),
            };
            foreach (var (name, args) in cases)
                await Compare(tool, Step(["-a", "3", .. args]), dir, name);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task CombinatorsMatchHashcatIncludingLoopOrderAndTruncation()
    {
        var tool = Tool();
        if (tool is null) return;
        string dir = Directory.CreateTempSubdirectory("rk-export-combinators").FullName;
        try
        {
            var cases = new (string Name, byte[] Left, byte[] Right)[]
            {
                ("left-shorter", "a\nb\n"u8.ToArray(), "1\n2\n3\n4\n"u8.ToArray()),
                ("left-longer", "a\nb\nc\nd\n"u8.ToArray(), "1\n2\n"u8.ToArray()),
                ("equal-and-empty", "a\r\n\n"u8.ToArray(), "1\n2\n"u8.ToArray()),
                ("empty-words", "\n\n"u8.ToArray(), "\n\n\n"u8.ToArray()),
                ("rejected-counts", "a\nb\n"u8.ToArray(), Encoding.ASCII.GetBytes("1\n" + new string('x', 32) + "\n2\n")),
                ("hex-and-bytes", "$HEX[6162]\n$HEX[]\n$HEX[ff00]\n$HEX[244845585b36315d]\n"u8.ToArray(), "x\r\ny\n"u8.ToArray()),
                ("lengths", LengthWords(), "x\n"u8.ToArray()),
                ("lengths-reversed", "x\n"u8.ToArray(), LengthWords()),
            };
            foreach (var (name, left, right) in cases)
            {
                string first = Path.Combine(dir, "first.txt"), second = Path.Combine(dir, "second.txt");
                await File.WriteAllBytesAsync(first, left);
                await File.WriteAllBytesAsync(second, right);
                foreach (bool optimized in new[] { false, true })
                {
                    var step = Step("-a", "1", first, second);
                    if (optimized) step.Args.Add("-O");
                    await Compare(tool, step, dir, name + (optimized ? "-optimized" : "-pure"));
                }
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task EmptyFilesKeepHashcatFailureHandling()
    {
        var tool = Tool();
        if (tool is null) return;
        string dir = Directory.CreateTempSubdirectory("rk-export-empty").FullName;
        try
        {
            string empty = Path.Combine(dir, "empty.txt"), words = Path.Combine(dir, "words.txt");
            await File.WriteAllBytesAsync(empty, []);
            await File.WriteAllTextAsync(words, "a\n");
            foreach (bool optimized in new[] { false, true })
            foreach (int mode in new[] { 0, 1 })
            {
                var step = mode == 0 ? Step("-a", "0", empty) : Step("-a", "1", empty, words);
                if (optimized) step.Args.Add("-O");
                Assert.Null(ExportCandidates.TryCreate(step, default, tool.Directory, tool.Exe));
                Assert.Empty(await HashcatCandidates(tool, step, default, usable: false));
                var error = await Assert.ThrowsAsync<IOException>(async () =>
                {
                    await foreach (string candidate in CandidateExport.CandidatesAsync(step, tool, default)) { }
                });
                Assert.Contains("No usable dictionary file found", error.Message);
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    private async Task Compare(HashcatTool tool, PreparedAttack step, string dir, string name)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var expected = await HashcatCandidates(tool, step, timeout.Token);
        var local = ExportCandidates.TryCreate(step, timeout.Token, tool.Directory, tool.Exe);
        Assert.True(local is not null, name + ": the in-process path was not selected.");
        Assert.Equal(expected, local!.ToArray());
        var actual = new List<string>();
        await foreach (string candidate in CandidateExport.CandidatesAsync(step, tool, timeout.Token)) actual.Add(candidate);
        Assert.Equal(expected, actual);
        foreach (string encoding in CandidateExport.Encodings)
        {
            var enc = CandidateExport.EncodingFor(encoding);
            string path = Path.Combine(dir, "export.txt");
            long count = await CandidateExport.WriteDictionaryAsync([step], tool, path, enc, null, timeout.Token);
            Assert.Equal(expected.Count, count);
            await using var memory = new MemoryStream();
            await using (var writer = new StreamWriter(memory, enc, leaveOpen: true) { NewLine = "\r\n" })
                foreach (string word in expected) await writer.WriteLineAsync(word);
            Assert.Equal(memory.ToArray(), await File.ReadAllBytesAsync(path, timeout.Token));
        }
        output.WriteLine($"{name}: {expected.Count} candidates matched in order; all four export encodings matched byte for byte.");
    }

    private static async Task<List<string>> HashcatCandidates(HashcatTool tool, PreparedAttack step, CancellationToken ct, bool usable = true)
    {
        bool mask = step.Args.IndexOf("-a") is int index && index >= 0 && step.Args[index + 1] == "3";
        var args = new List<string> { "--stdout", "--quiet" };
        if (mask) args.Add("--markov-disable");
        args.AddRange(step.Args);
        using var process = new Process { StartInfo = tool.StartInfo(args) };
        process.Start();
        var stderr = process.StandardError.ReadToEndAsync(ct);
        var result = new List<string>();
        try
        {
            string? line;
            while ((line = await process.StandardOutput.ReadLineAsync(ct)) is not null)
                result.Add(HashcatTool.DecodePlain(line));
            await process.WaitForExitAsync(ct);
            Assert.True(usable ? process.ExitCode == 0 : (process.ExitCode & 255) == 244, $"hashcat exit {process.ExitCode}: {await stderr}");
            return result;
        }
        finally
        {
            if (!process.HasExited) process.Kill(true);
        }
    }

    private HashcatTool? Tool()
    {
        string? configured = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        if (string.IsNullOrEmpty(configured))
        {
            output.WriteLine("Not run: set RECOVERKIT_TEST_HASHCAT to a private hashcat copy.");
            return null;
        }
        var tool = HashcatTool.Locate(configured);
        Assert.NotNull(tool);
        return tool;
    }

    private static PreparedAttack Step(params string[] args)
    {
        var step = new PreparedAttack { Description = "candidate comparison" };
        step.Args.AddRange(args);
        return step;
    }

    private static byte[] LengthWords()
    {
        using var stream = new MemoryStream();
        foreach (int length in new[] { 1, 30, 31, 32, 54, 55, 56, 255, 256, 257, 512, 513, 4096 })
        {
            byte[] word = Enumerable.Repeat((byte)'a', length).ToArray();
            stream.Write(word);
            stream.WriteByte((byte)'\n');
            stream.Write(Encoding.ASCII.GetBytes("$HEX[" + Convert.ToHexString(word) + "]\n"));
        }
        return stream.ToArray();
    }
}
