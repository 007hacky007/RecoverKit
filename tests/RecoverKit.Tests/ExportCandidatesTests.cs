using System.Buffers.Binary;
using System.Text;
using RecoverKit.Core.Attacks;
using Xunit;

namespace RecoverKit.Tests;

public sealed class ExportCandidatesTests
{
    [Fact]
    public void MasksUseHashcatExportOrder()
    {
        var symbols = Generate("-a", "3", "-1", "baba", "?1");
        Assert.Equal(["a", "b"], symbols.Order(StringComparer.Ordinal));
        string a = symbols[0], b = symbols[1];
        Assert.Equal([a + a, b + a, a + b, b + b], Generate("-a", "3", "-1", "baba", "?1?1"));
        Assert.Equal(["X", "X" + a, "X" + b, "X" + a + a, "X" + b + a, "X" + a + b, "X" + b + b],
            Generate("-a", "3", "-1", "ba", "-i", "--increment-min", "1", "--increment-max", "3", "X?1?1"));
        Assert.Equal(["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b"],
            Generate("-a", "3", "--hex-charset", "-1", "61?d62", "?1").Order(StringComparer.Ordinal));
        Assert.Equal(["a", "\u00a9", "\u00c3"], Generate("-a", "3", "-8", "éa", "?8").Order(StringComparer.Ordinal));
        Assert.Equal(["é0", "é1", "é2", "é3", "é4", "é5", "é6", "é7", "é8", "é9"], Generate("-a", "3", "é?d").Order(StringComparer.Ordinal));
    }

    [Fact]
    public void BinaryMasksKeepHexDecodingAndByteOrder()
    {
        var expected = new[] { "ÿ" }.Concat(Enumerable.Range(1, 254).Select(i => ((char)i).ToString())).Append("\0");
        var actual = Generate("-a", "3", "?b");
        Assert.Equal(expected.Order(StringComparer.Ordinal), actual.Order(StringComparer.Ordinal));
        if (OperatingSystem.IsMacOS()) Assert.Equal(expected, actual);
        Assert.Equal(["\0", "\n", "\r", "a", "b", "\u00ff"],
            Generate("-a", "3", "--hex-charset", "-1", "6261000a0dff", "?1").Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData(false, 256)]
    [InlineData(true, 31)]
    public void DictionariesKeepEmptyLinesDecodeBytesAndApplyLimits(bool optimized, int limit)
    {
        string dir = Directory.CreateTempSubdirectory("rk-export-words").FullName;
        try
        {
            string path = Path.Combine(dir, "words.txt");
            File.WriteAllBytes(path, [.. Encoding.UTF8.GetBytes("\uFEFF\nalpha\r\r\nbeta\rinside\n$HEX[ff]\n$HEX[0a]\n$HEX[244845585b363136325d]\n$HEX[no]\n"),
                .. Encoding.ASCII.GetBytes(new string('x', limit) + "\n" + new string('y', limit + 1) + "\n"), 0xff, 0xfe]);
            var args = new List<string> { "-a", "0", path };
            if (optimized) args.Add("-O");
            Assert.Equal(["", "alpha", "beta\rinside", "ÿ", "\n", "$HEX[6162]", "$HEX[no]", new string('x', limit), "ÿþ"], Generate([.. args]));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void UnsupportedArgumentsStayOnHashcatAndCancellationStopsEnumeration()
    {
        Assert.Null(ExportCandidates.TryCreate(Step("-a", "0", "words", "-r", "rules"), default));
        Assert.Null(ExportCandidates.TryCreate(Step("-a", "6", "words", "?d"), default));
        Assert.Null(ExportCandidates.TryCreate(Step("-a", "3", "--skip", "2", "?d"), default));
        Assert.Null(ExportCandidates.TryCreate(Step("-a", "3", "--hex-charset", "-1", " a", "?1"), default));
        using var ct = new CancellationTokenSource();
        var candidates = ExportCandidates.TryCreate(Step("-a", "3", "?d?d?d"), ct.Token)!;
        using var iterator = candidates.GetEnumerator();
        Assert.True(iterator.MoveNext());
        ct.Cancel();
        Assert.Throws<OperationCanceledException>(() => iterator.MoveNext());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CombinatorKeepsConcatenationWhenOptimizedTraversalSwaps(bool optimized)
    {
        string dir = Directory.CreateTempSubdirectory("rk-export-combine").FullName;
        try
        {
            string left = Path.Combine(dir, "left"), right = Path.Combine(dir, "right");
            File.WriteAllText(left, "a\nb\n");
            File.WriteAllText(right, "1\n2\n3\n");
            string[] args = optimized ? ["-a", "1", left, right, "-O"] : ["-a", "1", left, right];
            Assert.Equal(optimized ? ["a1", "b1", "a2", "b2", "a3", "b3"] : ["a1", "a2", "a3", "b1", "b2", "b3"], Generate(args));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("/lib64/ld-linux-x86-64.so.2", true)]
    [InlineData("/lib/ld-linux-aarch64.so.1", true)]
    [InlineData("/lib/ld-musl-x86_64.so.1", false)]
    [InlineData("", false)]
    public void UnknownLinuxRuntimesStayOnHashcat(string interpreter, bool expected)
    {
        string path = Path.GetTempFileName();
        try
        {
            byte[] name = Encoding.ASCII.GetBytes(interpreter + "\0");
            var elf = new byte[120 + name.Length];
            new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F', 2, 1 }.CopyTo(elf, 0);
            BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(32), 64);
            BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(54), 56);
            BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(56), (ushort)(interpreter.Length == 0 ? 0 : 1));
            BinaryPrimitives.WriteUInt32LittleEndian(elf.AsSpan(64), 3);
            BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(72), 120);
            BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(96), (ulong)name.Length);
            name.CopyTo(elf, 120);
            File.WriteAllBytes(path, elf);
            Assert.Equal(expected, HashcatMaskOrder.UsesSystemGlibc(path));
        }
        finally { File.Delete(path); }
    }

    internal static PreparedAttack Step(params string[] args)
    {
        var step = new PreparedAttack { Description = "export" };
        step.Args.AddRange(args);
        return step;
    }

    private static string[] Generate(params string[] args) => ExportCandidates.TryCreate(Step(args), default)!.ToArray();
}
