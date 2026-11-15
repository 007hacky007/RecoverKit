using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class RuleRescueTests
{
    [Fact]
    public void LengthCacheRecognizesAutohexPrefixesAcrossReadBuffers()
    {
        string dir = Directory.CreateTempSubdirectory("rk-autohex-cache-").FullName;
        string path = Path.Combine(dir, "words");
        try
        {
            File.WriteAllText(path, new string('a', 65533) + "\n$HEX[61]\n");
            var info = WordlistLengthCache.Analyze(path, cacheDirectory: dir);
            Assert.True(info!.HasAutohexWords);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void SelectedWordsUseRawBytesExceptForHashcatEscapesAndFileSignatures()
    {
        Assert.Equal("hashcat\n"u8.ToArray(), RuleRescue.SelectedWordLine("hashcat"u8));
        Assert.Equal("café\n"u8.ToArray(), RuleRescue.SelectedWordLine("café"u8));
        Assert.Equal(new byte[] { 0xff, (byte)'a', (byte)'\n' }, RuleRescue.SelectedWordLine(new byte[] { 0xff, (byte)'a' }));
        foreach (byte[] word in new byte[][] { "$HEX[61]"u8.ToArray(), "PKword"u8.ToArray(), [0xef, 0xbb, 0xbf, 97], [0xff, 0xfe, 97], [0xfe, 0xff, 97], [97, 0, 98], [97, 13, 98], [97, 10, 98] })
            Assert.Equal(PasswordConfirmation.HexPlain(word) + "\n", System.Text.Encoding.ASCII.GetString(RuleRescue.SelectedWordLine(word)));
    }

    [Theory]
    [InlineData(6, 288, true)]
    [InlineData(6, 287, false)]
    [InlineData(5, 1000, false)]
    [InlineData(0, 1000, false)]
    [InlineData(6, 0, false)]
    public void FileNeedsCandidateBudgetAndTwiceItsWorstCaseByteSize(long limit, long free, bool expected)
        => Assert.Equal(expected, RuleRescue.CanMaterialize(2, 3, 8, free, limit));

    [Fact]
    public void FileEstimateCannotOverflowIntoAnAllowedSize()
    {
        Assert.False(RuleRescue.CanMaterialize(long.MaxValue, long.MaxValue, 256, long.MaxValue, long.MaxValue));
        Assert.False(RuleRescue.CanMaterialize(long.MaxValue, 1, 256, long.MaxValue, long.MaxValue));
        Assert.False(RuleRescue.CanMaterialize(50_000_001, 1, 8, long.MaxValue, 50_000_000));
    }

    [Fact]
    public void EmptyFinishedStreamHasCompleteProgress()
    {
        Assert.Equal(1, new HashcatStatus { Status = 5 }.Fraction);
        Assert.Equal(0, new HashcatStatus { Status = 3 }.Fraction);
    }

    [Fact]
    public void ProducerFailureIsNotTreatedAsTheConsumerClosingItsPipe()
    {
        IEnumerable<string> FailedSource()
        {
            yield return "first";
            throw new IOException("Source failed");
        }
        using var output = new MemoryStream();
        var error = Assert.Throws<IOException>(() => Generators.Pump(FailedSource(), output, default));
        Assert.Equal("Source failed", error.Message);
    }

    [Fact]
    public void ManagedSelectionCanBeCancelledEvenWhenEveryWordIsFilteredOut()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "short\n");
            using var stop = new CancellationTokenSource();
            stop.Cancel();
            Assert.Throws<OperationCanceledException>(() => Wordlists.ReadWords(path, 100, 0, stop.Token).ToArray());
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void LongFilteredStreamsDoNotTimeOutWhileWaitingForValidCandidates()
    {
        string dir = Directory.CreateTempSubdirectory("rk-stream-arguments-").FullName;
        try
        {
            string exe = Path.Combine(dir, OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat");
            File.WriteAllText(exe, "unused");
            var runner = new HashcatRunner(HashcatTool.Locate(exe, dir, dir)!) { HashcatMajorVersion = 8 };
            var attack = new PreparedAttack { Description = "stream", Stdin = () => [], StdinTotalIsUpperBound = true, Args = { "-a", "0" } };
            var request = new RunRequest { Mode = 22000, HashFile = "unused", SessionName = "stream", SessionDir = dir, Attack = attack };
            var args = runner.BuildArguments(request);
            Assert.Equal("0", args[args.IndexOf("--stdin-timeout-abort") + 1]);
            attack.StdinTotalIsUpperBound = false;
            args = runner.BuildArguments(request);
            Assert.Equal("600", args[args.IndexOf("--stdin-timeout-abort") + 1]);
        }
        finally { Directory.Delete(dir, true); }
    }
}
