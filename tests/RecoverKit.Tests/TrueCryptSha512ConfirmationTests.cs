using RecoverKit.Core.Formats;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

public class TrueCryptSha512ConfirmationTests
{
    [Theory]
    [InlineData("")]
    [InlineData(" \t")]
    public void DefaultTrueCryptHitsRequireManagedReferenceConfirmation(string extraArguments)
    {
        var confirm = TrueCryptSha512Kernel.ConfirmHits(29321, TrueCryptSha512Kernel.BenchmarkHash(29321), null, extraArguments, null);
        Assert.NotNull(confirm);
        Assert.True(confirm("hashcat"u8.ToArray()));
        Assert.False(confirm("wrong"u8.ToArray()));
    }

    [Fact]
    public void CorruptHeaderCannotConfirmEvenItsCorrectPassword()
    {
        var confirm = TrueCryptSha512Kernel.ConfirmHits(29321,
            TrueCryptSha512Tests.MakeHeader(29321, "AES", corruptOffset: 32), null, "", null);
        Assert.NotNull(confirm);
        Assert.False(confirm("test7"u8.ToArray()));
    }

    [Fact]
    public void FixedVeraCryptPimKeepsHashcatPlaintextHandling()
    {
        var credentials = new VolumeCredentials(new VolumeOptions { Kind = VolumeKind.VeraCrypt, Pim = 1 });
        Func<byte[], bool> existing = _ => true;
        string line = TrueCryptSha512Tests.MakeHeader(29421, "AES", pim: 1);
        Assert.Same(existing, TrueCryptSha512Kernel.ConfirmHits(29421, line, credentials, "", existing));
        Assert.Null(TrueCryptSha512Kernel.ConfirmHits(29421, line, credentials, "", null));
    }

    [Fact]
    public void ExistingConfirmationIsComposedAndCanRejectAValidPassword()
    {
        bool accept = false;
        int calls = 0;
        Func<byte[], bool> existing = _ => { calls++; return accept; };
        var confirm = TrueCryptSha512Kernel.ConfirmHits(29321, TrueCryptSha512Kernel.BenchmarkHash(29321), null, "", existing)!;
        Assert.False(confirm("wrong"u8.ToArray()));
        Assert.Equal(0, calls);
        Assert.False(confirm("hashcat"u8.ToArray()));
        Assert.Equal(1, calls);
        accept = true;
        Assert.True(confirm("hashcat"u8.ToArray()));
        Assert.Equal(2, calls);
    }

    [Fact]
    public void ExtraArgumentsAndUnparseableTargetsKeepTheExistingConfirmation()
    {
        Func<byte[], bool> existing = _ => true;
        Assert.Same(existing, TrueCryptSha512Kernel.ConfirmHits(29321, TrueCryptSha512Kernel.BenchmarkHash(29321), null, "--encoding-to utf8", existing));
        Assert.Same(existing, TrueCryptSha512Kernel.ConfirmHits(29331, TrueCryptSha512Kernel.BenchmarkHash(29321), null, "", existing));
        Assert.Same(existing, TrueCryptSha512Kernel.ConfirmHits(29321, "malformed", null, "", existing));
        Assert.Null(TrueCryptSha512Kernel.ConfirmHits(29321, "malformed", null, "", null));
    }

    [Fact]
    public void KeyfileJobsKeepTheExistingConfirmationAndDeferToHashcat()
    {
        string dir = Path.Combine(Path.GetTempPath(), "rk-sha512-confirm-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string path = Path.Combine(dir, "keyfile.bin");
            File.WriteAllBytes(path, [1, 2, 3]);
            var credentials = new VolumeCredentials(new VolumeOptions { Kind = VolumeKind.TrueCrypt, Keyfiles = [path] });
            Func<byte[], bool> existing = _ => true;
            Assert.Same(existing, TrueCryptSha512Kernel.ConfirmHits(29321, TrueCryptSha512Kernel.BenchmarkHash(29321), credentials, "", existing));
            Assert.Null(TrueCryptSha512Kernel.ConfirmHits(29321, TrueCryptSha512Kernel.BenchmarkHash(29321), credentials, "", null));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}
