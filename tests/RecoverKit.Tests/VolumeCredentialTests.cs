using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

public sealed class VolumeCredentialTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-volume-").FullName;

    private string Write(string name, byte[] data)
    {
        string path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, data);
        return path;
    }

    private HashTarget Open(VolumeOptions options)
        => CryptVolume.Open(Write("volume.hc", new byte[VolumeOptions.BootOffset + 512]), options).Target!;

    [Theory]
    [InlineData(VolumeKind.TrueCrypt, "--truecrypt-keyfiles")]
    [InlineData(VolumeKind.VeraCrypt, "--veracrypt-keyfiles")]
    public void MultipleKeyfilesArePassedAsOneArgumentWithAbsolutePaths(VolumeKind kind, string flag)
    {
        string first = Write("first key.bin", [1, 2]);
        string second = Write("second.bin", [3, 4]);
        var target = Open(new VolumeOptions { Kind = kind, Keyfiles = [first, second] });
        Assert.Equal([flag, first + "," + second], target.VolumeCredentials!.Arguments);
    }

    [Theory]
    [InlineData(false, 1)]
    [InlineData(false, 2147468)]
    [InlineData(true, 65535)]
    public void CustomPimSetsBothHashcatBounds(bool boot, int pim)
    {
        var target = Open(new VolumeOptions { Pim = pim, BootVolume = boot, HeaderOffset = 0, Kdfs = VolumeKdf.Sha256 });
        Assert.Equal(["--veracrypt-pim-start", pim.ToString(), "--veracrypt-pim-stop", pim.ToString()], target.VolumeCredentials!.Arguments);
    }

    [Theory]
    [InlineData(VolumeKind.VeraCrypt, false, -1)]
    [InlineData(VolumeKind.VeraCrypt, false, 2147469)]
    [InlineData(VolumeKind.VeraCrypt, true, 65536)]
    [InlineData(VolumeKind.TrueCrypt, false, 1)]
    public void InvalidPimFailsBeforeRecovery(VolumeKind kind, bool boot, int pim)
        => Assert.ThrowsAny<ArgumentException>(() => Open(new VolumeOptions { Kind = kind, BootVolume = boot, Pim = pim }));

    [Fact]
    public void DefaultPimKeepsExistingTargetAndSessionIdentity()
    {
        var target = Open(new VolumeOptions());
        Assert.Null(target.VolumeCredentials);
        Assert.Equal(SessionState.KeyFor(target), SessionState.KeyFor(Open(new VolumeOptions { Pim = 0 })));
    }

    [Fact]
    public void BootVolumesRejectKeyfiles()
        => Assert.Throws<ArgumentException>(() => Open(new VolumeOptions { BootVolume = true, Keyfiles = [Write("key.bin", [1])] }));

    [Fact]
    public void InvalidKeyfilesFailBeforeRecovery()
    {
        Assert.ThrowsAny<IOException>(() => Open(new VolumeOptions { Keyfiles = [Path.Combine(_dir, "missing")] }));
        Assert.Throws<ArgumentException>(() => Open(new VolumeOptions { Keyfiles = [Write("empty.bin", [])] }));
        Assert.Throws<ArgumentException>(() => Open(new VolumeOptions { Keyfiles = [Write("comma,key.bin", [1])] }));
    }

    [Fact]
    public void SessionIdentityIncludesPimAndKeyfileContents()
    {
        string keyfile = Write("key.bin", [1, 2]);
        var plain = Open(new VolumeOptions());
        var first = Open(new VolumeOptions { Keyfiles = [keyfile], Pim = 7 });
        var otherPim = Open(new VolumeOptions { Keyfiles = [keyfile], Pim = 8 });
        Write("key.bin", [3, 4]);
        var otherKey = Open(new VolumeOptions { Keyfiles = [keyfile], Pim = 7 });
        Assert.Equal(first.HashLines, otherKey.HashLines);
        Assert.Equal(4, new[] { plain, first, otherPim, otherKey }.Select(SessionState.KeyFor).Distinct().Count());
        Assert.Throws<IOException>(() => first.VolumeCredentials!.ValidateUnchanged());
    }

    [Fact]
    public void TruncatedKeyfileIsReportedAsChanged()
    {
        string keyfile = Write("key.bin", [1, 2]);
        var target = Open(new VolumeOptions { Keyfiles = [keyfile] });
        Write("key.bin", []);
        Assert.Throws<IOException>(() => target.VolumeCredentials!.ValidateUnchanged());
    }

    [Theory]
    [InlineData(0, "")]
    [InlineData(7, "test7")]
    public async Task InstalledHashcatCanReadCredentialCache(int pim, string password)
    {
        if (HashcatTool.Locate(null) is not { } tool) return;
        string hash = TrueCryptWhirlpoolTests.Example.Replace("$truecrypt$", "$veracrypt$");
        string hashFile = Write("cache.hash", System.Text.Encoding.UTF8.GetBytes(hash + "\n"));
        string plain = password + (pim > 0 ? $"   (PIM={pim})" : "");
        string potfile = Write("cache.potfile", System.Text.Encoding.UTF8.GetBytes(hash + ":" + plain + "\n"));
        var credentials = Open(new VolumeOptions { Pim = pim, Keyfiles = [Write("key.bin", [1])] }).VolumeCredentials;
        Assert.Equal([password], await tool.ShowAsync(29421, hashFile, potfile, credentials));
        File.WriteAllText(potfile, "");
        Assert.Empty(await tool.ShowAsync(29421, hashFile, potfile, credentials));
    }

    [Fact]
    public void OnlyFirstMegabyteOfKeyfileAffectsIdentity()
    {
        var bytes = new byte[1024 * 1024 + 1];
        string keyfile = Write("large.bin", bytes);
        var first = Open(new VolumeOptions { Keyfiles = [keyfile] });
        bytes[^1] = 1;
        Write("large.bin", bytes);
        Assert.Equal(SessionState.KeyFor(first), SessionState.KeyFor(Open(new VolumeOptions { Keyfiles = [keyfile] })));
        first.VolumeCredentials!.ValidateUnchanged();
    }

    [Fact]
    public void NativePlannerCannotIgnoreKeyfiles()
    {
        var target = Open(new VolumeOptions { Kind = VolumeKind.TrueCrypt, Keyfiles = [Write("key.bin", [1])] });
        var mask = new PreparedAttack { Description = "mask", Args = { "-a", "3", "hashca?l" } };
        Assert.Null(NativeRunner.Plan(29331, TrueCryptWhirlpoolTests.Example, mask, new Settings(), [], credentials: target.VolumeCredentials));
        var gpu = new BackendDevice { Id = 1, Type = "GPU", Name = "Test GPU" };
        Assert.Null(NativeRunner.Plan(29331, TrueCryptWhirlpoolTests.Example, mask, new Settings(), [gpu], ignoreGpu: true, credentials: target.VolumeCredentials));
    }

    [Fact]
    public void PasswordCachesAreSeparatedByCredentials()
    {
        var settings = new Settings();
        var plain = Open(new VolumeOptions());
        var pim7 = Open(new VolumeOptions { Pim = 7 });
        var pim8 = Open(new VolumeOptions { Pim = 8 });
        Assert.Equal(settings.PotfilePath, SessionState.PasswordCacheFor(settings, plain));
        Assert.NotEqual(settings.PotfilePath, SessionState.PasswordCacheFor(settings, pim7));
        Assert.NotEqual(SessionState.PasswordCacheFor(settings, pim7), SessionState.PasswordCacheFor(settings, pim8));
        Assert.NotEqual(settings.SessionsDir, Path.GetDirectoryName(SessionState.PasswordCacheFor(settings, pim7)));
    }

    [Fact]
    public void RunnerUsesCredentialsAndScopedCacheWithoutSplittingPaths()
    {
        var target = Open(new VolumeOptions { Keyfiles = [Write("key with spaces.bin", [1])], Pim = 7 });
        var tool = HashcatTool.Locate(typeof(VolumeCredentialTests).Assembly.Location)!;
        var runner = new HashcatRunner(tool);
        string potfile = Path.Combine(_dir, "volume.potfile");
        var request = new RunRequest
        {
            Mode = 29421, HashFile = "volume.hash", Attack = new PreparedAttack { Description = "mask", Args = { "-a", "3", "test?d" } },
            SessionName = "test", SessionDir = _dir, VolumeCredentials = target.VolumeCredentials, PasswordCachePath = potfile,
        };
        var args = runner.BuildArguments(request);
        Assert.Equal(target.VolumeCredentials!.Arguments, args.Skip(args.IndexOf("--veracrypt-keyfiles")).Take(6));
        Assert.Equal(potfile, args[args.IndexOf("--potfile-path") + 1]);
    }

    [Theory]
    [InlineData("secret   (PIM=7)", "secret")]
    [InlineData("secret    (PIM=7)", "secret ")]
    [InlineData("$HEX[736563726574]   (PIM=7)", "$HEX[736563726574]")]
    [InlineData("$HEX[74c3a9372020202850494d3d3729]", "té7")]
    [InlineData("secret   (PIM=8)", "secret   (PIM=8)")]
    public void PimMetadataIsRemovedFromRecoveredPassword(string output, string password)
    {
        var credentials = Open(new VolumeOptions { Pim = 7 }).VolumeCredentials;
        Assert.Equal(password, HashcatTool.DecodePlain(output, credentials));
        if (!output.StartsWith("$HEX[")) Assert.Equal(output, HashcatTool.DecodePlain(output));
    }

    public void Dispose() => Directory.Delete(_dir, true);
}
