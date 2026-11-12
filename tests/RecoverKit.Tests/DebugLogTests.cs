using RecoverKit.Core;
using Xunit;

namespace RecoverKit.Tests;

public class DebugLogTests
{
    private const string Hash = "$pkzip2$1*1*2*0*29*1d*972eca9f*0*0*0*29*972e*5220*b3118b537bee6e1d72a8*$/pkzip2$";

    [Fact]
    public void RegisteredHashesAreMaskedUnlessIncluded()
    {
        DebugLog.RegisterHashes(Hash);
        var status = "{ \"status\": 3, \"target\": \"" + Hash + "\" }";

        DebugLog.IncludeHashes = false;
        var masked = DebugLog.Scrub(status);
        Assert.DoesNotContain(Hash, masked);
        Assert.Contains($"<hash, {Hash.Length} chars>", masked);

        DebugLog.IncludeHashes = true;
        Assert.Contains(Hash, DebugLog.Scrub(status));
        DebugLog.IncludeHashes = false;
    }

    [Fact]
    public void HashLoggingIsOffByDefault() => Assert.False(new Settings().DebugLogIncludeHashes);
}
