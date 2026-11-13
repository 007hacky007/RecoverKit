using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public sealed class BenchmarkMaskMetadataTests
{
    [Theory]
    [InlineData("?l?l?l?l?l", "N/A", 5)]
    [InlineData("?1?1?1?1?1?1?1", "?l?d", 7)]
    [InlineData("?b?b??", "N/A", 3)]
    [InlineData("?invalid", "N/A", 0)]
    public void LengthComesFromModuleMask(string mask, string charset, int expected)
        => Assert.Equal(expected, new HashModeInfo { BenchmarkMask = mask, BenchmarkCharset1 = charset }.BenchmarkLength);
}
