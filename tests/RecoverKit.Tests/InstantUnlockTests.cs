using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class InstantUnlockTests
{
    private static InstantUnlock Copying() => new()
    {
        Title = "t", Description = "d", SaveLabel = "Save...",
        SaveCopyAsync = (src, dst, ct) => File.WriteAllBytesAsync(dst, File.ReadAllBytes(src), ct),
    };

    [Fact]
    public void SuggestedPathKeepsFolderAndExtension()
    {
        var u = new InstantUnlock { Title = "t", Description = "d", SuggestedSuffix = "_unprotected" };
        var p = u.SuggestedPath(Path.Combine("dir", "Book.xlsx"));
        Assert.Equal("Book_unprotected.xlsx", Path.GetFileName(p));
        Assert.Equal(Path.GetFullPath("dir"), Path.GetDirectoryName(p));
    }

    [Fact]
    public async Task SaveWritesCopyAndNeverOverwritesSource()
    {
        var dir = Directory.CreateTempSubdirectory("rk-unlock").FullName;
        try
        {
            var src = Path.Combine(dir, "a.bin");
            File.WriteAllBytes(src, [1, 2, 3]);
            var u = Copying();
            await Assert.ThrowsAsync<IOException>(() => u.SaveAsync(src, src));
            var dst = u.SuggestedPath(src);
            await u.SaveAsync(src, dst);
            Assert.Equal([1, 2, 3], File.ReadAllBytes(dst));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task SaveWithoutActionFails()
    {
        var u = new InstantUnlock { Title = "t", Description = "d", Password = "" };
        await Assert.ThrowsAsync<InvalidOperationException>(() => u.SaveAsync("a", "b"));
    }
}
