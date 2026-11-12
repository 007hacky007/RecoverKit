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

    [Fact]
    public async Task AllAppliesEveryRestrictionInOneCopy()
    {
        var dir = Directory.CreateTempSubdirectory("rk-unlock-all").FullName;
        try
        {
            var src = Path.Combine(dir, "a.txt");
            File.WriteAllText(src, "ab");
            InstantUnlock Remove(char c) => new()
            {
                Title = "t", Description = "d", SaveLabel = "s",
                SaveCopyAsync = (i, o, ct) => File.WriteAllTextAsync(o, File.ReadAllText(i).Replace(c.ToString(), ""), ct),
            };
            Assert.Null(InstantUnlock.All([Remove('a')]));
            var all = InstantUnlock.All([Remove('a'), new InstantUnlock { Title = "p", Description = "d", Password = "x" }, Remove('b')])!;
            var dst = Path.Combine(dir, "out.txt");
            await all.SaveAsync(src, dst);
            Assert.Equal("", File.ReadAllText(dst));
            Assert.Equal("ab", File.ReadAllText(src));
            Assert.Equal(2, Directory.GetFiles(dir).Length);
        }
        finally { Directory.Delete(dir, true); }
    }
}
