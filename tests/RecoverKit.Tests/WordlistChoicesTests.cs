using RecoverKit.Core.Attacks;
using Xunit;

namespace RecoverKit.Tests;

public sealed class WordlistChoicesTests
{
    [Fact]
    public void NamesResolveAndRoundTripWithoutCollisions()
    {
        string first = Path.GetFullPath(Path.Combine("data", "words.txt"));
        string second = Path.GetFullPath(Path.Combine("other", "words.txt"));
        string downloaded = Path.GetFullPath(Path.Combine("library", "words.txt"));
        string anotherDownload = Path.GetFullPath(Path.Combine("library", "words-2.txt"));
        string builtinName = Path.GetFullPath(Path.Combine("data", BuiltinDictionaries.SmallEnglish));
        string suffixName = Path.GetFullPath(Path.Combine("data", "words.txt (downloaded)"));
        string spacedName = Path.GetFullPath(Path.Combine("data", " words.txt"));
        var choices = new WordlistChoices([("words.txt", downloaded), ("words.txt", anotherDownload)], [first, second, builtinName, suffixName, spacedName]);

        Assert.Equal(choices.Labels.Count, choices.Labels.Distinct().Count());
        Assert.Contains("words.txt", choices.Labels);
        Assert.Contains("words.txt (downloaded)", choices.Labels);
        Assert.Equal(BuiltinDictionaries.Reference(BuiltinDictionaries.SmallEnglish), choices.Value(BuiltinDictionaries.SmallEnglish));
        foreach (string value in new[] { first, second, downloaded, anotherDownload, builtinName, suffixName, spacedName, BuiltinDictionaries.Reference(BuiltinDictionaries.Numbers99) })
        {
            Assert.NotEqual(value, choices.Text(value));
            Assert.Equal(value, choices.Value(choices.Text(value)));
        }
        Assert.Null(choices.Value("  "));
        Assert.Equal(first, choices.Value(first));
        Assert.Equal("typed-missing.txt", choices.Value("typed-missing.txt"));
    }

    [Fact]
    public void PathsAreCaseInsensitiveOnlyOnWindows()
    {
        string path = Path.GetFullPath("MixedCase.txt");
        var choices = new WordlistChoices([], [path]);
        string otherCase = path.ToUpperInvariant();
        Assert.Equal(OperatingSystem.IsWindows() ? "MixedCase.txt" : otherCase, choices.Text(otherCase));
    }

    [Fact]
    public void RefreshPreservesValuesWhenCollisionLabelsChange()
    {
        string first = Path.GetFullPath(Path.Combine("first", "words.txt"));
        string second = Path.GetFullPath(Path.Combine("second", "words.txt"));
        var before = new WordlistChoices([], [first, second]);
        var after = new WordlistChoices([], [second]);
        string? value = before.Value(before.Text(second));
        Assert.NotEqual(before.Text(second), after.Text(value));
        Assert.Equal(second, after.Value(after.Text(value)));
    }

    [Fact]
    public void OnlyKnownLibraryFilesAreClearedAfterDeletion()
    {
        string dir = Directory.CreateTempSubdirectory("rk-choices").FullName;
        try
        {
            string file = Path.Combine(dir, "words.txt");
            string dataFile = Path.Combine(dir, "data.lst");
            File.WriteAllText(file, "alpha\n");
            File.WriteAllText(dataFile, "beta\n");
            var choices = new WordlistChoices([("words.txt", file)], [dataFile]);
            Assert.Null(choices.DeletedName(file));
            File.Delete(file);
            File.Delete(dataFile);
            Assert.Equal("words.txt", choices.DeletedName(file));
            Assert.Equal("data.lst", choices.DeletedName(dataFile));
            Assert.Null(choices.DeletedName(Path.Combine(dir, "never-in-library.txt")));
            Assert.Null(choices.DeletedName(BuiltinDictionaries.Reference(BuiltinDictionaries.Numbers99)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task FirstRefreshRecognizesMissingManifestFilesAndStillPrunesThem()
    {
        string dir = Directory.CreateTempSubdirectory("rk-choices").FullName;
        try
        {
            var entry = new LibraryWordlist(1, "words.txt", null, "words.txt", null, 0, 1, 6, "", DateTimeOffset.UnixEpoch);
            var invalid = entry with { Id = 2, FileName = "../never-in-library.txt" };
            string manifest = System.Text.Json.JsonSerializer.Serialize(new { Version = 1, Owner = "RecoverKit", Wordlists = new[] { entry, invalid } }, WeakpassCatalog.Json);
            await File.WriteAllTextAsync(Path.Combine(dir, "library.json"), manifest);
            var library = new WordlistLibrary(dir);
            var snapshot = await library.LoadAsync(includeMissing: true);
            Assert.Equal(entry, Assert.Single(snapshot));
            var choices = new WordlistChoices(snapshot.Select(item => (item.Name, library.FilePath(item))), []);
            Assert.Equal("words.txt", choices.DeletedName(library.FilePath(entry)));
            Assert.Null(choices.DeletedName(library.FilePath(invalid)));
            Assert.Empty(await library.LoadAsync());
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("*default")]
    [InlineData("*")]
    public void ScenarioDefaultResolvesBuiltinReference(string reference)
    {
        string builtin = BuiltinDictionaries.Reference(BuiltinDictionaries.Numbers99);
        string? path = AttackPlanner.ResolveDictionary(reference, new PlannerContext { DefaultDictionary = builtin });
        Assert.Equal(BuiltinDictionaries.Materialize(builtin), path);
        Assert.Equal("0", File.ReadLines(path!).First());
        Assert.Equal("99", File.ReadLines(path!).Last());
    }
}
