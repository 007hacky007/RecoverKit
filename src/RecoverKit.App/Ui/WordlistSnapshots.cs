#if DEBUG
using RecoverKit.App.Views;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;

namespace RecoverKit.App.Ui;

/// <summary>Deterministic offline states using an excerpt of the recorded ignis-10K metadata.</summary>
internal static class WordlistSnapshots
{
    internal static async Task RunAsync(MainWindow owner, string directory)
    {
        string root = Path.Combine(Settings.AppDataDir, "wordlist-preview");
        Directory.CreateDirectory(root);
        string words = Path.Combine(root, "sample.txt");
        await File.WriteAllTextAsync(words, "alpha\nbeta\ngamma\n");
        var settings = new Settings { DataPath = root, RecentWordlistFiles = [words] };
        var detail = new WeakpassDetail
        {
            Id = 1934, Name = "ignis-10K.txt", Slug = "ignis_10k.txt", Rank = "S", Rate = 2.0634,
            Size = 80456, SizeCompressed = 38284, Count = 10000,
            DownloadUrl = "https://weakpass.com/download/1934/ignis-10K.txt.7z",
            Description = "https://github.com/ignis-sec/Pwdb-Public", Downloaded = 9895,
            UpdatedAt = new DateTimeOffset(2026, 11, 15, 23, 6, 53, TimeSpan.Zero),
            Examples = ["123456", "123456789", "password", "qwerty", "12345678", "12345", "123123", "111111"],
            Masks = [new("l", 6387), new("ld", 2269), new("d", 911), new("lud", 219), new("lu", 104)],
            TopMasks = [new("?l?l?l?l?l?l", 2163), new("?l?l?l?l?l?l?l", 1337), new("?l?l?l?l?l?l?l?l", 1194), new("?l?l?l?l?l", 476)],
            LengthDistribution = [new(4, 379), new(5, 512), new(6, 2897), new(7, 1834), new(8, 2266), new(9, 947), new(10, 583), new(11, 105), new(12, 76), new(13, 18), new(14, 6), new(15, 3), new(16, 4), new(17, 11)],
        };
        var library = new WordlistLibrary(WordlistLibrary.Folder(settings));
        Directory.CreateDirectory(library.DirectoryPath);
        string saved = Path.Combine(library.DirectoryPath, "ignis-10K.txt");
        await File.WriteAllTextAsync(saved, "alpha\nbeta\ngamma\n");
        // The preview manifest belongs only to this private snapshot directory.
        await File.WriteAllTextAsync(Path.Combine(library.DirectoryPath, "library.json"), System.Text.Json.JsonSerializer.Serialize(new { Version = 1, Owner = "RecoverKit", Wordlists = new[]
        {
            new LibraryWordlist(detail.Id, detail.Name, detail.Slug, "ignis-10K.txt", detail.Rank, detail.Rate, detail.Count, detail.Size, "", DateTimeOffset.UtcNow)
        } }, new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower }));
        var items = new List<WeakpassWordlist>
        {
            detail,
            new() { Id = 2, Name = "hashmob.net_2025.large.found", Rank = "S", Rate = 18.7, Count = 57_400_000, Size = 510_000_000, SizeCompressed = 158_000_000 },
            new() { Id = 3, Name = "hashmob.net_2025.medium.found", Rank = "S", Rate = 15.4, Count = 14_500_000, Size = 130_000_000, SizeCompressed = 42_000_000 },
            new() { Id = 4, Name = "ignis-1M.txt", Rank = "A", Rate = 7.9, Count = 1_000_000, Size = 8_800_000, SizeCompressed = 3_500_000 },
            new() { Id = 5, Name = "sage.latin.txt", Rank = "B", Rate = 19.1, Count = 182_000_000, Size = 990_000_000, SizeCompressed = 533_000_000 },
            new() { Id = 7, Name = "sample-legacy.lst", Rank = "C", Rate = 2.1, Count = 100_000, Size = 900_000, SizeCompressed = 400_000 },
            new() { Id = 8, Name = "sample-small.dic", Rank = "D", Rate = 0.5, Count = 10_000, Size = 90_000, SizeCompressed = 40_000 },
            new() { Id = 6, Name = "dictionary_2021.txt", Rank = "B", Rate = 15.5, Count = 103_000_000, Size = 950_000_000, SizeCompressed = 520_000_000 },
        };
        var fixture = new WordlistCatalogCache(DateTimeOffset.UtcNow.AddHours(-3), items);
        string[] names = ["builtin", "downloaded", "weakpass", "file"];
        for (int tab = 0; tab < names.Length; tab++)
        {
            settings.LastWordlistTab = tab;
            var window = new WordlistWindow(settings, "Primary dictionary", tab == 3 ? words : null, 18236, 1, preview: true);
            window.Show(owner);
            for (int attempt = 0; !window.DebugReady && attempt < 100; attempt++) await Task.Delay(50);
            if (!window.DebugReady) throw new IOException("The wordlist snapshot did not initialize.");
            window.DebugShow(tab, fixture, detail);
            await Snapshots.Save(window, Path.Combine(directory, "wordlists-" + names[tab] + ".png"));
            window.Close();
        }
    }
}
#endif
