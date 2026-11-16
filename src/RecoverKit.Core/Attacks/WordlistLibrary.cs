using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace RecoverKit.Core.Attacks;

public sealed record LibraryWordlist(long Id, string Name, string? Slug, string FileName, string? Rank,
    double Rate, long Count, long Size, string Checksum, DateTimeOffset DownloadedAt);

/// <summary>Only manifest files and explicitly recorded partial downloads belong to the library.</summary>
public sealed class WordlistLibrary
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Gates = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim gate;
    public string DirectoryPath { get; }
    private string Manifest => Path.Combine(DirectoryPath, "library.json");
    private sealed record Partial(long Id, string FileName, string? Checksum);
    private sealed record ManifestData(int Version, string Owner, List<LibraryWordlist> Wordlists);

    public WordlistLibrary(string directory)
    {
        DirectoryPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        gate = Gates.GetOrAdd(DirectoryPath, _ => new SemaphoreSlim(1));
    }
    public static string Folder(Settings settings) => Path.Combine(string.IsNullOrWhiteSpace(settings.DataPath) ? Settings.AppDataDir : settings.DataPath, "wordlists");
    public string FilePath(LibraryWordlist item) => Path.Combine(DirectoryPath, item.FileName);

    public static string SafeName(string name)
    {
        var safe = new string(name.Select(c => c < 32 || "<>:\"/\\|?*".Contains(c) || char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.DashPunctuation && c != '-' ? '_' : c).ToArray()).Trim().TrimEnd('.');
        if (safe.Length == 0) safe = "wordlist";
        if (safe.Length > 180) safe = safe[..180];
        string stem = safe.Split('.')[0];
        if (new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" }.Contains(stem, StringComparer.OrdinalIgnoreCase)) safe = "_" + safe;
        return new[] { ".txt", ".dic", ".lst", ".wordlist", ".found", ".dict", ".udic", ".list", ".lex", ".utf", ".top", ".out", ".csv" }.Contains(Path.GetExtension(safe), StringComparer.OrdinalIgnoreCase) ? safe : safe + ".txt";
    }

    private static bool SafeFile(string? name) => !string.IsNullOrEmpty(name) && name == Path.GetFileName(name)
        && name != "." && name != ".." && !name.Contains('\\') && !name.Contains('/') && !name.Contains(':')
        && !name.Equals("library.json", StringComparison.OrdinalIgnoreCase) && !name.StartsWith("download-", StringComparison.OrdinalIgnoreCase)
        && !name.EndsWith(".part", StringComparison.OrdinalIgnoreCase) && !name.EndsWith(".unpacking", StringComparison.OrdinalIgnoreCase)
        && !name.Equals("catalog.json", StringComparison.OrdinalIgnoreCase) && !name.StartsWith("detail-", StringComparison.OrdinalIgnoreCase);

    private bool Regular(string file) => File.Exists(file) && (File.GetAttributes(file) & FileAttributes.ReparsePoint) == 0;

    private async Task<List<LibraryWordlist>> ReadManifest(CancellationToken ct)
    {
        if (!File.Exists(Manifest)) return [];
        if (!Regular(Manifest)) throw new IOException("The library manifest is a link. Choose another library folder.");
        ManifestData? manifest;
        try
        {
            await using var file = File.OpenRead(Manifest);
            manifest = await System.Text.Json.JsonSerializer.DeserializeAsync<ManifestData>(file, WeakpassCatalog.Json, ct);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        { throw new IOException("Could not read library.json. It was left unchanged. Move it or choose another library folder.", ex); }
        if (manifest is not { Version: 1, Owner: "RecoverKit", Wordlists: not null })
            throw new IOException("library.json does not belong to this library version. It was left unchanged. Move it or choose another library folder.");
        var stored = manifest.Wordlists;
        var valid = stored.Where(x => SafeFile(x.FileName) && Regular(FilePath(x))).DistinctBy(x => x.Id).ToList();
        if (valid.Count != stored.Count) await SaveManifest(valid, ct);
        return valid;
    }

    private Task SaveManifest(List<LibraryWordlist> items, CancellationToken ct)
        => WeakpassCatalog.WriteAsync(Manifest, new ManifestData(1, "RecoverKit", items), ct);

    public async Task<List<LibraryWordlist>> LoadAsync(CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try { return await ReadManifest(ct); }
        finally { gate.Release(); }
    }

    public long FreeSpace()
    {
        Directory.CreateDirectory(DirectoryPath);
        string resolved = ResolveDirectory(DirectoryPath);
        // DriveInfo(path) is root-based on Unix. Use the longest matching mount for external disks.
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var drive = DriveInfo.GetDrives().Where(d => resolved.StartsWith(Path.TrimEndingDirectorySeparator(d.Name) + Path.DirectorySeparatorChar, comparison)
            || resolved.Equals(Path.TrimEndingDirectorySeparator(d.Name), comparison)).OrderByDescending(d => d.Name.Length).FirstOrDefault();
        return (drive ?? new DriveInfo(Path.GetPathRoot(resolved)!)).AvailableFreeSpace;
    }

    internal static string ResolveDirectory(string path)
    {
        string resolved = Path.GetPathRoot(Path.GetFullPath(path))!;
        foreach (string part in Path.GetFullPath(path)[resolved.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            var directory = new DirectoryInfo(Path.Combine(resolved, part));
            resolved = directory.LinkTarget is null ? directory.FullName
                : directory.ResolveLinkTarget(true)?.FullName ?? throw new IOException("The library folder links to a missing drive.");
        }
        return resolved;
    }

    public static long RequiredSpace(WeakpassWordlist item)
    {
        if (item.Size < 0 || item.SizeCompressed < 0) throw new IOException("The wordlist has invalid sizes.");
        try { return checked(item.Size + item.SizeCompressed + Math.Max(64L * 1024 * 1024, item.Size / 20)); }
        catch (OverflowException) { throw new IOException("The wordlist is too large for this disk."); }
    }

    public async Task<string> PreparePartialAsync(WeakpassDetail detail, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            Directory.CreateDirectory(DirectoryPath);
            string marker = Path.Combine(DirectoryPath, $"download-{detail.Id}.json");
            var record = await WeakpassCatalog.ReadAsync<Partial>(marker, ct);
            string name = record is not null && record.Id == detail.Id && OwnedPartial(record) ? record.FileName : $"{detail.Id}-download.part";
            string part = Path.Combine(DirectoryPath, name);
            if (record is not null && record.Id == detail.Id && OwnedPartial(record))
            {
                if (File.Exists(part) && !Regular(part)) throw new IOException("The partial download is a link. Choose another library folder.");
                if (File.Exists(part + ".unpacking"))
                {
                    if (!Regular(part + ".unpacking")) throw new IOException("The unpacking file is a link. Choose another library folder.");
                    File.Delete(part + ".unpacking");
                }
                if (record.Checksum != detail.ChecksumCompressed)
                {
                    if (Regular(part)) File.Delete(part);
                    using (new FileStream(part, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
                    await WeakpassCatalog.WriteAsync(marker, new Partial(detail.Id, name, detail.ChecksumCompressed), ct);
                }
                else if (!File.Exists(part))
                {
                    using (new FileStream(part, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
                }
                File.SetLastWriteTimeUtc(marker, DateTime.UtcNow);
                return part;
            }
            if (File.Exists(part) || File.Exists(part + ".unpacking") || File.Exists(marker)) throw new IOException("A file already occupies this download's temporary name. Move it before retrying.");
            await WeakpassCatalog.WriteAsync(marker, new Partial(detail.Id, name, detail.ChecksumCompressed), ct);
            using (new FileStream(part, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
            return part;
        }
        finally { gate.Release(); }
    }

    private static bool OwnedPartial(Partial record) => record.FileName is { } name && name == Path.GetFileName(name)
        && !name.Contains('\\') && !name.Contains(':') && name.StartsWith($"{record.Id}-", StringComparison.Ordinal)
        && name.EndsWith(".part", StringComparison.Ordinal) && name.Length > $"{record.Id}-.part".Length;

    internal void RemovePartial(WeakpassDetail detail, string part)
    {
        if (Regular(part)) File.Delete(part);
        File.Delete(Path.Combine(DirectoryPath, $"download-{detail.Id}.json"));
    }

    public async Task<long> PartialSizeAsync(long id)
    {
        await gate.WaitAsync();
        try
        {
            var record = await WeakpassCatalog.ReadAsync<Partial>(Path.Combine(DirectoryPath, $"download-{id}.json"));
            if (record is null || record.Id != id || !OwnedPartial(record)) return 0;
            string part = Path.Combine(DirectoryPath, record.FileName);
            return Regular(part) ? new FileInfo(part).Length : 0;
        }
        finally { gate.Release(); }
    }

    internal async Task CancelPartialAsync(WeakpassDetail detail)
    {
        await gate.WaitAsync();
        try
        {
            string marker = Path.Combine(DirectoryPath, $"download-{detail.Id}.json");
            var record = await WeakpassCatalog.ReadAsync<Partial>(marker);
            if (record is null || record.Id != detail.Id || !OwnedPartial(record)) return;
            string part = Path.Combine(DirectoryPath, record.FileName);
            RemovePartial(detail, part);
            if (Regular(part + ".unpacking")) File.Delete(part + ".unpacking");
        }
        finally { gate.Release(); }
    }

    public async Task CleanStalePartialsAsync(CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            if (!Directory.Exists(DirectoryPath)) return;
            foreach (string marker in Directory.EnumerateFiles(DirectoryPath, "download-*.json"))
            {
                ct.ThrowIfCancellationRequested();
                if (File.GetLastWriteTimeUtc(marker) >= DateTime.UtcNow.AddDays(-7)) continue;
                var record = await WeakpassCatalog.ReadAsync<Partial>(marker, ct);
                if (record is null || !OwnedPartial(record)) continue;
                string part = Path.Combine(DirectoryPath, record.FileName);
                if (Regular(part)) File.Delete(part);
                if (Regular(part + ".unpacking")) File.Delete(part + ".unpacking");
                File.Delete(marker);
            }
        }
        finally { gate.Release(); }
    }

    internal async Task<LibraryWordlist> PublishAsync(WeakpassDetail detail, string unpacked, CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            var items = await ReadManifest(ct);
            if (items.Any(x => x.Id == detail.Id)) throw new IOException("This wordlist is already downloaded.");
            string name = SafeName(detail.Name);
            if (!SafeFile(name)) name = $"{detail.Id}-wordlist.txt";
            string candidate = name;
            for (int suffix = 0; File.Exists(Path.Combine(DirectoryPath, candidate)) || Directory.Exists(Path.Combine(DirectoryPath, candidate)); suffix++)
                candidate = $"{Path.GetFileNameWithoutExtension(name)}-{detail.Id}{(suffix == 0 ? "" : "-" + suffix)}{Path.GetExtension(name)}";
            string destination = Path.Combine(DirectoryPath, candidate);
            File.Move(unpacked, destination); // Never replace an existing file.
            var item = new LibraryWordlist(detail.Id, detail.Name, detail.Slug, candidate, detail.Rank, detail.Rate,
                detail.Count, detail.Size, detail.Checksum!, DateTimeOffset.UtcNow);
            items.Add(item);
            try { await SaveManifest(items, ct); }
            catch { File.Delete(destination); throw; }
            return item;
        }
        finally { gate.Release(); }
    }

    public async Task DeleteAsync(long id, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            var items = await ReadManifest(ct);
            var item = items.FirstOrDefault(x => x.Id == id);
            if (item is null) return;
            // A file replaced or edited outside RecoverKit is no longer ours to delete.
            await using (var file = File.OpenRead(FilePath(item)))
            {
                string checksum = Convert.ToHexString(await MD5.HashDataAsync(file, ct));
                if (!checksum.Equals(item.Checksum, StringComparison.OrdinalIgnoreCase)) throw new IOException("This file has changed outside the library. Move it yourself to keep your changes.");
            }
            File.Delete(FilePath(item));
            items.Remove(item);
            await SaveManifest(items, ct);
        }
        finally { gate.Release(); }
    }

    public static IEnumerable<string> DataFiles(string? dataPath) => dataPath is not null && Directory.Exists(dataPath)
        ? Directory.EnumerateFiles(dataPath).Where(p => new[] { ".txt", ".dic", ".lst" }.Contains(Path.GetExtension(p), StringComparer.OrdinalIgnoreCase)) : [];
}
