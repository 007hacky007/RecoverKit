using Avalonia.Controls;
using Avalonia.Platform.Storage;

namespace RecoverKit.App.Ui;

/// <summary>File and folder pickers taking WinForms-style filters ("Name|*.a;*.b|All files|*.*").</summary>
internal static class Pick
{
    public static List<FilePickerFileType> Filters(string filter)
    {
        var parts = filter.Split('|');
        var list = new List<FilePickerFileType>();
        for (int i = 0; i + 1 < parts.Length; i += 2)
        {
            var patterns = parts[i + 1].Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .SelectMany(Expand).Distinct().ToList();
            list.Add(new FilePickerFileType(parts[i]) { Patterns = patterns });
        }
        return list;
    }

    // The macOS open panel filters by plain extensions, so "?" wildcards are spelled out there.
    private static readonly Dictionary<string, string[]> Wildcards = new()
    {
        ["*.od?"] = ["*.odt", "*.ods", "*.odp", "*.odg", "*.odf", "*.odb", "*.odc", "*.odm"],
        ["*.sx?"] = ["*.sxw", "*.sxc", "*.sxi", "*.sxd", "*.sxm"],
    };

    private static IEnumerable<string> Expand(string p)
    {
        if (p == "*.*") return ["*"];
        if (!OperatingSystem.IsWindows() && Wildcards.TryGetValue(p, out var list)) return list;
        return [p];
    }

    private static async Task<IStorageFolder?> Folder(TopLevel top, string? dir)
    {
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return null;
        try { return await top.StorageProvider.TryGetFolderFromPathAsync(dir); }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException) { return null; }
    }

    public static async Task<string?> Open(Window owner, string filter, string? initialDir = null, string? title = null)
    {
        var files = await owner.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title, AllowMultiple = false, FileTypeFilter = Filters(filter), SuggestedStartLocation = await Folder(owner, initialDir),
        });
        return files.Count > 0 ? files[0].TryGetLocalPath() : null;
    }

    public static async Task<string?> Save(Window owner, string filter, string? suggestedName = null, string? initialDir = null, string? defaultExt = null)
    {
        var f = await owner.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            FileTypeChoices = Filters(filter), SuggestedFileName = suggestedName, DefaultExtension = defaultExt,
            SuggestedStartLocation = await Folder(owner, initialDir), ShowOverwritePrompt = true,
        });
        return f?.TryGetLocalPath();
    }

    public static async Task<string?> FolderPath(Window owner, string? initialDir = null)
    {
        var f = await owner.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            AllowMultiple = false, SuggestedStartLocation = await Folder(owner, initialDir),
        });
        return f.Count > 0 ? f[0].TryGetLocalPath() : null;
    }
}
