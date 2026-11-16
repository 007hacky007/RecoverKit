namespace RecoverKit.Core.Attacks;

/// <summary>Display names and stored values for editable dictionary fields.</summary>
public sealed class WordlistChoices
{
    private readonly Dictionary<string, string> values = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> labels = new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    private readonly Dictionary<string, string> files = new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    public IReadOnlyList<string> Labels { get; }

    public WordlistChoices(IEnumerable<(string Name, string Path)> downloaded, IEnumerable<string> dataFiles)
    {
        foreach (string name in BuiltinDictionaries.Names) Add(name, BuiltinDictionaries.Reference(name));
        foreach (var (name, path) in downloaded) AddFile(name + " (downloaded)", path);
        foreach (string path in dataFiles) AddFile(Path.GetFileName(path), path);
        Labels = values.Keys.ToArray();
    }

    private void Add(string label, string value)
    {
        string unique = label;
        for (int i = 2; values.ContainsKey(unique); i++) unique = label + $" ({i})";
        values.Add(unique, value);
        labels.Add(value, unique);
    }

    private void AddFile(string label, string path)
    {
        if (labels.ContainsKey(path)) return;
        Add(label, path);
        files.Add(path, Path.GetFileName(path));
    }

    public string? Value(string? text)
    {
        if (text is not null && values.TryGetValue(text, out var selected)) return selected;
        string value = (text ?? "").Trim();
        return value.Length == 0 ? null : values.GetValueOrDefault(value, value);
    }

    public string Text(string? value) => string.IsNullOrEmpty(value) ? ""
        : labels.GetValueOrDefault(value, BuiltinDictionaries.IsBuiltin(value) ? BuiltinDictionaries.DisplayName(value) : value);

    /// <summary>A previously offered file that is now missing; typed paths have no library history.</summary>
    public string? DeletedName(string? value) => value is not null && files.TryGetValue(value, out var name) && !File.Exists(value) ? name : null;
}
