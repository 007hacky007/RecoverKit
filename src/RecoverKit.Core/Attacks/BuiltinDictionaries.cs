using System.Reflection;
using System.Text;

namespace RecoverKit.Core.Attacks;

/// <summary>
/// Built-in dictionaries offered in the wizard's "Primary dictionary" list:
/// starter English word lists (embedded) and generated number ranges. A built-in is stored in an
/// AttackSpec as "builtin:&lt;name&gt;" and materialized to a cached file when an attack runs.
/// </summary>
public static class BuiltinDictionaries
{
    public const string Prefix = "builtin:";

    public const string SmallEnglish = "Small English dictionary";
    public const string MediumEnglish = "Medium English dictionary";
    public const string Numbers99 = "Numbers from 0 to 99";
    public const string Numbers999 = "Numbers from 0 to 999";
    public const string Numbers9999 = "Numbers from 0 to 9999";

    /// <summary>Display names in list order.</summary>
    public static readonly string[] Names =
    [
        SmallEnglish, MediumEnglish, Numbers99, Numbers999, Numbers9999,
    ];

    public static string Reference(string name) => Prefix + name;
    public static bool IsBuiltin(string? s) => s is not null && s.StartsWith(Prefix, StringComparison.Ordinal);
    public static string DisplayName(string reference) => IsBuiltin(reference) ? reference[Prefix.Length..] : reference;

    private static string CacheDir => Directory.CreateDirectory(Path.Combine(Settings.AppDataDir, "dictionaries")).FullName;

    /// <summary>Resolves a "builtin:&lt;name&gt;" reference to a real file on disk, creating it once and caching it.</summary>
    public static string Materialize(string reference)
    {
        string name = DisplayName(reference);
        string file = Path.Combine(CacheDir, Safe(name) + ".dic");
        if (File.Exists(file) && new FileInfo(file).Length > 0) return file;

        var tmp = file + ".tmp";
        switch (name)
        {
            case Numbers99: WriteNumbers(tmp, 99); break;
            case Numbers999: WriteNumbers(tmp, 999); break;
            case Numbers9999: WriteNumbers(tmp, 9999); break;
            case SmallEnglish: WriteResource(tmp, "RecoverKit.SmallEnglish.txt"); break;
            case MediumEnglish: WriteResource(tmp, "RecoverKit.MediumEnglish.txt"); break;
            default: throw new AttackPlanException($"Unknown built-in dictionary '{name}'.");
        }
        File.Move(tmp, file, overwrite: true);
        return file;
    }

    private static void WriteNumbers(string path, int max)
    {
        using var w = new StreamWriter(path, false, new UTF8Encoding(false));
        for (int i = 0; i <= max; i++) w.Write(i.ToString() + "\n");
    }

    private static void WriteResource(string path, string logicalName)
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(logicalName)
            ?? throw new AttackPlanException($"Built-in dictionary resource '{logicalName}' is missing.");
        using var f = new FileStream(path, FileMode.Create, FileAccess.Write);
        s.CopyTo(f);
    }

    private static string Safe(string name)
    {
        var sb = new StringBuilder();
        foreach (var c in name) sb.Append(char.IsLetterOrDigit(c) ? char.ToLowerInvariant(c) : '_');
        return sb.ToString();
    }
}
