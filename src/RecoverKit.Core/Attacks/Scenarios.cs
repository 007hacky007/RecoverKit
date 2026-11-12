using System.Globalization;
using System.Reflection;
using System.Text;

namespace RecoverKit.Core.Attacks;

/// <summary>An ordered list of attacks run one after another until the password is found.</summary>
public sealed class Scenario
{
    public required string Name { get; init; }
    public HashSet<string> DefaultFor { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public List<AttackSpec> Steps { get; init; } = new();
    public override string ToString() => Name;
}

/// <summary>
/// Scenario file format (UTF-8 or UTF-16 text):
/// <code>
/// Name of scenario
/// FMT1 FMT2 ...          (format ids this scenario is the default for, or NONE)
/// /a:b /c:sd /min:1 /max:6
/// /a:r /r:*1s /d:*default
/// (blank line)
/// </code>
/// Switches: /a: b|m|d|r (brute-force, mask, dictionary as-is, dictionary + rules);
/// /c: c|s|d|e|a (capitals, smalls, digits, specials, all); /u: user charset;
/// /l: national alphabet; /m: mask; /ms: mask symbol; /min: /max: lengths;
/// /1: .. /8: hashcat custom charsets (for /a:m); /r: rules (*1s *1a *1c *2s *2a *3s or a file);
/// /d: dictionary (up to four; *default = configured default dictionary).
/// Values with spaces go in double quotes ("" for a literal quote); \\ is a backslash,
/// \xHH and \XHHHH are character codes.
/// </summary>
public static class ScenarioParser
{
    public static List<Scenario> LoadDefault()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("RecoverKit.DefaultScenarios.txt")!;
        using var r = new StreamReader(s, Encoding.UTF8);
        return Parse(r.ReadToEnd(), out _);
    }

    public static List<Scenario> LoadFile(string path, out List<string> errors)
        => Parse(File.ReadAllText(path), out errors); // ReadAllText honours UTF-16/UTF-8 BOMs

    public static List<Scenario> Parse(string text, out List<string> errors)
    {
        errors = new();
        var result = new List<Scenario>();
        var blocks = text.Replace("\r\n", "\n").Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
        foreach (var block in blocks)
        {
            var lines = block.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith(';')).ToList();
            if (lines.Count < 3) continue;
            var sc = new Scenario { Name = lines[0].Trim('﻿') };
            foreach (var id in lines[1].Split(' ', StringSplitOptions.RemoveEmptyEntries))
                if (!id.Equals("NONE", StringComparison.OrdinalIgnoreCase)) sc.DefaultFor.Add(id);
            for (int i = 2; i < lines.Count; i++)
            {
                try { sc.Steps.Add(ParseLine(lines[i])); }
                catch (FormatException ex) { errors.Add($"{sc.Name}, line {i + 1}: {ex.Message}"); }
            }
            if (sc.Steps.Count > 0) result.Add(sc);
        }
        return result;
    }

    public static AttackSpec ParseLine(string line)
    {
        var a = new AttackSpec { Smalls = false, Digits = false };
        int dict = 0;
        bool charsetGiven = false, minGiven = false;
        foreach (var (key, value) in Switches(line))
        {
            switch (key.ToLowerInvariant())
            {
                case "a":
                    a.Kind = value switch
                    {
                        "b" => AttackKind.BruteForce,
                        "m" => AttackKind.Mask,
                        "d" or "r" => AttackKind.Dictionary,
                        "k" => AttackKind.KeySearch,
                        _ => throw new FormatException($"Unknown attack type '{value}'."),
                    };
                    break;
                case "c":
                    charsetGiven = true;
                    foreach (char c in value)
                    {
                        switch (c)
                        {
                            case 'c': a.Caps = true; break;
                            case 's': a.Smalls = true; break;
                            case 'd': a.Digits = true; break;
                            case 'e': a.Specials = true; break;
                            case 'a': a.Caps = a.Smalls = a.Digits = a.Specials = true; break;
                            default: throw new FormatException($"Unknown charset symbol '{c}'.");
                        }
                    }
                    break;
                case "u": a.UseUserCharset = true; a.UserCharset = value; charsetGiven = true; break;
                case "l": a.Alphabet = value; break;
                case "m": a.Mask = value; a.HashcatMask = value; break;
                case "ms": a.MaskSymbol = value.Length > 0 ? value[0] : '?'; break;
                case "min": a.MinLength = Num(value); minGiven = true; break;
                case "max": a.MaxLength = Num(value); break;
                case "r":
                    a.Kind = AttackKind.Dictionary;
                    a.Rules = Path.GetFileNameWithoutExtension(value.TrimStart('*')).ToLowerInvariant() switch
                    {
                        _ when !value.StartsWith('*') => RulesPreset.CustomFile,
                        "1s" => RulesPreset.Simple,
                        "1a" => RulesPreset.Advanced,
                        "1c" => RulesPreset.Complex,
                        "2s" => RulesPreset.TwoWords,
                        "2a" or "2a_2" => RulesPreset.TwoWordsAdvanced,
                        "3s" => RulesPreset.ThreeWords,
                        _ => throw new FormatException($"Unknown built-in rules '{value}'."),
                    };
                    if (a.Rules == RulesPreset.CustomFile) a.RulesFile = value;
                    break;
                case "d":
                    if (dict >= 4) throw new FormatException("Too many dictionaries used.");
                    a.Dictionaries[dict++] = value;
                    break;
                case "skip<": a.SkipShorterThan = Num(value); break;
                case "skip>": a.SkipLongerThan = Num(value); break;
                default:
                    if (key.Length == 1 && key[0] is >= '1' and <= '8') { a.CustomCharsets[key[0] - '1'] = value; break; }
                    throw new FormatException($"Unknown switch '/{key}'.");
            }
        }
        if (a.Kind == AttackKind.BruteForce && !charsetGiven) throw new FormatException("Brute-force attack needs /c: or /u:.");
        if (a.Kind == AttackKind.Mask)
        {
            int len = Charsets.MaskPositions(a.HashcatMask, a.CustomCharsets).Count;
            a.Increment = minGiven && a.MinLength < len;
            if (a.MaxLength > len || a.MaxLength <= 0) a.MaxLength = len;
        }
        if (a.Kind == AttackKind.Dictionary && dict == 0) throw new FormatException("Dictionary attack needs /d:.");
        return a;
    }

    private static int Num(string v) => int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n >= 0
        ? n : throw new FormatException($"Number is incorrect: '{v}'.");

    private static IEnumerable<(string Key, string Value)> Switches(string line)
    {
        int i = 0;
        while (i < line.Length)
        {
            while (i < line.Length && char.IsWhiteSpace(line[i])) i++;
            if (i >= line.Length) yield break;
            if (line[i] != '/') throw new FormatException($"Switch expected at position {i + 1}.");
            int k = ++i;
            while (i < line.Length && line[i] != ':' && !char.IsWhiteSpace(line[i])) i++;
            string key = line[k..i];
            string value = "";
            if (i < line.Length && line[i] == ':')
            {
                i++;
                var sb = new StringBuilder();
                bool quoted = i < line.Length && line[i] == '"';
                if (quoted) i++;
                while (i < line.Length)
                {
                    char c = line[i];
                    if (quoted && c == '"')
                    {
                        if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i += 2; continue; }
                        i++;
                        break;
                    }
                    if (!quoted && char.IsWhiteSpace(c)) break;
                    if (c == '\\' && i + 1 < line.Length)
                    {
                        char n = line[i + 1];
                        if (n == '\\') { sb.Append('\\'); i += 2; continue; }
                        if (n == 'x' && i + 3 < line.Length) { sb.Append((char)Convert.ToInt32(line.Substring(i + 2, 2), 16)); i += 4; continue; }
                        if (n == 'X' && i + 5 < line.Length) { sb.Append((char)Convert.ToInt32(line.Substring(i + 2, 4), 16)); i += 6; continue; }
                    }
                    sb.Append(c);
                    i++;
                }
                value = sb.ToString();
            }
            yield return (key, value);
        }
    }
}
