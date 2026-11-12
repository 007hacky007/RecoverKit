using System.Text;

namespace RecoverKit.Core.Attacks;

public enum AttackKind { BruteForce, Mask, Dictionary, KeySearch }

public enum RulesPreset
{
    AsIs,             // check words "as is"
    Simple,           // single word, simple mutations
    Advanced,         // single word, advanced mutations
    Complex,          // single word, complex mutations
    TwoWords,         // two words concatenated
    TwoWordsAdvanced, // two words with separators and case variants
    ThreeWords,       // three words concatenated
    CustomFile,       // user supplied hashcat .rule file
}

/// <summary>One attack, as configured in the wizard or a scenario line.</summary>
public sealed class AttackSpec
{
    public AttackKind Kind { get; set; } = AttackKind.BruteForce;

    // ---- brute-force
    public bool Caps { get; set; }
    public bool Smalls { get; set; } = true;
    public bool Digits { get; set; } = true;
    public bool Specials { get; set; }
    public bool UseUserCharset { get; set; }
    public string UserCharset { get; set; } = "";
    public string Alphabet { get; set; } = Charsets.LatinOnly;
    public int MinLength { get; set; } = 1;
    public int MaxLength { get; set; } = 6;
    /// <summary>Optional template, e.g. "password????" where the mask symbol marks unknown positions.</summary>
    public string Mask { get; set; } = "";
    public char MaskSymbol { get; set; } = '?';

    // ---- brute-force with extended mask (hashcat mask syntax)
    public string[] CustomCharsets { get; set; } = new string[8];
    public string HashcatMask { get; set; } = "";
    public bool Increment { get; set; }

    // ---- dictionary
    public RulesPreset Rules { get; set; } = RulesPreset.AsIs;
    public string? RulesFile { get; set; }
    public string?[] Dictionaries { get; set; } = new string?[4];
    public int SkipShorterThan { get; set; }
    public int SkipLongerThan { get; set; }

    public AttackSpec Clone()
    {
        var c = (AttackSpec)MemberwiseClone();
        c.CustomCharsets = (string[])CustomCharsets.Clone();
        c.Dictionaries = (string?[])Dictionaries.Clone();
        return c;
    }

    public string Describe()
    {
        switch (Kind)
        {
            case AttackKind.BruteForce:
            {
                var sb = new StringBuilder("Brute-force: ");
                var parts = new List<string>();
                if (Caps) parts.Add("capitals");
                if (Smalls) parts.Add("smalls");
                if (Digits) parts.Add("digits");
                if (Specials) parts.Add("specials");
                if (UseUserCharset && UserCharset.Length > 0) parts.Add($"user [{UserCharset}]");
                sb.Append(parts.Count > 0 ? string.Join(" + ", parts) : "(empty charset)");
                if (Alphabet != Charsets.LatinOnly && (Caps || Smalls)) sb.Append($" ({Alphabet})");
                sb.Append(Mask.Length > 0 ? $", mask \"{Mask}\"" : $", length {MinLength}-{MaxLength}");
                return sb.ToString();
            }
            case AttackKind.KeySearch:
                return "Key search: all 1,099,511,627,776 40-bit RC4 keys";
            case AttackKind.Mask:
            {
                var sets = CustomCharsets.Select((c, i) => (c, i)).Where(x => !string.IsNullOrEmpty(x.c)).Select(x => $"?{x.i + 1}=[{x.c}]");
                string inc = Increment ? $", length {MinLength}-{MaxLength}" : "";
                return $"Mask: {HashcatMask}{inc} {string.Join(' ', sets)}".TrimEnd();
            }
            default:
            {
                string dicts = string.Join(", ", Dictionaries.Where(x => !string.IsNullOrEmpty(x)).Select(x => Path.GetFileName(x!)));
                string rules = Rules == RulesPreset.CustomFile ? Path.GetFileName(RulesFile ?? "?") : RulesName(Rules);
                string len = SkipShorterThan > 0 || SkipLongerThan > 0
                    ? $", length {(SkipShorterThan > 0 ? SkipShorterThan : 1)}-{(SkipLongerThan > 0 ? SkipLongerThan.ToString() : "any")}"
                    : "";
                return $"Dictionary: {dicts}, rules: {rules}{len}";
            }
        }
    }

    public static string RulesName(RulesPreset r) => r switch
    {
        RulesPreset.AsIs => "Check words «as is»",
        RulesPreset.Simple => "Single word, simple mutations",
        RulesPreset.Advanced => "Single word, advanced mutations",
        RulesPreset.Complex => "Single word, complex mutations",
        RulesPreset.TwoWords => "Two words, simple combination",
        RulesPreset.TwoWordsAdvanced => "Two words, advanced combinations",
        RulesPreset.ThreeWords => "Three words, simple combination",
        _ => "Custom rules file",
    };

    public static readonly RulesPreset[] PresetOrder =
    [
        RulesPreset.AsIs, RulesPreset.Simple, RulesPreset.Advanced, RulesPreset.Complex,
        RulesPreset.TwoWords, RulesPreset.TwoWordsAdvanced, RulesPreset.ThreeWords,
    ];
}
