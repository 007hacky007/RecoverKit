using System.Globalization;
using System.Text;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Diagnostics;

/// <summary>Deterministic files shared by live diagnostics and the comparison export.</summary>
public static class BenchmarkTestFiles
{
    internal const string Password = "Compare!9Synthetic";
    public const string Attack = "brute force, lowercase letters a-z plus digits 0-9, exactly 7 characters";
    internal const string Charset = "?l?d";
    internal const string Mask = "?1?1?1?1?1?1?1";
    private static readonly Lazy<IReadOnlyList<TestFile>> Files = new(Build);
    public sealed record TestFile(string FileName, string Format, string Details, int Mode, byte[] Content, string Hash);
    public sealed record Comparison(string FileName, string Format, string Details, string Attack, double? Rate, string Configuration);
    internal static readonly string[] PublicFileNames =
    [
        "rk-zip-stored-small-check1.zip", "rk-zip-stored-small-check2.zip", "rk-zip-stored-453b-check1.zip", "rk-zip-stored-453b-check2.zip",
        "rk-zip-stored-4kb-check1.zip", "rk-zip-stored-4kb-check2.zip", "rk-zip-deflated-1kb-crc.zip", "rk-zip-deflated-1kb-crc-time.zip",
        "rk-zip-deflated-16kb-crc.zip", "rk-zip-deflated-16kb-crc-time.zip", "rk-zip-aes256.zip", "rk-pdf-r3.pdf", "rk-pdf-r6.pdf",
        "rk-office-2007.docx", "rk-office-2013.docx",
    ];
    public static IReadOnlyList<TestFile> Create() => Files.Value;

    private static IReadOnlyList<TestFile> Build()
    {
        var files = new List<TestFile>();
        void Add(string name, string format, string details, byte[] bytes)
        {
            var target = Extract(name, bytes);
            files.Add(new(name, format, details, target.Modes[0], bytes, target.HashLines));
        }
        foreach (var (length, deflate, label) in new[] { (17, false, "small"), (453, false, "453b"), (4096, false, "4kb"), (1024, true, "1kb"), (16384, true, "16kb") })
        foreach (bool two in new[] { false, true })
        {
            var rng = new Random(20261112 + length);
            byte[] data = deflate ? ZipCryptoSample.Text(length, rng) : new byte[length];
            if (!deflate) rng.NextBytes(data);
            string kind = deflate ? "deflated" : "stored";
            string checks = deflate ? two ? "crc-time" : "crc" : two ? "check2" : "check1";
            string detail = deflate
                ? two ? "data descriptor; CRC and DOS time accepted as alternative one-byte header checks" : "no data descriptor; one-byte CRC header check"
                : two ? "legacy ZIP 1.0; two-byte CRC header check" : "ZIP 2.0; one-byte CRC header check";
            byte[] archive = ZipCryptoSample.Archive([new("synthetic.dat", data, deflate, DataDescriptor: deflate && two, TwoCheckBytes: !deflate && two)], Encoding.ASCII.GetBytes(Password), rng);
            Add($"rk-zip-{kind}-{label}-{checks}.zip", "ZIP / ZipCrypto", $"synthetic.dat: {length} bytes uncompressed, {kind}; {detail}", archive);
        }
        Add("rk-zip-aes256.zip", "ZIP / WinZip AES-256", "synthetic.dat: 1024 stored bytes; AE-2; PBKDF2-HMAC-SHA1, 1000 iterations", DiagnosticZipSample.AesArchive(Password));
        Add("rk-pdf-r3.pdf", "PDF R3", "One synthetic page; RC4-128, MD5", DiagnosticPdfSample.Create(false, Password));
        Add("rk-pdf-r6.pdf", "PDF R6", "One synthetic page; AES-256, revision 6 password derivation", DiagnosticPdfSample.Create(true, Password));
        Add("rk-office-2007.docx", "Office 2007", "One synthetic paragraph; Standard AES-128/SHA-1, 50000 iterations", DiagnosticOfficeSample.Create(false, Password));
        Add("rk-office-2013.docx", "Office 2013", "One synthetic paragraph; Agile AES-256/SHA-512, 100000 iterations", DiagnosticOfficeSample.Create(true, Password));
        return files;
    }

    internal static HashTarget Extract(string name, byte[] bytes)
    {
        var detection = new Detection { FilePath = name };
        using var stream = new MemoryStream(bytes);
        if (name.EndsWith(".zip", StringComparison.Ordinal)) ZipExtractor.Extract(stream, detection);
        else if (name.EndsWith(".pdf", StringComparison.Ordinal)) PdfExtractor.Extract(stream, detection);
        else OfficeExtractor.Extract(new CompoundFile(stream), detection);
        return detection.Target ?? throw new InvalidOperationException("Synthetic comparison file did not produce a target.");
    }

    public static List<Comparison> Comparisons(DiagnosticReport report) => Create().Select(file =>
    {
        var rows = report.Measurements.Where(m => m.Correct && m.Error is null && double.IsFinite(m.Speed) && m.Speed > 0 && m.Mode == file.Mode && m.Length == 7
            && m.Details.GetValueOrDefault("Test file") == file.FileName && m.Details.GetValueOrDefault("Attack") == Attack).ToList();
        var row = rows.OrderByDescending(r => r.Repeat).FirstOrDefault();
        return new Comparison(file.FileName, file.Format, file.Details, Attack, row?.Speed,
            row is null ? "not measured, run the thorough test" : $"{row.Engine}; device {row.DeviceKey}; {row.Backend}; {row.Variant}; optimized kernel {row.Details.GetValueOrDefault("Optimized", "not recorded")}; {row.Threads} CPU workers");
    }).ToList();

    public static void Export(string directory, DiagnosticReport report)
    {
        Directory.CreateDirectory(directory);
        // Refuse overwrites so an export can never replace a tester's own file.
        var names = Create().Select(f => f.FileName).Concat(new[] { "readme.txt", "results.csv" }).ToList();
        if (names.Any(name => File.Exists(Path.Combine(directory, name)) || Directory.Exists(Path.Combine(directory, name))))
            throw new IOException("This folder already contains test export files. Choose an empty folder.");
        foreach (var file in Create())
        {
            using var output = new FileStream(Path.Combine(directory, file.FileName), FileMode.CreateNew, FileAccess.Write);
            output.Write(file.Content);
        }
        var readme = new StringBuilder("RecoverKit test files for comparison\n\nAll contents are synthetic. No personal files or data are included.\n");
        readme.AppendLine("Run each file separately in the other program with the attack below.");
        readme.AppendLine("Each GPU row measures one device only. Enable only the named device and use the same CPU worker count shown for that row. Disable dictionaries, rules and length increments.");
        readme.AppendLine("Compare steady candidates/second after startup and autotune, not total job time. Do not compare a built-in benchmark with these file rates.");
        readme.AppendLine("Run on AC power, close other GPU applications, and retain the same power and temperature limits.");
        readme.AppendLine("The password is deliberately outside the attack, so it will not end early. To check a crack, run a separate known-password test.");
        readme.AppendLine("Password for every exported file: " + Password);
        readme.AppendLine("Attack for every exported file: " + Attack + ".");
        readme.AppendLine("RAR 3 and RAR 5 are not exported: these diagnostics have reference hashes only, without complete synthetic archives. No fake archive is supplied.");
        readme.AppendLine("For deflated ZIP, crc-time means two alternative one-byte values, not a two-byte verifier. Legacy stored check2 files have the actual two-byte verifier.\n");
        var csv = new StringBuilder("File,Format,Entry details,Attack,RecoverKit candidates/s,RecoverKit configuration,Other program candidates/s,Notes\r\n");
        static string Q(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
        foreach (var comparison in Comparisons(report))
        {
            string rate = comparison.Rate?.ToString("F2", CultureInfo.InvariantCulture) ?? "not measured, run the thorough test";
            readme.AppendLine(comparison.FileName).AppendLine("  " + comparison.Format + "; " + comparison.Details)
                .AppendLine("  Attack: " + Attack).AppendLine("  RecoverKit candidates/s: " + rate)
                .AppendLine("  Configuration: " + comparison.Configuration).AppendLine("  Other program candidates/s: __________\n");
            csv.AppendLine(string.Join(',', new[] { comparison.FileName, comparison.Format, comparison.Details, Attack,
                comparison.Rate?.ToString("F2", CultureInfo.InvariantCulture) ?? "", comparison.Configuration, "", comparison.Rate is null ? "not measured, run the thorough test" : "" }.Select(Q)));
        }
        WriteNew("readme.txt", readme.ToString());
        WriteNew("results.csv", csv.ToString());
        void WriteNew(string name, string content)
        {
            using var output = new FileStream(Path.Combine(directory, name), FileMode.CreateNew, FileAccess.Write);
            using var writer = new StreamWriter(output, new UTF8Encoding(false));
            writer.Write(content);
        }
    }
}
