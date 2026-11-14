using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RecoverKit.Core.Diagnostics;

public static partial class DiagnosticHtml
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    // Reports accept metadata only. This last boundary also removes paths from unexpected errors.
    public static string Scrub(string value)
    {
        if (BenchmarkTestFiles.PublicFileNames.Contains(value, StringComparer.Ordinal)) return value;
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (home.Length > 1) value = value.Replace(home, "[private]", StringComparison.OrdinalIgnoreCase);
        value = PathPattern().Replace(value, "[private path]");
        value = HashPattern().Replace(value, "[redacted]");
        value = SecretPattern().Replace(value, "[redacted]");
        value = FileNamePattern().Replace(value, "[private file]");
        return value;
    }

    public static string Summary(DiagnosticReport report) => Scrub(string.Join(Environment.NewLine,
        new[] { $"RecoverKit detailed performance test ({report.Started:yyyy-MM-dd})", report.Cancelled ? "Partial report: abandoned." : "" }
            .Where(s => s.Length > 0).Concat(report.Summary).Append("Save test files exports synthetic targets, exact comparison attacks, measured rates and a results.csv template.")));

    public static string Render(DiagnosticReport report)
    {
        // Scrub string values before JSON encoding, preserving valid JSON and script escaping.
        var safe = JsonSerializer.SerializeToNode(report, Json)!;
        safe["ComparisonFiles"] = JsonSerializer.SerializeToNode(BenchmarkTestFiles.Comparisons(report), Json);
        ScrubNode(safe);
        string json = safe.ToJsonString(Json);
        static string H(string? s) => WebUtility.HtmlEncode(Scrub(s ?? ""));
        var html = new StringBuilder("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>RecoverKit performance report</title><style>body{font:15px system-ui,sans-serif;max-width:1400px;margin:2em auto;padding:0 1em;color:#222}table{border-collapse:collapse;width:100%;margin:1em 0}th,td{border:1px solid #ccc;padding:.5em;text-align:left;overflow-wrap:anywhere}th{background:#eee}pre{white-space:pre-wrap}button{padding:.7em}small{color:#555}</style><h1>Detailed performance test</h1><pre id=\"summary\">");
        html.Append(H(Summary(report))).Append("</pre><button onclick=\"copySummary()\">Copy summary</button><p id=\"copy-status\"></p>")
            .Append("<small>Only synthetic targets are used. Rates from different targets or lengths are separate measurements. Backend aliases are never added together. Zero rates and failed checks are ineligible for selection.</small><table><tr><th>System</th><th>Value</th></tr>");
        foreach (var (key, value) in report.System) html.Append("<tr><td>").Append(H(key)).Append("</td><td>").Append(H(value)).Append("</td></tr>");
        html.Append("</table>");
        var wide = report.WideVectorPaths;
        html.Append("<h2>Wide vector paths</h2>");
        if (wide.Note is { } note) html.Append("<p>").Append(H(note)).Append("</p>");
        if (wide.Rows.Count > 0)
        {
            int? threads = wide.Rows[0].AllThreads.Threads;
            string threadLabel = threads is null ? "All threads (count unknown)"
                : report.System.GetValueOrDefault("Logical threads") == threads.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    ? $"All {threads} logical threads" : $"{threads} threads (budget cap)";
            html.Append("<table><tr><th>Kernel</th><th>1 thread AVX2 / scalar</th><th>1 thread AVX-512</th><th>Ratio</th><th>")
                .Append(H(threadLabel)).Append(" AVX2 / scalar</th><th>").Append(H(threadLabel))
                .Append(" AVX-512</th><th>Ratio</th><th>Correctness</th><th>Self-test state</th></tr>");
            foreach (var row in wide.Rows)
            {
                html.Append("<tr><td>").Append(H($"{row.Kernel} ({row.Mode})"))
                    .Append("</td><td>").Append(H(WideRate(row.SingleThread.Scalar ?? row.SingleThread.Avx2)))
                    .Append("</td><td>").Append(H(WideRate(row.SingleThread.Avx512)))
                    .Append("</td><td>").Append(WideRatio(row.SingleThread.Ratio))
                    .Append("</td><td>").Append(H(WideRate(row.AllThreads.Scalar ?? row.AllThreads.Avx2)))
                    .Append("</td><td>").Append(H(WideRate(row.AllThreads.Avx512)))
                    .Append("</td><td>").Append(WideRatio(row.AllThreads.Ratio))
                    .Append("</td><td>").Append(H(row.Correctness))
                    .Append("</td><td>").Append(H(row.SelfTestState)).Append("</td></tr>");
            }
            html.Append("</table><p><small>Rates are median candidates/s for matching targets and lengths. Baseline is scalar for TrueCrypt Whirlpool and AVX2 for other kernels. Ratios are AVX-512 / baseline. Repeated samples include their range and count.</small></p>");
        }
        if (report.Decisions.Count > 0)
        {
            html.Append("<h2>Decisions for this PC</h2><table><tr><th>Mode / workload</th><th>Engine / variant / workers</th><th>Devices</th><th>Measured margin</th><th>Reason</th></tr>");
            foreach (var d in report.Decisions)
                html.Append("<tr><td>").Append(H($"{d.Mode} / {d.Target} / length {d.Length}"))
                    .Append("</td><td>").Append(H($"{d.Engine} / {d.Variant} / {d.Threads}"))
                    .Append("</td><td>").Append(H(string.Join(", ", d.DeviceKeys)))
                    .Append("</td><td>").Append(d.Margin.ToString("P1", System.Globalization.CultureInfo.InvariantCulture))
                    .Append("</td><td>").Append(H(d.Reason)).Append("</td></tr>");
            html.Append("</table>");
        }
        html.Append("<h2>Compare with another program</h2><p>Choose Save test files in the finished test, or use bench-full --export-tests with a folder. The export contains the exact synthetic targets, a readme with attacks and verification passwords, and results.csv for the other program's rates. RAR 3 and RAR 5 have reference hashes only, so no archive is exported.</p><table><tr><th>Test file</th><th>Format and entry details</th><th>Attack</th><th>RecoverKit candidates/s</th><th>Configuration</th></tr>");
        foreach (var c in BenchmarkTestFiles.Comparisons(report))
            html.Append("<tr><td>").Append(H(c.FileName)).Append("</td><td>").Append(H(c.Format + ": " + c.Details)).Append("</td><td>").Append(H(c.Attack))
                .Append("</td><td>").Append(c.Rate?.ToString("N1", System.Globalization.CultureInfo.InvariantCulture) ?? "not measured, run the thorough test")
                .Append("</td><td>").Append(H(c.Configuration)).Append("</td></tr>");
        html.Append("</table>");
        foreach (var section in report.Measurements.GroupBy(m => m.Section))
        {
            html.Append("<h2>").Append(H(section.Key)).Append("</h2><table><tr><th>Step / mode</th><th>Target / length</th><th>Engine / variant</th><th>Workers / device / backend</th><th>Check</th><th>Candidates/s</th><th>Elapsed (s) / repeat</th><th>Details / error</th></tr>");
            foreach (var r in section)
            {
                html.Append("<tr><td>").Append(H($"{r.Step} / {r.Mode}"))
                    .Append("</td><td>").Append(H($"{r.Target} / {(r.Length > 0 ? r.Length.ToString() : "module default")}"))
                    .Append("</td><td>").Append(H($"{r.Engine} / {r.Variant}"))
                    .Append("</td><td>").Append(H($"{r.Threads} / {r.DeviceKey} / {r.Backend}"))
                    .Append("</td><td>").Append(r.Correct ? "PASS" : "FAIL / not validated")
                    .Append("</td><td>").Append(r.Speed.ToString("N1", System.Globalization.CultureInfo.InvariantCulture))
                    .Append("</td><td>").Append(r.ElapsedSeconds.ToString("F2", System.Globalization.CultureInfo.InvariantCulture)).Append(" / ").Append(r.Repeat)
                    .Append("</td><td>").Append(H(string.Join("; ", r.Details.Select(d => $"{d.Key}: {d.Value}").Append(r.Error ?? "")))).Append("</td></tr>");
            }
            html.Append("</table>");
        }
        html.Append("<script id=\"recoverkit-results\" type=\"application/json\">").Append(json)
            .Append("</script><script>async function copySummary(){const t=document.getElementById('summary').textContent;try{await navigator.clipboard.writeText(t);document.getElementById('copy-status').textContent='Summary copied.'}catch(e){const r=document.createRange();r.selectNodeContents(document.getElementById('summary'));const s=window.getSelection();s.removeAllRanges();s.addRange(r);document.getElementById('copy-status').textContent='Summary selected. Press Ctrl+C or Command+C to copy.'}}</script></html>");
        return html.ToString();
    }

    private static string WideRatio(double? ratio) => ratio is { } value
        ? value.ToString("F2", System.Globalization.CultureInfo.InvariantCulture) + "x" : "not measured";

    private static string WideRate(WideVectorPathResult path)
    {
        if (path.Median is not { } median) return path.Status + (path.Reason is null ? "" : ": " + path.Reason);
        string rate = median.ToString("N1", System.Globalization.CultureInfo.InvariantCulture);
        return path.SampleCount < 2 ? rate : rate + $" (min {path.Minimum?.ToString("N1", System.Globalization.CultureInfo.InvariantCulture)}, max {path.Maximum?.ToString("N1", System.Globalization.CultureInfo.InvariantCulture)}; n={path.SampleCount})";
    }

    private static void ScrubNode(System.Text.Json.Nodes.JsonNode node)
    {
        if (node is System.Text.Json.Nodes.JsonObject obj)
            foreach (var pair in obj.ToList())
            {
                if (pair.Value is System.Text.Json.Nodes.JsonValue v && v.TryGetValue<string>(out var s)) obj[pair.Key] = Scrub(s);
                else if (pair.Value is { } child) ScrubNode(child);
            }
        else if (node is System.Text.Json.Nodes.JsonArray arr)
            for (int i = 0; i < arr.Count; i++)
                if (arr[i] is System.Text.Json.Nodes.JsonValue v && v.TryGetValue<string>(out var s)) arr[i] = Scrub(s);
                else if (arr[i] is { } child) ScrubNode(child);
    }

    [GeneratedRegex(@"(?:[A-Za-z]:[\\/]|\\\\|(?<![\w])/(?!/)[^\s/]|~[/\\]|\[private\][/\\])[^\r\n]*", RegexOptions.IgnoreCase)]
    private static partial Regex PathPattern();
    [GeneratedRegex(@"\$(?:pkzip2?|RAR3|rar5|pdf|oldoffice|truecrypt|zip2)\$[^\s\""<>]*", RegexOptions.IgnoreCase)]
    private static partial Regex HashPattern();
    [GeneratedRegex(@"(?<![A-Za-z0-9])[A-Za-z0-9_. -]+\.(?:zip|rar|7z|pdf|docx?|xlsx?|pptx?|hash|potfile)(?![A-Za-z0-9])", RegexOptions.IgnoreCase)]
    private static partial Regex FileNamePattern();
    [GeneratedRegex(@"(?:password|hash|filename)\s*[:=]\s*[^\s,;]+", RegexOptions.IgnoreCase)]
    private static partial Regex SecretPattern();
}
