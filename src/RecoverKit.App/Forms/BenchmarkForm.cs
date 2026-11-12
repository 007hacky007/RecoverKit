using System.Net;
using System.Runtime.Intrinsics.X86;
using System.Text;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.App.Forms;

/// <summary>
/// Benchmarking: it starts as soon as it opens, reports each format as Type / Protection / Engine /
/// Password recovery rate, and can save the report as HTML. The most common formats come first.
/// Measured speeds are stored for the wizard's time estimates.
/// </summary>
public sealed class BenchmarkForm : Form
{
    private sealed record Entry(int Mode, string Type, string Protection);

    private static readonly Entry[] Entries =
    [
        new(9400, "Microsoft® Word 2007", "MS Office 2007, SHA1, 128-bit AES"),
        new(9600, "Microsoft® PowerPoint 2013-2016", "MS Office 2013+, SHA512, 256-bit AES"),
        new(22000, "WPA Handshake", "WPA/WPA2-PSK, PBKDF2-HMAC-SHA1"),
        new(12500, "RAR 3.x", "RAR 3.x, SHA1, 128-bit AES"),
        new(13000, "RAR 5.x", "RAR 5.x, PBKDF2/SHA256"),
        new(17210, "ZIP/Classic", "ZipCrypto (PKWARE), 96-bit key"),
        new(13600, "WinZip/AES", "WinZip/AES, PBKDF2/SHA1, 256-bit AES"),
        new(29321, "TrueCrypt volume", "Volume header, PBKDF2-SHA-512, AES-XTS"),
        new(29311, "TrueCrypt volume", "Volume header, PBKDF2-RIPEMD-160, AES-XTS"),
        new(29331, "TrueCrypt volume", "Volume header, PBKDF2-Whirlpool, AES-XTS"),
        new(9700, "Microsoft® Word 97", "MS Office 97-2000, MD5, 40-bit RC4"),
        new(9800, "Microsoft® Word 2003", "MS Office XP-2003, SHA1, 128-bit RC4"),
        new(10500, "Adobe® PDF", "PDF /R 3, MD5, 128-bit RC4/AES"),
        new(10700, "Adobe® PDF", "PDF /R 6, SHA-256/384/512, 256-bit AES"),
        // Further formats.
        new(9500, "Microsoft® Word 2010", "MS Office 2010, SHA1, 128-bit AES"),
        new(18400, "OpenDocument", "ODF 1.2+, PBKDF2/SHA1, 256-bit AES"),
        new(10400, "Adobe® PDF", "PDF /R 2, MD5, 40-bit RC4"),
        new(10600, "Adobe® PDF", "PDF /R 5, SHA-256, 256-bit AES"),
        new(29421, "VeraCrypt volume", "VeraCrypt volume header, PBKDF2/SHA-512/AES"),
    ];

    private readonly HashcatTool _hashcat;
    private readonly Settings _settings;
    private readonly List<BackendDevice> _devices;
    private readonly RichTextBox _report = new() { ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = SystemColors.Window, Dock = DockStyle.Fill, Font = new Font("Segoe UI", 9f) };
    private readonly Label _step = new() { AutoSize = true, Margin = new Padding(0, 9, 12, 0) };
    private readonly Label _progress = new() { AutoSize = true, Margin = new Padding(0, 9, 0, 0) };
    private readonly Button _save = new() { Text = "Save as HTML...", Width = 130, Enabled = false };
    private readonly Button _abandon = new() { Text = "Abandon", Width = 100 };
    private readonly List<(Entry Entry, double Speed)> _results = new();
    private readonly Dictionary<int, string> _engines = new();

    private bool UseNative(int mode) =>
        _settings.UseNativeCpuEngine && string.IsNullOrWhiteSpace(_settings.ExtraArguments) && NativeKernels.Supports(mode) && (!GpuNames().Any() || _settings.Strategy == DeviceStrategy.CpuOnly)
        && NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]) is not null;
    private readonly CancellationTokenSource _cts = new();
    private DateTime _started, _finished;
    private bool _running;

    public BenchmarkForm(HashcatTool hashcat, Settings settings, List<BackendDevice> devices)
    {
        _hashcat = hashcat;
        _settings = settings;
        _devices = devices;
        Text = "Benchmarking";
        Font = new Font("Segoe UI", 9f);
        StartPosition = FormStartPosition.CenterParent;
        Size = new Size(740, 520);
        MinimizeBox = false;
        ShowInTaskbar = false;

        var host = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8), BackColor = SystemColors.Window, BorderStyle = BorderStyle.Fixed3D };
        host.Controls.Add(_report);
        var bar = new TableLayoutPanel { Dock = DockStyle.Bottom, Height = 40, ColumnCount = 4, Padding = new Padding(6, 4, 6, 4) };
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        bar.Controls.Add(_step, 0, 0);
        bar.Controls.Add(_progress, 1, 0);
        bar.Controls.Add(_save, 2, 0);
        bar.Controls.Add(_abandon, 3, 0);
        Controls.Add(host);
        Controls.Add(bar);
        CancelButton = _abandon;

        _abandon.Click += (_, _) => { if (_running) _cts.Cancel(); else Close(); };
        _save.Click += (_, _) => SaveHtml();
        FormClosing += (_, e) => { if (_running) { _cts.Cancel(); } };
        Shown += async (_, _) => await RunAsync();
    }

    private static string CpuFeatures()
    {
        var f = new List<string>();
        if (Sse2.IsSupported) f.Add("SSE2");
        if (Avx.IsSupported) f.Add("AVX");
        if (Avx2.IsSupported) f.Add("AVX2");
        if (Avx512F.IsSupported) f.Add("AVX-512");
        if (System.Runtime.Intrinsics.X86.Aes.IsSupported) f.Add("AES-NI");
        return string.Join(' ', f);
    }

    private IEnumerable<string> GpuNames() => _devices.Where(d => !d.IsSkippedAlias && d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase))
        .Select(d => $"#{d.Id} {d.Name} ({d.Backend})");

    private void Header()
    {
        void L(string s, bool bold = false) { _report.SelectionFont = new Font(_report.Font, bold ? FontStyle.Bold : FontStyle.Regular); _report.AppendText(s + Environment.NewLine); }
        L("Results", bold: true);
        L($"{MainForm.AppName} Version {MainForm.AppVersion} x64");
        L($"Benchmark started: {_started:F}");
        L($"CPU [{DebugLogCpu()}] {CpuFeatures()}, {Environment.ProcessorCount} threads");
        var gpus = GpuNames().ToList();
        L(gpus.Count == 0 ? "GPU devices not detected." : "GPU devices: " + string.Join(", ", gpus));
        L("");
    }

    private static string DebugLogCpu()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            return (k?.GetValue("ProcessorNameString") as string)?.Trim() ?? "unknown";
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return "unknown"; }
    }

    private async Task RunAsync()
    {
        _running = true;
        _started = DateTime.Now;
        Header();
        var deviceArgs = HashcatRunner.DeviceArguments(_settings, _devices);
        deviceArgs.AddRange(["-w", _settings.Workload.ToString()]);
        try
        {
            for (int i = 0; i < Entries.Length; i++)
            {
                _cts.Token.ThrowIfCancellationRequested();
                var e = Entries[i];
                _step.Text = $"Step {i + 1} of {Entries.Length}";
                _progress.Text = e.Type;
                // Same engine choice as a real attack: the built-in CPU kernels when no GPU is used.
                bool native = UseNative(e.Mode);
                double speed;
                if (native)
                {
                    int threads = _settings.MaxCpuThreads > 0 ? _settings.MaxCpuThreads : Environment.ProcessorCount;
                    speed = await Task.Run(() => NativeKernels.Benchmark(e.Mode, threads, TimeSpan.FromSeconds(8), _cts.Token));
                }
                else
                {
                    var args = new List<string>(deviceArgs);
                    if (_settings.OptimizedKernels && (await _hashcat.ModeInfoAsync(e.Mode))?.HasOptimizedKernel == true) args.Add("-O");
                    try { speed = await _hashcat.BenchmarkAsync(e.Mode, args, _cts.Token); }
                    catch (TimeoutException) { speed = 0; }
                }
                _cts.Token.ThrowIfCancellationRequested();
                _engines[e.Mode] = native ? "built-in CPU engine" : GpuNames().Any() ? "hashcat, GPU" : "hashcat, CPU (OpenCL)";
                _results.Add((e, speed));
                if (speed > 0) _settings.SpeedByMode[e.Mode] = speed;

                _report.SelectionFont = _report.Font;
                _report.AppendText($"Type: {e.Type}{Environment.NewLine}Protection: {e.Protection}{Environment.NewLine}Engine: {_engines[e.Mode]}{Environment.NewLine}");
                _report.SelectionFont = new Font(_report.Font, FontStyle.Bold);
                _report.AppendText((speed > 0 ? $"Password recovery rate: {speed:N0}" : "Password recovery rate: not supported on this device") + Environment.NewLine + Environment.NewLine);
                _report.ScrollToCaret();
                DebugLog.Info($"Benchmark mode {e.Mode} ({e.Type}, {e.Protection}): {speed:N0} p/s");
            }
            _finished = DateTime.Now;
            _report.SelectionFont = _report.Font;
            _report.AppendText($"Raw results: {string.Join(", ", _results.Select(r => ((long)r.Speed).ToString()))}{Environment.NewLine}");
            _report.AppendText($"Benchmark finished: {_finished:F}{Environment.NewLine}");
            _step.Text = "";
            _progress.Text = "";
            _settings.Save();
        }
        catch (OperationCanceledException)
        {
            _step.Text = "Benchmark abandoned";
            _progress.Text = "";
        }
        finally
        {
            _running = false;
            _abandon.Text = "Close";
            _save.Enabled = _results.Count > 0;
        }
    }

    private void SaveHtml()
    {
        using var d = new SaveFileDialog { Filter = "HTML files (*.html)|*.html", FileName = $"Benchmark_{DateTime.Now:yyyy-MM-dd}.html" };
        if (d.ShowDialog(this) != DialogResult.OK) return;
        static string H(string s) => WebUtility.HtmlEncode(s);
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>RecoverKit benchmark</title>")
          .Append("<style>body{font-family:Segoe UI,sans-serif;font-size:14px}p{margin:0 0 10px}</style></head><body>")
          .Append("<h2>Results</h2><p>")
          .Append(H($"{MainForm.AppName} Version {MainForm.AppVersion} x64")).Append("<br>")
          .Append(H($"Benchmark started: {_started:F}")).Append("<br>")
          .Append(H($"CPU [{DebugLogCpu()}] {CpuFeatures()}, {Environment.ProcessorCount} threads")).Append("<br>");
        var gpus = GpuNames().ToList();
        sb.Append(H(gpus.Count == 0 ? "GPU devices not detected." : "GPU devices: " + string.Join(", ", gpus))).Append("</p>");
        foreach (var (e, s) in _results)
            sb.Append("<p>Type: ").Append(H(e.Type)).Append("<br>Protection: ").Append(H(e.Protection))
              .Append("<br>Engine: ").Append(H(_engines.GetValueOrDefault(e.Mode, "")))
              .Append("<br><b>Password recovery rate: ").Append(s > 0 ? s.ToString("N0") : "not supported on this device").Append("</b></p>");
        sb.Append("<p>Raw results: ").Append(string.Join(", ", _results.Select(r => ((long)r.Speed).ToString()))).Append("<br>");
        if (_finished != default) sb.Append(H($"Benchmark finished: {_finished:F}"));
        sb.Append("</p></body></html>");
        File.WriteAllText(d.FileName, sb.ToString(), new UTF8Encoding(true));
    }
}
