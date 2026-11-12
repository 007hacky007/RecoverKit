using System.Net;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.App.Views;

/// <summary>
/// Benchmarking: it starts as soon as it opens, reports each format as Type / Protection / Engine /
/// Password recovery rate, and can save the report as HTML. The most common formats come first.
/// Measured speeds are stored for the wizard's time estimates.
/// </summary>
public sealed class BenchmarkWindow : Window
{
    private sealed record Entry(int Mode, string Type, string Protection);

    private static readonly Entry[] Entries =
    [
        new(9400, "Microsoft® Word 2007", "MS Office 2007, SHA1, 128-bit AES"),
        new(9600, "Microsoft® PowerPoint 2013-2016", "MS Office 2013+, SHA512, 256-bit AES"),
        new(22000, "WPA Handshake", "WPA/WPA2-PSK, PBKDF2-HMAC-SHA1"),
        new(12500, "RAR 3.x", "RAR 3.x, SHA1, 128-bit AES"),
        new(13000, "RAR 5.x", "RAR 5.x, PBKDF2/SHA256"),
        new(11600, "7-Zip", "7-Zip, SHA256, 256-bit AES"),
        new(13400, "KeePass KDB/KDBX 2/3", "KeePass, AES-KDF"),
        new(34300, "KeePass KDBX 4", "KeePass, Argon2"),
        new(17210, "ZIP/Classic", "ZipCrypto (PKWARE), 96-bit key"),
        new(13600, "WinZip/AES", "WinZip/AES, PBKDF2/SHA1, 256-bit AES"),
        new(29321, "TrueCrypt volume", "Volume header, PBKDF2-SHA-512, AES-XTS"),
        new(29311, "TrueCrypt volume", "Volume header, PBKDF2-RIPEMD-160, AES-XTS"),
        new(29331, "TrueCrypt volume", "Volume header, PBKDF2-Whirlpool, AES-XTS"),
        new(9700, "Microsoft® Word 97", "MS Office 97-2000, MD5, 40-bit RC4"),
        new(9800, "Microsoft® Word 2003", "MS Office XP-2003, SHA1, 128-bit RC4"),
        new(10500, "Adobe® PDF", "PDF /R 3, MD5, 128-bit RC4/AES"),
        new(10700, "Adobe® PDF", "PDF /R 6, SHA-256/384/512, 256-bit AES"),
        new(15600, "Ethereum keystore v3", "PBKDF2-SHA256, Keccak MAC"),
        new(15700, "Ethereum keystore v3", "scrypt, Keccak MAC"),
        new(16600, "Electrum seed / private key", "Double SHA256, AES-256-CBC"),
        new(21700, "Electrum encrypted wallet", "PBKDF2-SHA512, secp256k1, HMAC"),
        new(21800, "Electrum large encrypted wallet", "PBKDF2-SHA512, truncated verification"),
        new(26600, "MetaMask vault", "PBKDF2-SHA256, AES-GCM authentication"),
        new(26610, "MetaMask large vault", "PBKDF2-SHA256, partial plaintext verification"),
        new(12700, "Blockchain.com legacy wallet", "PBKDF2-SHA1, 10 iterations, AES-CBC"),
        new(15200, "Blockchain.com v2+ wallet", "PBKDF2-SHA1, AES-CBC"),
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
    private readonly SelectableTextBlock _report = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(14, 12) };
    private readonly ScrollViewer _scroll;
    private readonly TextBlock _step = L.Text("");
    private readonly TextBlock _progress = L.Text("", dim: true);
    private readonly Button _save;
    private readonly Button _abandon;
    private readonly List<(Entry Entry, double Speed)> _results = new();
    private readonly Dictionary<int, string> _engines = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly string _cpu = Platform.CpuName();
    private DateTime _started, _finished;
    private bool _running;


    public BenchmarkWindow(HashcatTool hashcat, Settings settings, List<BackendDevice> devices)
    {
        _hashcat = hashcat;
        _settings = settings;
        _devices = devices;
        Title = "Benchmark";
        Icon = Icons.AppIcon();
        Width = 760;
        Height = 560;
        MinWidth = 480;
        MinHeight = 320;
        CanMinimize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        _save = L.Button("Save as HTML...", () => _ = SaveHtmlAsync(), 130);
        _save.IsEnabled = false;
        _abandon = L.Button("Abandon", () => { if (_running) _cts.Cancel(); else Close(); }, 100, isCancel: true);

        var bar = L.Grid("Auto,*,Auto,Auto", columnSpacing: 10);
        bar.Put(_step, 0, 0);
        bar.Put(_progress, 0, 1);
        bar.Put(_save, 0, 2);
        bar.Put(_abandon, 0, 3);
        var footer = new Border { Padding = new Thickness(14, 10), Background = Palette.BandBrush, BorderBrush = Palette.LineBrush, BorderThickness = new Thickness(0, 1, 0, 0), Child = bar };

        _scroll = new ScrollViewer { Content = _report, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
        var root = new DockPanel();
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(new Border { Background = Palette.PaneBrush, Child = _scroll });
        Content = root;

        Closing += (_, _) => { if (_running) _cts.Cancel(); };
        Opened += async (_, _) => await RunAsync();
    }

    private IEnumerable<string> GpuNames() => _devices.Where(d => !d.IsSkippedAlias && d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase))
        .Select(d => $"#{d.Id} {d.Name} ({d.Backend})");

    private void Add(string s, bool bold = false)
    {
        var inl = _report.Inlines!;
        var r = new Run(s);
        if (bold) r.FontWeight = FontWeight.SemiBold;
        inl.Add(r);
        inl.Add(new LineBreak());
        Dispatcher.UIThread.Post(() => _scroll.ScrollToEnd(), DispatcherPriority.Background);
    }

    private string CpuLine => $"CPU [{_cpu}] {Platform.CpuFeatures()}, {Environment.ProcessorCount} threads";
    private string VersionLine => $"{MainWindow.AppName} Version {MainWindow.AppVersion} {Platform.Arch}";

    private void Header()
    {
        Add("Results", bold: true);
        Add(VersionLine);
        Add($"Benchmark started: {_started:F}");
        Add(CpuLine);
        var gpus = GpuNames().ToList();
        Add(gpus.Count == 0 ? "GPU devices not detected." : "GPU devices: " + string.Join(", ", gpus));
        Add("");
    }

    private async Task RunAsync()
    {
        _running = true;
        _started = DateTime.Now;
        Header();
        try
        {
            for (int i = 0; i < Entries.Length; i++)
            {
                _cts.Token.ThrowIfCancellationRequested();
                var e = Entries[i];
                _step.Text = $"Step {i + 1} of {Entries.Length}";
                _progress.Text = e.Type;
                // Same engine choice as a real attack: the built-in CPU kernels when no GPU is used.
                bool native = SpeedProbe.UseNative(_settings, _devices, e.Mode);
                double speed;
                try { (speed, native) = await SpeedProbe.MeasureAsync(_hashcat, _settings, _devices, e.Mode, TimeSpan.FromSeconds(8), _cts.Token); }
                catch (TimeoutException) { speed = 0; }
                _cts.Token.ThrowIfCancellationRequested();
                _engines[e.Mode] = native ? "built-in CPU engine" : GpuNames().Any() ? "hashcat, GPU" : "hashcat, CPU (OpenCL)";
                _results.Add((e, speed));
                if (speed > 0) _settings.SpeedByMode[e.Mode] = speed;

                Add($"Type: {e.Type}");
                Add($"Protection: {e.Protection}");
                Add($"Engine: {_engines[e.Mode]}");
                Add(speed > 0 ? $"Password recovery rate: {speed:N0}" : "Password recovery rate: not supported on this device", bold: true);
                Add("");
                DebugLog.Info($"Benchmark mode {e.Mode} ({e.Type}, {e.Protection}): {speed:N0} p/s");
            }
            _finished = DateTime.Now;
            Add($"Raw results: {string.Join(", ", _results.Select(r => ((long)r.Speed).ToString()))}");
            Add($"Benchmark finished: {_finished:F}");
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
            _abandon.Content = "Close";
            _save.IsEnabled = _results.Count > 0;
        }
    }

    private async Task SaveHtmlAsync()
    {
        var path = await Pick.Save(this, "HTML files (*.html)|*.html", $"Benchmark_{DateTime.Now:yyyy-MM-dd}.html", defaultExt: "html");
        if (path is null) return;
        static string H(string s) => WebUtility.HtmlEncode(s);
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>RecoverKit benchmark</title>")
          .Append("<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;font-size:14px}p{margin:0 0 10px}</style></head><body>")
          .Append("<h2>Results</h2><p>")
          .Append(H(VersionLine)).Append("<br>")
          .Append(H($"Benchmark started: {_started:F}")).Append("<br>")
          .Append(H(CpuLine)).Append("<br>");
        var gpus = GpuNames().ToList();
        sb.Append(H(gpus.Count == 0 ? "GPU devices not detected." : "GPU devices: " + string.Join(", ", gpus))).Append("</p>");
        foreach (var (e, s) in _results)
            sb.Append("<p>Type: ").Append(H(e.Type)).Append("<br>Protection: ").Append(H(e.Protection))
              .Append("<br>Engine: ").Append(H(_engines.GetValueOrDefault(e.Mode, "")))
              .Append("<br><b>Password recovery rate: ").Append(s > 0 ? s.ToString("N0") : "not supported on this device").Append("</b></p>");
        sb.Append("<p>Raw results: ").Append(string.Join(", ", _results.Select(r => ((long)r.Speed).ToString()))).Append("<br>");
        if (_finished != default) sb.Append(H($"Benchmark finished: {_finished:F}"));
        sb.Append("</p></body></html>");
        try { await File.WriteAllTextAsync(path, sb.ToString(), new UTF8Encoding(true)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { await Msg.Error(this, ex.Message, Title); }
    }
}
