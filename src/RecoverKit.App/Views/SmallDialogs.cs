using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using RecoverKit.App.Ui;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Views;

/// <summary>Shared layout of the progress dialogs: text, progress bar, detail line and buttons.</summary>
public abstract class ProgressDialog : Window
{
    protected readonly TextBlock Status = L.Text("", wrap: true);
    protected readonly ProgressBar Bar = new() { Minimum = 0, Maximum = 1000, Height = 6, MinHeight = 6 };
    protected readonly TextBlock Detail = L.Text("", dim: true);
    protected readonly Button Action;
    protected readonly Button CancelButton;
    protected CancellationTokenSource? Cts;
    protected bool Running;
    private bool _result;

    protected ProgressDialog(string title, string action)
    {
        Title = title;
        Icon = Icons.AppIcon();
        Width = 520;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        CanMinimize = false;
        CanMaximize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Detail.TextTrimming = TextTrimming.CharacterEllipsis;
        Action = L.Button(action, () => _ = RunAsync(), 110, isDefault: true);
        CancelButton = L.Button("Cancel", () => { if (Running) Cts?.Cancel(); else Close(_result); }, 110, isCancel: true);
        Closing += (_, e) => { if (Running) { e.Cancel = true; Cts?.Cancel(); } };
    }

    protected void Build(params Control[] middle)
    {
        var footer = L.Footer(Platform.IsMac ? [CancelButton, Action] : [Action, CancelButton]);
        var body = L.Column(10, [Status, .. middle, Bar, Detail]);
        body.Margin = new Thickness(18, 16, 18, 14);
        var root = new DockPanel();
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(body);
        Content = root;
    }

    protected Progress<InstallProgress> Reporter() => new(p =>
    {
        if (p.Message.Length > 0) Status.Text = p.Message;
        if (p.BytesTotal > 0)
        {
            Bar.Value = p.Fraction * 1000;
            Detail.Text = $"{p.BytesDone / 1_000_000.0:N1} / {p.BytesTotal / 1_000_000.0:N1} MB ({p.Fraction:P0})";
        }
        else Detail.Text = "";
    });

    protected void Succeed()
    {
        _result = true;
        Running = false;
        Close(true);
    }

    protected abstract Task RunAsync();
}

/// <summary>Downloads (Windows, Linux) or installs from the app bundle (macOS) the hashcat engine.</summary>
public sealed class HashcatDownloadWindow : ProgressDialog
{
    public string? InstalledExe { get; private set; }

    public static async Task<string?> RunAsync(Window owner)
    {
        var w = new HashcatDownloadWindow();
        return await w.ShowDialog<bool>(owner) ? w.InstalledExe : null;
    }

    private HashcatDownloadWindow() : base(Platform.IsMac ? "Install hashcat" : "Download hashcat", Platform.IsMac ? "Install" : "Download")
    {
        Status.Text = Platform.IsMac
            ? $"This copies hashcat {HashcatInstaller.Version}, which comes with RecoverKit, into your user folder, where it can keep its compiled GPU kernels."
            : $"This downloads hashcat {HashcatInstaller.Version} (about 20 MB) from hashcat.net and unpacks it for RecoverKit to use.";
        Build();
    }

    protected override async Task RunAsync()
    {
        Running = true;
        Action.IsEnabled = false;
        Cts = new CancellationTokenSource();
        try
        {
            var res = await new HashcatInstaller().InstallAsync(Reporter(), Cts.Token);
            Bar.Value = Bar.Maximum;
            if (res.ExecutablePath is { } exe)
            {
                InstalledExe = exe;
                Status.Text = "hashcat installed successfully.";
                Succeed();
            }
            else
            {
                Status.Text = "Extracted, but the release contains no hashcat binary for this system.";
                Detail.Text = res.Directory;
                CancelButton.Content = "Close";
            }
        }
        catch (OperationCanceledException)
        {
            Status.Text = "Cancelled.";
            Detail.Text = "";
            Action.IsEnabled = true;
        }
        catch (InstallException ex)
        {
            Status.Text = "Install failed.";
            Detail.Text = ex.Message;
            await Msg.Error(this, ex.Message, Title);
            Action.IsEnabled = true;
        }
        finally
        {
            Running = false;
        }
    }
}

/// <summary>
/// Downloads Intel's CPU Runtime for OpenCL (Windows) so passwords can be recovered on the processor when no
/// GPU driver is present. Intel's license must be accepted before anything is downloaded.
/// </summary>
public sealed class CpuRuntimeDownloadWindow : ProgressDialog
{
    private readonly CheckBox _accept = new() { Content = "I accept the " + CpuRuntime.LicenseName };

    public static async Task<bool> RunAsync(Window owner) => await new CpuRuntimeDownloadWindow().ShowDialog<bool>(owner);

    private CpuRuntimeDownloadWindow() : base("Download CPU runtime", "Download")
    {
        Status.Text = $"No GPU driver is available, so hashcat cannot run. This downloads Intel's CPU Runtime for OpenCL " +
                      $"{CpuRuntime.Version} (about {CpuRuntime.DownloadBytes / 1_000_000} MB, official packages, SHA-256 verified) " +
                      "into your user folder so passwords are recovered on the processor. Nothing is installed system-wide.";
        var license = new HyperlinkButton { Content = "Read the " + CpuRuntime.LicenseName, NavigateUri = new Uri(CpuRuntime.LicenseUrl), Padding = new Thickness(0) };
        Action.IsEnabled = false;
        _accept.IsCheckedChanged += (_, _) => Action.IsEnabled = _accept.IsChecked == true && !Running;
        Build(license, _accept);
    }

    protected override async Task RunAsync()
    {
        if (_accept.IsChecked != true) return;
        Running = true;
        Action.IsEnabled = _accept.IsEnabled = false;
        Cts = new CancellationTokenSource();
        try
        {
            await CpuRuntime.InstallAsync(Reporter(), Cts.Token);
            Bar.Value = Bar.Maximum;
            Succeed();
        }
        catch (OperationCanceledException)
        {
            Status.Text = "Cancelled.";
            Detail.Text = "";
        }
        catch (InstallException ex)
        {
            Status.Text = "Install failed.";
            Detail.Text = ex.Message;
            await Msg.Error(this, ex.Message, Title);
        }
        finally
        {
            Running = false;
            _accept.IsEnabled = true;
            Action.IsEnabled = _accept.IsChecked == true;
        }
    }
}

/// <summary>Shows recovered password(s) with a copy button.</summary>
public sealed class PasswordFoundWindow : Window
{
    public static Task RunAsync(Window owner, IReadOnlyList<string> passwords) => new PasswordFoundWindow(passwords).ShowDialog(owner);

    private PasswordFoundWindow(IReadOnlyList<string> passwords)
    {
        Title = "Password found";
        Icon = Icons.AppIcon();
        Width = 460;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        CanMinimize = false;
        CanMaximize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var box = new TextBox
        {
            IsReadOnly = true, FontFamily = new FontFamily("Menlo, Consolas, monospace"), FontSize = 20, FontWeight = FontWeight.Bold,
            Text = string.Join("\n", passwords.Select(p => p.Length == 0 ? "(empty password)" : p)),
            AcceptsReturn = passwords.Count > 1, MaxHeight = 160, TextWrapping = TextWrapping.Wrap,
        };
        var copy = L.Button("Copy", async () =>
        {
            if (passwords.Count > 0 && Clipboard is { } cb) await Avalonia.Input.Platform.ClipboardExtensions.SetTextAsync(cb, passwords[0]);
        }, 90);
        var ok = L.Button("OK", () => Close(), 90, isDefault: true, isCancel: true);
        var footer = L.Footer(Platform.IsMac ? [copy, ok] : [copy, ok]);
        var body = L.Column(10, L.Text("The password was successfully recovered:"), box);
        body.Margin = new Thickness(18, 16, 18, 14);
        var root = new DockPanel();
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(body);
        Content = root;
        Opened += (_, _) => box.Focus();
    }
}
