using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using System.IO.Compression;
using RecoverKit.App.Ui;
using RecoverKit.Core;
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

/// <summary>Downloads and verifies a newer RecoverKit release; the caller applies it and exits.</summary>
public sealed class UpdateWindow : ProgressDialog
{
    private readonly ReleaseInfo _release;
    private readonly InstallKind _kind;
    public PreparedUpdate? Prepared { get; private set; }

    /// <param name="start">Start the download as soon as the dialog opens (the toolbar's one-click Update).</param>
    public static async Task<PreparedUpdate?> RunAsync(Window owner, ReleaseInfo release, InstallKind kind, ReleaseAsset asset, bool start = false)
    {
        var w = new UpdateWindow(release, kind, asset);
        if (start) w.Opened += (_, _) => _ = w.RunAsync();
        return await w.ShowDialog<bool>(owner) ? w.Prepared : null;
    }

    private UpdateWindow(ReleaseInfo release, InstallKind kind, ReleaseAsset asset) : base("Update " + MainWindow.AppName, "Update")
    {
        _release = release;
        _kind = kind;
        Status.Text = $"{MainWindow.AppName} {release.Tag} is available (you have {MainWindow.AppVersion}).\n\n" +
                      $"This downloads {asset.Name}{(asset.Size > 0 ? $" ({asset.Size / 1_000_000.0:N0} MB)" : "")}, checks it and installs it. " +
                      $"{MainWindow.AppName} closes while the update runs and starts again afterwards." +
                      (kind == InstallKind.WindowsMsi ? " Windows may ask for permission to install." : "");
        Build();
    }

    protected override async Task RunAsync()
    {
        Running = true;
        Action.IsEnabled = false;
        Cts = new CancellationTokenSource();
        try
        {
            Prepared = await AppUpdater.PrepareAsync(_release, _kind, Reporter(), Cts.Token);
            Bar.Value = Bar.Maximum;
            Status.Text = $"{MainWindow.AppName} {_release.Tag} is ready. {MainWindow.AppName} now closes to install it.";
            Succeed();
        }
        catch (OperationCanceledException)
        {
            Status.Text = "Cancelled.";
            Detail.Text = "";
            Action.IsEnabled = true;
        }
        catch (Exception ex) when (ex is InstallException or HttpRequestException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            DebugLog.Error("Update failed", ex);
            Status.Text = "Update failed.";
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
/// Shows recovered password(s): a check mark that draws itself once, the password with Hide/Show and
/// Copy (confirmed by a small toast), and "Decrypt file..." when the format can be decrypted.
/// </summary>
public sealed class PasswordFoundWindow : Window
{
    public static Task RunAsync(Window owner, IReadOnlyList<string> passwords, string? fileName = null, TimeSpan? elapsed = null,
        Func<Window, Task>? decrypt = null) => new PasswordFoundWindow(passwords, fileName, elapsed, decrypt).ShowDialog(owner);

    private readonly CheckMark _check = new();
    private readonly Border _toast;
    private int _toastGeneration;

    internal PasswordFoundWindow(IReadOnlyList<string> passwords, string? fileName = null, TimeSpan? elapsed = null, Func<Window, Task>? decrypt = null)
    {
        Title = "Password found";
        Icon = Icons.AppIcon();
        Width = 440;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        CanMinimize = false;
        CanMaximize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        bool canCopy = passwords.Count > 0 && passwords[0].Length > 0;
        string Shown(string p, bool hidden) => p.Length == 0 ? "(empty password)" : hidden ? new string('•', Math.Min(p.Length, 24)) : p;
        bool hidden = false;
        var pw = new SelectableTextBlock
        {
            FontFamily = Ui.Styles.Mono, FontSize = 19, FontWeight = FontWeight.SemiBold, TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center, MaxHeight = 160,
            FontStyle = passwords.Count > 0 && passwords[0].Length == 0 ? FontStyle.Italic : FontStyle.Normal,
        };
        void Render() => pw.Text = string.Join("\n", passwords.Select(p => Shown(p, hidden)));
        Render();

        var hide = L.Button("Hide", () => { }, 64);
        hide.Click += (_, _) =>
        {
            hidden = !hidden;
            hide.Content = hidden ? "Show" : "Hide";
            Render();
        };
        hide.IsEnabled = canCopy;
        var copy = L.Button("Copy", () => _ = CopyAsync(passwords), 64);
        copy.Classes.Add("accent");
        copy.IsEnabled = canCopy;
        var pwButtons = L.Row(hide, copy);
        pwButtons.Spacing = 6;
        pwButtons.VerticalAlignment = VerticalAlignment.Center;
        var pwRow = new DockPanel();
        DockPanel.SetDock(pwButtons, Dock.Right);
        pwButtons.Margin = new Thickness(8, 0, 0, 0);
        pwRow.Children.Add(pwButtons);
        pwRow.Children.Add(pw);
        var pwBox = new Border
        {
            Background = Palette.InsetBrush, BorderBrush = Palette.LineBrush, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12, 8, 8, 8), Child = pwRow, HorizontalAlignment = HorizontalAlignment.Stretch,
        };

        var heading = new TextBlock { Text = passwords.Count > 1 ? "Passwords recovered" : "Password recovered", FontSize = 15, FontWeight = FontWeight.SemiBold, HorizontalAlignment = HorizontalAlignment.Center };
        var sub = new TextBlock
        {
            Foreground = Palette.DimBrush, FontSize = 12, HorizontalAlignment = HorizontalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis,
            Text = string.Join("  ·  ", new[] { fileName, elapsed is { } e ? "found in " + Fmt.Duration(e.TotalSeconds) : null }.Where(x => !string.IsNullOrEmpty(x))),
        };
        sub.IsVisible = sub.Text.Length > 0;
        _check.HorizontalAlignment = HorizontalAlignment.Center;
        if (!Platform.ReduceMotion) _check.Progress = 0;
        var body = L.Column(10, _check, heading, sub, pwBox);
        body.Margin = new Thickness(22, 22, 22, 18);

        var tick = Icons.Check(13);
        tick.Brush = Palette.GoodBrush;
        tick.VerticalAlignment = VerticalAlignment.Center;
        _toast = new Border
        {
            Background = Palette.ToastBrush, CornerRadius = new CornerRadius(8), Padding = new Thickness(12, 7),
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Bottom, Margin = new Thickness(0, 0, 0, 10),
            BorderBrush = new SolidColorBrush(Color.FromUInt32(0x33FFFFFF)), BorderThickness = new Thickness(1), IsVisible = false, IsHitTestVisible = false,
            Child = new StackPanel
            {
                Orientation = Orientation.Horizontal, Spacing = 8,
                Children = { tick, new TextBlock { Text = "Password copied to the clipboard", FontSize = 12, Foreground = new SolidColorBrush(Color.FromUInt32(0xFFE9EAED)) } },
            },
        };
        var middle = new Grid { Children = { body, _toast } };
        // Room for the toast under the password box.
        body.Margin = new Thickness(22, 22, 22, 52);

        var ok = L.Button("OK", () => Close(), 90, isDefault: true, isCancel: true);
        Control[] footerButtons = decrypt is null ? [ok] : [L.Button("Decrypt file...", () => _ = decrypt(this), 110), ok];
        var footer = L.Footer(footerButtons);
        var root = new DockPanel();
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(middle);
        Content = root;
        Opened += (_, _) => { ok.Focus(); _check.Play(); };
    }

    private async Task CopyAsync(IReadOnlyList<string> passwords)
    {
        if (passwords.Count == 0 || passwords[0].Length == 0 || Clipboard is not { } cb) return;
        try { await Avalonia.Input.Platform.ClipboardExtensions.SetTextAsync(cb, passwords[0]); }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.ExternalException)
        {
            RecoverKit.Core.DebugLog.Warn("Clipboard: " + ex.Message);
            return;
        }
        ShowToast();
    }

    /// <summary>"Password copied to the clipboard" for about two seconds.</summary>
    internal async void ShowToast()
    {
        int gen = ++_toastGeneration;
        _toast.IsVisible = true;
        if (!Platform.ReduceMotion) await Views.MainWindow.RiseAsync(_toast);
        await Task.Delay(2000);
        if (gen == _toastGeneration) _toast.IsVisible = false;
    }

#if DEBUG
    /// <summary>Snapshot mode: the finished check mark and the toast.</summary>
    internal void DebugFinish(bool toast)
    {
        _check.Progress = 1;
        if (toast) { _toastGeneration++; _toast.IsVisible = true; _toast.Opacity = 1; _toast.RenderTransform = null; }
    }
#endif
}
