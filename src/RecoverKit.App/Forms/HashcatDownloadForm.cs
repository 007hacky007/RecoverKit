using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Forms;

/// <summary>Downloads and installs hashcat with a progress bar, so the engine can be set up from the GUI.</summary>
public sealed class HashcatDownloadForm : Form
{
    private readonly Label _status = new() { Dock = DockStyle.Top, Height = 40, Padding = new Padding(2, 6, 2, 0), AutoEllipsis = true };
    private readonly ProgressBar _bar = new() { Dock = DockStyle.Top, Height = 22, Style = ProgressBarStyle.Continuous, Maximum = 1000 };
    private readonly Label _detail = new() { Dock = DockStyle.Top, Height = 24, ForeColor = Color.DimGray, Padding = new Padding(2, 4, 2, 0), AutoEllipsis = true };
    private readonly Button _action = new() { Text = "Download", Width = 100 };
    private readonly Button _cancel = new() { Text = "Cancel", Width = 100, DialogResult = DialogResult.Cancel };
    private CancellationTokenSource? _cts;
    private bool _running;

    /// <summary>The installed hashcat executable, set when the install succeeds.</summary>
    public string? InstalledExe { get; private set; }

    public HashcatDownloadForm()
    {
        Text = "Download hashcat";
        Font = new Font("Segoe UI", 9f);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(440, 170);

        _status.Text = $"This downloads hashcat {HashcatInstaller.Version} (about 20 MB) from hashcat.net\r\n" +
                       "and unpacks it for RecoverKit to use.";

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 44, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 8, 8, 0) };
        buttons.Controls.AddRange([_cancel, _action]);

        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10, 6, 10, 0) };
        body.Controls.Add(_detail);
        body.Controls.Add(_bar);
        body.Controls.Add(_status);

        Controls.Add(body);
        Controls.Add(buttons);
        AcceptButton = _action;
        CancelButton = _cancel;

        _action.Click += async (_, _) => await RunAsync();
        FormClosing += (_, e) => { if (_running) { e.Cancel = true; _cts?.Cancel(); } };
    }

    private async Task RunAsync()
    {
        _running = true;
        _action.Enabled = false;
        _cts = new CancellationTokenSource();
        var installer = new HashcatInstaller();
        var progress = new Progress<InstallProgress>(p =>
        {
            if (p.Message.Length > 0) _status.Text = p.Message;
            if (p.BytesTotal > 0)
            {
                _bar.Value = (int)(p.Fraction * 1000);
                _detail.Text = $"{p.BytesDone / 1_000_000.0:N1} / {p.BytesTotal / 1_000_000.0:N1} MB ({p.Fraction:P0})";
            }
            else _detail.Text = "";
        });

        try
        {
            var res = await installer.InstallAsync(progress, _cts.Token);
            _bar.Value = _bar.Maximum;
            if (res.ExecutablePath is { } exe)
            {
                InstalledExe = exe;
                _status.Text = "hashcat installed successfully.";
                DialogResult = DialogResult.OK;
                _running = false;
                Close();
            }
            else
            {
                _status.Text = "Extracted, but the release contains no hashcat binary for this OS.";
                _detail.Text = res.Directory;
                _cancel.Text = "Close";
            }
        }
        catch (OperationCanceledException)
        {
            _status.Text = "Cancelled.";
            _detail.Text = "";
            _action.Enabled = true;
        }
        catch (InstallException ex)
        {
            _status.Text = "Install failed.";
            _detail.Text = ex.Message;
            MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
            _action.Enabled = true;
        }
        finally
        {
            _running = false;
        }
    }
}
