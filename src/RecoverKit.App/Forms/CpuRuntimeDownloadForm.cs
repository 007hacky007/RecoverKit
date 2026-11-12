using System.Diagnostics;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Forms;

/// <summary>
/// Downloads Intel's CPU Runtime for OpenCL so passwords can be recovered on the processor when no GPU
/// driver is present. Intel's license must be accepted before anything is downloaded.
/// </summary>
public sealed class CpuRuntimeDownloadForm : Form
{
    private readonly Label _status = new() { Dock = DockStyle.Top, Height = 62, Padding = new Padding(2, 6, 2, 0) };
    private readonly LinkLabel _license = new() { Dock = DockStyle.Top, Height = 22, Padding = new Padding(2, 2, 2, 0) };
    private readonly CheckBox _accept = new() { Dock = DockStyle.Top, Height = 26, Text = "I accept the " + CpuRuntime.LicenseName };
    private readonly ProgressBar _bar = new() { Dock = DockStyle.Top, Height = 22, Style = ProgressBarStyle.Continuous, Maximum = 1000 };
    private readonly Label _detail = new() { Dock = DockStyle.Top, Height = 24, ForeColor = Color.DimGray, Padding = new Padding(2, 4, 2, 0), AutoEllipsis = true };
    private readonly Button _action = new() { Text = "Download", Width = 100, Enabled = false };
    private readonly Button _cancel = new() { Text = "Cancel", Width = 100, DialogResult = DialogResult.Cancel };
    private CancellationTokenSource? _cts;
    private bool _running;

    public CpuRuntimeDownloadForm()
    {
        Text = "Download CPU runtime";
        Font = new Font("Segoe UI", 9f);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(500, 250);

        _status.Text = $"No GPU driver is available, so hashcat cannot run. This downloads Intel's CPU Runtime for OpenCL " +
                       $"{CpuRuntime.Version} (about {CpuRuntime.DownloadBytes / 1_000_000} MB, official packages, SHA-256 verified) " +
                       "into your user folder so passwords are recovered on the processor. Nothing is installed system-wide.";
        _license.Text = "Read the " + CpuRuntime.LicenseName;
        _license.LinkArea = new LinkArea(9, CpuRuntime.LicenseName.Length);
        _license.LinkClicked += (_, _) => Process.Start(new ProcessStartInfo(CpuRuntime.LicenseUrl) { UseShellExecute = true })?.Dispose();
        _accept.CheckedChanged += (_, _) => _action.Enabled = _accept.Checked && !_running;

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 44, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 8, 8, 0) };
        buttons.Controls.AddRange([_cancel, _action]);

        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10, 6, 10, 0) };
        body.Controls.Add(_detail);
        body.Controls.Add(_bar);
        body.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 6 });
        body.Controls.Add(_accept);
        body.Controls.Add(_license);
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
        if (!_accept.Checked) return;
        _running = true;
        _action.Enabled = _accept.Enabled = false;
        _cts = new CancellationTokenSource();
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
            await CpuRuntime.InstallAsync(progress, _cts.Token);
            _bar.Value = _bar.Maximum;
            _running = false;
            DialogResult = DialogResult.OK;
            Close();
        }
        catch (OperationCanceledException)
        {
            _status.Text = "Cancelled.";
            _detail.Text = "";
        }
        catch (InstallException ex)
        {
            _status.Text = "Install failed.";
            _detail.Text = ex.Message;
            MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            _running = false;
            _accept.Enabled = true;
            _action.Enabled = _accept.Checked;
        }
    }
}
