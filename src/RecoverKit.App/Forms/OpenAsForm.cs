using System.Globalization;
using RecoverKit.Core;
using RecoverKit.Core.Formats;

namespace RecoverKit.App.Forms;

/// <summary>"Open As": TrueCrypt/VeraCrypt volume settings, or a hash entered manually.</summary>
public sealed class OpenAsForm : Form
{
    public Detection? Result { get; private set; }

    private readonly RadioButton _tc = new() { Text = "TrueCrypt volume", AutoSize = true };
    private readonly RadioButton _vc = new() { Text = "VeraCrypt volume", AutoSize = true, Checked = true };
    private readonly RadioButton _manual = new() { Text = "Enter hash manually (any hashcat mode)", AutoSize = true };
    private readonly TextBox _file = new() { Dock = DockStyle.Fill };
    private readonly ComboBox _offset = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 170 };
    private readonly TextBox _customOffset = new() { Width = 90, Text = "0" };
    private readonly RadioButton _hex = new() { Text = "Hex", AutoSize = true }, _dec = new() { Text = "Dec", AutoSize = true, Checked = true };
    private readonly CheckBox _ripemd = new() { Text = "RIPEMD-160", AutoSize = true };
    private readonly CheckBox _sha512 = new() { Text = "SHA-512", AutoSize = true, Checked = true };
    private readonly CheckBox _whirl = new() { Text = "Whirlpool", AutoSize = true };
    private readonly CheckBox _sha256 = new() { Text = "SHA-256", AutoSize = true };
    private readonly CheckBox _streebog = new() { Text = "Streebog", AutoSize = true };
    private readonly CheckBox _single = new() { Text = "Single cipher (AES, Serpent, Twofish, Camellia, Kuznyechik)", AutoSize = true, Checked = true };
    private readonly CheckBox _double = new() { Text = "Two-cipher cascades (e.g. AES-Twofish)", AutoSize = true };
    private readonly CheckBox _triple = new() { Text = "Three-cipher cascades (e.g. AES-Twofish-Serpent)", AutoSize = true };
    private readonly NumericUpDown _mode = new() { Minimum = 0, Maximum = 999999, Width = 90 };
    private readonly TextBox _hash = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = new Font("Consolas", 9f) };
    private readonly GroupBox _volBox = new() { Text = "Volume settings", Dock = DockStyle.Fill };
    private readonly GroupBox _hashBox = new() { Text = "Hash", Dock = DockStyle.Fill };

    public OpenAsForm(Settings s)
    {
        Text = "Choose file protection";
        Font = new Font("Segoe UI", 9f);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(520, 520);

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), RowCount = 6, ColumnCount = 1 };
        var kinds = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        kinds.Controls.AddRange([_vc, _tc, _manual]);
        root.Controls.Add(kinds);

        var fileRow = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 3, Height = 30 };
        fileRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 40));
        fileRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        fileRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 40));
        var browse = new Button { Text = "...", Width = 34 };
        browse.Click += (_, _) =>
        {
            using var d = new OpenFileDialog { Filter = "All files|*.*", InitialDirectory = s.LastOpenedDirectory ?? "" };
            if (d.ShowDialog(this) == DialogResult.OK) _file.Text = d.FileName;
        };
        fileRow.Controls.Add(new Label { Text = "File:", AutoSize = true, Margin = new Padding(0, 7, 0, 0) }, 0, 0);
        fileRow.Controls.Add(_file, 1, 0);
        fileRow.Controls.Add(browse, 2, 0);
        root.Controls.Add(fileRow);

        _offset.Items.AddRange(["Normal volume", "Hidden volume", "System (boot) encryption", "Custom"]);
        _offset.SelectedIndex = 0;
        var vol = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7, Padding = new Padding(6) };
        var off = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        off.Controls.AddRange([new Label { Text = "Volume header offset", AutoSize = true, Margin = new Padding(0, 6, 8, 0) }, _offset, _customOffset, _hex, _dec]);
        vol.Controls.Add(off);
        vol.Controls.Add(new Label { Text = "Hash function(s) for key derivation", AutoSize = true, Font = new Font(Font, FontStyle.Bold), Margin = new Padding(0, 8, 0, 2) });
        var kdf = new FlowLayoutPanel { AutoSize = true };
        kdf.Controls.AddRange([_sha512, _ripemd, _whirl, _sha256, _streebog]);
        vol.Controls.Add(kdf);
        vol.Controls.Add(new Label { Text = "Encryption", AutoSize = true, Font = new Font(Font, FontStyle.Bold), Margin = new Padding(0, 8, 0, 2) });
        var enc = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown };
        enc.Controls.AddRange([_single, _double, _triple]);
        vol.Controls.Add(enc);
        vol.Controls.Add(new Label
        {
            AutoSize = true, MaximumSize = new Size(470, 0), ForeColor = Color.DimGray, Margin = new Padding(0, 8, 0, 0),
            Text = "Only XTS mode is supported. Each extra hash function or cascade adds a full pass, so select only what may have been used. Keyfiles and PIM are not supported.",
        });
        _volBox.Controls.Add(vol);
        root.Controls.Add(_volBox);
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 60));

        var hashGrid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(6) };
        var modeRow = new FlowLayoutPanel { AutoSize = true };
        var link = new LinkLabel { Text = "list of modes", AutoSize = true, Margin = new Padding(8, 6, 0, 0) };
        link.LinkClicked += (_, _) => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://hashcat.net/wiki/doku.php?id=example_hashes") { UseShellExecute = true });
        modeRow.Controls.AddRange([new Label { Text = "hashcat mode (-m)", AutoSize = true, Margin = new Padding(0, 6, 8, 0) }, _mode, link]);
        hashGrid.Controls.Add(modeRow);
        hashGrid.Controls.Add(_hash);
        hashGrid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        hashGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _hashBox.Controls.Add(hashGrid);
        root.Controls.Add(_hashBox);
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 40));

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, Height = 36 };
        var ok = new Button { Text = "OK", Width = 80 };
        var cancel = new Button { Text = "Cancel", Width = 80, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => Accept();
        buttons.Controls.AddRange([cancel, ok]);
        root.Controls.Add(buttons);
        Controls.Add(root);
        AcceptButton = ok;
        CancelButton = cancel;

        foreach (var rb in new[] { _tc, _vc, _manual }) rb.CheckedChanged += (_, _) => Sync();
        _offset.SelectedIndexChanged += (_, _) => Sync();
        Sync();
    }

    private void Sync()
    {
        bool vol = !_manual.Checked;
        _volBox.Enabled = vol;
        _hashBox.Enabled = !vol;
        _file.Enabled = vol;
        _sha256.Enabled = _streebog.Enabled = _vc.Checked;
        _customOffset.Enabled = _hex.Enabled = _dec.Enabled = _offset.SelectedIndex == 3;
    }

    private void Accept()
    {
        try
        {
            if (_manual.Checked)
            {
                if (_hash.Text.Trim().Length == 0) throw new ArgumentException("Enter a hash.");
                Result = FormatDetector.FromManualHash("(manual hash)", (int)_mode.Value, _hash.Text);
            }
            else
            {
                if (!File.Exists(_file.Text)) throw new ArgumentException("Select the volume file.");
                var o = new VolumeOptions { Kind = _tc.Checked ? VolumeKind.TrueCrypt : VolumeKind.VeraCrypt, Kdfs = VolumeKdf.None, Ciphers = VolumeCipher.None };
                o.HeaderOffset = _offset.SelectedIndex switch
                {
                    1 => VolumeOptions.HiddenOffset,
                    2 => VolumeOptions.BootOffset,
                    3 => long.Parse(_customOffset.Text.Trim(), _hex.Checked ? NumberStyles.HexNumber : NumberStyles.Integer, CultureInfo.InvariantCulture),
                    _ => VolumeOptions.NormalOffset,
                };
                o.BootVolume = _offset.SelectedIndex == 2;
                if (_ripemd.Checked) o.Kdfs |= VolumeKdf.Ripemd160;
                if (_sha512.Checked) o.Kdfs |= VolumeKdf.Sha512;
                if (_whirl.Checked) o.Kdfs |= VolumeKdf.Whirlpool;
                if (_sha256.Checked && _vc.Checked) o.Kdfs |= VolumeKdf.Sha256;
                if (_streebog.Checked && _vc.Checked) o.Kdfs |= VolumeKdf.Streebog;
                if (_single.Checked) o.Ciphers |= VolumeCipher.Single;
                if (_double.Checked) o.Ciphers |= VolumeCipher.Double;
                if (_triple.Checked) o.Ciphers |= VolumeCipher.Triple;
                Result = CryptVolume.Open(_file.Text, o);
            }
            DialogResult = DialogResult.OK;
            Close();
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or IOException or OverflowException)
        {
            MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
