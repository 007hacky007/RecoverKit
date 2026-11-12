using System.Globalization;
using System.Collections.ObjectModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Formats;

namespace RecoverKit.App.Views;

/// <summary>"Open As": TrueCrypt/VeraCrypt volume settings, or a hash entered manually.</summary>
public sealed class OpenAsWindow : Window
{
    public Detection? Result { get; private set; }

    private readonly RadioButton _tc = new() { GroupName = "kind", Content = "TrueCrypt volume" };
    private readonly RadioButton _vc = new() { GroupName = "kind", Content = "VeraCrypt volume", IsChecked = true };
    private readonly RadioButton _manual = new() { GroupName = "kind", Content = "Enter hash manually (any hashcat mode)" };
    private readonly TextBox _file = new();
    private readonly ComboBox _offset = new() { ItemsSource = new[] { "Normal volume", "Hidden volume", "System (boot) encryption", "Custom" }, SelectedIndex = 0, MinWidth = 210 };
    private readonly TextBox _customOffset = new() { Width = 100, Text = "0" };
    private readonly RadioButton _hex = new() { GroupName = "base", Content = "Hex" }, _dec = new() { GroupName = "base", Content = "Dec", IsChecked = true };
    private readonly CheckBox _ripemd = new() { Content = "RIPEMD-160" };
    private readonly CheckBox _sha512 = new() { Content = "SHA-512", IsChecked = true };
    private readonly CheckBox _whirl = new() { Content = "Whirlpool" };
    private readonly CheckBox _sha256 = new() { Content = "SHA-256" };
    private readonly CheckBox _streebog = new() { Content = "Streebog" };
    private readonly CheckBox _single = new() { Content = "Single cipher (AES, Serpent, Twofish, Camellia, Kuznyechik)", IsChecked = true };
    private readonly CheckBox _double = new() { Content = "Two-cipher cascades (e.g. AES-Twofish)" };
    private readonly CheckBox _triple = new() { Content = "Three-cipher cascades (e.g. AES-Twofish-Serpent)" };
    private readonly ObservableCollection<string> _keyfilePaths = new();
    private readonly ListBox _keyfiles = new() { Height = 90, SelectionMode = SelectionMode.Multiple };
    private readonly NumericUpDown _pim = L.Number(0, VolumeCredentials.MaxPim, 0, 130);
    private readonly Control _keyfileBox;
    private readonly NumericUpDown _mode = L.Number(0, 999999, 0, 130);
    private readonly TextBox _hash = new() { AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, Height = 110, FontFamily = new FontFamily("Menlo, Consolas, monospace") };
    private readonly Control _volBox, _hashBox, _fileRow;

    public static async Task<Detection?> RunAsync(Window owner, Settings s)
    {
        var w = new OpenAsWindow(s);
        return await w.ShowDialog<bool>(owner) ? w.Result : null;
    }

    public OpenAsWindow(Settings s)
    {
        Title = "Choose file protection";
        Icon = Icons.AppIcon();
        Width = 720;
        MaxHeight = 760;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        CanMinimize = false;
        CanMaximize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var kinds = L.Row(_vc, _tc, _manual);
        kinds.Spacing = 16;

        var fileRow = L.Grid("Auto,*,Auto");
        fileRow.Put(L.Text("File:"), 0, 0);
        fileRow.Put(_file, 0, 1);
        fileRow.Put(L.Button("...", async () => { if (await Pick.Open(this, "All files|*.*", s.LastOpenedDirectory) is { } p) _file.Text = p; }, 40), 0, 2);
        _fileRow = fileRow;

        var off = new WrapPanel { ItemSpacing = 8, LineSpacing = 6 };
        foreach (var c in new Control[] { L.Text("Volume header offset"), _offset, _customOffset, _hex, _dec }) off.Children.Add(c);
        var kdf = new WrapPanel { ItemSpacing = 16, LineSpacing = 4 };
        foreach (var c in new Control[] { _sha512, _ripemd, _whirl, _sha256, _streebog }) kdf.Children.Add(c);
        _keyfiles.ItemsSource = _keyfilePaths;
        var keys = L.Grid("*,Auto");
        keys.Put(_keyfiles, 0, 0);
        var addKey = L.Button("Add...", async () =>
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Select keyfiles", AllowMultiple = true, FileTypeFilter = Pick.Filters("All files|*.*"),
            });
            var comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
            foreach (var file in files)
                if (file.TryGetLocalPath() is { } path && !_keyfilePaths.Contains(path, comparer)) _keyfilePaths.Add(path);
        });
        var removeKey = L.Button("Remove", () =>
        {
            foreach (var path in _keyfiles.SelectedItems!.Cast<string>().ToArray()) _keyfilePaths.Remove(path);
        });
        keys.Put(L.Column(6, addKey, removeKey), 0, 1);
        _keyfileBox = L.Column(6, L.Text("Keyfiles (all selected files are required)", bold: true), keys);
        _volBox = L.Group("Volume settings", L.Column(8,
            off,
            L.Text("Hash function(s) for key derivation", bold: true), kdf,
            L.Text("Encryption", bold: true), L.Column(2, _single, _double, _triple),
            _keyfileBox,
            L.Row(L.Text("VeraCrypt PIM"), _pim, L.Text("0 = default", dim: true)),
            L.Text("Only XTS mode is supported. Each extra hash function or cascade adds a full pass. Keyfiles are not supported for system encryption. PIM applies only to VeraCrypt.", dim: true, wrap: true)));

        var link = new HyperlinkButton { Content = "list of modes", NavigateUri = new Uri("https://hashcat.net/wiki/doku.php?id=example_hashes"), VerticalAlignment = VerticalAlignment.Center };
        _hashBox = L.Group("Hash", L.Column(8, L.Row(L.Text("hashcat mode (-m)"), _mode, link), _hash));

        var ok = L.Button("OK", () => _ = AcceptAsync(), 90, isDefault: true);
        var cancel = L.Button("Cancel", () => Close(false), 90, isCancel: true);
        var footer = L.Footer(Platform.IsMac ? [cancel, ok] : [ok, cancel]);

        var body = L.Column(12, kinds, _fileRow, _volBox, _hashBox);
        body.Margin = new Thickness(16, 14, 16, 14);
        var root = new DockPanel();
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(new ScrollViewer { Content = body });
        Content = root;

        foreach (var rb in new[] { _tc, _vc, _manual }) rb.IsCheckedChanged += (_, _) => Sync();
        _offset.SelectionChanged += (_, _) => Sync();
        Sync();
    }

    private void Sync()
    {
        bool vol = _manual.IsChecked != true;
        _volBox.IsVisible = vol;
        _hashBox.IsVisible = !vol;
        _pim.IsEnabled = vol && _vc.IsChecked == true;
        _keyfileBox.IsEnabled = vol && _offset.SelectedIndex != 2;
        _fileRow.IsEnabled = vol;
        _sha256.IsEnabled = _streebog.IsEnabled = _vc.IsChecked == true;
        _customOffset.IsEnabled = _hex.IsEnabled = _dec.IsEnabled = _offset.SelectedIndex == 3;
    }

    private async Task AcceptAsync()
    {
        try
        {
            if (_manual.IsChecked == true)
            {
                if ((_hash.Text ?? "").Trim().Length == 0) throw new ArgumentException("Enter a hash.");
                Result = FormatDetector.FromManualHash("(manual hash)", _mode.IntValue(), _hash.Text!);
            }
            else
            {
                var file = _file.Text ?? "";
                if (!File.Exists(file)) throw new ArgumentException("Select the volume file.");
                bool vc = _vc.IsChecked == true;
                var o = new VolumeOptions { Kind = vc ? VolumeKind.VeraCrypt : VolumeKind.TrueCrypt, Kdfs = VolumeKdf.None, Ciphers = VolumeCipher.None };
                o.HeaderOffset = _offset.SelectedIndex switch
                {
                    1 => VolumeOptions.HiddenOffset,
                    2 => VolumeOptions.BootOffset,
                    3 => long.Parse((_customOffset.Text ?? "").Trim(), _hex.IsChecked == true ? NumberStyles.HexNumber : NumberStyles.Integer, CultureInfo.InvariantCulture),
                    _ => VolumeOptions.NormalOffset,
                };
                o.BootVolume = _offset.SelectedIndex == 2;
                o.Keyfiles = o.BootVolume ? [] : _keyfilePaths.ToList();
                o.Pim = vc ? _pim.IntValue() : 0;
                if (_ripemd.IsChecked == true) o.Kdfs |= VolumeKdf.Ripemd160;
                if (_sha512.IsChecked == true) o.Kdfs |= VolumeKdf.Sha512;
                if (_whirl.IsChecked == true) o.Kdfs |= VolumeKdf.Whirlpool;
                if (_sha256.IsChecked == true && vc) o.Kdfs |= VolumeKdf.Sha256;
                if (_streebog.IsChecked == true && vc) o.Kdfs |= VolumeKdf.Streebog;
                if (_single.IsChecked == true) o.Ciphers |= VolumeCipher.Single;
                if (_double.IsChecked == true) o.Ciphers |= VolumeCipher.Double;
                if (_triple.IsChecked == true) o.Ciphers |= VolumeCipher.Triple;
                Result = CryptVolume.Open(file, o);
            }
            Close(true);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or IOException or OverflowException or UnauthorizedAccessException)
        {
            await Msg.Warn(this, ex.Message, Title);
        }
    }
}
