using RecoverKit.Core;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Forms;

/// <summary>Preferences: Performance, GPU Configuration, Files and Paths, Key search and rainbow tables, Other.</summary>
public sealed class PreferencesForm : Form
{
    private readonly Settings _s;
    private readonly HashcatTool? _hashcat;
    private List<BackendDevice> _devices;
    public bool HashcatChanged { get; private set; }

    private readonly ComboBox _strategy = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
    private readonly ComboBox _priority = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 220 };
    private readonly NumericUpDown _maxThreads = new() { Minimum = 1, Maximum = Math.Max(1, Environment.ProcessorCount), Width = 60 };
    private readonly CheckBox _optimized = new() { Text = "Use optimized kernels for brute-force (faster, limits password length to 27)", AutoSize = true };
    private readonly CheckBox _native = new() { Text = "Use the built-in CPU engine when no GPU is used (ZIP, Office 97-2003, PDF R2-R4 and R6, RAR 3.x)", AutoSize = true };
    private readonly TextBox _extra = new() { Dock = DockStyle.Fill };
    private readonly ListView _gpuList = new() { View = View.Details, CheckBoxes = true, FullRowSelect = true, Dock = DockStyle.Fill, HeaderStyle = ColumnHeaderStyle.Nonclickable };
    private readonly TrackBar _workload = new() { Minimum = 1, Maximum = 4, TickStyle = TickStyle.Both, Dock = DockStyle.Fill, LargeChange = 1 };
    private readonly Label _backendLabel = new() { AutoSize = true };
    private readonly CheckBox _screensaver = new() { Text = "Keep the screensaver off while GPUs are working", AutoSize = true };
    private readonly CheckBox _useScenario = new() { Text = "Use external scenario file", AutoSize = true };
    private readonly TextBox _scenarioFile = new() { Dock = DockStyle.Fill };
    private readonly TextBox _hashcatPath = new() { Dock = DockStyle.Fill };
    private readonly TextBox _dataPath = new() { Dock = DockStyle.Fill };
    private readonly TextBox _defaultDict = new() { Dock = DockStyle.Fill };
    private readonly TextBox _onSuccess = new() { Dock = DockStyle.Fill };
    private readonly TextBox _onFail = new() { Dock = DockStyle.Fill };
    private readonly TextBox _rainbowPath = new() { Dock = DockStyle.Fill };
    private readonly CheckBox _autoDecrypt = new() { Text = "Decrypt the document after a successful attack and save it with the suffix", AutoSize = true };
    private readonly TextBox _decryptSuffix = new() { Dock = DockStyle.Fill };
    private readonly CheckBox _noCache = new() { Text = "Don't use password cache", AutoSize = true };
    private readonly CheckBox _noKeyCache = new() { Text = "Don't use key cache", AutoSize = true };
    private readonly CheckBox _reduce = new() { Text = "Reduce informational output (hide hashcat messages)", AutoSize = true };
    private readonly CheckBox _logHashes = new() { Text = "Include extracted hashes (only needed to debug file parsing)", AutoSize = true };

    public PreferencesForm(Settings s, HashcatTool? hashcat, List<BackendDevice> devices, int tab)
    {
        _s = s;
        _hashcat = hashcat;
        _devices = devices;
        Text = "Preferences";
        Font = new Font("Segoe UI", 9f);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(560, 380);

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(PerformanceTab());
        tabs.TabPages.Add(GpuTab());
        tabs.TabPages.Add(PathsTab());
        tabs.TabPages.Add(KeySearchTab());
        tabs.TabPages.Add(OtherTab());
        tabs.SelectedIndex = Math.Clamp(tab, 0, tabs.TabCount - 1);

        var ok = new Button { Text = "OK", Width = 80 };
        var cancel = new Button { Text = "Cancel", Width = 80, DialogResult = DialogResult.Cancel };
        var apply = new Button { Text = "&Apply", Width = 80, Enabled = false };
        ok.Click += (_, _) => { Apply(); DialogResult = DialogResult.OK; Close(); };
        apply.Click += (_, _) => { Apply(); s.Save(); apply.Enabled = false; };
        var footer = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 42, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 6, 8, 0) };
        footer.Controls.AddRange([apply, cancel, ok]);
        Controls.Add(tabs);
        Controls.Add(footer);
        AcceptButton = ok;
        CancelButton = cancel;
        Load();
        // Apply stays disabled until something changes.
        TrackChanges(tabs, () => apply.Enabled = true);
    }

    private static void TrackChanges(Control root, Action changed)
    {
        foreach (Control c in root.Controls)
        {
            switch (c)
            {
                case CheckBox cb: cb.CheckedChanged += (_, _) => changed(); break;
                case RadioButton rb: rb.CheckedChanged += (_, _) => changed(); break;
                case ComboBox co: co.SelectedIndexChanged += (_, _) => changed(); co.TextChanged += (_, _) => changed(); break;
                case NumericUpDown nu: nu.ValueChanged += (_, _) => changed(); break;
                case TrackBar tb: tb.ValueChanged += (_, _) => changed(); break;
                case ListView lv: lv.ItemChecked += (_, _) => changed(); break;
                case TextBox tx: tx.TextChanged += (_, _) => changed(); break;
            }
            TrackChanges(c, changed);
        }
    }

    private static TabPage Tab(string name, Control content)
    {
        var p = new TabPage(name) { Padding = new Padding(8), UseVisualStyleBackColor = true };
        p.Controls.Add(content);
        return p;
    }

    private static GroupBox Group(string text, Control content, int height)
    {
        var g = new GroupBox { Text = text, Dock = DockStyle.Top, Height = height, Padding = new Padding(8, 4, 8, 4) };
        g.Controls.Add(content);
        return g;
    }

    private static Control PathRow(TextBox box, Func<string?> pick)
    {
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Height = 30 };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 40));
        var b = new Button { Text = "...", Width = 34 };
        b.Click += (_, _) => { if (pick() is { } p) box.Text = p; };
        t.Controls.Add(box, 0, 0);
        t.Controls.Add(b, 1, 0);
        return t;
    }

    /// <summary>hashcat path row with a Browse ("...") and a Download button.</summary>
    private Control HashcatRow()
    {
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, Height = 30 };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 40));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
        var browse = new Button { Text = "...", Width = 34 };
        browse.Click += (_, _) => { if (PickFile("hashcat|hashcat.exe;hashcat|All files|*.*") is { } p) _hashcatPath.Text = p; };
        var download = new Button { Text = "Download", Width = 94 };
        download.Click += (_, _) =>
        {
            using var f = new HashcatDownloadForm();
            if (f.ShowDialog(this) == DialogResult.OK && f.InstalledExe is { } exe)
            {
                _hashcatPath.Text = exe;
                HashcatChanged = true;
            }
        };
        t.Controls.Add(_hashcatPath, 0, 0);
        t.Controls.Add(browse, 1, 0);
        t.Controls.Add(download, 2, 0);
        return t;
    }

    private string? PickFile(string filter)
    {
        using var d = new OpenFileDialog { Filter = filter };
        return d.ShowDialog(this) == DialogResult.OK ? d.FileName : null;
    }

    private string? PickFolder()
    {
        using var d = new FolderBrowserDialog();
        return d.ShowDialog(this) == DialogResult.OK ? d.SelectedPath : null;
    }

    // ------------------------------------------------------------------ tabs

    private TabPage PerformanceTab()
    {
        _strategy.Items.AddRange([
            "Keep one CPU thread free for each GPU (recommended)",
            "Avoid the CPU whenever a GPU can run (fast GPUs)",
            "Use all CPU threads next to the GPUs (slow GPUs)",
            "CPU only, no GPUs (for testing)",
        ]);
        _priority.Items.AddRange(["Idle (recommended)", "Below normal", "Normal", "High (not recommended)"]);
        var strategy = Group("CPU/GPU performance strategy", _strategy, 52);

        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 2 };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 200));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
        grid.Controls.Add(new Label { Text = "Application priority", AutoSize = true, Margin = new Padding(0, 6, 0, 0) }, 0, 0);
        grid.Controls.Add(_priority, 1, 0); grid.SetColumnSpan(_priority, 2);
        grid.Controls.Add(new Label { Text = "Maximum number of CPU threads", AutoSize = true, Margin = new Padding(0, 6, 0, 0) }, 0, 1);
        _maxThreads.Anchor = AnchorStyles.Left;
        grid.Controls.Add(_maxThreads, 1, 1);
        var detect = new Button { Text = "Detect", Width = 74, Anchor = AnchorStyles.Right };
        detect.Click += (_, _) => _maxThreads.Value = _maxThreads.Maximum;
        grid.Controls.Add(detect, 2, 1);
        var other = Group("", grid, 76);

        // hashcat engine options.
        var hc = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3 };
        hc.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170));
        hc.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        hc.Controls.Add(_optimized, 0, 0); hc.SetColumnSpan(_optimized, 2);
        hc.Controls.Add(_native, 0, 1); hc.SetColumnSpan(_native, 2);
        hc.Controls.Add(new Label { Text = "Extra hashcat arguments", AutoSize = true, Margin = new Padding(0, 6, 0, 0) }, 0, 2);
        hc.Controls.Add(_extra, 1, 2);
        var hcGroup = Group("Recovery engines", hc, 102);

        var host = new Panel { Dock = DockStyle.Fill };
        host.Controls.Add(hcGroup);
        host.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 6 });
        host.Controls.Add(other);
        host.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 6 });
        host.Controls.Add(strategy);
        return Tab("Performance", host);
    }

    private TabPage GpuTab()
    {
        _gpuList.Columns.Add("GPU Name", 220);
        _gpuList.Columns.Add("SP/ALU count", 100);
        _gpuList.Columns.Add("Frequency", 90);
        _gpuList.Columns.Add("RAM", 90);
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 5 };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        t.Controls.Add(_gpuList, 0, 0); t.SetColumnSpan(_gpuList, 2);
        t.Controls.Add(new Label { Text = "Lag free display", AutoSize = true }, 0, 1);
        t.Controls.Add(new Label { Text = "Performance", AutoSize = true, Anchor = AnchorStyles.Right }, 1, 1);
        t.Controls.Add(_workload, 0, 2); t.SetColumnSpan(_workload, 2);
        var refresh = new Button { Text = "Detect", Width = 80, Anchor = AnchorStyles.Right };
        refresh.Click += async (_, _) =>
        {
            if (_hashcat is null) return;
            UseWaitCursor = true;
            try { _devices = await _hashcat.DevicesAsync(); FillDevices(); }
            finally { UseWaitCursor = false; }
        };
        t.Controls.Add(_backendLabel, 0, 3);
        t.Controls.Add(refresh, 1, 3);
        t.Controls.Add(_screensaver, 0, 4); t.SetColumnSpan(_screensaver, 2);
        return Tab("GPU Configuration", t);
    }

    private TabPage PathsTab()
    {
        var host = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        // Engine-specific groups placed last.
        host.Controls.Add(Group("Default dictionary (used by scenarios as *default)", PathRow(_defaultDict, () => PickFile("Dictionary files (*.dic; *.txt)|*.dic;*.txt|All files|*.*")), 50));
        host.Controls.Add(Group("hashcat executable (hashcat.exe)", HashcatRow(), 50));
        var exec = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2 };
        exec.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 70));
        exec.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        exec.Controls.Add(new Label { Text = "On success", AutoSize = true, Margin = new Padding(0, 7, 0, 0) }, 0, 0);
        exec.Controls.Add(PathRow(_onSuccess, () => PickFile("All files|*.*")), 1, 0);
        exec.Controls.Add(new Label { Text = "On fail", AutoSize = true, Margin = new Padding(0, 7, 0, 0) }, 0, 1);
        exec.Controls.Add(PathRow(_onFail, () => PickFile("All files|*.*")), 1, 1);
        host.Controls.Add(Group("Run these programs when recovery ends", exec, 84));
        host.Controls.Add(Group("Folder for dictionaries and rule files", PathRow(_dataPath, PickFolder), 50));
        var scen = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2 };
        scen.Controls.Add(_useScenario, 0, 0);
        scen.Controls.Add(PathRow(_scenarioFile, () => PickFile("Scenario files (*.txt)|*.txt|All files|*.*")), 0, 1);
        host.Controls.Add(Group("", scen, 64));
        return Tab("Files and Paths", host);
    }

    private TabPage KeySearchTab()
    {
        var host = new Panel { Dock = DockStyle.Fill };
        var dec = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2 };
        dec.Controls.Add(_autoDecrypt, 0, 0);
        _decryptSuffix.Margin = new Padding(20, 2, 8, 2);
        dec.Controls.Add(_decryptSuffix, 0, 1);
        host.Controls.Add(Group("", dec, 70));
        host.Controls.Add(Group("Default path for rainbow tables", PathRow(_rainbowPath, PickFolder), 50));
        var note = new Label
        {
            Dock = DockStyle.Bottom, AutoSize = false, Height = 40, ForeColor = Color.DimGray, Padding = new Padding(4, 6, 4, 0),
            Text = "Key search is available in the wizard for 40-bit RC4 documents. Rainbow tables are not supported by the hashcat engine; the path is kept for compatibility.",
        };
        host.Controls.Add(note);
        return Tab("Key search and rainbow tables", host);
    }

    private TabPage OtherTab()
    {
        var pwCache = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
        var clearPw = new Button { Text = "Clear", Width = 80, Anchor = AnchorStyles.Right };
        clearPw.Click += (_, _) =>
        {
            if (MessageBox.Show(this, "Delete all cached recovered passwords?", Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            try { File.Delete(_s.PotfilePath); MessageBox.Show(this, "Done!", Text); } catch (IOException ex) { MessageBox.Show(this, ex.Message, Text); }
        };
        pwCache.Controls.AddRange([_noCache, clearPw]);

        var clearKey = new Button { Text = "Clear", Width = 80, Anchor = AnchorStyles.Right, Enabled = File.Exists(_s.KeyCachePath) };
        clearKey.Click += (_, _) =>
        {
            try { File.Delete(_s.KeyCachePath); clearKey.Enabled = false; MessageBox.Show(this, "Done!", Text); } catch (IOException ex) { MessageBox.Show(this, ex.Message, Text); }
        };
        var keyRow = new FlowLayoutPanel { Dock = DockStyle.Top, WrapContents = false, Height = 26 };
        keyRow.Controls.AddRange([_noKeyCache, clearKey]);
        var keyNote = new Label { Dock = DockStyle.Top, ForeColor = Color.DimGray, AutoSize = false, Height = 18, Text = "Keys recovered by key search (40-bit RC4: MS Office 97-2003, PDF 1.1-1.3)." };
        var keyCache = new Panel { Dock = DockStyle.Fill };
        keyCache.Controls.Add(keyNote);
        keyCache.Controls.Add(keyRow);

        var sessions = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
        var clearSessions = new Button { Text = "Clear saved sessions", Width = 150 };
        clearSessions.Click += (_, _) =>
        {
            foreach (var f in Directory.EnumerateFiles(_s.SessionsDir)) try { File.Delete(f); } catch (IOException) { }
            MessageBox.Show(this, "Done!", Text);
        };
        sessions.Controls.Add(clearSessions);

        // RecoverKit addition: what goes into the per-run debug log (Help > Open debug log folder).
        var log = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
        var openLog = new Button { Text = "Open folder", AutoSize = true };
        openLog.Click += (_, _) =>
        {
            Directory.CreateDirectory(DebugLog.Directory);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(DebugLog.Directory) { UseShellExecute = true })?.Dispose();
        };
        log.Controls.AddRange([_logHashes, openLog]);

        var host = new Panel { Dock = DockStyle.Fill };
        host.Controls.Add(Group("Debug log", log, 54));
        host.Controls.Add(Group("Interrupted attacks", sessions, 54));
        host.Controls.Add(Group("", _reduce, 40));
        host.Controls.Add(Group("Key Cache", keyCache, 72));
        host.Controls.Add(Group("Password Cache", pwCache, 54));
        return Tab("Other", host);
    }

    // ------------------------------------------------------------------ load / apply

    private new void Load()
    {
        _strategy.SelectedIndex = (int)_s.Strategy;
        _priority.SelectedIndex = (int)_s.Priority;
        // 0 means "one per logical processor"; show the number it resolves to.
        _maxThreads.Value = _s.MaxCpuThreads <= 0 ? _maxThreads.Maximum : Math.Clamp(_s.MaxCpuThreads, 1, (int)_maxThreads.Maximum);
        _optimized.Checked = _s.OptimizedKernels;
        _native.Checked = _s.UseNativeCpuEngine;
        _extra.Text = _s.ExtraArguments;
        _workload.Value = Math.Clamp(_s.Workload, 1, 4);
        _screensaver.Checked = _s.PreventScreensaver;
        _useScenario.Checked = _s.UseExternalScenarioFile;
        _scenarioFile.Text = _s.ExternalScenarioFile ?? "";
        _hashcatPath.Text = _s.HashcatPath ?? _hashcat?.Exe ?? "";
        _dataPath.Text = _s.DataPath ?? "";
        _defaultDict.Text = _s.DefaultDictionary ?? "";
        _onSuccess.Text = _s.ExecuteOnSuccess ?? "";
        _onFail.Text = _s.ExecuteOnFail ?? "";
        _rainbowPath.Text = _s.RainbowTablesPath ?? "";
        _autoDecrypt.Checked = _s.AutoDecrypt;
        _decryptSuffix.Text = string.IsNullOrEmpty(_s.DecryptSuffix) ? "_decrypted" : _s.DecryptSuffix;
        _noCache.Checked = _s.DontUsePasswordCache;
        _noKeyCache.Checked = _s.DontUseKeyCache;
        _reduce.Checked = _s.ReduceOutput;
        _logHashes.Checked = _s.DebugLogIncludeHashes;
        FillDevices();
    }

    private void FillDevices()
    {
        // GPUs only: the processor is configured on the Performance tab
        // (strategy, thread count), and the workload slider only governs GPU kernels.
        _gpuList.Items.Clear();
        var gpus = _devices.Where(d => !d.IsSkippedAlias && d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var d in gpus)
        {
            var it = new ListViewItem(d.Name) { Checked = !_s.DisabledDevices.Contains(d.Id), Tag = d.Id };
            it.SubItems.Add(d.Processors > 0 ? d.Processors.ToString() : "n/a");
            it.SubItems.Add(d.ClockMhz > 0 ? $"{d.ClockMhz} Mhz" : "n/a");
            it.SubItems.Add(d.MemoryMb > 0 ? $"{d.MemoryMb} MB" : "n/a");
            _gpuList.Items.Add(it);
        }
        _gpuList.CheckBoxes = gpus.Count > 0;
        if (gpus.Count == 0) _gpuList.Items.Add(new ListViewItem("No compatible GPU devices detected."));
        _workload.Enabled = gpus.Count > 0;
        _backendLabel.Text = gpus.Count == 0 ? ""
            : string.Join(", ", gpus.Select(d => d.Backend + (d.BackendVersion.Length > 0 ? " " + d.BackendVersion : "")).Distinct());
    }

    private void Apply()
    {
        _s.Strategy = (DeviceStrategy)Math.Max(0, _strategy.SelectedIndex);
        _s.Priority = (ProcessPriority)Math.Max(0, _priority.SelectedIndex);
        _s.MaxCpuThreads = _maxThreads.Value >= _maxThreads.Maximum ? 0 : (int)_maxThreads.Value;
        _s.OptimizedKernels = _optimized.Checked;
        _s.UseNativeCpuEngine = _native.Checked;
        _s.ExtraArguments = _extra.Text.Trim();
        _s.Workload = _workload.Value;
        _s.PreventScreensaver = _screensaver.Checked;
        _s.DisabledDevices = _gpuList.Items.Cast<ListViewItem>().Where(i => i.Tag is int && !i.Checked).Select(i => (int)i.Tag!).ToList();
        _s.UseExternalScenarioFile = _useScenario.Checked;
        _s.ExternalScenarioFile = Null(_scenarioFile.Text);
        var hp = Null(_hashcatPath.Text);
        if (hp != _s.HashcatPath && hp != _hashcat?.Exe) HashcatChanged = true;
        _s.HashcatPath = hp;
        _s.DataPath = Null(_dataPath.Text);
        _s.DefaultDictionary = Null(_defaultDict.Text);
        _s.ExecuteOnSuccess = Null(_onSuccess.Text);
        _s.ExecuteOnFail = Null(_onFail.Text);
        _s.RainbowTablesPath = Null(_rainbowPath.Text);
        _s.AutoDecrypt = _autoDecrypt.Checked;
        _s.DecryptSuffix = string.IsNullOrWhiteSpace(_decryptSuffix.Text) ? "_decrypted" : _decryptSuffix.Text.Trim();
        _s.DontUsePasswordCache = _noCache.Checked;
        _s.DontUseKeyCache = _noKeyCache.Checked;
        _s.ReduceOutput = _reduce.Checked;
        _s.DebugLogIncludeHashes = _logHashes.Checked;
        DebugLog.IncludeHashes = _logHashes.Checked;
    }

    private static string? Null(string s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
