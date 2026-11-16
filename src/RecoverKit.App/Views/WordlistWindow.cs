using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.Styling;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;

namespace RecoverKit.App.Views;

/// <summary>The library picker stores ordinary dictionary paths, so attacks need no new reference type.</summary>
internal sealed class WordlistWindow : Window
{
    private readonly Settings settings;
    private readonly string? dataPath;
    private readonly WordlistLibrary library;
    private readonly WeakpassCatalog catalog = new();
    private readonly WordlistDownloads downloads = WordlistDownloads.Shared;
    private readonly double speed;
    private readonly long? outputs;
    private readonly string rules;
    private readonly bool preview;
    private readonly CancellationTokenSource lifetime = new();
    private CancellationTokenSource? detailCancellation, fileCancellation;
    private WordlistCatalogCache? cache;
    private List<LibraryWordlist> local = [];
    private WeakpassWordlist? selected;
    private WeakpassDetail? detail;
    private WordlistDownload? useWhenReady;
    private int useGeneration, downloadsDirty;
    private bool initializing, updatingDownloads;
    private readonly HashSet<WordlistDownload> observedFinished = [];
    private readonly DispatcherTimer downloadTimer = new() { Interval = TimeSpan.FromMilliseconds(250) };
    private readonly TextBlock errorNote = L.Text("", wrap: true);
    private readonly Button retryInitialization;
    private readonly TabControl tabs = new();
    private readonly ListBox builtins = new();
    private readonly StackPanel downloaded = new() { Spacing = 8 };
    private readonly ListBox lists = new();
    private readonly StackPanel details = new() { Spacing = 5, Margin = new(0, 0, 16, 0) };
    private readonly TextBox search = new() { PlaceholderText = "Search by name", Width = 210 };
    private readonly ComboBox sizeFilter = new() { ItemsSource = new[] { "Up to 10 MB", "Up to 100 MB", "Up to 1 GB", "Up to 10 GB", "Any size" }, SelectedIndex = 2, MinWidth = 130 };
    private readonly ComboBox rateFilter = new() { ItemsSource = new[] { "Any", "5%", "10%", "15%", "20%" }, SelectedIndex = 0, MinWidth = 80 };
    private readonly List<ToggleButton> ranks = [];
    private readonly TextBlock catalogNote = L.Text("", dim: true, wrap: true);
    private readonly TextBlock matchCount = L.Text("", dim: true);
    private readonly TextBlock age = L.Text("", dim: true);
    private readonly Button refresh;
    private readonly Button use;
    private readonly TextBlock transfer = L.Text("", dim: true, wrap: true);
    private readonly ProgressBar progress = new() { Minimum = 0, Maximum = 1, Height = 6, Width = 130, MinWidth = 0 };
    private readonly Button cancelDownload;
    private readonly TextBox filePath = new() { PlaceholderText = "Wordlist path", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly TextBlock fileDetails = L.Text("Choose a file to see its details.", dim: true, wrap: true);
    private readonly StackPanel recentFiles = new() { Spacing = 4 };
    private readonly StackPanel dataFiles = new() { Spacing = 4 };
    private WordlistSort sort;
    private bool descending, refreshing, closed, fileReady, initialized, weakpassOpened;
    private int fileGeneration;

    public WordlistWindow(Settings settings, string label, string? current, double speed = 0, long? ruleOutputs = null, string rules = "as is", bool preview = false,
        string? dataPath = null)
    {
        this.settings = settings;
        this.dataPath = dataPath is null ? settings.DataPath : string.IsNullOrWhiteSpace(dataPath) ? null : dataPath;
        this.speed = speed;
        outputs = ruleOutputs;
        this.rules = rules;
        this.preview = preview;
        library = new WordlistLibrary(Path.Combine(this.dataPath ?? Settings.AppDataDir, "wordlists"));
        Title = "Choose wordlist for: " + label;
        Icon = Icons.AppIcon();
        Width = 1180; Height = 790; MinWidth = 1020; MinHeight = 640;
        CanMinimize = false; ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Opened += (_, _) => Dispatcher.UIThread.Post(KeepOnScreen, DispatcherPriority.Loaded);
        errorNote.Foreground = Palette.ErrorBrush;
        errorNote.IsVisible = false;
        retryInitialization = L.Button("Retry", async () => await InitializeAsync(current, preserveTab: true));
        retryInitialization.IsVisible = false;
        refresh = L.Button("Refresh", async () => await RefreshAsync());
        use = L.Button("Use this wordlist", async () => await UseAsync(), 150, isDefault: true);
        use.MaxWidth = 230;
        cancelDownload = L.Button("Cancel download", async () => { if (ActiveJob() is { } job) await CancelAsync(job); }, 110);
        var heading = L.Text(Title, bold: true, size: 18);
        heading.Foreground = Palette.TitleBrush;
        tabs.Styles.Add(new Style(x => x.OfType<TabItem>()) { Setters = { new Setter(TabItem.FontSizeProperty, 13.0) } });
        tabs.ItemsSource = new[] {
            new TabItem { Header = L.Text("Built-in (5)", size: 13), Content = BuiltinTab() },
            new TabItem { Header = L.Text("Downloaded", size: 13), Content = DownloadedTab() },
            new TabItem { Header = L.Text("weakpass.com", size: 13), Content = CatalogTab() },
            new TabItem { Header = L.Text("File on disk", size: 13), Content = FileTab() }
        };
        var bottom = L.Grid("*,Auto,Auto,Auto");
        bottom.Put(transfer, 0, 0); bottom.Put(progress, 0, 1); bottom.Put(cancelDownload, 0, 2);
        bottom.Put(L.Row(L.Button("Cancel", () => Close(), isCancel: true), use), 0, 3);
        var layout = new Grid { RowDefinitions = new("Auto,*,Auto") };
        layout.Put(new Border { Padding = new(18, 12), Child = heading }, 0, 0);
        layout.Put(tabs, 1, 0);
        layout.Put(new Border { Padding = new(16, 12), Background = Palette.BandBrush, BorderBrush = Palette.LineBrush, BorderThickness = new(0, 1, 0, 0), Child = L.Column(6, L.Row(errorNote, retryInitialization), bottom) }, 2, 0);
        Content = layout;
        builtins.SelectionChanged += (_, _) => UpdateUse();
        tabs.SelectionChanged += async (_, e) =>
        {
            if (e.Source != tabs) return;
            await GuardAsync(async () =>
            {
                if (!initialized) { await InitializeAsync(current, preserveTab: true); return; }
                settings.LastWordlistTab = tabs.SelectedIndex;
                if (tabs.SelectedIndex == 2) await OpenCatalogAsync();
                UpdateUse();
            });
        };
        Opened += async (_, _) => await InitializeAsync(current);
        downloads.Changed += DownloadChanged;
        downloadTimer.Tick += async (_, _) => await UpdateDownloadsAsync();
        downloadTimer.Start();
        Closed += (_, _) =>
        {
            closed = true; lifetime.Cancel(); detailCancellation?.Cancel(); fileCancellation?.Cancel();
            downloads.Changed -= DownloadChanged;
            downloadTimer.Stop();
            if (!preview)
            {
                try { settings.Save(); }
                catch (Exception ex) { DebugLog.Info("Could not save wordlist preferences: " + ex.Message); }
            }
        };
    }

    private static void StretchItems(ListBox list)
    {
        list.Styles.Add(new Style(x => x.OfType<ListBoxItem>()) { Setters =
        {
            new Setter(ListBoxItem.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch),
            new Setter(ListBoxItem.PaddingProperty, new Thickness(4, 2)),
        } });
    }

    private Control BuiltinTab()
    {
        builtins.ItemsSource = BuiltinDictionaries.Names;
        StretchItems(builtins);
        builtins.ItemTemplate = new FuncDataTemplate<string>((name, scope) =>
        {
            int index = Array.IndexOf(BuiltinDictionaries.Names, name!);
            string[] descriptions = ["Common English words and passwords", "A larger set of English words and passwords", "Numbers, useful for word combinations", "Every number from 0 to 999", "Every number from 0 to 9999"];
            var row = L.Grid("280,100,*");
            row.Margin = new(8, 10);
            row.Put(L.Text(name!), 0, 0); row.Put(L.Text("Counting...", dim: true), 0, 1);
            row.Put(L.Text(descriptions[Math.Max(0, index)], dim: true, wrap: true), 0, 2);
            _ = CountBuiltinAsync(name!, row);
            return row;
        });
        builtins.SelectedIndex = 0;
        var grid = new Grid { RowDefinitions = new("Auto,*,Auto"), Margin = new(16) };
        var headers = L.Grid("280,100,*");
        headers.Margin = new(12, 0);
        headers.Put(L.Text("Name", dim: true), 0, 0); headers.Put(L.Text("Words", dim: true), 0, 1); headers.Put(L.Text("What it is", dim: true), 0, 2);
        grid.Put(headers, 0, 0);
        grid.Put(builtins, 1, 0);
        grid.Put(L.Text("Shipped inside RecoverKit, nothing to download.", dim: true), 2, 0);
        return grid;
    }

    private async Task CountBuiltinAsync(string name, Grid row)
    {
        try
        {
            long count = await Task.Run(() => Wordlists.CountLines(BuiltinDictionaries.Materialize(BuiltinDictionaries.Reference(name)), lifetime.Token));
            if (!closed) ((TextBlock)row.Children[1]).Text = count.ToString("N0");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { ShowError("Could not count words: " + ex.Message); }
    }

    private Control DownloadedTab() => new ScrollViewer { Margin = new(16), Content = downloaded };

    private Control CatalogTab()
    {
        var filters = new WrapPanel { ItemSpacing = 8, LineSpacing = 6, Margin = new(0, 0, 0, 8) };
        filters.Children.Add(search); filters.Children.Add(L.Text("Rank", dim: true));
        foreach (string rank in new[] { "S", "A", "B", "C", "D", "E", "F" })
        {
            var chip = new ToggleButton { Content = rank, IsChecked = "SAB".Contains(rank), MinWidth = 30, Padding = new(8, 3), CornerRadius = new(12) };
            void PaintChip()
            {
                chip.Background = chip.IsChecked == true ? Palette.AccentSoftBrush : Palette.ChipBrush;
                chip.BorderBrush = chip.IsChecked == true ? Palette.AccentBrush : Palette.LineBrush;
            }
            ranks.Add(chip); filters.Children.Add(chip); PaintChip();
            chip.IsCheckedChanged += (_, _) => { PaintChip(); Filter(); };
        }
        foreach (var control in new Control[] { L.Text("Size", dim: true), sizeFilter, L.Text("Cracks at least", dim: true), rateFilter }) filters.Children.Add(control);
        search.TextChanged += (_, _) => Filter();
        sizeFilter.SelectionChanged += (_, _) => Filter(); rateFilter.SelectionChanged += (_, _) => Filter();
        var headers = L.Grid("*,44,62,76,88,98", columnSpacing: 4);
        string[] names = ["Name", "Rank", "Cracks", "Words", "Download", "Time for file"];
        WordlistSort[] sorts = [WordlistSort.Name, WordlistSort.Rank, WordlistSort.Cracks, WordlistSort.Words, WordlistSort.Download, WordlistSort.Time];
        for (int i = 0; i < names.Length; i++)
        {
            int k = i;
            var button = L.Button(names[i], () => { descending = sort == sorts[k] && !descending; sort = sorts[k]; Filter(); }, 0);
            button.Padding = new(3, 6); button.FontSize = 11; button.Classes.Add("tool");
            headers.Put(button, 0, i);
        }
        StretchItems(lists);
        lists.ItemTemplate = new FuncDataTemplate<WeakpassWordlist>((item, _) => CatalogRow(item!));
        lists.SelectionChanged += async (_, _) => await SelectAsync(lists.SelectedItem as WeakpassWordlist);
        var left = new Grid { RowDefinitions = new("Auto,*,Auto"), Margin = new(0, 0, 12, 0) };
        left.Put(headers, 0, 0); left.Put(lists, 1, 0); left.Put(matchCount, 2, 0);
        var columns = L.Grid("1.8*,1*", columnSpacing: 0);
        columns.Put(left, 0, 0);
        columns.RowDefinitions[0].Height = new GridLength(1, GridUnitType.Star);
        columns.Put(new Border { BorderBrush = Palette.LineBrush, BorderThickness = new(1, 0, 0, 0), Padding = new(14, 4, 0, 0), Background = Palette.PaneBrush, Child = new ScrollViewer { Content = details } }, 0, 1);
        details.Children.Add(L.Text("Select a wordlist to see its details.", dim: true, wrap: true));
        var controls = L.Grid("*,Auto,Auto");
        controls.Put(catalogNote, 0, 0); controls.Put(age, 0, 1); controls.Put(refresh, 0, 2);
        var panel = new Grid { RowDefinitions = new("Auto,Auto,*,Auto"), Margin = new(16, 8) };
        panel.Put(filters, 0, 0); panel.Put(controls, 1, 0); panel.Put(columns, 2, 0);
        panel.Put(L.Text("Wordlists and statistics from weakpass.com", dim: true, size: 11), 3, 0);
        return panel;
    }

    private Control CatalogRow(WeakpassWordlist item)
    {
        var row = L.Grid("*,44,62,76,88,98", columnSpacing: 4);
        row.Margin = new(0, 6);
        var name = L.Text(item.Name); name.TextTrimming = TextTrimming.CharacterEllipsis; ToolTip.SetTip(name, item.Name);
        row.Put(name, 0, 0);
        row.Put(Rank(item.Rank), 0, 1);
        row.Put(L.Text($"{item.Rate:0.0}%", size: 12), 0, 2);
        row.Put(L.Text(Compact(item.Count), size: 12), 0, 3);
        var saved = local.Any(x => x.Id == item.Id);
        var download = L.Text(saved ? "Downloaded" : Bytes(item.SizeCompressed), size: 11);
        if (saved) download.Foreground = Palette.SuccessBrush;
        row.Put(download, 0, 4);
        row.Put(L.Text(Time(item.Count), dim: true, size: 12), 0, 5);
        return row;
    }

    private Control FileTab()
    {
        var pathRow = L.Grid("*,Auto");
        pathRow.Put(filePath, 0, 0);
        pathRow.Put(L.Button("Browse...", async () => await GuardAsync(async () =>
        {
            if (await Pick.Open(this, "Wordlist files (*.txt; *.dic; *.lst)|*.txt;*.dic;*.lst|All files|*.*", settings.LastDictionaryDirectory ?? dataPath, "Choose wordlist") is { } path)
            { filePath.Text = path; settings.LastDictionaryDirectory = Path.GetDirectoryName(path); }
        })), 0, 1);
        filePath.TextChanged += async (_, _) => await InspectFileAsync();
        return new ScrollViewer
        {
            Margin = new(18), Content = L.Column(12,
                L.Text("Wordlist file", bold: true), pathRow,
                L.Text("Browse opens the system file browser. You can also type or paste a path.", dim: true),
                fileDetails, L.Text("Recently used files", bold: true), recentFiles,
                L.Text("In the data folder", bold: true), dataFiles)
        };
    }

    private async Task InitializeAsync(string? current, bool preserveTab = false)
    {
        if (initializing || initialized) return;
        initializing = true;
        retryInitialization.IsVisible = false;
        try
        {
            await Task.Run(() => library.CleanStalePartialsAsync(lifetime.Token));
            local = await Task.Run(() => library.LoadAsync(lifetime.Token));
            int tab = string.IsNullOrWhiteSpace(current) ? Math.Clamp(settings.LastWordlistTab, 0, 3)
                : BuiltinDictionaries.IsBuiltin(current) || BuiltinDictionaries.Names.Contains(current) ? 0
                : local.Any(x => library.FilePath(x) == current) ? 1 : 3;
            if (preserveTab) tab = tabs.SelectedIndex;
            if (BuiltinDictionaries.IsBuiltin(current)) builtins.SelectedItem = BuiltinDictionaries.DisplayName(current!);
            else if (BuiltinDictionaries.Names.Contains(current)) builtins.SelectedItem = current;
            if (tab == 3 && !string.IsNullOrWhiteSpace(current)) filePath.Text = current;
            settings.RecentWordlistFiles = settings.RecentWordlistFiles.Where(File.Exists).Distinct().Take(10).ToList();
            RenderFileLinks();
            RenderDownloaded();
            tabs.SelectedIndex = tab;
            settings.LastWordlistTab = tab;
            initialized = true;
            errorNote.IsVisible = false;
            if (tab == 2) await OpenCatalogAsync();
            UpdateUse();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (closed) return;
            initialized = false;
            ShowError("Could not open the wordlist library: " + ex.Message);
            retryInitialization.IsVisible = true;
        }
        finally { initializing = false; }
    }

    private void RenderFileLinks()
    {
        recentFiles.Children.Clear(); dataFiles.Children.Clear();
        foreach (string path in settings.RecentWordlistFiles) recentFiles.Children.Add(FileLink(path));
        if (recentFiles.Children.Count == 0) recentFiles.Children.Add(L.Text("No recently used files.", dim: true));
        foreach (string path in WordlistLibrary.DataFiles(dataPath)) dataFiles.Children.Add(FileLink(path));
        if (dataFiles.Children.Count == 0) dataFiles.Children.Add(L.Text("No wordlist files in the data folder.", dim: true));
    }

    private Control FileLink(string path)
    {
        var button = L.Button(Path.GetFileName(path) + "   " + Bytes(new FileInfo(path).Length), () => filePath.Text = path, 0);
        button.HorizontalAlignment = HorizontalAlignment.Stretch; button.HorizontalContentAlignment = HorizontalAlignment.Left;
        ToolTip.SetTip(button, path);
        return button;
    }

    private async Task InspectFileAsync()
    {
        fileReady = false; UpdateUse();
        fileCancellation?.Cancel();
        var cts = fileCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        int generation = ++fileGeneration;
        string path = (filePath.Text ?? "").Trim();
        fileDetails.Text = "Counting words...";
        try
        {
            var text = await Task.Run(() =>
            {
                var info = new FileInfo(path);
                long count = Wordlists.CountLines(path, cts.Token);
                return $"Words: {count:N0} (counted)\nSize: {Bytes(info.Length)}   Encoding: {EncodingName(Wordlists.Detect(path))}\n{Estimate(count)}";
            }, cts.Token);
            if (cts.IsCancellationRequested || generation != fileGeneration) return;
            fileDetails.Text = text; fileReady = true; UpdateUse();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        { if (generation == fileGeneration && !closed) fileDetails.Text = "Could not read file: " + ex.Message; }
    }

    private async Task OpenCatalogAsync()
    {
        if (preview || weakpassOpened) return;
        weakpassOpened = true;
        try
        {
            cache = await Task.Run(() => catalog.LoadAsync(lifetime.Token));
            if (closed) return;
            Filter(); ShowAge();
            if (WeakpassCatalog.RefreshDue(cache, DateTimeOffset.UtcNow)) await RefreshAsync();
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            weakpassOpened = false;
            if (!closed) { catalogNote.Text = "Could not refresh: " + ex.Message; refresh.Content = "Retry"; }
        }
    }

    private async Task RefreshAsync()
    {
        if (refreshing || preview) return;
        refreshing = true; refresh.IsEnabled = false; catalogNote.Text = "Refreshing catalog...";
        try
        {
            cache = await catalog.RefreshAsync(lifetime.Token);
            if (closed) return;
            catalogNote.Text = ""; refresh.Content = "Refresh";
            Filter(); ShowAge();
            if (selected is not null) await SelectAsync(selected);
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (closed) return;
            weakpassOpened = false;
            catalogNote.Text = "Could not refresh: " + ex.Message;
            refresh.Content = cache is null ? "Retry" : "Refresh";
        }
        finally { refreshing = false; if (!closed) refresh.IsEnabled = true; }
    }

    private void ShowAge()
    {
        if (cache is null) { age.Text = "No cached catalog"; return; }
        var elapsed = DateTimeOffset.UtcNow - cache.FetchedAt;
        age.Text = elapsed.TotalHours >= 1 ? $"Updated {Math.Max(0, (int)elapsed.TotalHours)} h ago" : "Updated just now";
    }

    private void Filter()
    {
        if (cache is null) return;
        long id = selected?.Id ?? -1;
        long[] sizes = [10_000_000, 100_000_000, 1_000_000_000, 10_000_000_000, long.MaxValue];
        double[] rates = [0, 5, 10, 15, 20];
        var matches = WordlistQuery.Apply(cache.Items, new WordlistQuery
        {
            Search = search.Text ?? "", Ranks = ranks.Where(x => x.IsChecked == true).Select(x => (string)x.Content!).ToHashSet(),
            MaxSize = sizes[Math.Max(0, sizeFilter.SelectedIndex)], MinRate = rates[Math.Max(0, rateFilter.SelectedIndex)],
            Sort = sort, Descending = descending, Speed = speed, RuleOutputs = outputs,
        }).ToList();
        lists.ItemsSource = matches;
        lists.SelectedItem = matches.FirstOrDefault(x => x.Id == id);
        matchCount.Text = $"{matches.Count:N0} of {cache.Items.Count:N0} lists";
    }

    private async Task SelectAsync(WeakpassWordlist? item)
    {
        CancellationTokenSource? cts = null;
        try
        {
            detailCancellation?.Cancel();
            selected = item; detail = null;
            RenderDetails(item, item is null ? "" : "Loading details..."); UpdateUse();
            if (item is null || preview) return;
            cts = detailCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            await Task.Delay(250, cts.Token);
            var loaded = await catalog.DetailAsync(item, cache?.FetchedAt ?? DateTimeOffset.MinValue, cts.Token);
            if (cts.IsCancellationRequested || closed || selected?.Id != item.Id) return;
            detail = loaded; RenderDetails(loaded); UpdateUse();
        }
        catch (OperationCanceledException) when (cts?.IsCancellationRequested == true || closed) { }
        catch (Exception ex)
        {
            if (closed || selected?.Id != item?.Id) return;
            detail = null;
            details.Children.Clear();
            details.Children.Add(L.Text("Could not load details: " + ex.Message, wrap: true));
            UpdateUse();
        }
    }

    /// <summary>Shrinks the dialog to the owner's screen before it is shown (small laptop screens, scaling).</summary>
    public void FitTo(Window owner)
    {
        if (owner.Screens.ScreenFromWindow(owner) is not { } screen) return;
        double maxW = screen.WorkingArea.Width / screen.Scaling - 24, maxH = screen.WorkingArea.Height / screen.Scaling - 48;
        MinWidth = Math.Min(MinWidth, maxW); MinHeight = Math.Min(MinHeight, maxH);
        Width = Math.Min(Width, maxW); Height = Math.Min(Height, maxH);
    }

    // Centering on a small owner can push the title bar above the screen; move it back into the working area.
    private void KeepOnScreen()
    {
        if (Screens.ScreenFromWindow(this) is not { } screen) return;
        var area = screen.WorkingArea;
        var frame = FrameSize ?? new Size(Width, Height);
        int w = (int)(frame.Width * screen.Scaling), h = (int)(frame.Height * screen.Scaling);
        int x = Math.Clamp(Position.X, area.X, Math.Max(area.X, area.Right - w));
        int y = Math.Clamp(Position.Y, area.Y, Math.Max(area.Y, area.Bottom - h));
        if (x != Position.X || y != Position.Y) Position = new PixelPoint(x, y);
    }

    private void RenderDetails(WeakpassWordlist? item, string note = "")
    {
        details.Children.Clear();
        if (item is null) { details.Children.Add(L.Text("Select a wordlist to see its details.", dim: true)); return; }
        var title = L.Text(item.Name, size: 18, wrap: true); title.Foreground = Palette.TitleBrush;
        var titleRow = L.Grid("*,Auto");
        titleRow.Put(title, 0, 0); titleRow.Put(Rank(item.Rank), 0, 1);
        details.Children.Add(titleRow);
        if (note.Length > 0) details.Children.Add(L.Text(note, dim: true, wrap: true, size: 11));
        var stats = L.Grid("Auto,*", rowSpacing: 4);
        void Stat(string name, string value) { int r = stats.RowDefinitions.Count; stats.Put(L.Text(name, dim: true, size: 12), r, 0); stats.Put(L.Text(value, wrap: true, size: 12), r, 1); }
        if (item is WeakpassDetail d)
        {
            var description = WordlistText.Description(d.Description);
            if (description.Text.Length > 0 && !description.Links.Contains(description.Text)) details.Children.Add(L.Text(description.Text, dim: true, wrap: true, size: 11));
            foreach (string link in description.Links) details.Children.Add(Link(link, link));
        }
        Stat("Words", item.Count.ToString("N0"));
        Stat("Cracks", $"{item.Rate:0.0}% of weakpass test hashes");
        Stat("Download", $"{Bytes(item.SizeCompressed)} ({Path.GetExtension(item.DownloadUrl ?? "")})");
        Stat("On disk", Bytes(item.Size));
        details.Children.Add(stats);
        var space = L.Text("Checking free space...", dim: true, size: 12);
        details.Children.Add(space); _ = ShowSpaceAsync(item, space);
        if (Estimate(item.Count) is { Length: > 0 } estimate) details.Children.Add(L.Text(estimate, wrap: true, size: 12));
        if (item.DownloadUrl is null) details.Children.Add(L.Text("No download is available for this list.", dim: true, wrap: true));
        if (item is WeakpassDetail info)
        {
            details.Children.Add(L.Text($"Downloaded {info.Downloaded:N0} times, updated {info.UpdatedAt:dd MMM yyyy}", dim: true, wrap: true, size: 11));
            details.Children.Add(L.Text("Password lengths", bold: true, size: 12));
            details.Children.Add(Histogram(info));
            long middle = info.LengthDistribution.Where(x => x.Length is >= 6 and <= 10).Sum(x => x.Count);
            details.Children.Add(L.Text($"{Percent(middle, info.Count)} are 6 to 10 characters.", dim: true, size: 11));
            details.Children.Add(L.Text("Character mix", bold: true, size: 12));
            foreach (var mask in info.Masks.OrderByDescending(x => x.Count).Take(5))
            {
                var row = L.Grid("*,70,44", columnSpacing: 6);
                row.Put(L.Text(WordlistText.CharacterClasses(mask.Mask), size: 11, wrap: true), 0, 0);
                row.Put(new ProgressBar { Minimum = 0, Maximum = Math.Max(1, info.Count), Value = mask.Count, MinWidth = 0, Width = 70, Height = 6, Foreground = Palette.AccentBrush }, 0, 1);
                row.Put(L.Text(Percent(mask.Count, info.Count), size: 11), 0, 2); details.Children.Add(row);
            }
            details.Children.Add(L.Text("Most common patterns", bold: true, size: 12));
            foreach (var mask in info.TopMasks.OrderByDescending(x => x.Count).Take(4))
            { var text = L.Text($"{mask.Mask}   {Percent(mask.Count, info.Count)}", size: 11); text.FontFamily = Ui.Styles.Mono; details.Children.Add(text); }
            details.Children.Add(L.Text("Sample", bold: true, size: 12));
            var examples = L.Text(string.Join("   ", info.Examples.Take(8)), dim: true, wrap: true, size: 12);
            examples.FontFamily = Ui.Styles.Mono; details.Children.Add(examples);
        }
        details.Children.Add(Link("Open on weakpass.com", $"https://weakpass.com/wordlist/{item.Id}"));
    }

    private async Task ShowSpaceAsync(WeakpassWordlist item, TextBlock label)
    {
        try
        {
            long free = await Task.Run(() => library.FreeSpace());
            if (closed) return;
            label.Text = $"{Bytes(free)} free on the library drive";
            label.Foreground = free < WordlistLibrary.RequiredSpace(item) ? Palette.WarningBrush : Palette.SuccessBrush;
        }
        catch (Exception) { if (!closed) label.Text = "Could not read free space."; }
    }

    private static Control Histogram(WeakpassDetail detail)
    {
        long[] buckets = WordlistText.LengthBuckets(detail.LengthDistribution);
        long max = Math.Max(1, buckets.Max());
        var chart = L.Grid(string.Join(",", Enumerable.Repeat("*", 14)), columnSpacing: 2);
        for (int i = 0; i < buckets.Length; i++)
        {
            var bar = new Border { Height = Math.Max(1, 65.0 * buckets[i] / max), Background = Palette.AccentBrush, VerticalAlignment = VerticalAlignment.Bottom };
            ToolTip.SetTip(bar, $"{(i == 13 ? "17+" : (i + 4).ToString())}: {buckets[i]:N0}");
            chart.Put(new Border { Height = 65, Child = bar }, 0, i);
            var label = L.Text(i == 13 ? "17+" : (i + 4).ToString(), dim: true, size: 10); label.HorizontalAlignment = HorizontalAlignment.Center;
            chart.Put(label, 1, i);
        }
        return chart;
    }

    private static Control Rank(string? rank)
    {
        var text = L.Text(rank ?? "-", bold: true, size: 11);
        text.HorizontalAlignment = HorizontalAlignment.Center;
        text.Foreground = Palette.RankText(rank);
        return new Border { Padding = new(5, 2), CornerRadius = new(4), Background = Palette.RankBackground(rank), Child = text, HorizontalAlignment = HorizontalAlignment.Left };
    }

    private static Control Link(string title, string url)
    {
        var button = L.Button(title, () => Platform.Shell(url), 0); button.Classes.Add("tool"); button.Foreground = Palette.LinkBrush;
        button.FontSize = 11; button.Padding = new(0); button.HorizontalAlignment = HorizontalAlignment.Left;
        button.MaxWidth = 340; button.Content = L.Text(title, wrap: true, size: 11); ToolTip.SetTip(button, url); return button;
    }

    private void RenderDownloaded()
    {
        downloaded.Children.Clear();
        foreach (var item in local)
        {
            var row = L.Grid("*,44,100,100,Auto,Auto,Auto");
            row.Put(L.Text(item.Name, wrap: true), 0, 0); row.Put(Rank(item.Rank), 0, 1);
            row.Put(L.Text($"{Compact(item.Count)} words", dim: true, size: 12), 0, 2); row.Put(L.Text(Bytes(item.Size), dim: true), 0, 3);
            row.Put(L.Button("Show in folder", () => Platform.Reveal(library.FilePath(item)), 0), 0, 4);
            row.Put(L.Button("Delete", async () =>
            {
                await GuardAsync(async () =>
                {
                    if (await Msg.Show(this, $"Delete {item.Name} from the library?", "Delete wordlist", MsgButtons.YesNo, MsgIcon.Question) != MsgResult.Yes) return;
                    await Task.Run(() => library.DeleteAsync(item.Id));
                    local = await Task.Run(() => library.LoadAsync()); RenderDownloaded(); Filter(); UpdateUse();
                });
            }, 0), 0, 5);
            row.Put(L.Button("Use", () => Complete(library.FilePath(item)), 0), 0, 6);
            downloaded.Children.Add(new Border { Padding = new(8), Background = Palette.CardBrush, Child = row });
        }
        foreach (var job in downloads.Jobs.Where(x => x.Library.DirectoryPath == library.DirectoryPath && (!x.Finished || x.Error is not null)))
        {
            var line = L.Grid("*,Auto");
            line.Put(L.Text(job.Error ?? job.Detail.Name + "   " + ProgressText(job), wrap: true), 0, 0);
            if (!job.Finished) line.Put(L.Button("Cancel", async () => await CancelAsync(job), 0), 0, 1);
            if (!job.Finished && job.Progress.Total > 0)
                line.Put(new ProgressBar { Minimum = 0, Maximum = 1, Value = job.Progress.Fraction, Height = 6, Margin = new(0, 6, 0, 0) }, 1, 0);
            downloaded.Children.Add(line);
        }
        if (downloaded.Children.Count == 0) downloaded.Children.Add(L.Text("No downloaded wordlists yet. Open weakpass.com to choose one.", dim: true));
        downloaded.Children.Add(L.Text($"Stored in {library.DirectoryPath}\n{Bytes(local.Sum(x => x.Size))} used", dim: true, wrap: true, size: 12));
        UpdateTransfer();
    }

    private WordlistDownload? ActiveJob() => useWhenReady is { Finished: false } ? useWhenReady
        : downloads.Jobs.FirstOrDefault(x => !x.Finished && x.Detail.Id == selected?.Id && x.Library.DirectoryPath == library.DirectoryPath)
        ?? downloads.Jobs.FirstOrDefault(x => !x.Finished);
    private void UpdateTransfer()
    {
        var job = ActiveJob();
        transfer.Text = job is null ? "" : job.Detail.Name + "   " + ProgressText(job) + $"   ({downloads.Jobs.Count(x => !x.Finished && x != job)} queued)";
        progress.IsVisible = cancelDownload.IsVisible = job is not null;
        if (job is not null) { progress.Value = job.Progress.Fraction; progress.IsIndeterminate = job.Progress.Total <= 0; }
        UpdateUse();
    }

    private static string ProgressText(WordlistDownload job)
    {
        var p = job.Progress;
        return p.Total > 0 ? $"{p.Stage}   {p.Fraction:P0}   {Bytes(p.Bytes)} of {Bytes(p.Total)}   {Bytes((long)p.BytesPerSecond)}/s   {(p.SecondsLeft is { } left ? Duration(left) + " left" : "estimating...")}"
            : p.Stage;
    }

    private void DownloadChanged(WordlistDownload job) => Interlocked.Exchange(ref downloadsDirty, 1);

    private async Task UpdateDownloadsAsync()
    {
        if (closed || updatingDownloads || Interlocked.Exchange(ref downloadsDirty, 0) == 0) return;
        updatingDownloads = true;
        try
        {
            var finished = downloads.Jobs.Where(x => x.Library.DirectoryPath == library.DirectoryPath && x.Finished && observedFinished.Add(x)).ToArray();
            if (finished.Length > 0)
            {
                local = await Task.Run(() => library.LoadAsync(lifetime.Token));
                if (closed) return;
                Filter();
                if (finished.LastOrDefault(x => x.Error is not null) is { } failed) ShowError(failed.Error!);
            }
            UpdateTransfer();
            if (tabs.SelectedIndex == 1) RenderDownloaded();
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex) { ShowError("Could not update downloads: " + ex.Message); }
        finally { updatingDownloads = false; }
    }

    private async Task CancelAsync(WordlistDownload job)
    {
        await GuardAsync(async () =>
        {
            long bytes = Math.Max(job.DownloadedBytes, await Task.Run(() => job.Library.PartialSizeAsync(job.Detail.Id)));
            if (job.Finished) return;
            bool keep = bytes > 100_000_000 && await Msg.Show(this,
                "Keep the partial download so it can resume later?", "Cancel download", MsgButtons.YesNo, MsgIcon.Question,
                ("Keep", "Delete")) == MsgResult.Yes;
            job.Cancel(keep);
        });
    }

    private void UpdateUse()
    {
        var job = selected is null ? null : downloads.Jobs.FirstOrDefault(x => x.Detail.Id == selected.Id && x.Library.DirectoryPath == library.DirectoryPath && !x.Finished);
        bool saved = local.Any(x => x.Id == selected?.Id);
        use.Content = tabs.SelectedIndex switch { 3 => "Use this file", 2 when job is not null => $"Use when ready ({job.Progress.Fraction:P0})", 2 when !saved => "Download and use", _ => "Use this wordlist" };
        use.IsVisible = tabs.SelectedIndex != 1;
        use.IsEnabled = tabs.SelectedIndex switch { 0 => builtins.SelectedItem is not null, 2 => selected is not null && (saved || job is not null || detail?.DownloadUrl is not null), 3 => fileReady, _ => false };
    }

    private async Task UseAsync()
    {
        int generation = ++useGeneration;
        useWhenReady = null;
        try
        {
            switch (tabs.SelectedIndex)
            {
                case 0:
                    if (builtins.SelectedItem is string name) Complete(BuiltinDictionaries.Reference(name));
                    break;
                case 3:
                    string path = Path.GetFullPath((filePath.Text ?? "").Trim());
                    if (!fileReady || !File.Exists(path)) return;
                    settings.LastDictionaryDirectory = Path.GetDirectoryName(path);
                    settings.RecentWordlistFiles = new[] { path }.Concat(settings.RecentWordlistFiles).Where(File.Exists).Distinct().Take(10).ToList();
                    Complete(path);
                    break;
                case 2:
                    if (local.FirstOrDefault(x => x.Id == selected?.Id) is { } saved) { Complete(library.FilePath(saved)); return; }
                    var job = downloads.Jobs.FirstOrDefault(x => !x.Finished && x.Detail.Id == selected?.Id && x.Library.DirectoryPath == library.DirectoryPath);
                    if (job is null)
                    {
                        if (detail is null) return;
                        var chosen = detail;
                        if (chosen.Size > 10_000_000_000 && await Msg.Show(this, $"{chosen.Name} downloads {Bytes(chosen.SizeCompressed)} and uses {Bytes(chosen.Size)} on disk. Download it?", "Large wordlist", MsgButtons.YesNo, MsgIcon.Question) != MsgResult.Yes) return;
                        if (generation != useGeneration || closed) return;
                        job = downloads.Enqueue(library, chosen);
                    }
                    useWhenReady = job;
                    UpdateTransfer();
                    var entry = await job.Completion;
                    if (!closed && generation == useGeneration && useWhenReady == job) Complete(library.FilePath(entry));
                    break;
            }
        }
        catch (OperationCanceledException) { if (!closed) UpdateUse(); }
        catch (Exception ex)
        { if (!closed && generation == useGeneration) { ShowError(ex.Message); UpdateUse(); } }
    }

    private void ShowError(string message)
    {
        if (closed) return;
        errorNote.Text = message;
        errorNote.IsVisible = true;
    }

    private async Task GuardAsync(Func<Task> action)
    {
        try { await action(); }
        catch (OperationCanceledException) when (closed) { }
        catch (Exception ex) { ShowError(ex.Message); }
    }

    private static string EncodingName(WordlistEncoding encoding) => encoding switch
    {
        WordlistEncoding.Utf8 => "UTF-8",
        WordlistEncoding.Utf8Bom => "UTF-8 (BOM)",
        WordlistEncoding.Utf16Le => "UTF-16 LE",
        WordlistEncoding.Utf16Be => "UTF-16 BE",
        _ => "ANSI",
    };
    private void Complete(string value) => Close(value);
    private string Time(long count) => WordlistQuery.Seconds(count, outputs, speed) is { } seconds ? Duration(seconds) : "";
    private string Estimate(long count) => Time(count) is { Length: > 0 } time ? $"Time for this file: {time} at {speed:N0} p/s, rules \"{rules}\"" : "";
    internal static string Bytes(long bytes) => bytes >= 1_000_000_000 ? $"{bytes / 1_000_000_000.0:0.##} GB" : bytes >= 1_000_000 ? $"{bytes / 1_000_000.0:0.##} MB" : bytes >= 1000 ? $"{bytes / 1000.0:0.##} KB" : $"{bytes:N0} B";
    private static string Compact(long count) => count >= 1_000_000_000 ? $"{count / 1_000_000_000.0:0.#} B" : count >= 1_000_000 ? $"{count / 1_000_000.0:0.#} M" : count >= 1000 ? $"{count / 1000.0:0.#} K" : count.ToString();
    private static string Percent(long count, long total) => total > 0 ? $"{100.0 * count / total:0.#}%" : "0%";
    private static string Duration(double seconds) => seconds >= 3600 ? $"{seconds / 3600:0.#} h" : seconds >= 60 ? $"{seconds / 60:0.#} min" : $"{Math.Ceiling(seconds):0} s";

#if DEBUG
    internal bool DebugReady => initialized && !initializing;

    internal void DebugShow(int tab, WordlistCatalogCache fixture, WeakpassDetail selectedDetail)
    {
        cache = fixture; weakpassOpened = true; initialized = true;
        foreach (var chip in ranks) chip.IsChecked = true;
        tabs.SelectedIndex = tab; Filter(); ShowAge();
        lists.SelectedItem = fixture.Items.FirstOrDefault(x => x.Id == selectedDetail.Id);
        selected = selectedDetail; detail = selectedDetail;
        RenderDetails(selectedDetail); UpdateUse();
        var active = L.Grid("*,Auto");
        active.Put(L.Text("Unpacking preview-list.txt   42%   84 of 200 MB   33.5 MB/s   4 s left", wrap: true), 0, 0);
        active.Put(new ProgressBar { Minimum = 0, Maximum = 1, Value = 0.42, Height = 6, Margin = new(0, 6, 0, 0) }, 1, 0);
        active.Put(L.Button("Cancel", () => { }, 0), 0, 1);
        downloaded.Children.Insert(Math.Max(0, downloaded.Children.Count - 1), active);
        downloaded.Children.Insert(Math.Max(0, downloaded.Children.Count - 1), L.Text("Queued: another-list.txt", dim: true));
        transfer.Text = "Unpacking preview-list.txt   42%   84 of 200 MB   33.5 MB/s   4 s left   (1 queued)";
        progress.IsVisible = cancelDownload.IsVisible = true;
        progress.MinWidth = 0; progress.IsIndeterminate = false; progress.Value = 0.42;
    }
#endif
}
