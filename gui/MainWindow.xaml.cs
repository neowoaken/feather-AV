using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Ellipse = System.Windows.Shapes.Ellipse;

namespace Feather.Gui;

public partial class MainWindow : Window
{
    private readonly Scanner _scanner = new();
    private Policy _policy = Policy.CreateDefault();

    private readonly string _configDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Feather");
    private readonly string _policyPath;
    private readonly string _allowPath;

    private readonly List<(CheckBox Box, Finding Finding)> _resultRows = new();
    private readonly List<(string Sha256, Button RestoreButton)> _quarantineRows = new();

    private bool _busy;
    private string? _enginePath;
    private string _lastScan = "never";
    private int _lastFlagged;
    private int _quarantineCount;

    public MainWindow()
    {
        InitializeComponent();

        _policyPath = Path.Combine(_configDir, "policy.json");
        _allowPath = Path.Combine(_configDir, "allow.txt");

        LoadPolicy();
        BuildCategories();
        PathBox.Text = @"C:\";
        LoadScanner();
        RefreshDashboard();
        ShowDashboard();
    }

    // ------------------------------------------------------------- navigation

    private void ShowDashboard() => ShowPage(DashboardPage, NavDashboard);
    private void ShowScan() => ShowPage(ScanPage, NavScan);
    private void ShowQuarantine()
    {
        ShowPage(QuarantinePage, NavQuarantine);
        _ = LoadQuarantineAsync();
    }
    private void ShowCategories() => ShowPage(CategoriesPage, NavCategories);
    private void ShowSettings() => ShowPage(SettingsPage, NavSettings);

    private void ShowPage(ScrollViewer page, Button active)
    {
        foreach (var view in new[] { DashboardPage, ScanPage, QuarantinePage, CategoriesPage, SettingsPage })
        {
            view.Visibility = ReferenceEquals(view, page) ? Visibility.Visible : Visibility.Collapsed;
        }
        SetActive(active);
    }

    private void SetActive(Button active)
    {
        foreach (var button in new[] { NavDashboard, NavScan, NavQuarantine, NavCategories, NavSettings })
        {
            bool on = ReferenceEquals(button, active);
            button.Background = on ? Res("SidebarActiveBrush") : Brushes.Transparent;
            button.Foreground = on
                ? Res("AccentGlowBrush")
                : (Brush)new SolidColorBrush(Color.FromRgb(0xA8, 0xAF, 0xBA));
        }
    }

    private void OnNavDashboard(object sender, RoutedEventArgs e) => ShowDashboard();
    private void OnNavScan(object sender, RoutedEventArgs e) => ShowScan();
    private void OnNavQuarantine(object sender, RoutedEventArgs e) => ShowQuarantine();
    private void OnNavCategories(object sender, RoutedEventArgs e) => ShowCategories();
    private void OnNavSettings(object sender, RoutedEventArgs e) => ShowSettings();

    private static Brush Res(string key) => (Brush)Application.Current.FindResource(key);

    // ---------------------------------------------------------------- start-up

    private void LoadPolicy()
    {
        Directory.CreateDirectory(_configDir);
        _policy = Policy.Load(_policyPath);
    }

    private void LoadScanner()
    {
        _enginePath = Scanner.FindExecutable();
        if (string.IsNullOrEmpty(_enginePath))
        {
            Status.Text = "feather.exe was not found. Open Settings to locate it.";
            SetBusy(false);
            return;
        }

        EnsureAllowFile();
        _scanner.Configure(_enginePath, ioc: null, allow: _allowPath);
        Status.Text = "Ready. Click Scan to check drive C.";
        SetBusy(false);
    }

    private void EnsureAllowFile()
    {
        try
        {
            Directory.CreateDirectory(_configDir);
            if (!File.Exists(_allowPath))
            {
                File.WriteAllText(_allowPath,
                    "# feather allow list" + Environment.NewLine +
                    "# Format: sha256 <64 hex chars>  note" + Environment.NewLine);
            }
        }
        catch
        {
            // An unwritable allow list only disables the allow action later.
        }
    }

    // ---------------------------------------------------------------- dashboard

    private void RefreshDashboard()
    {
        bool ready = _scanner.Ready;

        EngineLabel.Text = ready ? "engine: " + Path.GetFileName(_enginePath) : "engine: not found";
        EnginePathLabel.Text = ready ? _enginePath ?? "" : "Not found";
        LastScanLabel.Text = "Last scan: " + _lastScan +
                             (_lastFlagged > 0 ? $"  ({_lastFlagged} flagged)" : "");

        _quarantineCount = CountQuarantine();
        int allowCount = CountEntries(_allowPath);
        AllowListLabel.Text = $"{allowCount} hash(es) allowed from {_allowPath}";

        AdvisorPanel.Children.Clear();
        AddAdvisorRow("On-demand scanner",
            ready ? "Ready to scan drive C" : "Engine not found - see Settings",
            ready ? Res("SuccessBrush") : Res("DangerBrush"));
        AddAdvisorRow("Real-time protection",
            "Not included in this build",
            Res("MutedBrush"));
        AddAdvisorRow("Quarantine",
            $"{_quarantineCount} file(s) held, restorable anytime",
            _quarantineCount > 0 ? Res("WarnBrush") : Res("SuccessBrush"));
        AddAdvisorRow("Allow list",
            $"{allowCount} hash(es) allowed",
            Res("AccentBrush"));

        StatusHeadline.Text = ready ? "Scanner ready" : "Engine required";
        StatusGlyph.Fill = ready ? Res("SuccessBrush") : Res("DangerBrush");
        StatusNote.Text = ready
            ? "On-demand scanning is available. Real-time protection is not part of this build."
            : "Locate feather.exe in Settings to enable scanning.";

        StatusDetails.Children.Clear();
        AddStatusDetail("Mode", "Classify only. You decide every action.");
        AddStatusDetail("Engine", ready ? Path.GetFileName(_enginePath ?? "") : "missing");
        AddStatusDetail("Definitions", DefinitionsText());

        DefinitionsLabel.Text = DefinitionsText();
    }

    private void AddAdvisorRow(string title, string subtitle, Brush dot)
    {
        var row = new Grid { Margin = new Thickness(0, 0, 0, 14) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var marker = new Ellipse
        {
            Width = 8, Height = 8, Fill = dot,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(2, 0, 12, 0)
        };
        Grid.SetColumn(marker, 0);

        var text = new StackPanel();
        Grid.SetColumn(text, 1);
        text.Children.Add(new TextBlock { Text = title, FontSize = 13, FontWeight = FontWeights.SemiBold });
        text.Children.Add(new TextBlock
        {
            Text = subtitle, FontSize = 11.5,
            Foreground = Res("MutedBrush"), Margin = new Thickness(0, 2, 0, 0)
        });

        row.Children.Add(marker);
        row.Children.Add(text);
        AdvisorPanel.Children.Add(row);
    }

    private void AddStatusDetail(string label, string value)
    {
        var row = new Grid { Margin = new Thickness(0, 0, 0, 7) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(98) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var key = new TextBlock { Text = label, FontSize = 11.5, Foreground = Res("MutedBrush") };
        var val = new TextBlock
        {
            Text = value, FontSize = 11.5,
            TextTrimming = TextTrimming.CharacterEllipsis
        };
        Grid.SetColumn(key, 0);
        Grid.SetColumn(val, 1);
        row.Children.Add(key);
        row.Children.Add(val);
        StatusDetails.Children.Add(row);
    }

    private static int CountEntries(string path)
    {
        try
        {
            return File.Exists(path)
                ? File.ReadLines(path).Count(l =>
                    !string.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith("#"))
                : 0;
        }
        catch { return 0; }
    }

    private static int CountQuarantine()
    {
        var manifest = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Feather", "quarantine", "manifest.tsv");
        return Math.Max(0, CountEntries(manifest) - 1);
    }

    private static string? FindDefinitionsFile()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir != null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "rules", "ioc.sample.txt");
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    private static string DefinitionsText()
    {
        var path = FindDefinitionsFile();
        if (path is null) return "Local signature file not found";
        int count = CountEntries(path);
        return count > 0 ? $"{count} local signature(s) available" : "No signatures loaded";
    }

    private void OnCheckDefinitions(object sender, RoutedEventArgs e)
    {
        var path = FindDefinitionsFile();
        RefreshDashboard();
        MessageBox.Show(this,
            path is null
                ? "No local signature file was found next to the application."
                : "Signature file:\n" + path + "\n\n" +
                  "Update this file to add indicators. Feather never downloads rules silently.",
            "Protection updates", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    // ------------------------------------------------------------------ settings

    private void OnLocate(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Locate feather.exe",
            Filter = "feather.exe|feather.exe|All files|*.*",
            FileName = "feather.exe"
        };
        if (dialog.ShowDialog(this) != true) return;

        _enginePath = dialog.FileName;
        EnsureAllowFile();
        _scanner.Configure(_enginePath, ioc: null, allow: _allowPath);
        Status.Text = "Engine set. Ready to scan.";
        RefreshDashboard();
        SetBusy(false);
    }

    // -------------------------------------------------------------------- scan

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Choose a folder to scan",
            ValidateNames = false,
            CheckFileExists = false,
            CheckPathExists = true,
            FileName = "Folder Selection."
        };
        if (dialog.ShowDialog(this) == true)
        {
            PathBox.Text = Path.GetDirectoryName(dialog.FileName) ?? PathBox.Text;
        }
    }

    private void OnMoreOptions(object sender, RoutedEventArgs e)
    {
        FolderPanel.Visibility = FolderPanel.Visibility == Visibility.Visible
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    private void OnDashboardScan(object sender, RoutedEventArgs e)
    {
        ShowScan();
        _ = RunScanAsync();
    }

    private async void OnScan(object sender, RoutedEventArgs e) => await RunScanAsync();

    private async Task RunScanAsync()
    {
        string folder;
        if (FolderPanel.Visibility == Visibility.Visible)
        {
            folder = PathBox.Text.Trim();
            if (!Directory.Exists(folder))
            {
                MessageBox.Show(this, "Pick an existing folder first.", "feather",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
        }
        else
        {
            folder = @"C:\";
        }

        SetBusy(true);
        ResultsPanel.Children.Clear();
        _resultRows.Clear();
        SetFindingsCount(0);
        Status.Text = "Scanning " + folder + " ...";

        try
        {
            var all = await _scanner.ScanAsync(folder, null);

            var flagged = all
                .Where(f => f.Verdict is "unwanted" or "malicious")
                .OrderByDescending(f => f.Verdict == "malicious")
                .ThenBy(f => f.CategoryLabel, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var finding in flagged)
            {
                ResultsPanel.Children.Add(CreateResultCard(finding));
            }

            SetFindingsCount(flagged.Count);

            var preselected = _resultRows.Count(r => r.Box.IsChecked == true);
            var malicious = flagged.Count(f => f.Verdict == "malicious");
            var unwanted = flagged.Count(f => f.Verdict == "unwanted");

            var summary = $"{flagged.Count} flagged ({malicious} malicious, {unwanted} unwanted), " +
                          $"{preselected} preselected";
            if (!string.IsNullOrEmpty(_scanner.LastSummary))
            {
                summary += "  |  " + _scanner.LastSummary;
            }
            Status.Text = summary;

            _lastScan = DateTime.Now.ToString("HH:mm");
            _lastFlagged = flagged.Count;
            RefreshDashboard();
        }
        catch (Exception ex)
        {
            Status.Text = "Scan failed.";
            MessageBox.Show(this, ex.Message, "Scan failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetFindingsCount(int count)
    {
        ((TextBlock)FindingsCount.Child).Text = count.ToString();
        FindingsCount.Background = count == 0
            ? Res("SurfaceBrush")
            : new SolidColorBrush(count > 0 && _resultRows.Any(r =>
                r.Finding.Verdict == "malicious") ? Color.FromRgb(0x7A, 0x2B, 0x2E)
                : Color.FromRgb(0x6B, 0x4E, 0x16));
    }

    private Border CreateResultCard(Finding finding)
    {
        var selected = _policy.ActionFor(finding.Category) == CategoryAction.Swipe;

        var card = new Border
        {
            Style = (Style)FindResource("Card"),
            Padding = new Thickness(14),
            Margin = new Thickness(0, 0, 0, 10)
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var check = new CheckBox
        {
            VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, 3, 14, 0),
            IsChecked = selected,
            Tag = finding
        };
        Grid.SetColumn(check, 0);

        var info = new StackPanel();
        Grid.SetColumn(info, 1);

        var titleRow = new Grid { Margin = new Thickness(0, 0, 0, 6) };
        titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var name = new TextBlock
        {
            Text = finding.FileName,
            FontWeight = FontWeights.SemiBold,
            FontSize = 14,
            TextTrimming = TextTrimming.CharacterEllipsis
        };
        Grid.SetColumn(name, 0);

        var badges = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center
        };
        Grid.SetColumn(badges, 1);
        badges.Children.Add(CreateBadge(finding.CategoryLabel, CategoryColor(finding.Category)));
        badges.Children.Add(CreateBadge(finding.Verdict, VerdictColor(finding.Verdict), 8));

        titleRow.Children.Add(name);
        titleRow.Children.Add(badges);
        info.Children.Add(titleRow);

        info.Children.Add(new TextBlock
        {
            Text = finding.Path,
            Foreground = Res("MutedBrush"),
            FontSize = 11,
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(0, 0, 0, 6)
        });

        info.Children.Add(new TextBlock
        {
            Text = finding.Reason,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap
        });

        if (finding.Warnings.Count > 0)
        {
            info.Children.Add(new TextBlock
            {
                Text = string.Join("  |  ", finding.Warnings),
                Foreground = Res("WarnBrush"),
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });
        }

        grid.Children.Add(check);
        grid.Children.Add(info);
        card.Child = grid;

        _resultRows.Add((check, finding));
        return card;
    }

    private Border CreateBadge(string text, Color color, int leftMargin = 0)
    {
        var badge = new Border
        {
            Style = (Style)FindResource("Badge"),
            Background = new SolidColorBrush(color) { Opacity = 0.16 },
            BorderBrush = new SolidColorBrush(color) { Opacity = 0.5 },
            BorderThickness = new Thickness(1),
            Margin = new Thickness(leftMargin, 0, 0, 0)
        };
        badge.Child = new TextBlock
        {
            Text = text,
            Foreground = new SolidColorBrush(color),
            FontSize = 11,
            FontWeight = FontWeights.SemiBold
        };
        return badge;
    }

    // ------------------------------------------------------- quarantine / allow

    private async void OnQuarantineChecked(object sender, RoutedEventArgs e)
    {
        var selected = _resultRows.Where(r => r.Box.IsChecked == true).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show(this, "Tick the files you want to remove first.",
                "Nothing selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // Malware is wiped permanently; everything else stays restorable in quarantine.
        var malicious = selected.Where(r => r.Finding.Verdict == "malicious").ToList();
        var restorable = selected.Where(r => r.Finding.Verdict != "malicious").ToList();

        var details = new StringBuilder();
        if (malicious.Count > 0)
        {
            details.AppendLine($"{malicious.Count} malicious file(s) will be permanently " +
                               "wiped (overwritten with zeros, not recoverable).");
        }
        if (restorable.Count > 0)
        {
            details.AppendLine($"{restorable.Count} other file(s) will be quarantined and " +
                               "can be restored from the Quarantine page.");
        }
        details.AppendLine("\nContinue?");

        var confirm = MessageBox.Show(this, details.ToString(),
            "Remove selected", MessageBoxButton.YesNo, MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (confirm != MessageBoxResult.Yes) return;

        SetBusy(true);
        var wiped = 0;
        var quarantined = 0;
        var failures = new List<string>();

        void RemoveRow(CheckBox box)
        {
            if (box.Parent is Grid grid && grid.Parent is Border card)
            {
                ResultsPanel.Children.Remove(card);
            }
            _resultRows.RemoveAll(r => ReferenceEquals(r.Box, box));
        }

        foreach (var (box, finding) in malicious)
        {
            var (ok, message) = await _scanner.WipeAsync(finding.Path);
            if (ok)
            {
                ++wiped;
                RemoveRow(box);
            }
            else
            {
                failures.Add(finding.FileName + ": " + message);
            }
        }

        foreach (var (box, finding) in restorable)
        {
            var (ok, message) = await _scanner.QuarantineAsync(finding.Path, finding.Category);
            if (ok)
            {
                ++quarantined;
                RemoveRow(box);
            }
            else
            {
                failures.Add(finding.FileName + ": " + message);
            }
        }

        SetBusy(false);
        SetFindingsCount(_resultRows.Count);
        Status.Text = $"Wiped {wiped} malicious file(s); quarantined {quarantined} file(s).";
        RefreshDashboard();

        if (failures.Count > 0)
        {
            MessageBox.Show(this,
                "Some files were left alone:\n\n" + string.Join("\n", failures.Take(10)),
                "Removal incomplete", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnAllowChecked(object sender, RoutedEventArgs e)
    {
        var selected = _resultRows.Where(r => r.Box.IsChecked == true).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show(this, "Tick the files you want to allow first.",
                "Nothing selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            foreach (var (box, finding) in selected)
            {
                _scanner.AddAllow(finding.Sha256, "allowed from Feather GUI: " + finding.Category);
                if (box.Parent is Grid grid && grid.Parent is Border card)
                {
                    ResultsPanel.Children.Remove(card);
                }
                _resultRows.RemoveAll(r => ReferenceEquals(r.Box, box));
            }
            SetFindingsCount(_resultRows.Count);
            Status.Text = $"Allowed {selected.Count} file(s) by hash. Future scans will not flag them.";
            RefreshDashboard();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Could not write the allow list",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // -------------------------------------------------------------- quarantine

    private async Task LoadQuarantineAsync()
    {
        QuarantinePanel.Children.Clear();
        _quarantineRows.Clear();

        List<QuarantineItem> items;
        try
        {
            items = await _scanner.QuarantineListAsync();
        }
        catch (Exception ex)
        {
            QuarantinePanel.Children.Add(new TextBlock
            {
                Text = "Could not read the quarantine: " + ex.Message,
                Foreground = Res("MutedBrush")
            });
            return;
        }

        if (items.Count == 0)
        {
            QuarantinePanel.Children.Add(new Border
            {
                Style = (Style)FindResource("Card"),
                Child = new TextBlock
                {
                    Text = "Quarantine is empty. Nothing has been removed.",
                    Foreground = Res("MutedBrush")
                }
            });
            RefreshDashboard();
            return;
        }

        foreach (var item in items)
        {
            QuarantinePanel.Children.Add(CreateQuarantineCard(item));
        }
        RefreshDashboard();
    }

    private Border CreateQuarantineCard(QuarantineItem item)
    {
        var card = new Border
        {
            Style = (Style)FindResource("Card"),
            Padding = new Thickness(14),
            Margin = new Thickness(0, 0, 0, 10)
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var info = new StackPanel();
        Grid.SetColumn(info, 0);
        info.Children.Add(new TextBlock
        {
            Text = Path.GetFileName(item.OriginalPath),
            FontWeight = FontWeights.SemiBold,
            FontSize = 14,
            TextTrimming = TextTrimming.CharacterEllipsis
        });
        info.Children.Add(new TextBlock
        {
            Text = item.OriginalPath,
            Foreground = Res("MutedBrush"),
            FontSize = 11,
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(0, 0, 0, 6)
        });
        info.Children.Add(new TextBlock
        {
            Text = $"{item.Timestamp}   {item.Category}   {item.SizeText}   {item.Sha256[..16]}...",
            Foreground = Res("MutedBrush"),
            FontSize = 11
        });

        var restore = new Button
        {
            Content = "Restore",
            Style = (Style)FindResource("ButtonBase"),
            VerticalAlignment = VerticalAlignment.Center,
            Tag = item.Sha256
        };
        restore.Click += async (_, _) =>
        {
            var (ok, message) = await _scanner.RestoreAsync(item.Sha256);
            if (ok)
            {
                await LoadQuarantineAsync();
            }
            else
            {
                MessageBox.Show(this, message, "Restore failed",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        };
        Grid.SetColumn(restore, 1);

        grid.Children.Add(info);
        grid.Children.Add(restore);
        card.Child = grid;
        return card;
    }

    private void OnRefreshQuarantine(object sender, RoutedEventArgs e) => _ = LoadQuarantineAsync();

    // -------------------------------------------------------------- categories

    private void BuildCategories()
    {
        CategoryPanel.Children.Clear();
        foreach (var (id, label) in Policy.KnownCategories)
        {
            var row = new Grid { Margin = new Thickness(10, 8, 10, 8) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var name = new TextBlock
            {
                Text = label,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 14
            };
            Grid.SetColumn(name, 0);

            var toggle = new CheckBox
            {
                Content = "Auto-select",
                VerticalAlignment = VerticalAlignment.Center,
                IsChecked = _policy.ActionFor(id) == CategoryAction.Swipe,
                Tag = id
            };
            toggle.Checked += OnCategoryToggled;
            toggle.Unchecked += OnCategoryToggled;
            Grid.SetColumn(toggle, 1);

            row.Children.Add(name);
            row.Children.Add(toggle);
            CategoryPanel.Children.Add(row);
        }
    }

    private void OnCategoryToggled(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox check || check.Tag is not string id) return;
        _policy.Set(id, check.IsChecked == true ? CategoryAction.Swipe : CategoryAction.Warn);
        try
        {
            _policy.Save(_policyPath);
        }
        catch
        {
            // Saving a preference is never worth interrupting the user.
        }
    }

    // ------------------------------------------------------------------ state

    private void SetBusy(bool busy)
    {
        _busy = busy;
        ScanButton.IsEnabled = !busy && _scanner.Ready;
        DashboardScanButton.IsEnabled = !busy && _scanner.Ready;
        MoreOptionsButton.IsEnabled = !busy;
        BrowseButton.IsEnabled = !busy;
        LocateButton.IsEnabled = !busy;
        QuarantineButton.IsEnabled = !busy;
        AllowButton.IsEnabled = !busy;
        RefreshQuarantineButton.IsEnabled = !busy;
        CheckDefinitionsButton.IsEnabled = !busy;
        Progress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        Mouse.OverrideCursor = busy ? Cursors.Wait : null;
    }

    // ------------------------------------------------------------------ colors

    private static Color VerdictColor(string verdict) => verdict switch
    {
        "malicious" => Color.FromRgb(0xE5, 0x48, 0x4D),
        "unwanted" => Color.FromRgb(0xF5, 0xA5, 0x24),
        "info" => Color.FromRgb(0x3B, 0x82, 0xF6),
        "clean" => Color.FromRgb(0x30, 0xA4, 0x6C),
        _ => Color.FromRgb(0x6B, 0x76, 0x86)
    };

    private static Color CategoryColor(string category) => category.ToLowerInvariant() switch
    {
        "malware" or "trojan" or "ransomware" or "stealer" or "spyware"
            or "dropper" or "worm" or "virus" or "injector" => Color.FromRgb(0xE5, 0x48, 0x4D),
        "hacktool" => Color.FromRgb(0x4E, 0xAC, 0xE9),
        "adware" or "suspicious" or "miner" => Color.FromRgb(0xF5, 0xA5, 0x24),
        "pua" => Color.FromRgb(0x8B, 0x5C, 0xF6),
        "test" => Color.FromRgb(0x30, 0xA4, 0x6C),
        _ => Color.FromRgb(0x6B, 0x76, 0x86)
    };
}
