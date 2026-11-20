using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

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

    public MainWindow()
    {
        InitializeComponent();

        _policyPath = Path.Combine(_configDir, "policy.json");
        _allowPath = Path.Combine(_configDir, "allow.txt");

        LoadPolicy();
        BuildCategories();
        LoadScanner();

        ShowScan();
    }

    // ------------------------------------------------------------- navigation

    private void ShowScan()
    {
        SetActive(NavScan);
        ScanPage.Visibility = Visibility.Visible;
        QuarantinePage.Visibility = Visibility.Collapsed;
        CategoriesPage.Visibility = Visibility.Collapsed;
    }

    private void ShowQuarantine()
    {
        SetActive(NavQuarantine);
        ScanPage.Visibility = Visibility.Collapsed;
        QuarantinePage.Visibility = Visibility.Visible;
        CategoriesPage.Visibility = Visibility.Collapsed;
        _ = LoadQuarantineAsync();
    }

    private void ShowCategories()
    {
        SetActive(NavCategories);
        ScanPage.Visibility = Visibility.Collapsed;
        QuarantinePage.Visibility = Visibility.Collapsed;
        CategoriesPage.Visibility = Visibility.Visible;
    }

    private void SetActive(Button active)
    {
        foreach (var button in new[] { NavScan, NavQuarantine, NavCategories })
        {
            button.Background = ReferenceEquals(button, active)
                ? (Brush)FindResource("SidebarActiveBrush")
                : Brushes.Transparent;
            button.Foreground = ReferenceEquals(button, active)
                ? Brushes.White
                : (Brush)new SolidColorBrush(Color.FromRgb(0xB9, 0xC2, 0xD0));
        }
    }

    private void OnNavScan(object sender, RoutedEventArgs e) => ShowScan();
    private void OnNavQuarantine(object sender, RoutedEventArgs e) => ShowQuarantine();
    private void OnNavCategories(object sender, RoutedEventArgs e) => ShowCategories();

    // ---------------------------------------------------------------- start-up

    private void LoadPolicy()
    {
        Directory.CreateDirectory(_configDir);
        _policy = Policy.Load(_policyPath);
    }

    private void LoadScanner()
    {
        var exe = Scanner.FindExecutable();
        if (string.IsNullOrEmpty(exe))
        {
            EngineLabel.Text = "engine: not found - use File > Locate";
            SetBusy(false);
            return;
        }

        EnsureAllowFile();
        _scanner.Configure(exe, ioc: null, allow: _allowPath);
        EngineLabel.Text = "engine: " + exe;
        Status.Text = "Ready.";
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

    private async void OnScan(object sender, RoutedEventArgs e)
    {
        var folder = PathBox.Text.Trim();
        if (!Directory.Exists(folder))
        {
            MessageBox.Show(this, "Pick an existing folder first.", "feather",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SetBusy(true);
        ResultsPanel.Children.Clear();
        _resultRows.Clear();
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
        Grid.SetColumn(badges, 1);

        titleRow.Children.Add(name);
        titleRow.Children.Add(badges);
        info.Children.Add(titleRow);

        info.Children.Add(new TextBlock
        {
            Text = finding.Path,
            Foreground = (Brush)FindResource("MutedBrush"),
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
                Foreground = (Brush)FindResource("UnwantedBrush"),
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
            Background = new SolidColorBrush(color) { Opacity = 0.14 },
            BorderBrush = new SolidColorBrush(color) { Opacity = 0.45 },
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
            MessageBox.Show(this, "Tick the files you want to quarantine first.",
                "Nothing selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(this,
            $"Copy {selected.Count} file(s) into quarantine and remove the originals?\n\n" +
            "Each file is re-hashed before the original is touched, and it can be " +
            "restored from the Quarantine page.",
            "Quarantine", MessageBoxButton.YesNo, MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (confirm != MessageBoxResult.Yes) return;

        SetBusy(true);
        var removed = 0;
        var failures = new List<string>();

        foreach (var (box, finding) in selected)
        {
            var (ok, message) = await _scanner.QuarantineAsync(finding.Path, finding.Category);
            if (ok)
            {
                ++removed;
                if (box.Parent is Grid grid && grid.Parent is Border card)
                {
                    ResultsPanel.Children.Remove(card);
                }
                _resultRows.RemoveAll(r => ReferenceEquals(r.Box, box));
            }
            else
            {
                failures.Add(finding.FileName + ": " + message);
            }
        }

        SetBusy(false);
        Status.Text = $"Quarantined {removed} file(s).";

        if (failures.Count > 0)
        {
            MessageBox.Show(this,
                "Some files were left alone:\n\n" + string.Join("\n", failures.Take(10)),
                "Quarantine incomplete", MessageBoxButton.OK, MessageBoxImage.Warning);
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
                _scanner.AddAllow(finding.Sha256, "allowed from GUI: " + finding.Category);
                if (box.Parent is Grid grid && grid.Parent is Border card)
                {
                    ResultsPanel.Children.Remove(card);
                }
                _resultRows.RemoveAll(r => ReferenceEquals(r.Box, box));
            }
            Status.Text = $"Allowed {selected.Count} file(s) by hash. Future scans will not flag them.";
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
                Foreground = (Brush)FindResource("MutedBrush")
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
                    Foreground = (Brush)FindResource("MutedBrush")
                }
            });
            return;
        }

        foreach (var item in items)
        {
            QuarantinePanel.Children.Add(CreateQuarantineCard(item));
        }
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
            Foreground = (Brush)FindResource("MutedBrush"),
            FontSize = 11,
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(0, 0, 0, 6)
        });
        info.Children.Add(new TextBlock
        {
            Text = $"{item.Timestamp}   {item.Category}   {item.SizeText}   {item.Sha256[..16]}...",
            Foreground = (Brush)FindResource("MutedBrush"),
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
        BrowseButton.IsEnabled = !busy;
        QuarantineButton.IsEnabled = !busy;
        AllowButton.IsEnabled = !busy;
        RefreshQuarantineButton.IsEnabled = !busy;
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
        "hacktool" => Color.FromRgb(0x2F, 0x6F, 0xED),
        "adware" or "suspicious" or "miner" => Color.FromRgb(0xF5, 0xA5, 0x24),
        "pua" => Color.FromRgb(0x8B, 0x5C, 0xF6),
        "test" => Color.FromRgb(0x30, 0xA4, 0x6C),
        _ => Color.FromRgb(0x6B, 0x76, 0x86)
    };
}
