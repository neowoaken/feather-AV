using System.Diagnostics;

namespace Feather.Gui;

/// <summary>
/// The window. It owns no detection logic: it runs the CLI, shows what came
/// back, and lets you decide per file. Checked rows are only *preselected*
/// according to your category policy - nothing is removed until you press the
/// quarantine button.
/// </summary>
public sealed class MainForm : Form
{
    private readonly Scanner _scanner = new();
    private Policy _policy = Policy.CreateDefault();

    private readonly string _configDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Feather");
    private readonly string _policyPath;
    private readonly string _allowPath;

    private readonly TextBox _pathBox = new();
    private readonly Button _browseButton = new();
    private readonly Button _scanButton = new();
    private readonly Button _quarantineButton = new();
    private readonly Button _allowButton = new();
    private readonly ListView _list = new();
    private readonly TextBox _details = new();
    private readonly DataGridView _policyGrid = new();
    private readonly ToolStripStatusLabel _statusLabel = new();
    private readonly ToolStripStatusLabel _engineLabel = new();
    private readonly ToolStripProgressBar _progress = new();

    private List<Finding> _findings = new();

    public MainForm()
    {
        _policyPath = Path.Combine(_configDir, "policy.json");
        _allowPath = Path.Combine(_configDir, "allow.txt");

        BuildUi();
        LoadPolicy();
        LoadScanner();
    }

    // ---------------------------------------------------------------- layout

    private void BuildUi()
    {
        Text = "feather";
        MinimumSize = new Size(980, 620);
        Size = new Size(1200, 740);
        StartPosition = FormStartPosition.CenterScreen;
        AllowDrop = true;

        var menu = BuildMenu();

        var toolbar = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 6,
            Padding = new Padding(8, 6, 8, 6)
        };
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 4; ++i)
        {
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        }

        var folderLabel = new Label
        {
            Text = "Folder",
            AutoSize = true,
            Anchor = AnchorStyles.Left,
            Margin = new Padding(0, 8, 8, 0)
        };

        _pathBox.Dock = DockStyle.Fill;
        _pathBox.Margin = new Padding(0, 4, 8, 4);
        _pathBox.PlaceholderText = @"C:\Games, C:\Downloads, ...";

        ConfigureButton(_browseButton, "Browse...");
        ConfigureButton(_scanButton, "Scan");
        ConfigureButton(_quarantineButton, "Quarantine checked");
        ConfigureButton(_allowButton, "Allow checked");

        _scanButton.Font = new Font(_scanButton.Font, FontStyle.Bold);

        _browseButton.Click += OnBrowse;
        _scanButton.Click += OnScan;
        _quarantineButton.Click += OnQuarantineChecked;
        _allowButton.Click += OnAllowChecked;
        _pathBox.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                OnScan(this, EventArgs.Empty);
            }
        };

        toolbar.Controls.Add(folderLabel, 0, 0);
        toolbar.Controls.Add(_pathBox, 1, 0);
        toolbar.Controls.Add(_browseButton, 2, 0);
        toolbar.Controls.Add(_scanButton, 3, 0);
        toolbar.Controls.Add(_quarantineButton, 4, 0);
        toolbar.Controls.Add(_allowButton, 5, 0);

        var content = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            Padding = new Padding(8, 0, 8, 0)
        };
        content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 63));
        content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 37));
        content.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        _list.Dock = DockStyle.Fill;
        _list.View = View.Details;
        _list.CheckBoxes = true;
        _list.FullRowSelect = true;
        _list.HideSelection = false;
        _list.MultiSelect = true;
        _list.ShowItemToolTips = true;
        _list.GridLines = false;
        _list.Columns.Add("File", 260);
        _list.Columns.Add("Verdict", 90);
        _list.Columns.Add("Category", 110);
        _list.Columns.Add("Why", 420);
        _list.SelectedIndexChanged += OnSelectionChanged;
        _list.ItemChecked += OnItemChecked;

        var tabs = new TabControl { Dock = DockStyle.Fill, Margin = new Padding(8, 0, 0, 0) };

        var detailsPage = new TabPage("Details");
        _details.Dock = DockStyle.Fill;
        _details.Multiline = true;
        _details.ReadOnly = true;
        _details.ScrollBars = ScrollBars.Both;
        _details.WordWrap = false;
        _details.Font = new Font("Consolas", 9.5f);
        _details.BackColor = SystemColors.Window;
        _details.BorderStyle = BorderStyle.None;
        detailsPage.Controls.Add(_details);

        var policyPage = new TabPage("Categories");
        var policyLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(8)
        };
        policyLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        policyLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        policyLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var policyHelp = new Label
        {
            AutoSize = true,
            Dock = DockStyle.Fill,
            MaximumSize = new Size(420, 0),
            Text = "Categories come from whatever produced the signal (built-in rules, " +
                   "IOC hashes, ClamAV signature names). \"Auto-select\" only ticks the " +
                   "checkbox on new results. Nothing is quarantined until you press the " +
                   "button, and nothing is ever deleted silently."
        };

        _policyGrid.Dock = DockStyle.Fill;
        _policyGrid.AllowUserToAddRows = false;
        _policyGrid.AllowUserToDeleteRows = false;
        _policyGrid.AllowUserToResizeRows = false;
        _policyGrid.RowHeadersVisible = false;
        _policyGrid.BackgroundColor = SystemColors.Window;
        _policyGrid.BorderStyle = BorderStyle.FixedSingle;
        _policyGrid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        _policyGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _policyGrid.MultiSelect = false;
        _policyGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "Category",
            HeaderText = "Category",
            ReadOnly = true,
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill
        });
        _policyGrid.Columns.Add(new DataGridViewCheckBoxColumn
        {
            Name = "Swipe",
            HeaderText = "Auto-select",
            Width = 110
        });

        var policyFooter = new Label
        {
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Text = "Saved to " + _policyPath
        };

        policyLayout.Controls.Add(policyHelp, 0, 0);
        policyLayout.Controls.Add(_policyGrid, 0, 1);
        policyLayout.Controls.Add(policyFooter, 0, 2);
        policyPage.Controls.Add(policyLayout);

        tabs.TabPages.Add(detailsPage);
        tabs.TabPages.Add(policyPage);

        content.Controls.Add(_list, 0, 0);
        content.Controls.Add(tabs, 1, 0);

        var status = new StatusStrip();
        _statusLabel.Text = "Ready.";
        _statusLabel.Spring = true;
        _statusLabel.TextAlign = ContentAlignment.MiddleLeft;
        _engineLabel.Text = "engine: not found";
        _progress.Visible = false;
        _progress.Style = ProgressBarStyle.Marquee;
        _progress.MarqueeAnimationSpeed = 30;
        status.Items.Add(_statusLabel);
        status.Items.Add(_progress);
        status.Items.Add(_engineLabel);

        Controls.Add(content);
        Controls.Add(toolbar);
        Controls.Add(status);
        Controls.Add(menu);

        DragEnter += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true)
            {
                e.Effect = DragDropEffects.Copy;
            }
        };
        DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths)
            {
                _pathBox.Text = Directory.Exists(paths[0])
                    ? paths[0]
                    : Path.GetDirectoryName(paths[0]) ?? paths[0];
                OnScan(this, EventArgs.Empty);
            }
        };
    }

    private MenuStrip BuildMenu()
    {
        var menu = new MenuStrip();

        var file = new ToolStripMenuItem("&File");
        var scan = new ToolStripMenuItem("&Scan folder...", null, OnScan)
        {
            ShortcutKeys = Keys.Control | Keys.O
        };
        var locate = new ToolStripMenuItem("Locate feather.exe...", null, OnLocateExe);
        var openConfig = new ToolStripMenuItem("Open config folder", null, (_, _) =>
        {
            Directory.CreateDirectory(_configDir);
            Process.Start(new ProcessStartInfo(_configDir) { UseShellExecute = true });
        });
        var exit = new ToolStripMenuItem("E&xit", null, (_, _) => Close());
        file.DropDownItems.AddRange(new ToolStripItem[]
        {
            scan, locate, openConfig, new ToolStripSeparator(), exit
        });

        var help = new ToolStripMenuItem("&Help");
        help.DropDownItems.Add(new ToolStripMenuItem("&About", null, (_, _) =>
            MessageBox.Show(this,
                "feather " + Environment.NewLine + Environment.NewLine +
                "Classifies instead of condemning. Findings are suggestions; " +
                "quarantine only happens when you ask for it." + Environment.NewLine +
                Environment.NewLine +
                "Engine: " + (_scanner.Ready ? "found" : "not located") +
                Environment.NewLine + "Config: " + _configDir,
                "About feather", MessageBoxButtons.OK, MessageBoxIcon.Information)));

        menu.Items.Add(file);
        menu.Items.Add(help);
        return menu;
    }

    private static void ConfigureButton(Button button, string text)
    {
        button.Text = text;
        button.AutoSize = true;
        button.Margin = new Padding(0, 3, 8, 3);
        button.Padding = new Padding(6, 2, 6, 2);
    }

    // ------------------------------------------------------------ start-up

    private void LoadPolicy()
    {
        Directory.CreateDirectory(_configDir);
        _policy = Policy.Load(_policyPath);

        _policyGrid.Rows.Clear();
        foreach (var (id, label) in Policy.KnownCategories)
        {
            var index = _policyGrid.Rows.Add();
            var row = _policyGrid.Rows[index];
            row.Cells["Category"].Value = label;
            row.Cells["Swipe"].Value = _policy.ActionFor(id) == CategoryAction.Swipe;
            row.Tag = id;
        }
        _policyGrid.CellValueChanged += OnPolicyChanged;
        _policyGrid.CurrentCellDirtyStateChanged += (_, _) =>
        {
            if (_policyGrid.IsCurrentCellDirty)
            {
                _policyGrid.CommitEdit(DataGridViewDataErrorContexts.Commit);
            }
        };
    }

    private void LoadScanner()
    {
        var exe = Scanner.FindExecutable();
        if (string.IsNullOrEmpty(exe))
        {
            _engineLabel.Text = "engine: not found";
            _statusLabel.Text = "Point File > Locate feather.exe at the scanner binary.";
            SetBusy(false);
            return;
        }

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
            // An unwritable allow list must not stop a scan; it only disables
            // the allow button at the end.
        }

        _scanner.Configure(exe, ioc: null, allow: _allowPath);
        _engineLabel.Text = "engine: " + Path.GetFileName(Path.GetDirectoryName(exe)) +
                            "\\" + Path.GetFileName(exe);
        _statusLabel.Text = "Ready. Pick a folder and press Scan.";
        SetBusy(false);
    }

    // ---------------------------------------------------------------- events

    private void OnBrowse(object? sender, EventArgs e)
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Choose a folder to scan",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = false
        };

        if (Directory.Exists(_pathBox.Text))
        {
            dialog.SelectedPath = _pathBox.Text;
        }

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            _pathBox.Text = dialog.SelectedPath;
        }
    }

    private async void OnScan(object? sender, EventArgs e)
    {
        var folder = _pathBox.Text.Trim();
        if (!Directory.Exists(folder))
        {
            MessageBox.Show(this, "Pick an existing folder first.", "feather",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        SetBusy(true);
        _list.Items.Clear();
        _details.Clear();
        _findings = new List<Finding>();
        _statusLabel.Text = "Scanning " + folder + " ...";

        try
        {
            var all = await _scanner.ScanAsync(folder,
                new Progress<string>(message => _statusLabel.Text = message));

            _findings = all
                .Where(f => f.Verdict is "unwanted" or "malicious")
                .OrderByDescending(f => f.Verdict == "malicious")
                .ThenBy(f => f.CategoryLabel, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
                .ToList();

            Populate(all);
        }
        catch (Exception ex)
        {
            _statusLabel.Text = "Scan failed.";
            MessageBox.Show(this, ex.Message, "Scan failed",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void Populate(List<Finding> all)
    {
        var errors = all.Count(f => !string.IsNullOrEmpty(f.Error));
        var preselected = 0;

        _list.BeginUpdate();
        foreach (var finding in _findings)
        {
            var item = new ListViewItem(Path.GetFileName(finding.Path))
            {
                Tag = finding,
                ToolTipText = finding.Path
            };
            item.SubItems.Add(finding.Verdict);
            item.SubItems.Add(finding.CategoryLabel);
            item.SubItems.Add(finding.Reason);

            if (finding.Verdict == "malicious")
            {
                item.ForeColor = Color.FromArgb(155, 30, 30);
            }
            else
            {
                item.ForeColor = Color.FromArgb(140, 84, 0);
            }

            if (_policy.ActionFor(finding.Category) == CategoryAction.Swipe)
            {
                item.Checked = true;
                ++preselected;
            }

            _list.Items.Add(item);
        }
        _list.EndUpdate();

        var summary = $"{_findings.Count} flagged " +
                      $"({_findings.Count(f => f.Verdict == "malicious")} malicious, " +
                      $"{_findings.Count(f => f.Verdict == "unwanted")} unwanted), " +
                      $"{preselected} preselected";

        if (errors > 0)
        {
            summary += $", {errors} unreadable";
        }

        if (!string.IsNullOrEmpty(_scanner.LastSummary))
        {
            summary += "  |  " + _scanner.LastSummary;
        }

        _statusLabel.Text = summary + ".";
    }

    private void OnSelectionChanged(object? sender, EventArgs e)
    {
        if (_list.SelectedItems.Count == 0)
        {
            _details.Clear();
            return;
        }

        if (_list.SelectedItems[0].Tag is Finding finding)
        {
            ShowDetails(finding);
        }
    }

    private void ShowDetails(Finding finding)
    {
        var text = new System.Text.StringBuilder();
        text.AppendLine("Path      " + finding.Path);
        text.AppendLine("Verdict   " + finding.Verdict + " (" + finding.CategoryLabel + ")");
        text.AppendLine("Size      " + FormatSize(finding.Size));
        text.AppendLine("SHA-256   " + finding.Sha256);
        text.AppendLine("Cached    " + (finding.Cached ? "yes" : "no"));
        text.AppendLine();

        if (!string.IsNullOrEmpty(finding.Error))
        {
            text.AppendLine("Error");
            text.AppendLine("  " + finding.Error);
            text.AppendLine();
        }

        if (finding.Warnings.Count > 0)
        {
            text.AppendLine("Warnings");
            foreach (var warning in finding.Warnings)
            {
                text.AppendLine("  " + warning);
            }
            text.AppendLine();
        }

        text.AppendLine("Signals");
        foreach (var hit in finding.Hits)
        {
            text.AppendLine($"  [{hit.Source}] {hit.Id}  ({hit.Severity}, {hit.Category})");
            text.AppendLine("    " + hit.Detail);
        }

        _details.Text = text.ToString();
    }

    private void OnItemChecked(object? sender, ItemCheckedEventArgs e)
    {
        // Selection is the user's, so do not fight it. This only refreshes the
        // count shown in the status bar.
        if (_list.Items.Count == 0) return;
        var count = _list.CheckedItems.Count;
        _statusLabel.Text = $"{count} of {_list.Items.Count} flagged files selected for quarantine.";
    }

    private void OnPolicyChanged(object? sender, DataGridViewCellEventArgs e)
    {
        if (e.RowIndex < 0 || e.ColumnIndex != _policyGrid.Columns["Swipe"]!.Index)
        {
            return;
        }

        var row = _policyGrid.Rows[e.RowIndex];
        if (row.Tag is not string id) return;

        var swipe = row.Cells["Swipe"].Value is true;
        _policy.Set(id, swipe ? CategoryAction.Swipe : CategoryAction.Warn);

        try
        {
            _policy.Save(_policyPath);
        }
        catch
        {
            // Saving a preference is never worth interrupting the user.
        }
    }

    private async void OnQuarantineChecked(object? sender, EventArgs e)
    {
        var items = _list.CheckedItems.Cast<ListViewItem>()
            .Where(i => i.Tag is Finding)
            .ToList();

        if (items.Count == 0)
        {
            MessageBox.Show(this, "Tick the files you want to quarantine first.",
                "Nothing selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var confirm = MessageBox.Show(this,
            $"Copy {items.Count} file(s) into quarantine and remove the originals?\n\n" +
            "Each file is re-hashed before the original is touched, and it can be " +
            "restored with: feather restore <sha256>",
            "Quarantine", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);

        if (confirm != DialogResult.Yes) return;

        SetBusy(true);
        var removed = 0;
        var failures = new List<string>();

        foreach (var item in items)
        {
            var finding = (Finding)item.Tag!;
            var (ok, message) = await _scanner.QuarantineAsync(finding.Path, finding.Category);
            if (ok)
            {
                ++removed;
                _list.Items.Remove(item);
            }
            else
            {
                failures.Add(Path.GetFileName(finding.Path) + ": " + message);
            }
        }

        SetBusy(false);
        _statusLabel.Text = $"Quarantined {removed} file(s).";

        if (failures.Count > 0)
        {
            MessageBox.Show(this,
                "Some files were left alone:" + Environment.NewLine + Environment.NewLine +
                string.Join(Environment.NewLine, failures.Take(10)),
                "Quarantine incomplete", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void OnAllowChecked(object? sender, EventArgs e)
    {
        var items = _list.CheckedItems.Cast<ListViewItem>()
            .Where(i => i.Tag is Finding)
            .ToList();

        if (items.Count == 0)
        {
            MessageBox.Show(this, "Tick the files you want to allow first.",
                "Nothing selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        try
        {
            foreach (var item in items)
            {
                var finding = (Finding)item.Tag!;
                _scanner.AddAllow(finding.Sha256, "allowed from GUI: " + finding.Category);
                _list.Items.Remove(item);
            }
            _statusLabel.Text = $"Allowed {items.Count} file(s) by hash. Future scans will not flag them.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Could not write the allow list",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void OnLocateExe(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Locate feather.exe",
            Filter = "feather scanner (feather.exe)|feather.exe|Executables (*.exe)|*.exe"
        };

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            EnsureAllowFile();
            _scanner.Configure(dialog.FileName, ioc: null, allow: _allowPath);
            _engineLabel.Text = "engine: " + dialog.FileName;
            _statusLabel.Text = "Engine located. Pick a folder and press Scan.";
            SetBusy(false);
        }
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
            // An unwritable allow list only disables the allow button later.
        }
    }

    private void SetBusy(bool busy)
    {
        _scanButton.Enabled = !busy && _scanner.Ready;
        _browseButton.Enabled = !busy;
        _quarantineButton.Enabled = !busy;
        _allowButton.Enabled = !busy;
        _progress.Visible = busy;
        UseWaitCursor = busy;
        if (!busy)
        {
            _scanButton.Enabled = _scanner.Ready;
        }
    }

    private static string FormatSize(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            ++unit;
        }
        return value.ToString(unit == 0 ? "0" : "0.0") + " " + units[unit];
    }
}
