using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Feather.Gui;

/// <summary>
/// Thin, honest wrapper over the feather CLI. The GUI does not reimplement any
/// detection; it parses the scanner's JSON contract and shells out for actions.
/// </summary>
public sealed class Scanner
{
    private string _exe = "";
    private string? _ioc;
    private string? _allow;

    public bool Ready => !string.IsNullOrWhiteSpace(_exe) && File.Exists(_exe);

    public static string SystemConfigDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Feather");

    /// <summary>
    /// Last few lines the scanner printed ("scanned 399 files in 0.55s"). The
    /// JSON array only carries flagged files, so totals come from here.
    /// </summary>
    public string LastSummary { get; private set; } = "";

    public static string? FindExecutable()
    {
        var candidates = new List<string>();
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir != null; i++, dir = dir.Parent)
        {
            // Installed layout: {app}\Feather.exe + {app}\bin\feather.exe.
            candidates.Add(Path.Combine(dir.FullName, "bin", "feather.exe"));
            // Development layout: gui\bin\...\Feather.exe + repo\build\Release\feather.exe.
            candidates.Add(Path.Combine(dir.FullName, "build", "Release", "feather.exe"));
            candidates.Add(Path.Combine(dir.FullName, "build", "Debug", "feather.exe"));
            candidates.Add(Path.Combine(dir.FullName, "feather.exe"));
        }

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate)) return candidate;
        }

        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var entry in path.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(entry.Trim(), "feather.exe");
                if (File.Exists(candidate)) return candidate;
            }
            catch
            {
                // Ignore malformed PATH entries.
            }
        }
        return null;
    }

    public void Configure(string exe, string? ioc, string? allow)
    {
        _exe = exe;
        _ioc = ioc;
        _allow = allow;
    }

    public async Task<List<Finding>> ScanAsync(string folder, IProgress<string>? progress,
                                               CancellationToken cancellationToken = default)
    {
        progress?.Report("Scanning " + folder + " ...");

        var jsonPath = Path.Combine(Path.GetTempPath(), $"feather-{Guid.NewGuid():N}.json");
        var args = new List<string> { "scan", folder, "--json", jsonPath, "--quiet" };
        if (!string.IsNullOrEmpty(_ioc)) { args.Add("--ioc"); args.Add(_ioc); }
        if (!string.IsNullOrEmpty(_allow)) { args.Add("--allow"); args.Add(_allow); }

        try
        {
            var (exit, stdout, stderr) = await RunAsync(args, cancellationToken);
            if (exit == 1)
            {
                throw new InvalidOperationException(
                    string.IsNullOrWhiteSpace(stderr) ? "scanner failed" : stderr.Trim());
            }

            LastSummary = Summarize(stdout);

            if (!File.Exists(jsonPath)) return new List<Finding>();

            var json = await File.ReadAllTextAsync(jsonPath, cancellationToken);
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            return JsonSerializer.Deserialize<List<Finding>>(json, options) ?? new List<Finding>();
        }
        finally
        {
            try { File.Delete(jsonPath); } catch { }
        }
    }

    public async Task<(bool Ok, string Message)> QuarantineAsync(
        string file, string categoryId, CancellationToken cancellationToken = default)
    {
        var args = new List<string>
        {
            "quarantine", file, "--category", categoryId,
            "--reason", "quarantined from Feather GUI"
        };
        var (exit, _, stderr) = await RunAsync(args, cancellationToken);
        return (exit == 0, exit == 0 ? "" : stderr.Trim());
    }

    public async Task<List<QuarantineItem>> QuarantineListAsync(
        string? quarantineDir = null, CancellationToken cancellationToken = default)
    {
        var jsonPath = Path.Combine(Path.GetTempPath(), $"feather-q-{Guid.NewGuid():N}.json");
        try
        {
            var args = new List<string> { "quarantine-list", "--json", jsonPath };
            if (!string.IsNullOrEmpty(quarantineDir))
            {
                args.Add("--quarantine-dir");
                args.Add(quarantineDir);
            }
            var (exit, _, stderr) = await RunAsync(args, cancellationToken);
            if (exit != 0)
            {
                throw new InvalidOperationException(
                    string.IsNullOrWhiteSpace(stderr) ? "quarantine-list failed" : stderr.Trim());
            }
            if (!File.Exists(jsonPath)) return new List<QuarantineItem>();
            var json = await File.ReadAllTextAsync(jsonPath, cancellationToken);
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var items = JsonSerializer.Deserialize<List<QuarantineItem>>(json, options)
                        ?? new List<QuarantineItem>();
            foreach (var item in items) item.Root = quarantineDir ?? "";
            return items;
        }
        finally
        {
            try { File.Delete(jsonPath); } catch { }
        }
    }

    public async Task<(bool Ok, string Message)> RestoreAsync(
        string sha256, string? quarantineDir = null,
        CancellationToken cancellationToken = default)
    {
        var args = new List<string> { "restore", sha256 };
        if (!string.IsNullOrEmpty(quarantineDir))
        {
            args.Add("--quarantine-dir");
            args.Add(quarantineDir);
        }
        var (exit, _, stderr) = await RunAsync(args, cancellationToken);
        return (exit == 0, exit == 0 ? "" : stderr.Trim());
    }

    public async Task<RealtimeStatus?> RealtimeStatusAsync(
        CancellationToken cancellationToken = default)
    {
        var file = Path.Combine(SystemConfigDir, "realtime-status.json");
        if (!File.Exists(file)) return null;
        try
        {
            var json = await File.ReadAllTextAsync(file, cancellationToken);
            return JsonSerializer.Deserialize<RealtimeStatus>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch { return null; }
    }

    public async Task<List<RealtimeEvent>> RealtimeEventsAsync(
        CancellationToken cancellationToken = default)
    {
        var file = Path.Combine(SystemConfigDir, "realtime-events.jsonl");
        var events = new List<RealtimeEvent>();
        if (!File.Exists(file)) return events;
        try
        {
            var lines = await File.ReadAllLinesAsync(file, cancellationToken);
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var item = JsonSerializer.Deserialize<RealtimeEvent>(line, options);
                    if (item != null) events.Add(item);
                }
                catch { /* keep reading; one malformed line is not fatal */ }
            }
        }
        catch { }
        events.Reverse();
        return events;
    }

    public async Task<(bool Ok, string Message)> WipeAsync(
        string file, CancellationToken cancellationToken = default)
    {
        var args = new List<string>
        {
            "wipe", file, "--reason", "wiped from Feather GUI: malicious verdict"
        };
        var (exit, _, stderr) = await RunAsync(args, cancellationToken);
        return (exit == 0, exit == 0 ? "" : stderr.Trim());
    }

    public void AddAllow(string sha256, string note)
    {
        if (string.IsNullOrEmpty(_allow))
        {
            throw new InvalidOperationException("no allow list is configured");
        }
        Directory.CreateDirectory(Path.GetDirectoryName(_allow)!);
        File.AppendAllText(_allow, $"sha256 {sha256}  {note}{Environment.NewLine}");
    }

    private static string Summarize(string stdout)
    {
        var lines = stdout.Split('\n',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var scanned = lines.FirstOrDefault(l => l.StartsWith("scanned "));
        var counts = lines.FirstOrDefault(l => l.StartsWith("malicious "));
        if (scanned != null && counts != null) return scanned + ", " + counts;
        return scanned ?? counts ?? "";
    }

    private async Task<(int Exit, string StdOut, string StdErr)> RunAsync(
        IEnumerable<string> args, CancellationToken cancellationToken)
    {
        if (!Ready)
        {
            throw new InvalidOperationException(
                "feather.exe was not found. Set its path in the toolbar.");
        }

        var startInfo = new ProcessStartInfo(_exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var arg in args) startInfo.ArgumentList.Add(arg);

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        return (process.ExitCode, await stdout, await stderr);
    }
}
