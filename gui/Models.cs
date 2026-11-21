using System.IO;

namespace Feather.Gui;

public sealed class Hit
{
    public string Source { get; set; } = "";
    public string Id { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Category { get; set; } = "unknown";
    public int Weight { get; set; }
    public string Detail { get; set; } = "";
}

public sealed class Finding
{
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public string Sha256 { get; set; } = "";
    public string Verdict { get; set; } = "";
    public string Category { get; set; } = "unknown";
    public string CategoryLabel { get; set; } = "Unknown";
    public bool Suppressed { get; set; }
    public bool Cached { get; set; }
    public string? Error { get; set; }
    public List<string> Warnings { get; set; } = new();
    public List<Hit> Hits { get; set; } = new();

    public string FileName => System.IO.Path.GetFileName(Path);

    public string Reason =>
        Hits.Count > 0 ? Hits[0].Detail : (Error ?? Warnings.FirstOrDefault() ?? "");

    public bool IsMalicious => Verdict == "malicious";
}

public sealed class QuarantineItem
{
    public string Timestamp { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string Category { get; set; } = "";
    public long Size { get; set; }
    public string OriginalPath { get; set; } = "";

    // Absolute quarantine root this item came from. The CLI needs it for
    // restore; it is set by the GUI after deserialising the manifest.
    public string Root { get; set; } = "";

    public string SizeText => FormatSize(Size);

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

// Written by feathersvc to %PROGRAMDATA%\Feather\realtime-status.json.
public sealed class RealtimeStatus
{
    public int Version { get; set; }
    public string Service { get; set; } = "";
    public string ProductVersion { get; set; } = "";
    public string Filter { get; set; } = "";
    public string Clamav { get; set; } = "";
    public string Endpoint { get; set; } = "";
    public string Rules { get; set; } = "";
    public int IocCount { get; set; }
    public long Scans { get; set; }
    public long Blocks { get; set; }
    public long Quarantines { get; set; }
    public long FailOpen { get; set; }
    public string LastAction { get; set; } = "";
    public string Updated { get; set; } = "";
}

public sealed class RealtimeEvent
{
    public string Timestamp { get; set; } = "";
    public int Pid { get; set; }
    public string Path { get; set; } = "";
    public string Action { get; set; } = "";
    public int Verdict { get; set; }
    public string Severity { get; set; } = "";
    public string Category { get; set; } = "";
    public string Source { get; set; } = "";
    public string Detail { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string Note { get; set; } = "";

    public string FileName => System.IO.Path.GetFileName(Path);
}
