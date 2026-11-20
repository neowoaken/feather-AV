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
