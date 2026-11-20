using System.Text.Json;

namespace Feather.Gui;

public enum CategoryAction
{
    // Show it, do not preselect anything. You decide per file.
    Warn,

    // Preselect for quarantine. This is the "swipe" default.
    Swipe
}

/// <summary>
/// Per-category default action. Categories are the reason this GUI exists:
/// "HackTool" and "Adware" are both unwanted, but they deserve different
/// defaults, and only you can decide which is which.
/// </summary>
public sealed class Policy
{
    private static readonly (string Id, string Label, CategoryAction Action)[] Defaults =
    {
        ("hacktool",   "HackTool",   CategoryAction.Warn),
        ("adware",     "Adware",     CategoryAction.Swipe),
        ("pua",        "PUA",        CategoryAction.Warn),
        ("packer",     "Packer",     CategoryAction.Warn),
        ("injector",   "Injector",   CategoryAction.Warn),
        ("dropper",    "Dropper",    CategoryAction.Swipe),
        ("spyware",    "Spyware",    CategoryAction.Swipe),
        ("stealer",    "Stealer",    CategoryAction.Swipe),
        ("miner",      "Miner",      CategoryAction.Swipe),
        ("ransomware", "Ransomware", CategoryAction.Swipe),
        ("trojan",     "Trojan",     CategoryAction.Swipe),
        ("worm",       "Worm",       CategoryAction.Swipe),
        ("virus",      "Virus",      CategoryAction.Swipe),
        ("test",       "Test",       CategoryAction.Warn),
        ("suspicious", "Suspicious", CategoryAction.Warn),
        ("malware",    "Malware",    CategoryAction.Swipe),
        ("unknown",    "Unknown",    CategoryAction.Warn)
    };

    private readonly Dictionary<string, CategoryAction> _actions =
        new(StringComparer.OrdinalIgnoreCase);

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Feather", "policy.json");

    public static Policy CreateDefault()
    {
        var policy = new Policy();
        foreach (var (id, _, action) in Defaults)
        {
            policy._actions[id] = action;
        }
        return policy;
    }

    public static IEnumerable<(string Id, string Label)> KnownCategories =>
        Defaults.Select(d => (d.Id, d.Label));

    public CategoryAction ActionFor(string categoryId) =>
        _actions.TryGetValue(categoryId, out var action) ? action : CategoryAction.Warn;

    public void Set(string categoryId, CategoryAction action) =>
        _actions[categoryId] = action;

    public static Policy Load(string path)
    {
        var policy = CreateDefault();
        try
        {
            if (!File.Exists(path)) return policy;

            var map = JsonSerializer.Deserialize<Dictionary<string, string>>(
                File.ReadAllText(path)) ?? new();
            foreach (var (key, value) in map)
            {
                if (Enum.TryParse<CategoryAction>(value, ignoreCase: true, out var action))
                {
                    policy._actions[key] = action;
                }
            }
        }
        catch
        {
            // A broken policy file must never block the app: fall back to defaults.
        }
        return policy;
    }

    public void Save(string path)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        var map = _actions.ToDictionary(kv => kv.Key, kv => kv.Value.ToString());
        File.WriteAllText(path, JsonSerializer.Serialize(map,
            new JsonSerializerOptions { WriteIndented = true }));
    }
}
