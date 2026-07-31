using System.IO;
using System.Text.Json;

namespace DestinyBlackBox;

public static class SettingsStore
{
    private static readonly string SettingsDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PCBlackBox");
    private static readonly string SettingsPath = Path.Combine(SettingsDirectory, "settings.json");

    public static string LoadLanguage()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return "ja";
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(SettingsPath));
            return document.RootElement.TryGetProperty("language", out JsonElement value) && value.GetString() == "en" ? "en" : "ja";
        }
        catch
        {
            return "ja";
        }
    }

    public static void SaveLanguage(string language)
    {
        try
        {
            Directory.CreateDirectory(SettingsDirectory);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(new { language }, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }
}
