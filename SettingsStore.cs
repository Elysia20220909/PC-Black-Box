using System.IO;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace DestinyBlackBox;

public static class SettingsStore
{
    private static readonly string SettingsDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PCBlackBox");
    private static readonly string SettingsPath = Path.Combine(SettingsDirectory, "settings.json");

    public static string LoadLanguage()
    {
        try
        {
            string settingsDirectory = SecurityPolicy.ValidateLocalDirectory(SettingsDirectory, mustExist: false);
            if (!Directory.Exists(settingsDirectory)) return "ja";
            SecurityPolicy.ValidateLocalDirectory(settingsDirectory, mustExist: true);
            if (!File.Exists(SettingsPath)) return "ja";
            var info = new FileInfo(SettingsPath);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.Length > 4096) return "ja";
            using FileStream stream = SecureFileReader.OpenRead(SettingsPath, 4096);
            using JsonDocument document = JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 4 });
            return document.RootElement.TryGetProperty("language", out JsonElement value) && value.GetString() == "en" ? "en" : "ja";
        }
        catch
        {
            return "ja";
        }
    }

    public static void SaveLanguage(string language)
    {
        string? temporaryPath = null;
        try
        {
            language = language == "en" ? "en" : "ja";
            string settingsDirectory = SecurityPolicy.ValidateLocalDirectory(SettingsDirectory, mustExist: false);
            Directory.CreateDirectory(settingsDirectory);
            SecurityPolicy.ValidateLocalDirectory(settingsDirectory, mustExist: true);
            using SafeFileHandle settingsGuard = SecureFileReader.OpenDirectoryGuard(settingsDirectory);
            if (File.Exists(SettingsPath) && (File.GetAttributes(SettingsPath) & FileAttributes.ReparsePoint) != 0) return;

            temporaryPath = Path.Combine(settingsDirectory, $"settings-{Guid.NewGuid():N}.tmp");
            byte[] data = JsonSerializer.SerializeToUtf8Bytes(new { language }, new JsonSerializerOptions { WriteIndented = true });
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(data);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, SettingsPath, overwrite: true);
            temporaryPath = null;
        }
        catch { }
        finally
        {
            if (temporaryPath is not null)
            {
                try { File.Delete(temporaryPath); } catch { }
            }
        }
    }
}
