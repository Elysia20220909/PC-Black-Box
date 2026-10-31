using System.IO;
using System.Security;
using System.Security.Cryptography;

namespace DestinyBlackBox;

internal static partial class ProductSelfTest
{
    private static string ReportWriteFixtureSnapshot(string directory)
    {
        var entries = new List<string> { $"root:{Directory.GetLastWriteTimeUtc(directory).Ticks}" };
        foreach (string path in Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(directory, path);
            entries.Add(Directory.Exists(path)
                ? $"directory:{relative}:{Directory.GetLastWriteTimeUtc(path).Ticks}"
                : $"file:{relative}:{File.GetLastWriteTimeUtc(path).Ticks}:{Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))}");
        }
        return String.Join("\n", entries.OrderBy(entry => entry, StringComparer.Ordinal));
    }

    private static bool RejectsBatchSaveWithoutChanges(
        string directory, string output, IReadOnlyList<string> targets, bool overwrite, bool invalidBoundary = false)
    {
        string before = ReportWriteFixtureSnapshot(directory);
        bool refused = false;
        try { SafeReportWriter.WriteBatch(output, "replacement", targets, ".json", overwrite); }
        catch (IOException) { refused = true; }
        catch (Exception exception) when (invalidBoundary && (exception is SecurityException or ArgumentException))
        {
            refused = true;
        }
        return refused && before == ReportWriteFixtureSnapshot(directory);
    }

    private static bool TestBatchWriterRejectsFileTargets() =>
        WithFixtureDirectory(directory =>
        {
            string target = Path.Combine(directory, "selected.json");
            string other = Path.Combine(directory, "other.txt");
            File.WriteAllText(target, "original target");
            File.WriteAllText(other, "other target");
            string[] variants =
            [
                target, target.ToUpperInvariant(), target.Replace('\\', '/'),
                Path.GetRelativePath(Environment.CurrentDirectory, target)
            ];
            foreach (string variant in variants)
                foreach (bool overwrite in new[] { false, true })
                    if (!RejectsBatchSaveWithoutChanges(directory, target, [other, variant], overwrite)) return false;
            return true;
        });

    private static bool TestBatchWriterRejectsDirectoryTargets() =>
        WithFixtureDirectory(directory =>
        {
            string target = Path.Combine(directory, "selected");
            string nested = Path.Combine(target, "nested");
            Directory.CreateDirectory(nested);
            string other = Path.Combine(directory, "other.txt");
            File.WriteAllText(other, "other target");
            string existing = Path.Combine(nested, "existing.json");
            File.WriteAllText(existing, "original report target");
            string[] outputs = [Path.Combine(target, "new.json"), Path.Combine(nested, "new.json"), existing];
            string[] variants =
            [
                target, target + Path.DirectorySeparatorChar, target.ToUpperInvariant(),
                target.Replace('\\', '/'), Path.GetRelativePath(Environment.CurrentDirectory, target)
            ];
            foreach (string variant in variants)
                foreach (string output in outputs)
                    foreach (bool overwrite in new[] { false, true })
                        if (!RejectsBatchSaveWithoutChanges(directory, output, [other, variant], overwrite)) return false;
            // The output path itself is normalized before comparison as well.
            return RejectsBatchSaveWithoutChanges(directory, Path.Combine(nested, "..", "normalized.json"), [target], true);
        });

    private static bool TestBatchWriterAllowsOutsideTargets() =>
        WithFixtureDirectory(directory =>
        {
            string target = Path.Combine(directory, "selected");
            string sibling = Path.Combine(directory, "selected-sibling");
            Directory.CreateDirectory(target);
            Directory.CreateDirectory(sibling);
            string file = Path.Combine(directory, "file.txt");
            File.WriteAllText(file, "original file");
            string output = Path.Combine(sibling, "report.json");
            string[] targets = [file, target, Path.Combine(directory, "missing-target")];
            SafeReportWriter.WriteBatch(output, "{\"version\":1}", targets, ".json", false);
            if (File.ReadAllText(output) != "{\"version\":1}") return false;
            SafeReportWriter.WriteBatch(output, "{\"version\":2}", targets, ".json", true);
            return File.ReadAllText(output) == "{\"version\":2}" &&
                   File.ReadAllText(file) == "original file" &&
                   !Directory.EnumerateFileSystemEntries(target).Any() &&
                   Directory.GetFiles(sibling).Length == 1;
        });

    private static bool TestBatchWriterProtectsUnknownTargets() =>
        WithFixtureDirectory(directory =>
        {
            string missing = Path.Combine(directory, "missing.json");
            if (!RejectsBatchSaveWithoutChanges(directory, missing, [missing], false)) return false;
            var failed = new ScanResult { TargetPath = Path.Combine(directory, "failed-folder"), IsPartial = true };
            Directory.CreateDirectory(failed.TargetPath);
            return !failed.TargetWasDirectory && RejectsBatchSaveWithoutChanges(
                directory, Path.Combine(failed.TargetPath, "report.json"), [failed.TargetPath], true);
        });

    private static bool TestReportContainmentPathBoundaries()
    {
        string root = Path.GetPathRoot(Path.GetFullPath(Path.GetTempPath()))!;
        string target = Path.Combine(root, "InspectionBoundary", "selected");
        string child = Path.Combine(target, "child", "report.json");
        return SecurityPolicy.IsSameOrDescendant(child, root) &&
               SecurityPolicy.IsSameOrDescendant(root, root) &&
               SecurityPolicy.IsSameOrDescendant(child, target + Path.DirectorySeparatorChar) &&
               SecurityPolicy.IsSameOrDescendant(child.ToUpperInvariant(), target.ToLowerInvariant()) &&
               SecurityPolicy.IsSameOrDescendant(child.Replace('\\', '/'), target) &&
               SecurityPolicy.IsSameOrDescendant(Path.Combine(target, "child", "..", "report.json"), target) &&
               SecurityPolicy.IsSameOrDescendant(Path.Combine("fixtures", "selected", "child", "..", "report.json"), Path.Combine("fixtures", "selected")) &&
               !SecurityPolicy.IsSameOrDescendant(Path.Combine(root, "InspectionBoundary", "selected-sibling", "report.json"), target) &&
               !SecurityPolicy.IsSameOrDescendant(Path.Combine(root, "InspectionBoundary", "parent.json"), target);
    }

    private static bool TestBatchWriterRejectsUnverifiableTargets() =>
        WithFixtureDirectory(directory =>
        {
            string target = Path.Combine(directory, "selected");
            Directory.CreateDirectory(target);
            string output = Path.Combine(directory, "outside.json");
            IReadOnlyList<string>[] invalid =
            [
                [], null!, [String.Empty], ["invalid\0target"], [@"\\server\share\target"],
                [@"\\?\C:\target"], [target + "."], [target + " "]
            ];
            foreach (IReadOnlyList<string> targets in invalid)
                if (!RejectsBatchSaveWithoutChanges(directory, output, targets, false, invalidBoundary: true)) return false;

            string locked = Path.Combine(directory, "locked.txt");
            File.WriteAllText(locked, "locked target");
            string before = ReportWriteFixtureSnapshot(directory);
            bool refused = false;
            using (var guard = new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                try { SafeReportWriter.WriteBatch(output, "replacement", [locked], ".json", false); }
                catch (IOException) { refused = true; }
            }
            return refused && before == ReportWriteFixtureSnapshot(directory);
        });
}
