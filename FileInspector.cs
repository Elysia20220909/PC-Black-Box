using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DestinyBlackBox;

public sealed class FileInspector
{
    private const int MaxFiles = 2500;
    private const long MaxTotalBytes = 12L * 1024 * 1024 * 1024;
    private const int MaxArchiveEntries = 10000;
    private const int SampleBytes = 8 * 1024 * 1024;

    private static readonly HashSet<string> ActiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".msp", ".ps1", ".psm1", ".psd1",
        ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".reg"
    };

    private static readonly HashSet<string> SignatureExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".msp", ".ps1", ".psm1", ".psd1", ".cat", ".cab"
    };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".reg"
    };

    private static readonly (string Code, Regex Pattern, int Score, string Ja, string En)[] CapabilityPatterns =
    [
        ("defender-change", new Regex(@"(?i)(Add-MpPreference|Set-MpPreference|DisableRealtimeMonitoring|DisableBehaviorMonitoring|ExclusionPath|ExclusionProcess)"), 40, "Microsoft Defenderの設定変更能力", "Microsoft Defender configuration capability"),
        ("process-injection", new Regex(@"(?i)(WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|QueueUserAPC|NtCreateThreadEx)"), 35, "他プロセスへの注入に関連するAPI", "APIs associated with process injection"),
        ("credential-access", new Regex(@"(?i)(Get-Credential|ConvertTo-SecureString|CredentialManager|mimikatz|lsass|Login Data|Cookies\\b)"), 25, "資格情報アクセスに関連する語句", "Terms associated with credential access"),
        ("persistence", new Regex(@"(?i)(Register-ScheduledTask|New-ScheduledTask|schtasks(?:\.exe)?|New-Service|sc(?:\.exe)?\s+create|CurrentVersion\\Run|Startup\\)"), 22, "永続化に利用できる処理", "Capability that can establish persistence"),
        ("remote-download", new Regex(@"(?i)(Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile|Start-BitsTransfer|System\.Net\.WebClient|curl(?:\.exe)?\s+https?://|wget\s+https?://)"), 18, "外部からファイルやデータを取得する処理", "Capability to download files or data"),
        ("obfuscation", new Regex(@"(?i)(FromBase64String|-EncodedCommand|\bIEX\b|Invoke-Expression|GZipStream|DeflateStream)"), 17, "難読化または動的実行に使われる処理", "Capability associated with obfuscation or dynamic execution"),
        ("shell-launch", new Regex(@"(?i)(Start-Process|ProcessStartInfo|cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-)"), 10, "別プロセスやシェルを起動する処理", "Capability to launch another process or shell"),
        ("destructive-file", new Regex(@"(?i)(Remove-Item|DeleteFile|rmdir\s+/s|del\s+/[fq])"), 9, "ファイル削除能力", "File-deletion capability"),
        ("force-stop", new Regex(@"(?i)(Stop-Process|TerminateProcess|taskkill(?:\.exe)?)"), 6, "プロセスを強制停止する能力", "Capability to terminate processes")
    ];

    public static bool IsActiveContentExtension(string? extension) => extension is not null && ActiveExtensions.Contains(extension);

    public Task<ScanResult> ScanAsync(string targetPath, IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
    {
        return Task.Run(() => ScanCore(targetPath, progress, cancellationToken), cancellationToken);
    }

    private static ScanResult ScanCore(string targetPath, IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
    {
        string fullTarget = Path.GetFullPath(targetPath);
        if (!File.Exists(fullTarget) && !Directory.Exists(fullTarget))
        {
            throw new FileNotFoundException("The selected target no longer exists.", fullTarget);
        }

        var result = new ScanResult
        {
            TargetPath = fullTarget,
            TargetName = File.Exists(fullTarget) ? Path.GetFileName(fullTarget) : new DirectoryInfo(fullTarget).Name,
            StartedAt = DateTime.Now
        };

        Stopwatch stopwatch = Stopwatch.StartNew();
        List<string> files = CollectFiles(fullTarget, result, cancellationToken);
        string root = Directory.Exists(fullTarget) ? fullTarget : Path.GetDirectoryName(fullTarget) ?? fullTarget;

        for (int index = 0; index < files.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string file = files[index];
            progress?.Report(new ScanProgress(index, files.Count, Path.GetFileName(file)));
            FileAnalysis analysis = AnalyzeFile(file, root, File.Exists(fullTarget), cancellationToken);
            result.Files.Add(analysis);
        }

        ApplySignatures(result.Files, cancellationToken);
        foreach (FileAnalysis file in result.Files)
        {
            ApplySignatureRisk(file);
        }

        progress?.Report(new ScanProgress(files.Count, files.Count, String.Empty));
        stopwatch.Stop();
        result.Duration = stopwatch.Elapsed;
        return result;
    }

    private static List<string> CollectFiles(string target, ScanResult result, CancellationToken cancellationToken)
    {
        if (File.Exists(target))
        {
            return [target];
        }

        var files = new List<string>();
        var directories = new Stack<string>();
        directories.Push(target);
        long totalBytes = 0;

        while (directories.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string directory = directories.Pop();
            IEnumerable<FileSystemInfo> entries;
            try
            {
                entries = new DirectoryInfo(directory).EnumerateFileSystemInfos().ToArray();
            }
            catch
            {
                result.IsPartial = true;
                result.PartialReason = "One or more directories could not be read.";
                continue;
            }

            foreach (FileSystemInfo entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    result.IsPartial = true;
                    result.PartialReason = "Reparse points were skipped.";
                    continue;
                }

                if (entry is DirectoryInfo childDirectory)
                {
                    directories.Push(childDirectory.FullName);
                    continue;
                }

                if (entry is not FileInfo file)
                {
                    continue;
                }

                if (files.Count >= MaxFiles || totalBytes + file.Length > MaxTotalBytes)
                {
                    result.IsPartial = true;
                    result.PartialReason = $"Safety limit reached ({MaxFiles} files or {FileAnalysis.FormatSize(MaxTotalBytes)}).";
                    return files;
                }

                files.Add(file.FullName);
                totalBytes += file.Length;
            }
        }

        return files.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static FileAnalysis AnalyzeFile(string path, string root, bool singleFile, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        var analysis = new FileAnalysis
        {
            FullPath = path,
            RelativePath = singleFile ? info.Name : Path.GetRelativePath(root, path),
            Size = info.Length
        };

        DateTime originalWrite = info.LastWriteTimeUtc;
        long originalLength = info.Length;
        byte[] sample = ReadSampleAndHash(path, analysis, cancellationToken);
        analysis.FileType = DetectFileType(sample, Path.GetExtension(path));
        analysis.Entropy = CalculateEntropy(sample);
        ReadVersionAndPeMetadata(path, analysis);
        ReadInternetZone(path, analysis);
        DetectNameAndTypeMismatch(analysis, sample);
        DetectCapabilities(analysis, sample);
        InspectStructuredFormats(path, analysis);

        info.Refresh();
        if (!info.Exists || info.Length != originalLength || info.LastWriteTimeUtc != originalWrite)
        {
            AddIndicator(analysis, new("danger", "changed-during-scan", "調査中にファイルが変更されました", "The file changed while it was being inspected", 35));
        }

        return analysis;
    }

    private static byte[] ReadSampleAndHash(string path, FileAnalysis analysis, CancellationToken cancellationToken)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 1024, FileOptions.SequentialScan);
        using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[1024 * 1024];
        using var sample = new MemoryStream(capacity: (int)Math.Min(SampleBytes, Math.Max(0, stream.Length)));
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            hasher.AppendData(buffer, 0, read);
            if (sample.Length < SampleBytes)
            {
                int toCopy = (int)Math.Min(read, SampleBytes - sample.Length);
                sample.Write(buffer, 0, toCopy);
            }
        }

        analysis.Sha256 = Convert.ToHexString(hasher.GetHashAndReset());
        return sample.ToArray();
    }

    private static string DetectFileType(byte[] bytes, string extension)
    {
        if (StartsWith(bytes, [0x4D, 0x5A])) return "Windows PE";
        if (StartsWith(bytes, [0x50, 0x4B, 0x03, 0x04]) || StartsWith(bytes, [0x50, 0x4B, 0x05, 0x06])) return "ZIP / package";
        if (StartsWith(bytes, Encoding.ASCII.GetBytes("%PDF"))) return "PDF";
        if (StartsWith(bytes, [0x7F, 0x45, 0x4C, 0x46])) return "ELF binary";
        if (StartsWith(bytes, [0x52, 0x61, 0x72, 0x21])) return "RAR archive";
        if (StartsWith(bytes, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return "7-Zip archive";
        if (StartsWith(bytes, [0x1F, 0x8B])) return "GZip archive";
        if (ScriptExtensions.Contains(extension)) return "Script / active text";
        if (LooksLikeText(bytes)) return "Text";
        return "Binary / unknown";
    }

    private static bool StartsWith(byte[] bytes, byte[] prefix) => bytes.Length >= prefix.Length && bytes.AsSpan(0, prefix.Length).SequenceEqual(prefix);

    private static bool LooksLikeText(byte[] bytes)
    {
        if (bytes.Length == 0) return true;
        int sampleLength = Math.Min(bytes.Length, 4096);
        int controls = 0;
        for (int i = 0; i < sampleLength; i++)
        {
            byte value = bytes[i];
            if (value == 0) return false;
            if (value < 9 || value is > 13 and < 32) controls++;
        }
        return controls == 0 || controls < Math.Max(1, sampleLength / 50);
    }

    private static double CalculateEntropy(byte[] bytes)
    {
        if (bytes.Length == 0) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (byte value in bytes) counts[value]++;
        double entropy = 0;
        foreach (int count in counts)
        {
            if (count == 0) continue;
            double probability = count / (double)bytes.Length;
            entropy -= probability * Math.Log2(probability);
        }
        return entropy;
    }

    private static void ReadVersionAndPeMetadata(string path, FileAnalysis analysis)
    {
        if (analysis.FileType != "Windows PE") return;
        try
        {
            FileVersionInfo version = FileVersionInfo.GetVersionInfo(path);
            analysis.ProductName = String.IsNullOrWhiteSpace(version.ProductName) ? "—" : version.ProductName;
            analysis.CompanyName = String.IsNullOrWhiteSpace(version.CompanyName) ? "—" : version.CompanyName;
        }
        catch { }

        try
        {
            using FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
            analysis.Architecture = pe.PEHeaders.CoffHeader.Machine.ToString() + (pe.HasMetadata ? " / .NET" : " / native");
        }
        catch { }
    }

    private static void ReadInternetZone(string path, FileAnalysis analysis)
    {
        try
        {
            string zoneText = File.ReadAllText(path + ":Zone.Identifier");
            Match zone = Regex.Match(zoneText, @"(?im)^ZoneId=(?<value>\d+)");
            if (zone.Success && Int32.TryParse(zone.Groups["value"].Value, out int zoneId))
            {
                analysis.InternetZone = zoneId;
                if (zoneId >= 3)
                {
                    AddIndicator(analysis, new("info", "internet-origin", "Internet Zone由来のファイルです", "The file carries an Internet Zone mark", 0));
                }
            }

            Match host = Regex.Match(zoneText, @"(?im)^HostUrl=(?<value>.+)$");
            if (host.Success && Uri.TryCreate(host.Groups["value"].Value.Trim(), UriKind.Absolute, out Uri? uri))
            {
                analysis.SourceHost = uri.Host;
            }
        }
        catch { }
    }

    private static void DetectNameAndTypeMismatch(FileAnalysis analysis, byte[] sample)
    {
        string name = Path.GetFileName(analysis.RelativePath);
        string extension = Path.GetExtension(name);
        if (name.Contains('\u202E'))
        {
            AddIndicator(analysis, new("danger", "rtl-override", "ファイル名に右から左への表示制御文字があります", "The file name contains a right-to-left override character", 45));
        }

        if (Regex.IsMatch(name, @"(?i)\.(pdf|png|jpe?g|gif|docx?|xlsx?|pptx?|txt)\.(exe|scr|com|bat|cmd|ps1|vbs|js|hta)$"))
        {
            AddIndicator(analysis, new("danger", "double-extension", "文書や画像に見せる二重拡張子です", "A double extension makes active content look like a document or image", 40));
        }

        if (analysis.FileType == "Windows PE" && !new[] { ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx" }.Contains(extension, StringComparer.OrdinalIgnoreCase))
        {
            AddIndicator(analysis, new("danger", "pe-extension-mismatch", "拡張子とWindows実行形式が一致しません", "The extension does not match the Windows executable format", 38));
        }
        else if (analysis.FileType == "PDF" && !extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase))
        {
            AddIndicator(analysis, new("watch", "pdf-extension-mismatch", "拡張子とPDF形式が一致しません", "The extension does not match the PDF format", 20));
        }

        if (extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            AddIndicator(analysis, new("watch", "shortcut", "ショートカットです。リンク先は自動実行せず手動確認が必要です", "This is a shortcut; its destination needs review without launching it", 18));
        }
    }

    private static void DetectCapabilities(FileAnalysis analysis, byte[] sample)
    {
        string extension = Path.GetExtension(analysis.RelativePath);
        bool script = ScriptExtensions.Contains(extension);
        bool pe = analysis.FileType == "Windows PE";
        if (!script && !pe && analysis.FileType != "PDF") return;

        string ascii = Encoding.Latin1.GetString(sample);
        string unicode = sample.Length >= 2 ? Encoding.Unicode.GetString(sample) : String.Empty;
        string searchable = ascii + "\n" + unicode;

        foreach (var capability in CapabilityPatterns)
        {
            if (!capability.Pattern.IsMatch(searchable)) continue;
            int score = script ? capability.Score : Math.Max(4, capability.Score / 2);
            AddIndicator(analysis, new(score >= 30 ? "danger" : "watch", capability.Code, capability.Ja, capability.En, score));
        }

        if (analysis.FileType == "PDF")
        {
            if (Regex.IsMatch(ascii, @"(?i)/(JavaScript|JS|OpenAction|Launch)\b"))
            {
                AddIndicator(analysis, new("watch", "pdf-active-action", "PDFにJavaScriptまたは自動起動アクションの兆候があります", "The PDF contains an indicator of JavaScript or an automatic launch action", 28));
            }
        }
    }

    private static void InspectStructuredFormats(string path, FileAnalysis analysis)
    {
        if (analysis.FileType != "ZIP / package") return;
        try
        {
            using ZipArchive archive = ZipFile.OpenRead(path);
            int activeEntries = 0;
            int nestedArchives = 0;
            bool traversal = false;
            bool macro = false;
            bool extremeRatio = false;
            int count = 0;

            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                count++;
                if (count > MaxArchiveEntries)
                {
                    analysis.InspectionLimited = true;
                    break;
                }

                string entryPath = entry.FullName.Replace('\\', '/');
                string[] segments = entryPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                if (Path.IsPathRooted(entryPath) || segments.Any(segment => segment == "..")) traversal = true;
                if (IsActiveContentExtension(Path.GetExtension(entryPath))) activeEntries++;
                if (new[] { ".zip", ".rar", ".7z", ".gz", ".iso" }.Contains(Path.GetExtension(entryPath), StringComparer.OrdinalIgnoreCase)) nestedArchives++;
                if (entryPath.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)) macro = true;
                if (entry.Length > 100L * 1024 * 1024 && entry.Length / Math.Max(1d, entry.CompressedLength) > 1000d) extremeRatio = true;
            }

            analysis.ArchiveEntries = Math.Min(count, MaxArchiveEntries);
            if (traversal) AddIndicator(analysis, new("danger", "archive-traversal", "圧縮ファイルに展開先を逸脱するパスがあります", "The archive contains a path that can escape the extraction directory", 45));
            if (extremeRatio) AddIndicator(analysis, new("danger", "archive-ratio", "極端な圧縮率の大容量項目があります", "The archive contains a very large entry with an extreme compression ratio", 40));
            if (macro) AddIndicator(analysis, new("watch", "office-macro", "Officeマクロを含みます", "The package contains an Office macro", 28));
            if (activeEntries > 0) AddIndicator(analysis, new("watch", "archive-active-content", $"圧縮ファイル内に実行可能な内容が{activeEntries}件あります", $"The archive contains {activeEntries} active-content item(s)", Math.Min(25, 8 + activeEntries * 2)));
            if (nestedArchives > 0) AddIndicator(analysis, new("info", "nested-archive", $"内部に別の圧縮ファイルが{nestedArchives}件あります", $"The archive contains {nestedArchives} nested archive(s)", 3));
            if (analysis.InspectionLimited) AddIndicator(analysis, new("watch", "archive-limit", $"内部一覧は{MaxArchiveEntries}件で打ち切りました", $"Archive inspection stopped at {MaxArchiveEntries} entries", 10));
        }
        catch (InvalidDataException)
        {
            AddIndicator(analysis, new("watch", "invalid-archive", "ZIP形式として正常に読み取れませんでした", "The package could not be read as a valid ZIP archive", 20));
        }
        catch (IOException)
        {
            AddIndicator(analysis, new("watch", "archive-read-error", "圧縮ファイルの内部確認を完了できませんでした", "Archive content inspection could not be completed", 12));
        }
    }

    private static void ApplySignatures(List<FileAnalysis> files, CancellationToken cancellationToken)
    {
        List<FileAnalysis> candidates = files.Where(ShouldCheckSignature).Take(300).ToList();
        if (candidates.Count == 0) return;

        string command = "while (($line=[Console]::In.ReadLine()) -ne $null) { try { $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($line)); $s=Get-AuthenticodeSignature -LiteralPath $p; $sub=[string]$s.SignerCertificate.Subject; $b=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sub)); [Console]::WriteLine((\"{0}`t{1}\" -f $s.Status,$b)) } catch { [Console]::WriteLine((\"UnknownError`t\")) } }";
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(command);
        startInfo.Environment.Remove("PSModulePath");

        try
        {
            using Process? process = Process.Start(startInfo);
            if (process is null) return;
            foreach (FileAnalysis candidate in candidates)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(candidate.FullPath));
                process.StandardInput.WriteLine(encoded);
            }
            process.StandardInput.Close();

            for (int i = 0; i < candidates.Count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string? line = process.StandardOutput.ReadLine();
                if (line is null) break;
                string[] parts = line.Split('\t', 2);
                candidates[i].SignatureStatus = parts[0];
                if (parts.Length == 2 && !String.IsNullOrWhiteSpace(parts[1]))
                {
                    try { candidates[i].Signer = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1])); } catch { }
                }
            }
            if (!process.WaitForExit(15000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
            }
        }
        catch { }

        if (files.Count(ShouldCheckSignature) > candidates.Count)
        {
            foreach (FileAnalysis skipped in files.Where(ShouldCheckSignature).Skip(candidates.Count))
            {
                skipped.InspectionLimited = true;
                AddIndicator(skipped, new("info", "signature-limit", "署名確認の安全上限を超えたため未確認です", "Signature verification was skipped after the safety limit", 2));
            }
        }
    }

    private static void ApplySignatureRisk(FileAnalysis analysis)
    {
        bool active = IsActiveContentExtension(Path.GetExtension(analysis.RelativePath));
        bool external = analysis.InternetZone >= 3;
        if (analysis.FileType == "Windows PE" && analysis.SignatureStatus.Equals("Valid", StringComparison.OrdinalIgnoreCase))
        {
            analysis.Indicators.RemoveAll(indicator => indicator.Score <= 5 && indicator.Code is "shell-launch" or "destructive-file" or "force-stop");
        }

        if (analysis.SignatureStatus.Equals("NotSigned", StringComparison.OrdinalIgnoreCase) && active && external)
        {
            AddIndicator(analysis, new("watch", "unsigned-active-download", "インターネット由来の未署名アクティブコンテンツです", "Unsigned active content carrying an Internet Zone mark", 18));
        }
        else if (analysis.SignatureStatus is "HashMismatch" or "NotTrusted" or "UnknownError")
        {
            AddIndicator(analysis, new("danger", "signature-invalid", $"署名状態を信頼できません: {analysis.SignatureStatus}", $"The signature is not trusted: {analysis.SignatureStatus}", 42));
        }

        if (analysis.FileType == "Windows PE" && analysis.Entropy >= 7.55 && !analysis.SignatureStatus.Equals("Valid", StringComparison.OrdinalIgnoreCase))
        {
            AddIndicator(analysis, new("watch", "high-entropy-pe", "未署名PEのエントロピーが高く、圧縮・暗号化の可能性があります", "The unsigned PE has high entropy and may be packed or encrypted", 18));
        }
    }

    private static bool ShouldCheckSignature(FileAnalysis analysis) =>
        analysis.FileType == "Windows PE" || SignatureExtensions.Contains(Path.GetExtension(analysis.RelativePath));

    private static void AddIndicator(FileAnalysis analysis, Indicator indicator)
    {
        if (analysis.Indicators.All(existing => !existing.Code.Equals(indicator.Code, StringComparison.OrdinalIgnoreCase)))
        {
            analysis.Indicators.Add(indicator);
        }
    }
}
