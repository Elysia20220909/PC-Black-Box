using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection.PortableExecutable;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DestinyBlackBox;

public sealed class FileInspector
{
    private const int MaxFiles = 2500;
    private const long MaxTotalBytes = SecurityPolicy.MaxTargetBytes;
    private const int MaxArchiveEntries = 10000;
    private const int MaxArchiveEntryNameChars = 2048;
    private const int MaxSignatureChecks = 300;
    private const int SampleBytes = 8 * 1024 * 1024;
    private static readonly TimeSpan RegexMatchTimeout = TimeSpan.FromSeconds(1);
    private static readonly Regex ZoneIdPattern = CreatePattern(@"^ZoneId=(?<value>\d+)", RegexOptions.IgnoreCase | RegexOptions.Multiline);
    private static readonly Regex HostUrlPattern = CreatePattern(@"^HostUrl=(?<value>.+)$", RegexOptions.IgnoreCase | RegexOptions.Multiline);
    private static readonly Regex DoubleExtensionPattern = CreatePattern(@"\.(pdf|png|jpe?g|gif|docx?|xlsx?|pptx?|txt)\.(exe|scr|com|bat|cmd|ps1|vbs|js|hta)$", RegexOptions.IgnoreCase);
    private static readonly Regex PdfActivePattern = CreatePattern(@"/(JavaScript|JS|OpenAction|Launch)\b", RegexOptions.IgnoreCase);
    private static readonly Regex ArchiveDrivePathPattern = CreatePattern(@"^[A-Za-z]:/", RegexOptions.None);

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
        ("defender-change", CreateCapabilityPattern(@"(Add-MpPreference|Set-MpPreference|DisableRealtimeMonitoring|DisableBehaviorMonitoring|ExclusionPath|ExclusionProcess)"), 40, "Microsoft Defenderの設定変更能力", "Microsoft Defender configuration capability"),
        ("process-injection", CreateCapabilityPattern(@"(WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|QueueUserAPC|NtCreateThreadEx)"), 35, "他プロセスへの注入に関連するAPI", "APIs associated with process injection"),
        ("credential-access", CreateCapabilityPattern(@"(Get-Credential|ConvertTo-SecureString|CredentialManager|mimikatz|lsass|Login Data|Cookies\\b)"), 25, "資格情報アクセスに関連する語句", "Terms associated with credential access"),
        ("persistence", CreateCapabilityPattern(@"(Register-ScheduledTask|New-ScheduledTask|schtasks(?:\.exe)?|New-Service|sc(?:\.exe)?\s+create|CurrentVersion\\Run|Startup\\)"), 22, "永続化に利用できる処理", "Capability that can establish persistence"),
        ("remote-download", CreateCapabilityPattern(@"(Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile|Start-BitsTransfer|System\.Net\.WebClient|curl(?:\.exe)?\s+https?://|wget\s+https?://)"), 18, "外部からファイルやデータを取得する処理", "Capability to download files or data"),
        ("obfuscation", CreateCapabilityPattern(@"(FromBase64String|-EncodedCommand|\bIEX\b|Invoke-Expression|GZipStream|DeflateStream)"), 17, "難読化または動的実行に使われる処理", "Capability associated with obfuscation or dynamic execution"),
        ("shell-launch", CreateCapabilityPattern(@"(Start-Process|ProcessStartInfo|cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-)"), 10, "別プロセスやシェルを起動する処理", "Capability to launch another process or shell"),
        ("destructive-file", CreateCapabilityPattern(@"(Remove-Item|DeleteFile|rmdir\s+/s|del\s+/[fq])"), 9, "ファイル削除能力", "File-deletion capability"),
        ("force-stop", CreateCapabilityPattern(@"(Stop-Process|TerminateProcess|taskkill(?:\.exe)?)"), 6, "プロセスを強制停止する能力", "Capability to terminate processes")
    ];

    private static Regex CreateCapabilityPattern(string pattern) => new(
        pattern,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
        RegexMatchTimeout);

    private static Regex CreatePattern(string pattern, RegexOptions options) => new(
        pattern,
        options | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
        RegexMatchTimeout);

    public static bool IsActiveContentExtension(string? extension) => extension is not null && ActiveExtensions.Contains(extension);

    public Task<ScanResult> ScanAsync(string targetPath, IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
    {
        return Task.Run(() => ScanCore(targetPath, progress, cancellationToken), cancellationToken);
    }

    private static ScanResult ScanCore(string targetPath, IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
    {
        string fullTarget = SecurityPolicy.ValidateTargetPath(targetPath);
        bool targetIsFile = File.Exists(fullTarget);

        var result = new ScanResult
        {
            TargetPath = fullTarget,
            TargetName = SecurityPolicy.SanitizeText(targetIsFile ? Path.GetFileName(fullTarget) : new DirectoryInfo(fullTarget).Name, 512),
            TargetWasDirectory = !targetIsFile,
            StartedAt = DateTime.Now
        };

        Stopwatch stopwatch = Stopwatch.StartNew();
        List<string> files = CollectFiles(fullTarget, result, cancellationToken);
        string root = targetIsFile ? Path.GetDirectoryName(fullTarget) ?? fullTarget : fullTarget;
        int signatureChecks = 0;

        for (int index = 0; index < files.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string file = files[index];
            progress?.Report(new ScanProgress(index, files.Count, Path.GetFileName(file)));
            try
            {
                result.Files.Add(AnalyzeFile(file, root, targetIsFile, ref signatureChecks, cancellationToken));
            }
            catch (Exception exception) when (IsExpectedFileFailure(exception))
            {
                MarkPartial(result, "One or more files could not be inspected safely.");
                result.Files.Add(CreateUnreadableAnalysis(file, root, targetIsFile));
            }
        }

        ValidateFilesUnchanged(result.Files);
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
            try
            {
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                {
                    MarkPartial(result, "A directory became a reparse point and was skipped.");
                    continue;
                }
            }
            catch (Exception exception) when (IsExpectedFileFailure(exception))
            {
                MarkPartial(result, "One or more directories could not be revalidated.");
                continue;
            }

            IEnumerator<FileSystemInfo>? enumerator = null;
            try
            {
                enumerator = new DirectoryInfo(directory).EnumerateFileSystemInfos().GetEnumerator();
                while (enumerator.MoveNext())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    FileSystemInfo entry = enumerator.Current;
                    FileAttributes attributes;
                    try { attributes = entry.Attributes; }
                    catch (Exception exception) when (IsExpectedFileFailure(exception))
                    {
                        MarkPartial(result, "One or more entries could not be read.");
                        continue;
                    }

                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        MarkPartial(result, "Reparse points were skipped.");
                        continue;
                    }

                    if (entry is DirectoryInfo childDirectory)
                    {
                        directories.Push(childDirectory.FullName);
                        continue;
                    }

                    if (entry is not FileInfo file) continue;

                    long length;
                    try
                    {
                        file.Refresh();
                        length = file.Length;
                    }
                    catch (Exception exception) when (IsExpectedFileFailure(exception))
                    {
                        MarkPartial(result, "One or more file sizes could not be read.");
                        continue;
                    }

                    if (files.Count >= MaxFiles || length > MaxTotalBytes - totalBytes)
                    {
                        MarkPartial(result, $"Safety limit reached ({MaxFiles} files or {FileAnalysis.FormatSize(MaxTotalBytes)}).");
                        return files;
                    }

                    files.Add(file.FullName);
                    totalBytes += length;
                }
            }
            catch (Exception exception) when (IsExpectedFileFailure(exception))
            {
                MarkPartial(result, "One or more directories could not be read.");
                continue;
            }
            finally
            {
                enumerator?.Dispose();
            }
        }

        return files.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static FileAnalysis AnalyzeFile(string path, string root, bool singleFile, ref int signatureChecks, CancellationToken cancellationToken)
    {
        using FileStream secureStream = SecureFileReader.OpenRead(path);
        SecureFileSnapshot originalSnapshot = SecureFileReader.GetSnapshot(secureStream.SafeFileHandle);
        if (originalSnapshot.Length > MaxTotalBytes) throw new IOException("The file exceeds the inspection safety limit.");

        string rawRelativePath = singleFile ? Path.GetFileName(path) : Path.GetRelativePath(root, path);
        var analysis = new FileAnalysis
        {
            FullPath = path,
            RelativePath = SecurityPolicy.SanitizeText(rawRelativePath, 1024),
            Size = originalSnapshot.Length,
            ObservedLength = originalSnapshot.Length,
            ObservedLastWriteUtc = originalSnapshot.LastWriteUtc,
            ObservedIdentity = originalSnapshot.Identity
        };

        byte[] sample = ReadSampleAndHash(secureStream, analysis, cancellationToken);
        analysis.FileType = DetectFileType(sample, Path.GetExtension(path));
        analysis.Entropy = CalculateEntropy(sample);
        ReadVersionAndPeMetadata(path, secureStream, analysis);
        ReadInternetZone(path, analysis);
        DetectNameAndTypeMismatch(analysis, sample, rawRelativePath);
        DetectCapabilities(analysis, sample);
        InspectStructuredFormats(secureStream, analysis, cancellationToken);

        if (ShouldCheckSignature(analysis))
        {
            if (signatureChecks < MaxSignatureChecks)
            {
                signatureChecks++;
                SignatureResult signature = OfflineSignatureVerifier.Verify(path);
                analysis.SignatureStatus = signature.Status;
                analysis.Signer = SecurityPolicy.SanitizeText(signature.Signer, 512);
            }
            else
            {
                analysis.InspectionLimited = true;
                AddIndicator(analysis, new("info", "signature-limit", "署名確認の安全上限を超えたため未確認です", "Signature verification was skipped after the safety limit", 2));
            }
        }

        SecureFileSnapshot finalSnapshot = SecureFileReader.GetSnapshot(secureStream.SafeFileHandle);
        if (finalSnapshot != originalSnapshot)
        {
            MarkChangedDuringScan(analysis);
        }

        return analysis;
    }

    private static byte[] ReadSampleAndHash(FileStream stream, FileAnalysis analysis, CancellationToken cancellationToken)
    {
        stream.Position = 0;
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

    private static void ReadVersionAndPeMetadata(string path, FileStream stream, FileAnalysis analysis)
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
            stream.Position = 0;
            using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
            analysis.Architecture = pe.PEHeaders.CoffHeader.Machine.ToString() + (pe.HasMetadata ? " / .NET" : " / native");
        }
        catch { }
    }

    private static void ReadInternetZone(string path, FileAnalysis analysis)
    {
        try
        {
            string zoneText = ReadBoundedText(path + ":Zone.Identifier", SecurityPolicy.MaxZoneIdentifierBytes);
            Match zone = ZoneIdPattern.Match(zoneText);
            if (zone.Success && Int32.TryParse(zone.Groups["value"].Value, out int zoneId))
            {
                analysis.InternetZone = zoneId;
                if (zoneId >= 3)
                {
                    AddIndicator(analysis, new("info", "internet-origin", "Internet Zone由来のファイルです", "The file carries an Internet Zone mark", 0));
                }
            }

            Match host = HostUrlPattern.Match(zoneText);
            if (host.Success && Uri.TryCreate(host.Groups["value"].Value.Trim(), UriKind.Absolute, out Uri? uri) &&
                uri.Scheme is "http" or "https" && !String.IsNullOrWhiteSpace(uri.IdnHost))
            {
                analysis.SourceHost = SecurityPolicy.SanitizeText(uri.IdnHost, 253);
            }
        }
        catch { }
    }

    private static string ReadBoundedText(string path, int maxBytes)
    {
        using FileStream stream = SecureFileReader.OpenRead(path, 4096);
        if (stream.Length > maxBytes) throw new IOException("Metadata stream exceeds the safety limit.");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, 4096, leaveOpen: false);
        char[] buffer = new char[maxBytes];
        int count = reader.ReadBlock(buffer, 0, buffer.Length);
        return new string(buffer, 0, count);
    }

    private static void DetectNameAndTypeMismatch(FileAnalysis analysis, byte[] sample, string rawRelativePath)
    {
        string name = Path.GetFileName(rawRelativePath);
        string extension = Path.GetExtension(name);
        if (SecurityPolicy.ContainsDirectionalOrInvisibleControl(name))
        {
            AddIndicator(analysis, new("danger", "unicode-control", "ファイル名に表示を偽装できる不可視制御文字があります", "The file name contains an invisible control character that can spoof its display", 45));
        }

        if (DoubleExtensionPattern.IsMatch(name))
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
            bool matched;
            try
            {
                matched = capability.Pattern.IsMatch(searchable);
            }
            catch (RegexMatchTimeoutException)
            {
                analysis.InspectionLimited = true;
                AddIndicator(analysis, new("watch", "regex-time-limit", "能力語の照合が時間上限に達しました", "Capability matching reached its time limit", 8));
                break;
            }
            if (!matched) continue;
            int score = script ? capability.Score : Math.Max(4, capability.Score / 2);
            AddIndicator(analysis, new(score >= 30 ? "danger" : "watch", capability.Code, capability.Ja, capability.En, score));
        }

        if (analysis.FileType == "PDF")
        {
            try
            {
                if (PdfActivePattern.IsMatch(ascii))
                {
                    AddIndicator(analysis, new("watch", "pdf-active-action", "PDFにJavaScriptまたは自動起動アクションの兆候があります", "The PDF contains an indicator of JavaScript or an automatic launch action", 28));
                }
            }
            catch (RegexMatchTimeoutException)
            {
                analysis.InspectionLimited = true;
                AddIndicator(analysis, new("watch", "regex-time-limit", "PDF能力語の照合が時間上限に達しました", "PDF capability matching reached its time limit", 8));
            }
        }
    }

    private static void InspectStructuredFormats(FileStream stream, FileAnalysis analysis, CancellationToken cancellationToken)
    {
        if (analysis.FileType != "ZIP / package") return;
        if (analysis.Size > SecurityPolicy.MaxArchiveInspectionBytes)
        {
            analysis.InspectionLimited = true;
            AddIndicator(analysis, new("watch", "archive-size-limit", $"ZIP内部確認は{FileAnalysis.FormatSize(SecurityPolicy.MaxArchiveInspectionBytes)}までです", $"ZIP metadata inspection is limited to {FileAnalysis.FormatSize(SecurityPolicy.MaxArchiveInspectionBytes)}", 12));
            return;
        }

        try
        {
            stream.Position = 0;
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            int activeEntries = 0;
            int nestedArchives = 0;
            bool traversal = false;
            bool alternateStream = false;
            bool linkEntry = false;
            bool deceptiveName = false;
            bool oversizedName = false;
            bool macro = false;
            bool extremeRatio = false;
            int count = 0;
            long declaredBytes = 0;

            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                count++;
                if (count > MaxArchiveEntries)
                {
                    analysis.InspectionLimited = true;
                    break;
                }

                string entryPath = entry.FullName.Replace('\\', '/');
                if (entryPath.Length > MaxArchiveEntryNameChars)
                {
                    oversizedName = true;
                    continue;
                }
                string[] segments = entryPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                if (entryPath.StartsWith('/') || ArchiveDrivePathPattern.IsMatch(entryPath) || segments.Any(segment => segment == "..")) traversal = true;
                if (segments.Any(segment => segment.Contains(':'))) alternateStream = true;
                if (SecurityPolicy.ContainsDirectionalOrInvisibleControl(entryPath)) deceptiveName = true;
                uint unixType = ((uint)entry.ExternalAttributes >> 16) & 0xF000;
                if (unixType == 0xA000 || (((FileAttributes)entry.ExternalAttributes) & FileAttributes.ReparsePoint) != 0) linkEntry = true;
                if (IsActiveContentExtension(Path.GetExtension(entryPath))) activeEntries++;
                if (new[] { ".zip", ".rar", ".7z", ".gz", ".iso" }.Contains(Path.GetExtension(entryPath), StringComparer.OrdinalIgnoreCase)) nestedArchives++;
                if (entryPath.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)) macro = true;
                if (entry.Length > SecurityPolicy.MaxArchiveDeclaredBytes - declaredBytes)
                {
                    declaredBytes = SecurityPolicy.MaxArchiveDeclaredBytes + 1;
                }
                else
                {
                    declaredBytes += entry.Length;
                }
                if (entry.Length > 100L * 1024 * 1024 && entry.Length / Math.Max(1d, entry.CompressedLength) > 1000d) extremeRatio = true;
            }

            analysis.ArchiveEntries = Math.Min(count, MaxArchiveEntries);
            if (traversal) AddIndicator(analysis, new("danger", "archive-traversal", "圧縮ファイルに展開先を逸脱するパスがあります", "The archive contains a path that can escape the extraction directory", 45));
            if (alternateStream) AddIndicator(analysis, new("danger", "archive-ads", "圧縮ファイル内に代替データストリーム形式の名前があります", "The archive contains a name that can target an alternate data stream", 40));
            if (linkEntry) AddIndicator(analysis, new("danger", "archive-link", "圧縮ファイル内にリンクまたは再解析ポイント形式の項目があります", "The archive contains a link or reparse-point entry", 40));
            if (deceptiveName) AddIndicator(analysis, new("watch", "archive-unicode-control", "圧縮ファイル内の名前に不可視制御文字があります", "An archive entry name contains an invisible control character", 25));
            if (oversizedName) AddIndicator(analysis, new("watch", "archive-name-limit", "安全上限を超える長い項目名があります", "An archive entry name exceeds the safety limit", 15));
            if (extremeRatio || declaredBytes > SecurityPolicy.MaxArchiveDeclaredBytes) AddIndicator(analysis, new("danger", "archive-ratio", "展開後サイズまたは圧縮率が安全上限を超えています", "The declared expanded size or compression ratio exceeds the safety limit", 40));
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

    private static void ValidateFilesUnchanged(IEnumerable<FileAnalysis> files)
    {
        foreach (FileAnalysis analysis in files)
        {
            if (analysis.ObservedLength < 0) continue;
            try
            {
                using FileStream stream = SecureFileReader.OpenRead(analysis.FullPath);
                SecureFileSnapshot snapshot = SecureFileReader.GetSnapshot(stream.SafeFileHandle);
                if (snapshot.Length != analysis.ObservedLength ||
                    snapshot.LastWriteUtc != analysis.ObservedLastWriteUtc ||
                    snapshot.Identity != analysis.ObservedIdentity)
                {
                    MarkChangedDuringScan(analysis);
                }
            }
            catch (Exception exception) when (IsExpectedFileFailure(exception))
            {
                MarkChangedDuringScan(analysis);
            }
        }
    }

    private static void MarkChangedDuringScan(FileAnalysis analysis)
    {
        analysis.InspectionLimited = true;
        analysis.SignatureStatus = "Indeterminate";
        analysis.Signer = "—";
        AddIndicator(analysis, new("danger", "changed-during-scan", "調査中にファイルが変更されたため、結果を信頼できません", "The file changed during inspection, so the result is not trustworthy", 60));
    }

    private static FileAnalysis CreateUnreadableAnalysis(string path, string root, bool singleFile)
    {
        string rawRelativePath;
        try { rawRelativePath = singleFile ? Path.GetFileName(path) : Path.GetRelativePath(root, path); }
        catch { rawRelativePath = Path.GetFileName(path); }

        var analysis = new FileAnalysis
        {
            FullPath = path,
            RelativePath = SecurityPolicy.SanitizeText(rawRelativePath, 1024),
            Size = 0,
            ObservedLength = -1,
            SignatureStatus = "Indeterminate",
            InspectionLimited = true
        };
        AddIndicator(analysis, new("watch", "file-read-failed", "ファイルを安全に読み取れなかったため、内容を判定できません", "The file could not be read safely, so its content is indeterminate", 30));
        return analysis;
    }

    private static bool IsExpectedFileFailure(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or SecurityException or NotSupportedException;

    private static void MarkPartial(ScanResult result, string reason)
    {
        result.IsPartial = true;
        if (String.IsNullOrWhiteSpace(result.PartialReason))
        {
            result.PartialReason = reason;
        }
        else if (!result.PartialReason.Contains(reason, StringComparison.Ordinal))
        {
            result.PartialReason = SecurityPolicy.SanitizeText(result.PartialReason + " " + reason, 512);
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
        else if (analysis.SignatureStatus is "HashMismatch" or "NotTrusted" or "NotTimeValid" or "Revoked" or "UnknownError" or "Indeterminate")
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
