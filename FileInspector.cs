using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using Microsoft.Win32.SafeHandles;
using System.Reflection.PortableExecutable;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DestinyBlackBox;

public sealed class FileInspector
{
    private const int MaxFiles = 2500;
    private const int MaxDirectories = 10000;
    private const int MaxDirectoryDepth = 128;
    private const int MaxEnumeratedEntries = 20000;
    private const long MaxRetainedPathCharacters = 8L * 1024 * 1024;
    private const long MaxTotalBytes = SecurityPolicy.MaxTargetBytes;
    private const int MaxArchiveEntries = 10000;
    private const int MaxArchiveEntryNameChars = 2048;
    private const int MaxArchiveEntryNameBytes = 4096;
    private const long MaxArchiveCentralDirectoryBytes = 64L * 1024 * 1024;
    private const int EndOfCentralDirectoryLength = 22;
    private const uint CentralDirectoryHeaderSignature = 0x02014B50;
    private const uint CentralDirectoryDigitalSignature = 0x05054B50;
    private const uint Zip64EndOfCentralDirectorySignature = 0x06064B50;
    private const uint Zip64EndOfCentralDirectoryLocatorSignature = 0x07064B50;
    private const uint EndOfCentralDirectorySignature = 0x06054B50;
    private const int MaxSignatureChecks = 300;
    private const int ShowMinimizedNoActivate = 7;
    private const int MaxOrdinaryShortcutArguments = 260;
    private const int SampleBytes = 8 * 1024 * 1024;
    private const int CapabilityChunkBytes = 1024 * 1024;
    private const int CapabilityOverlapBytes = 4096;
    // The byte budgets decide how much is actually inspected; the time budgets only bound
    // pathological slowness (a stalling network share, a crafted input) so a scan cannot hang.
    // Measured throughput on this class of machine is roughly 50 MiB/s, so the per-inspection
    // byte budget is reached in about 75 seconds — well inside its time budget. Sizing them the
    // other way round would let an ordinary folder of installers exhaust the budget and report
    // INCOMPLETE for content that was never the reason for the limit.
    internal const long MaxCapabilityBytesPerFile = 1024L * 1024 * 1024;
    internal const long MaxCapabilityBytesPerScan = 4096L * 1024 * 1024;
    internal static readonly TimeSpan MaxCapabilityTimePerFile = TimeSpan.FromSeconds(60);
    internal static readonly TimeSpan MaxCapabilityTimePerScan = TimeSpan.FromSeconds(180);
    private static readonly TimeSpan RegexMatchTimeout = TimeSpan.FromSeconds(1);
    private static readonly Regex ZoneIdPattern = CreatePattern(@"^ZoneId=(?<value>\d+)", RegexOptions.IgnoreCase | RegexOptions.Multiline);
    private static readonly Regex HostUrlPattern = CreatePattern(@"^HostUrl=(?<value>.+)$", RegexOptions.IgnoreCase | RegexOptions.Multiline);
    private static readonly Regex DoubleExtensionPattern = CreatePattern(@"\.(pdf|png|jpe?g|gif|docx?|xlsx?|pptx?|txt)\.(exe|scr|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|url|msi|iso|img|pif|cpl|reg)$", RegexOptions.IgnoreCase);
    private static readonly Regex PdfActivePattern = CreatePattern(@"/(JavaScript|JS|OpenAction|Launch)\b", RegexOptions.IgnoreCase);
    private static readonly Regex ShortcutInterpreterPattern = CreateCapabilityPattern(
        @"(powershell(?:\.exe)?|pwsh(?:\.exe)?|\bcmd\.exe|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|msiexec(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|forfiles(?:\.exe)?|installutil(?:\.exe)?|msbuild(?:\.exe)?|curl\.exe|wget\.exe)");
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
        ("persistence", CreateCapabilityPattern(@"(Register-ScheduledTask|New-ScheduledTask|schtasks(?:\.exe)?|New-Service|sc(?:\.exe)?\s{1,256}create|CurrentVersion\\Run|Startup\\)"), 22, "永続化に利用できる処理", "Capability that can establish persistence"),
        ("remote-download", CreateCapabilityPattern(@"(Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile|Start-BitsTransfer|System\.Net\.WebClient|curl(?:\.exe)?\s{1,256}https?://|wget\s{1,256}https?://)"), 18, "外部からファイルやデータを取得する処理", "Capability to download files or data"),
        ("encoded-command", CreateCapabilityPattern(@"[\s""'](?:-|/)e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\s{1,8}[A-Za-z0-9+/=]{16,}"), 40, "Base64で符号化されたコマンドを実行する指定です", "A switch that runs a Base64-encoded command"),
        ("hidden-window", CreateCapabilityPattern(@"((?:-|/)w(?:indowstyle)?\s{1,8}hidden|CreateNoWindow\s{0,8}=\s{0,8}true|WindowStyle\s{0,8}=\s{0,8}Hidden)"), 15, "実行中の画面を隠す指定です", "A switch that hides the window while it runs"),
        ("obfuscation", CreateCapabilityPattern(@"(FromBase64String|-EncodedCommand|\bIEX\b|Invoke-Expression|GZipStream|DeflateStream)"), 17, "難読化または動的実行に使われる処理", "Capability associated with obfuscation or dynamic execution"),
        ("shell-launch", CreateCapabilityPattern(@"(Start-Process|ProcessStartInfo|cmd(?:\.exe)?\s{1,256}/c|powershell(?:\.exe)?\s{1,256}-)"), 10, "別プロセスやシェルを起動する処理", "Capability to launch another process or shell"),
        ("destructive-file", CreateCapabilityPattern(@"(Remove-Item|DeleteFile|rmdir\s{1,256}/s|del\s{1,256}/[fq])"), 9, "ファイル削除能力", "File-deletion capability"),
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
        if (ProcessElevation.IsElevated)
        {
            throw new SecurityException("PC Black Box does not inspect files with administrator rights.");
        }

        SecurityPosture posture = WindowsProcessHardening.Current;
        if (!posture.IsEnforced)
        {
            throw new SecurityException("The required process security baseline is not enforced.");
        }

        string fullTarget = SecurityPolicy.ValidateTargetPath(targetPath);
        bool targetIsFile = File.Exists(fullTarget);

        var result = new ScanResult
        {
            TargetPath = fullTarget,
            TargetName = SecurityPolicy.SanitizeText(targetIsFile ? Path.GetFileName(fullTarget) : new DirectoryInfo(fullTarget).Name, 512),
            SecurityProfile = SecurityPosture.ProfileId,
            SecurityControlsEnforced = posture.EnforcedCount,
            SecurityControlsRequired = posture.RequiredCount,
            SecurityReinforcementsEnforced = posture.ReinforcementEnforcedCount,
            SecurityReinforcementsAvailable = posture.ReinforcementCount,
            TargetWasDirectory = !targetIsFile,
            StartedAt = DateTime.Now
        };

        Stopwatch stopwatch = Stopwatch.StartNew();
        CollectedTargets collected = CollectFiles(fullTarget, result, cancellationToken);
        List<string> files = collected.Files;
        string root = targetIsFile ? Path.GetDirectoryName(fullTarget) ?? fullTarget : fullTarget;
        int signatureChecks = 0;
        long inspectedBytes = 0;
        var capabilityBudget = new CapabilityScanBudget();

        for (int index = 0; index < files.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string file = files[index];
            progress?.Report(new ScanProgress(index, files.Count, Path.GetFileName(file)));
            try
            {
                FileAnalysis analysis = AnalyzeFile(file, root, targetIsFile, inspectedBytes, ref signatureChecks, capabilityBudget, cancellationToken);
                result.Files.Add(analysis);
                inspectedBytes += analysis.Size;
            }
            catch (InspectionSafetyLimitException)
            {
                MarkPartial(result, $"Safety limit reached ({MaxFiles} files or {FileAnalysis.FormatSize(MaxTotalBytes)}).");
                break;
            }
            catch (Exception exception) when (IsExpectedFileFailure(exception))
            {
                MarkPartial(result, "One or more files could not be inspected safely.");
                result.Files.Add(CreateUnreadableAnalysis(file, root, targetIsFile));
            }
        }

        ValidateFilesUnchanged(result.Files);
        ValidateDirectoriesUnchanged(collected.Directories, result);
        foreach (FileAnalysis file in result.Files)
        {
            ApplySignatureRisk(file);
        }
        PromoteInspectionLimits(result);

        progress?.Report(new ScanProgress(files.Count, files.Count, String.Empty));
        stopwatch.Stop();
        result.Duration = stopwatch.Elapsed;
        return result;
    }

    private static CollectedTargets CollectFiles(string target, ScanResult result, CancellationToken cancellationToken)
    {
        if (File.Exists(target))
        {
            return new CollectedTargets([target], []);
        }

        var files = new List<string>();
        var observations = new List<DirectoryObservation>();
        var directories = new Stack<PendingDirectory>();
        directories.Push(new PendingDirectory(target, 0));
        int discoveredDirectories = 1;
        int enumeratedEntries = 0;
        long retainedPathCharacters = target.Length;
        long totalBytes = 0;

        while (directories.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PendingDirectory pending = directories.Pop();
            string directory = pending.Path;
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

            try
            {
                using SafeFileHandle directoryGuard = SecureFileReader.OpenDirectoryGuard(directory);
                SecureFileSnapshot originalDirectorySnapshot = SecureFileReader.GetSnapshot(directoryGuard);
                using IEnumerator<FileSystemInfo> enumerator = new DirectoryInfo(directory).EnumerateFileSystemInfos().GetEnumerator();
                while (enumerator.MoveNext())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (WouldExceedEnumerationLimit(enumeratedEntries))
                    {
                        MarkPartial(result, $"Directory entry safety limit reached ({MaxEnumeratedEntries} entries).");
                        return BuildCollectedTargets(files, observations);
                    }
                    enumeratedEntries++;
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
                        int childDepth = checked(pending.Depth + 1);
                        if (WouldExceedDirectoryLimits(discoveredDirectories, childDepth))
                        {
                            MarkPartial(result, $"Directory safety limit reached ({MaxDirectories} directories or depth {MaxDirectoryDepth}).");
                            if (discoveredDirectories >= MaxDirectories)
                            {
                                return BuildCollectedTargets(files, observations);
                            }
                            continue;
                        }

                        if (WouldExceedRetainedPathLimit(retainedPathCharacters, childDirectory.FullName.Length))
                        {
                            MarkPartial(result, "The retained path-metadata safety limit was reached.");
                            return BuildCollectedTargets(files, observations);
                        }

                        directories.Push(new PendingDirectory(childDirectory.FullName, childDepth));
                        discoveredDirectories++;
                        retainedPathCharacters += childDirectory.FullName.Length;
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
                        return BuildCollectedTargets(files, observations);
                    }
                    if (WouldExceedRetainedPathLimit(retainedPathCharacters, file.FullName.Length))
                    {
                        MarkPartial(result, "The retained path-metadata safety limit was reached.");
                        return BuildCollectedTargets(files, observations);
                    }

                    files.Add(file.FullName);
                    totalBytes += length;
                    retainedPathCharacters += file.FullName.Length;
                }

                SecureFileSnapshot finalDirectorySnapshot = SecureFileReader.GetSnapshot(directoryGuard);
                if (finalDirectorySnapshot != originalDirectorySnapshot)
                {
                    MarkPartial(result, "A directory changed while it was being enumerated.");
                }
                observations.Add(new DirectoryObservation(directory, finalDirectorySnapshot));
            }
            catch (Exception exception) when (IsExpectedFileFailure(exception))
            {
                MarkPartial(result, "One or more directories could not be read.");
                continue;
            }
        }

        return BuildCollectedTargets(files, observations);
    }

    private static CollectedTargets BuildCollectedTargets(List<string> files, List<DirectoryObservation> observations) =>
        new(files.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToList(), observations);

    internal static bool WouldExceedDirectoryLimits(int discoveredDirectories, int childDepth) =>
        discoveredDirectories >= MaxDirectories || childDepth > MaxDirectoryDepth;

    internal static bool WouldExceedEnumerationLimit(int enumeratedEntries) =>
        enumeratedEntries >= MaxEnumeratedEntries;

    internal static bool WouldExceedRetainedPathLimit(long retainedCharacters, int nextPathCharacters) =>
        SecurityPolicy.WouldExceedCumulativeLimit(retainedCharacters, nextPathCharacters, MaxRetainedPathCharacters);

    internal static string GetInspectionExtension(FileAnalysis analysis)
    {
        string path = String.IsNullOrWhiteSpace(analysis.FullPath) ? analysis.RelativePath : analysis.FullPath;
        try
        {
            return Path.GetExtension(path);
        }
        catch (ArgumentException)
        {
            return String.Empty;
        }
    }

    private static FileAnalysis AnalyzeFile(
        string path,
        string root,
        bool singleFile,
        long inspectedBytes,
        ref int signatureChecks,
        CapabilityScanBudget capabilityBudget,
        CancellationToken cancellationToken)
    {
        using FileStream secureStream = SecureFileReader.OpenRead(path);
        SecureFileSnapshot originalSnapshot = SecureFileReader.GetSnapshot(secureStream.SafeFileHandle);
        if (SecurityPolicy.WouldExceedCumulativeLimit(inspectedBytes, originalSnapshot.Length, MaxTotalBytes))
        {
            throw new InspectionSafetyLimitException();
        }

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
        if (analysis.FileType == ShortcutType) InspectShortcut(secureStream, analysis);
        DetectCapabilities(secureStream, analysis, capabilityBudget, cancellationToken);
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
                LimitInspection(analysis, InspectionLimit.Signature, new("info", "signature-limit", "署名確認の安全上限を超えたため未確認です", "Signature verification was skipped after the safety limit", 2));
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
        if (StartsWith(bytes, [0x52, 0x61, 0x72, 0x21])) return RarType;
        if (StartsWith(bytes, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return SevenZipType;
        if (StartsWith(bytes, [0x1F, 0x8B])) return GZipType;
        if (StartsWith(bytes, [0x4D, 0x53, 0x43, 0x46])) return CabinetType;
        if (LooksLikeIsoImage(bytes)) return IsoImageType;
        if (StartsWith(bytes, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])) return OleCompoundType;
        if (ShortcutInspector.LooksLikeShortcut(bytes)) return ShortcutType;
        if (ScriptExtensions.Contains(extension)) return "Script / active text";
        if (LooksLikeText(bytes)) return "Text";
        return "Binary / unknown";
    }

    internal const string ShortcutType = "Windows shortcut";
    internal const string OleCompoundType = "OLE compound";
    internal const string RarType = "RAR archive";
    internal const string SevenZipType = "7-Zip archive";
    internal const string GZipType = "GZip archive";
    internal const string CabinetType = "Cabinet archive";
    internal const string IsoImageType = "ISO image";

    /// <summary>
    /// ISO 9660 declares itself at the start of sector 16 rather than at offset zero. Recognizing it matters
    /// because Mark-of-the-Web does not propagate to the files inside a mounted image, which is the reason
    /// this container is chosen for delivery in the first place.
    /// </summary>
    private static bool LooksLikeIsoImage(byte[] bytes) =>
        bytes.Length >= 0x8006 && bytes.AsSpan(0x8001, 5).SequenceEqual("CD001"u8);

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

    private static void DetectCapabilities(
        FileStream stream,
        FileAnalysis analysis,
        CapabilityScanBudget budget,
        CancellationToken cancellationToken)
    {
        string extension = GetInspectionExtension(analysis);
        bool script = ScriptExtensions.Contains(extension);
        bool pe = analysis.FileType == "Windows PE";
        // A shortcut carries a command line and an OLE package carries its strings in the open, so both are
        // read as content. Only formats whose bytes are compressed or unrecognized stay outside this pass.
        bool structured = analysis.FileType is "PDF" or ShortcutType or OleCompoundType;
        if (!script && !pe && !structured) return;

        analysis.CapabilityScanApplicable = true;
        if (stream.Length == 0) return;

        long remainingScanBytes = Math.Max(0, MaxCapabilityBytesPerScan - budget.BytesScanned);
        long targetBytes = Math.Min(stream.Length, Math.Min(MaxCapabilityBytesPerFile, remainingScanBytes));
        if (targetBytes == 0)
        {
            LimitInspection(analysis, InspectionLimit.Content, new("watch", "capability-scan-budget", "能力語の内容走査が1回あたりの上限に達しました", "Capability content scanning reached the per-inspection budget", 8));
            return;
        }

        stream.Position = 0;
        byte[] buffer = new byte[CapabilityChunkBytes + CapabilityOverlapBytes];
        var matchedCapabilities = new HashSet<string>(StringComparer.Ordinal);
        bool pdfActiveMatched = false;
        int overlap = 0;
        Stopwatch timer = Stopwatch.StartNew();

        try
        {
            while (analysis.CapabilityScannedBytes < targetBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (timer.Elapsed >= MaxCapabilityTimePerFile || budget.Elapsed + timer.Elapsed >= MaxCapabilityTimePerScan)
                {
                    LimitInspection(analysis, InspectionLimit.Content, new("watch", "capability-scan-time", "能力語の内容走査が時間上限に達しました", "Capability content scanning reached its time limit", 8));
                    return;
                }

                int requested = (int)Math.Min(CapabilityChunkBytes, targetBytes - analysis.CapabilityScannedBytes);
                int read = stream.Read(buffer, overlap, requested);
                if (read == 0) break;

                analysis.CapabilityScannedBytes += read;
                budget.BytesScanned += read;
                int available = overlap + read;
                string ascii = Encoding.Latin1.GetString(buffer, 0, available);
                int evenUnicodeBytes = available & ~1;
                string unicodeEven = evenUnicodeBytes >= 2 ? Encoding.Unicode.GetString(buffer, 0, evenUnicodeBytes) : String.Empty;
                int oddUnicodeBytes = (available - 1) & ~1;
                string unicodeOdd = oddUnicodeBytes >= 2 ? Encoding.Unicode.GetString(buffer, 1, oddUnicodeBytes) : String.Empty;
                string searchable = ascii + "\n" + unicodeEven + "\n" + unicodeOdd;

                foreach (var capability in CapabilityPatterns)
                {
                    if (matchedCapabilities.Contains(capability.Code)) continue;

                    bool matched;
                    try
                    {
                        matched = capability.Pattern.IsMatch(searchable);
                    }
                    catch (RegexMatchTimeoutException)
                    {
                        LimitInspection(analysis, InspectionLimit.Content, new("watch", "regex-time-limit", "能力語の照合が時間上限に達しました", "Capability matching reached its time limit", 8));
                        return;
                    }
                    if (!matched) continue;

                    matchedCapabilities.Add(capability.Code);
                    int score = script || analysis.FileType == ShortcutType
                        ? capability.Score
                        : Math.Max(4, capability.Score / 2);
                    AddIndicator(analysis, new(score >= 30 ? "danger" : "watch", capability.Code, capability.Ja, capability.En, score));
                }

                if (analysis.FileType == "PDF" && !pdfActiveMatched)
                {
                    try
                    {
                        if (PdfActivePattern.IsMatch(ascii))
                        {
                            pdfActiveMatched = true;
                            AddIndicator(analysis, new("watch", "pdf-active-action", "PDFにJavaScriptまたは自動起動アクションの兆候があります", "The PDF contains an indicator of JavaScript or an automatic launch action", 28));
                        }
                    }
                    catch (RegexMatchTimeoutException)
                    {
                        LimitInspection(analysis, InspectionLimit.Content, new("watch", "regex-time-limit", "PDF能力語の照合が時間上限に達しました", "PDF capability matching reached its time limit", 8));
                        return;
                    }
                }

                overlap = Math.Min(CapabilityOverlapBytes, available);
                Buffer.BlockCopy(buffer, available - overlap, buffer, 0, overlap);
            }

            if (analysis.CapabilityScannedBytes < stream.Length)
            {
                analysis.Limits |= InspectionLimit.Content;
                if (analysis.CapabilityScannedBytes >= MaxCapabilityBytesPerFile)
                {
                    AddIndicator(analysis, new("watch", "capability-file-limit", $"能力語の内容走査は1ファイル{FileAnalysis.FormatSize(MaxCapabilityBytesPerFile)}までです", $"Capability content scanning is limited to {FileAnalysis.FormatSize(MaxCapabilityBytesPerFile)} per file", 8));
                }
                else
                {
                    AddIndicator(analysis, new("watch", "capability-scan-budget", $"能力語の内容走査は1回{FileAnalysis.FormatSize(MaxCapabilityBytesPerScan)}までです", $"Capability content scanning is limited to {FileAnalysis.FormatSize(MaxCapabilityBytesPerScan)} per inspection", 8));
                }
            }
        }
        finally
        {
            timer.Stop();
            budget.Elapsed += timer.Elapsed;
        }
    }

    /// <summary>
    /// Turns a shortcut into the only question that matters about one: what would it run, and with what.
    /// The recovered command line is matched with the same capability patterns as a script, because a
    /// command line is what a script is. Nothing here resolves, follows, or launches the target.
    /// </summary>
    private static void InspectShortcut(FileStream stream, FileAnalysis analysis)
    {
        ShortcutDetails details;
        try
        {
            details = ShortcutInspector.Read(stream, analysis.Size);
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or OverflowException)
        {
            LimitInspection(analysis, InspectionLimit.Structure, new("watch", "shortcut-unreadable", "ショートカットの構造を読み取れませんでした", "The shortcut structure could not be read", 25));
            return;
        }

        analysis.ShortcutTarget = FormatShortcutField(details.Target);
        analysis.ShortcutArguments = FormatShortcutField(details.Arguments);

        if (details.Truncated)
        {
            LimitInspection(analysis, InspectionLimit.Structure, new("watch", "shortcut-truncated", "ショートカットの構造が途中で終わっており、全体を読めていません", "The shortcut structure ends early, so it could not be read in full", 25));
        }

        // These three come from the header and the flags, so they survive a command line that could not be
        // recovered. They are checked before the early return for exactly that reason: a shortcut that
        // defeats the string walk must not also shed the evidence the header still carries.
        if (details.ShowCommand == ShowMinimizedNoActivate)
        {
            AddIndicator(analysis, new("watch", "shortcut-hidden-start", "ショートカットは最小化・非アクティブで起動する設定です", "The shortcut is set to start minimized and inactive", 20));
        }

        if (details.RunAsAdministrator)
        {
            AddIndicator(analysis, new("watch", "shortcut-run-as-admin", "ショートカットは昇格して実行するよう指定されています", "The shortcut is marked to run elevated", 10));
        }

        if (details.Arguments.Length > MaxOrdinaryShortcutArguments)
        {
            AddIndicator(analysis, new("watch", "shortcut-long-command", "ショートカットの引数が通常より長く、内容を隠している可能性があります", "The shortcut carries an unusually long command line", 15));
        }

        // The joined surface is prefixed with a space so a command line that begins with a switch still has
        // the leading separator the capability patterns expect.
        string surface = " " + details.CommandSurface;
        if (surface.Length <= 1) return;

        try
        {
            foreach (var capability in CapabilityPatterns)
            {
                if (!capability.Pattern.IsMatch(surface)) continue;
                AddIndicator(analysis, new(capability.Score >= 30 ? "danger" : "watch", capability.Code, capability.Ja, capability.En, capability.Score));
            }

            if (ShortcutInterpreterPattern.IsMatch(surface))
            {
                // Legitimate developer tooling ships shortcuts that open a shell with arguments — measured on
                // this machine, 6 of 72 Start Menu shortcuts do. Pointing at an interpreter is therefore only
                // a starting point; the danger call is reserved for one that also carries another signal.
                bool corroborated =
                    analysis.InternetZone >= 3 ||
                    details.Arguments.Length > MaxOrdinaryShortcutArguments ||
                    analysis.Indicators.Any(existing => existing.Code is
                        "encoded-command" or "hidden-window" or "remote-download" or "obfuscation" or
                        "defender-change" or "persistence" or "process-injection" or "credential-access" or
                        "double-extension" or "unicode-control");

                AddIndicator(analysis, details.Arguments.Length == 0
                    ? new("watch", "shortcut-interpreter", "ショートカットの起動先がスクリプト実行環境です", "The shortcut points at a script interpreter", 12)
                    : corroborated
                        ? new("danger", "shortcut-runs-interpreter", "ショートカットがスクリプト実行環境を起動し、その引数に別の危険指標もあります", "The shortcut launches a script interpreter, and its command line carries other risk indicators too", 45)
                        : new("watch", "shortcut-interpreter-command", "ショートカットがスクリプト実行環境を引数付きで起動します", "The shortcut launches a script interpreter with arguments", 15));
            }
        }
        catch (RegexMatchTimeoutException)
        {
            LimitInspection(analysis, InspectionLimit.Content, new("watch", "regex-time-limit", "能力語の照合が時間上限に達しました", "Capability matching reached its time limit", 8));
        }

    }

    private static string FormatShortcutField(string value) =>
        String.IsNullOrWhiteSpace(value) ? "—" : SecurityPolicy.SanitizeText(value, 512);

    private static void InspectStructuredFormats(FileStream stream, FileAnalysis analysis, CancellationToken cancellationToken)
    {
        // A container this product can name but cannot open is the same failure the OLE case was: refusing to
        // look is not the same as having looked. Scoring it at the floor would let an attacker pick the
        // wrapper we do not open — the .7z form of a payload must not be cheaper than the .zip form.
        if (analysis.FileType is RarType or SevenZipType or GZipType or CabinetType or IsoImageType)
        {
            LimitInspection(analysis, InspectionLimit.Structure, new("watch", "container-unopened", "この書庫・イメージ形式は中身を開けないため、内部は未確認です", "This archive or image format is not opened, so its contents are unexamined", 15));
            return;
        }

        if (analysis.FileType == OleCompoundType)
        {
            // The capability pass reads this file's strings, but the storage tree, the installer tables and
            // any VBA project inside are not parsed. Reporting that as a complete inspection would repeat
            // exactly the lie the first-8-MiB sample used to tell.
            LimitInspection(analysis, InspectionLimit.Structure, new("watch", "ole-structure-unparsed", "MSIやOfficeなどOLE複合ファイルの内部構造は解析していません", "The internal structure of this OLE compound file (installer or Office document) was not parsed", 10));
            return;
        }

        if (analysis.FileType != "ZIP / package") return;
        if (analysis.Size > SecurityPolicy.MaxArchiveInspectionBytes)
        {
            LimitInspection(analysis, InspectionLimit.Structure, new("watch", "archive-size-limit", $"ZIP内部確認は{FileAnalysis.FormatSize(SecurityPolicy.MaxArchiveInspectionBytes)}までです", $"ZIP metadata inspection is limited to {FileAnalysis.FormatSize(SecurityPolicy.MaxArchiveInspectionBytes)}", 12));
            return;
        }

        try
        {
            stream.Position = 0;
            ValidateArchiveCentralDirectory(stream, cancellationToken);
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
            bool entriesTruncated = false;
            int count = 0;
            long declaredBytes = 0;

            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                count++;
                if (count > MaxArchiveEntries)
                {
                    entriesTruncated = true;
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
                uint unixType = (unchecked((uint)entry.ExternalAttributes) >> 16) & 0xF000;
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
            if (entriesTruncated) LimitInspection(analysis, InspectionLimit.Structure, new("watch", "archive-limit", $"内部一覧は{MaxArchiveEntries}件で打ち切りました", $"Archive inspection stopped at {MaxArchiveEntries} entries", 10));
        }
        catch (ArchiveSafetyLimitException)
        {
            LimitInspection(analysis, InspectionLimit.Structure, new("watch", "archive-directory-limit", "ZIP中央ディレクトリが安全上限を超えたため、標準解析へ渡さず停止しました", "The ZIP central directory exceeded the safety boundary and was rejected before standard parsing", 25));
        }
        catch (InvalidDataException)
        {
            LimitInspection(analysis, InspectionLimit.Structure, new("watch", "invalid-archive", "ZIP形式として正常に読み取れませんでした", "The package could not be read as a valid ZIP archive", 20));
        }
        catch (OverflowException)
        {
            LimitInspection(analysis, InspectionLimit.Structure, new("watch", "invalid-archive", "ZIP形式の数値境界が不正です", "The package contains invalid ZIP numeric boundaries", 20));
        }
        catch (IOException)
        {
            LimitInspection(analysis, InspectionLimit.Structure, new("watch", "archive-read-error", "圧縮ファイルの内部確認を完了できませんでした", "Archive content inspection could not be completed", 12));
        }
    }

    private static void ValidateArchiveCentralDirectory(Stream stream, CancellationToken cancellationToken)
    {
        if (!stream.CanRead || !stream.CanSeek)
        {
            throw new InvalidDataException("ZIP preflight requires a readable, seekable stream.");
        }

        long originalPosition = stream.Position;
        try
        {
            long length = stream.Length;
            if (length < EndOfCentralDirectoryLength)
            {
                throw new InvalidDataException("The ZIP end record is missing.");
            }

            int tailLength = checked((int)Math.Min(length, EndOfCentralDirectoryLength + UInt16.MaxValue));
            byte[] tail = new byte[tailLength];
            stream.Position = length - tailLength;
            stream.ReadExactly(tail);

            int endIndex = FindUnambiguousEndOfCentralDirectory(tail);
            if (endIndex < 0)
            {
                throw new InvalidDataException("The ZIP end record is invalid.");
            }

            ReadOnlySpan<byte> endRecord = tail.AsSpan(endIndex, EndOfCentralDirectoryLength);
            long endOffset = checked(length - tailLength + endIndex);
            ushort diskNumber = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[4..]);
            ushort centralDirectoryDisk = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[6..]);
            ushort entriesOnDisk16 = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[8..]);
            ushort totalEntries16 = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[10..]);
            uint centralDirectorySize32 = BinaryPrimitives.ReadUInt32LittleEndian(endRecord[12..]);
            uint centralDirectoryOffset32 = BinaryPrimitives.ReadUInt32LittleEndian(endRecord[16..]);

            bool requiresZip64 =
                diskNumber == UInt16.MaxValue || centralDirectoryDisk == UInt16.MaxValue ||
                entriesOnDisk16 == UInt16.MaxValue || totalEntries16 == UInt16.MaxValue ||
                centralDirectorySize32 == UInt32.MaxValue || centralDirectoryOffset32 == UInt32.MaxValue;

            ulong entryCount;
            ulong centralDirectorySize;
            ulong centralDirectoryOffset;
            long directoryTerminalOffset = endOffset;
            if (requiresZip64)
            {
                ReadZip64DirectoryMetadata(
                    stream,
                    endOffset,
                    out entryCount,
                    out centralDirectorySize,
                    out centralDirectoryOffset,
                    out directoryTerminalOffset);
            }
            else
            {
                if (diskNumber != 0 || centralDirectoryDisk != 0 || entriesOnDisk16 != totalEntries16)
                {
                    throw new InvalidDataException("Split ZIP archives are not accepted.");
                }
                entryCount = totalEntries16;
                centralDirectorySize = centralDirectorySize32;
                centralDirectoryOffset = centralDirectoryOffset32;
            }

            if (entryCount > MaxArchiveEntries || centralDirectorySize > MaxArchiveCentralDirectoryBytes)
            {
                throw new ArchiveSafetyLimitException();
            }
            if (centralDirectoryOffset > Int64.MaxValue || centralDirectorySize > Int64.MaxValue)
            {
                throw new InvalidDataException("The ZIP central directory exceeds supported offsets.");
            }

            long centralStart = checked((long)centralDirectoryOffset);
            long centralEnd = checked(centralStart + (long)centralDirectorySize);
            if (centralStart < 0 || centralEnd != directoryTerminalOffset || (entryCount == 0 && centralStart != 0))
            {
                throw new InvalidDataException("The ZIP central-directory boundary is ambiguous or inconsistent.");
            }

            ValidateCentralDirectoryRecords(stream, centralStart, centralEnd, checked((int)entryCount), cancellationToken);
        }
        finally
        {
            stream.Position = originalPosition;
        }
    }

    private static int FindUnambiguousEndOfCentralDirectory(ReadOnlySpan<byte> tail)
    {
        int match = -1;
        for (int index = tail.Length - EndOfCentralDirectoryLength; index >= 0; index--)
        {
            ReadOnlySpan<byte> candidate = tail[index..];
            if (BinaryPrimitives.ReadUInt32LittleEndian(candidate) != EndOfCentralDirectorySignature) continue;
            if (match >= 0) return -1;
            ushort commentLength = BinaryPrimitives.ReadUInt16LittleEndian(candidate[20..]);
            if (index + EndOfCentralDirectoryLength + commentLength != tail.Length) return -1;
            match = index;
        }
        return match;
    }

    private static void ReadZip64DirectoryMetadata(
        Stream stream,
        long endOffset,
        out ulong entryCount,
        out ulong centralDirectorySize,
        out ulong centralDirectoryOffset,
        out long zip64EndOffset)
    {
        const int locatorLength = 20;
        const int fixedZip64EndLength = 56;
        if (endOffset < locatorLength)
        {
            throw new InvalidDataException("The ZIP64 locator is missing.");
        }

        Span<byte> locator = stackalloc byte[locatorLength];
        stream.Position = endOffset - locatorLength;
        stream.ReadExactly(locator);
        if (BinaryPrimitives.ReadUInt32LittleEndian(locator) != Zip64EndOfCentralDirectoryLocatorSignature ||
            BinaryPrimitives.ReadUInt32LittleEndian(locator[4..]) != 0 ||
            BinaryPrimitives.ReadUInt32LittleEndian(locator[16..]) != 1)
        {
            throw new InvalidDataException("Split or malformed ZIP64 archives are not accepted.");
        }

        ulong zip64OffsetValue = BinaryPrimitives.ReadUInt64LittleEndian(locator[8..]);
        if (zip64OffsetValue > Int64.MaxValue)
        {
            throw new InvalidDataException("The ZIP64 end record offset is unsupported.");
        }
        zip64EndOffset = checked((long)zip64OffsetValue);
        if (zip64EndOffset < 0 || zip64EndOffset > endOffset - locatorLength - fixedZip64EndLength)
        {
            throw new InvalidDataException("The ZIP64 end record points outside the archive.");
        }

        Span<byte> zip64End = stackalloc byte[fixedZip64EndLength];
        stream.Position = zip64EndOffset;
        stream.ReadExactly(zip64End);
        ulong zip64RecordSize = BinaryPrimitives.ReadUInt64LittleEndian(zip64End[4..]);
        if (BinaryPrimitives.ReadUInt32LittleEndian(zip64End) != Zip64EndOfCentralDirectorySignature ||
            zip64RecordSize < 44 || zip64RecordSize > MaxArchiveCentralDirectoryBytes ||
            checked(zip64EndOffset + 12 + (long)zip64RecordSize) != endOffset - locatorLength ||
            BinaryPrimitives.ReadUInt32LittleEndian(zip64End[16..]) != 0 ||
            BinaryPrimitives.ReadUInt32LittleEndian(zip64End[20..]) != 0)
        {
            throw new InvalidDataException("The ZIP64 end record is malformed or unsupported.");
        }

        ulong entriesOnDisk = BinaryPrimitives.ReadUInt64LittleEndian(zip64End[24..]);
        entryCount = BinaryPrimitives.ReadUInt64LittleEndian(zip64End[32..]);
        if (entriesOnDisk != entryCount)
        {
            throw new InvalidDataException("Split ZIP64 archives are not accepted.");
        }
        centralDirectorySize = BinaryPrimitives.ReadUInt64LittleEndian(zip64End[40..]);
        centralDirectoryOffset = BinaryPrimitives.ReadUInt64LittleEndian(zip64End[48..]);
    }

    private static void ValidateCentralDirectoryRecords(
        Stream stream,
        long centralStart,
        long centralEnd,
        int expectedEntries,
        CancellationToken cancellationToken)
    {
        const int fixedHeaderLength = 46;
        stream.Position = centralStart;
        Span<byte> header = stackalloc byte[fixedHeaderLength];
        for (int entryIndex = 0; entryIndex < expectedEntries; entryIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (centralEnd - stream.Position < fixedHeaderLength)
            {
                throw new InvalidDataException("A ZIP central-directory header is truncated.");
            }

            stream.ReadExactly(header);
            if (BinaryPrimitives.ReadUInt32LittleEndian(header) != CentralDirectoryHeaderSignature)
            {
                throw new InvalidDataException("A ZIP central-directory header signature is invalid.");
            }

            ushort nameLength = BinaryPrimitives.ReadUInt16LittleEndian(header[28..]);
            ushort extraLength = BinaryPrimitives.ReadUInt16LittleEndian(header[30..]);
            ushort commentLength = BinaryPrimitives.ReadUInt16LittleEndian(header[32..]);
            if (nameLength > MaxArchiveEntryNameBytes)
            {
                throw new ArchiveSafetyLimitException();
            }

            long variableLength = checked((long)nameLength + extraLength + commentLength);
            if (variableLength > centralEnd - stream.Position)
            {
                throw new InvalidDataException("A ZIP central-directory entry exceeds its declared boundary.");
            }
            stream.Position = checked(stream.Position + variableLength);
        }

        if (stream.Position < centralEnd)
        {
            const int digitalSignatureHeaderLength = 6;
            if (centralEnd - stream.Position < digitalSignatureHeaderLength)
            {
                throw new InvalidDataException("The ZIP central-directory trailer is invalid.");
            }
            Span<byte> signatureHeader = stackalloc byte[digitalSignatureHeaderLength];
            stream.ReadExactly(signatureHeader);
            ushort signatureLength = BinaryPrimitives.ReadUInt16LittleEndian(signatureHeader[4..]);
            if (BinaryPrimitives.ReadUInt32LittleEndian(signatureHeader) != CentralDirectoryDigitalSignature ||
                signatureLength != centralEnd - stream.Position)
            {
                throw new InvalidDataException("The ZIP central-directory trailer is unsupported.");
            }
            stream.Position = centralEnd;
        }

        if (stream.Position != centralEnd)
        {
            throw new InvalidDataException("The ZIP central-directory size is inconsistent.");
        }
    }

    internal static bool IsArchiveStructureWithinLimits(Stream stream)
    {
        try
        {
            ValidateArchiveCentralDirectory(stream, CancellationToken.None);
            return true;
        }
        catch (Exception exception) when (exception is InvalidDataException or ArchiveSafetyLimitException or OverflowException)
        {
            return false;
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

    private static void ValidateDirectoriesUnchanged(IEnumerable<DirectoryObservation> directories, ScanResult result)
    {
        foreach (DirectoryObservation observation in directories)
        {
            try
            {
                using SafeFileHandle handle = SecureFileReader.OpenDirectoryGuard(observation.Path);
                if (SecureFileReader.GetSnapshot(handle) != observation.Snapshot)
                {
                    MarkPartial(result, "A directory changed after enumeration, so the folder result is incomplete.");
                }
            }
            catch (Exception exception) when (IsExpectedFileFailure(exception))
            {
                MarkPartial(result, "A directory could not be revalidated after enumeration.");
            }
        }
    }

    private static void MarkChangedDuringScan(FileAnalysis analysis)
    {
        // Everything read before the change describes a file that no longer exists, so no aspect survives it.
        analysis.SignatureStatus = "Indeterminate";
        analysis.Signer = "—";
        LimitInspection(analysis, InspectionLimit.Everything, new("danger", "changed-during-scan", "調査中にファイルが変更されたため、結果を信頼できません", "The file changed during inspection, so the result is not trustworthy", 60));
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
            SignatureStatus = "Indeterminate"
        };
        LimitInspection(analysis, InspectionLimit.Everything, new("watch", "file-read-failed", "ファイルを安全に読み取れなかったため、内容を判定できません", "The file could not be read safely, so its content is indeterminate", 30));
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

    internal static void PromoteInspectionLimits(ScanResult result)
    {
        // Anything that made the result partial before this point was a fact about the walk — a skipped
        // reparse point, a directory that changed, a safety limit on enumeration — not about a file.
        result.TraversalComplete = !result.IsPartial;

        InspectionLimit limits = result.Limits;
        if (limits == InspectionLimit.None) return;

        string aspects = String.Join(", ", InspectionAspects.All
            .Where(aspect => (limits & aspect) != 0)
            .Select(aspect => InspectionAspects.Describe(aspect, japanese: false)));
        MarkPartial(result, $"Not every file was fully examined ({aspects}).");
    }

    private static void ApplySignatureRisk(FileAnalysis analysis)
    {
        bool active = IsActiveContentExtension(GetInspectionExtension(analysis));
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
        analysis.FileType == "Windows PE" || SignatureExtensions.Contains(GetInspectionExtension(analysis));

    /// <summary>
    /// Records that one aspect of a file was not examined, together with the reason the operator will read.
    /// The two happen in one call on purpose: a limit the report never mentions is indistinguishable from a
    /// clean result, and that silence is the failure this product exists to prevent.
    /// </summary>
    private static void LimitInspection(FileAnalysis analysis, InspectionLimit aspect, Indicator reason)
    {
        analysis.Limits |= aspect;
        AddIndicator(analysis, reason);
    }

    private static void AddIndicator(FileAnalysis analysis, Indicator indicator)
    {
        if (analysis.Indicators.All(existing => !existing.Code.Equals(indicator.Code, StringComparison.OrdinalIgnoreCase)))
        {
            analysis.Indicators.Add(indicator);
        }
    }

    private sealed class InspectionSafetyLimitException : IOException
    {
    }

    private sealed class ArchiveSafetyLimitException : IOException
    {
    }

    private sealed class CapabilityScanBudget
    {
        public long BytesScanned { get; set; }
        public TimeSpan Elapsed { get; set; }
    }

    private readonly record struct PendingDirectory(string Path, int Depth);
    private readonly record struct DirectoryObservation(string Path, SecureFileSnapshot Snapshot);
    private sealed record CollectedTargets(List<string> Files, List<DirectoryObservation> Directories);
}
