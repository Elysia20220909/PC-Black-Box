using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using OpenMcdf;

namespace DestinyBlackBox;

internal static partial class ProductSelfTest
{
    private static bool HasOleFinding(FileAnalysis file, string code) =>
        file.Indicators.Any(indicator => indicator.Code.Equals(code, StringComparison.Ordinal));

    private static byte[] OrdinaryOleBytes() => CreateOleCompoundBytes(root =>
    {
        using CfbStream body = root.CreateStream("Notes");
        body.Write("ordinary document text"u8);
    });

    private static bool TestOrdinaryOlePreservesCoverageAndInput() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "ordinary.dat");
            byte[] bytes = OrdinaryOleBytes();
            File.WriteAllBytes(path, bytes);
            FileAnalysis file = Inspect(path).Files.Single();
            return file.FileType == FileInspector.OleCompoundType &&
                   file.Limits == InspectionLimit.None &&
                   file.ArchiveContentScannedBytes == "ordinary document text"u8.Length &&
                   SHA256.HashData(File.ReadAllBytes(path)).SequenceEqual(SHA256.HashData(bytes)) &&
                   Directory.GetFiles(directory).Length == 1;
        });

    // These are CFB name fixtures, not a claim to implement the Installer database format.
    // Neither an absent literal table nor an encoded name may imply decoded MSI semantics.
    private static bool TestInstallerWithoutLiteralTableName() =>
        WithFixtureDirectory(directory =>
        {
            foreach (string extension in new[] { ".msi", ".MSP" })
            {
                foreach (string name in new[] { "Notes", "\u4840\u3f3f\u4566\u3e72" })
                {
                    string path = Path.Combine(directory, "installer" + extension);
                    File.WriteAllBytes(path, CreateOleCompoundBytes(root =>
                    {
                        using CfbStream body = root.CreateStream(name);
                        body.Write("table bytes"u8);
                    }));
                    FileAnalysis file = Inspect(path).Files.Single();
                    if (!HasOleFinding(file, "ole-tables-unparsed") ||
                        HasOleFinding(file, "ole-custom-action") ||
                        HasOleFinding(file, "ole-structure-unparsed") ||
                        (file.Limits & InspectionLimit.Structure) == 0) return false;
                }
            }
            return true;
        });

    private static bool TestOleRegexTimeoutDoesNotAbortScan() =>
        WithFixtureDirectory(directory =>
        {
            File.WriteAllBytes(Path.Combine(directory, "first.dat"), OrdinaryOleBytes());
            File.WriteAllBytes(Path.Combine(directory, "second.dat"), OrdinaryOleBytes());
            int calls = 0;
            var inspector = new FileInspector(TimeProvider.System, (pattern, text) =>
            {
                if (++calls == 1)
                {
                    // Exercise an actual regex timeout at the OLE matching seam. The fixture is
                    // synthetic and the deliberately backtracking pattern has a one-millisecond limit.
                    var slow = new Regex("(a+)+$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(1));
                    return slow.IsMatch(new string('a', 32768) + "!");
                }
                return pattern.IsMatch(text);
            });
            ScanResult result = inspector.ScanAsync(directory, null, default).GetAwaiter().GetResult();
            FileAnalysis[] limited = result.Files.Where(file => HasOleFinding(file, "ole-regex-time-limit")).ToArray();
            return calls > 1 && result.Files.Count == 2 && limited.Length == 1 &&
                   limited[0].Limits == (InspectionLimit.Content | InspectionLimit.Structure) &&
                   result.Files.Count(file => file.Limits == InspectionLimit.None) == 1 &&
                   result.CompletenessCode == "INCOMPLETE";
        });

    private sealed class InspectionTestClock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public void Advance(TimeSpan elapsed) => _ticks += elapsed.Ticks;
    }

    private static bool TestOleAndZipShareFileTime() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "polyglot.dat");
            File.WriteAllBytes(path, [.. OrdinaryOleBytes(), .. CreateZipBytes("payload.txt", "tail"u8.ToArray())]);
            FileAnalysis control = Inspect(path).Files.Single();
            if (!control.EmbeddedZipPayload || control.Limits != InspectionLimit.Structure ||
                !HasOleFinding(control, "archive-prefix") ||
                control.ArchiveContentScannedBytes != "ordinary document text"u8.Length + 4) return false;

            var clock = new InspectionTestClock();
            bool advanced = false;
            var inspector = new FileInspector(clock, (pattern, text) =>
            {
                if (!advanced)
                {
                    clock.Advance(FileInspector.MaxArchiveContentTimePerFile);
                    advanced = true;
                }
                return pattern.IsMatch(text);
            });
            FileAnalysis file = inspector.ScanAsync(path, null, default).GetAwaiter().GetResult().Files.Single();
            return advanced && HasOleFinding(file, "ole-content-time") &&
                   HasOleFinding(file, "archive-content-time") &&
                   file.ArchiveContentScannedBytes == "ordinary document text"u8.Length &&
                   file.Limits == (InspectionLimit.Content | InspectionLimit.Structure);
        });

    private static bool TestOleFilesShareScanTime() =>
        WithFixtureDirectory(directory =>
        {
            for (int index = 0; index < 6; index++)
                File.WriteAllBytes(Path.Combine(directory, $"file-{index}.dat"), OrdinaryOleBytes());
            var clock = new InspectionTestClock();
            int advances = 0;
            Regex? firstPattern = null;
            var inspector = new FileInspector(clock, (pattern, _) =>
            {
                firstPattern ??= pattern;
                if (ReferenceEquals(pattern, firstPattern))
                {
                    advances++;
                    clock.Advance(FileInspector.MaxArchiveContentTimePerFile);
                }
                return false;
            });
            ScanResult result = inspector.ScanAsync(directory, null, default).GetAwaiter().GetResult();
            return result.Files.Count == 6 && advances == 4 &&
                   result.Files.All(file => HasOleFinding(file, "ole-content-time")) &&
                   result.Files.Count(file => file.ArchiveContentScannedBytes == 0) == 2;
        });

    private static bool TestOleDepthBoundary() =>
        WithFixtureDirectory(directory =>
        {
            foreach (int depth in new[] { FileInspector.MaxOleStorageDepth, FileInspector.MaxOleStorageDepth + 1 })
            {
                string path = Path.Combine(directory, "depth.dat");
                File.WriteAllBytes(path, CreateOleCompoundBytes(root =>
                {
                    Storage parent = root;
                    for (int level = 0; level < depth; level++) parent = parent.CreateStorage("Child");
                    using CfbStream body = parent.CreateStream("Notes");
                    body.Write("leaf"u8);
                }));
                FileAnalysis file = Inspect(path).Files.Single();
                bool over = depth > FileInspector.MaxOleStorageDepth;
                if (HasOleFinding(file, "ole-depth-limit") != over ||
                    ((file.Limits & InspectionLimit.Structure) != 0) != over) return false;
            }
            return true;
        });

    private static bool TestOleEntryBoundary() =>
        WithFixtureDirectory(directory =>
        {
            foreach (int count in new[] { 10000, 10016 })
            {
                string path = Path.Combine(directory, "entries.dat");
                byte[] bytes = CreateOleCompoundBytes(root =>
                {
                    // Put the wide directory at the depth boundary. Each leaf still consumes
                    // an entry visit, without thousands of redundant name lookups/open operations.
                    Storage parent = root;
                    for (int depth = 0; depth < FileInspector.MaxOleStorageDepth; depth++)
                        parent = parent.CreateStorage("Child");
                    for (int index = FileInspector.MaxOleStorageDepth; index < count; index++)
                        parent.CreateStorage($"Entry{index:D5}");
                });
                if (count > 10000)
                {
                    // Poison a tail beyond the first over-limit entry (and the iterator's lookahead).
                    // Eager ToList would reach it and fail before recording the entry limit.
                    SetCfbUInt(bytes, CfbDirectoryEntryOffset(bytes, (uint)count) + 0x48, (uint)count);
                }
                File.WriteAllBytes(path, bytes);
                var inspector = new FileInspector(new InspectionTestClock(), static (_, _) => false);
                FileAnalysis file = inspector.ScanAsync(path, null, default).GetAwaiter().GetResult().Files.Single();
                if (HasOleFinding(file, "ole-entry-limit") != (count > 10000) ||
                    HasOleFinding(file, "ole-content-time") ||
                    HasOleFinding(file, "ole-structure-unparsed") ||
                    !HasOleFinding(file, "ole-depth-limit")) return false;
            }
            return true;
        });

    private static bool TestOleStreamByteBoundary() =>
        WithFixtureDirectory(directory =>
        {
            foreach (long size in new[] { FileInspector.MaxArchiveContentBytesPerEntry - 1,
                         FileInspector.MaxArchiveContentBytesPerEntry, FileInspector.MaxArchiveContentBytesPerEntry + 1 })
            {
                string path = Path.Combine(directory, "stream-boundary.dat");
                using (FileStream target = File.Create(path))
                using (var root = RootStorage.Create(target, OpenMcdf.Version.V3, StorageModeFlags.LeaveOpen))
                using (CfbStream body = root.CreateStream("Body"))
                {
                    byte[] block = new byte[1024 * 1024];
                    for (long written = 0; written < size; written += block.Length)
                        body.Write(block.AsSpan(0, (int)Math.Min(block.Length, size - written)));
                }
                var inspector = new FileInspector(new InspectionTestClock(), static (_, _) => false);
                FileAnalysis file = inspector.ScanAsync(path, null, default).GetAwaiter().GetResult().Files.Single();
                bool over = size > FileInspector.MaxArchiveContentBytesPerEntry;
                if (HasOleFinding(file, "ole-stream-budget") != over ||
                    file.ArchiveContentScannedBytes != Math.Min(size, FileInspector.MaxArchiveContentBytesPerEntry) ||
                    file.Limits != (over ? InspectionLimit.Content | InspectionLimit.Structure : InspectionLimit.None))
                {
                    Console.Error.WriteLine($"OLE_BYTE_BOUNDARY size={size} scanned={file.ArchiveContentScannedBytes} limits={file.Limits}");
                    return false;
                }
            }
            return true;
        });

    private static bool TestOleAndZipShareBytes() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "byte-budget.dat");
            // Populate directly into the private fixture file; do not retain a 256 MiB CFB in RAM.
            using (FileStream target = File.Create(path))
            {
                using (var root = RootStorage.Create(target, OpenMcdf.Version.V3, StorageModeFlags.LeaveOpen))
                {
                    byte[] block = new byte[1024 * 1024];
                    for (int index = 0; index < 5; index++)
                    {
                        using CfbStream body = root.CreateStream($"Body{index}");
                        int blocks = index < 4 ? 64 : 1;
                        for (int part = 0; part < blocks; part++) body.Write(block);
                    }
                }
                target.Position = target.Length;
                target.Write(CreateZipBytes("tail.txt", "tail"u8.ToArray()));
            }
            var inspector = new FileInspector(new InspectionTestClock(), static (_, _) => false);
            FileAnalysis file = inspector.ScanAsync(path, null, default).GetAwaiter().GetResult().Files.Single();
            return file.EmbeddedZipPayload && file.ArchiveEntries == 1 &&
                   HasOleFinding(file, "ole-stream-budget") && HasOleFinding(file, "archive-content-limit") &&
                   file.ArchiveContentScannedBytes == FileInspector.MaxArchiveContentBytesPerFile &&
                   (file.Limits & (InspectionLimit.Content | InspectionLimit.Structure)) ==
                       (InspectionLimit.Content | InspectionLimit.Structure);
        });

    // Helpers address V3 fixtures generated here, not arbitrary user files. Resolve sector IDs
    // from the header instead of depending on the allocator's current output layout.
    private static uint CfbUInt(byte[] bytes, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, sizeof(uint)));

    private static void SetCfbUInt(byte[] bytes, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset, sizeof(uint)), value);

    private static int CfbSectorOffset(uint sector) => checked((int)(sector + 1) * 512);

    private static int FirstCfbBodyEntry(byte[] bytes) => CfbSectorOffset(CfbUInt(bytes, 0x30)) + 128;

    private static int CfbDirectoryEntryOffset(byte[] bytes, uint entryId)
    {
        uint sector = CfbUInt(bytes, 0x30);
        for (uint index = 0; index < entryId / 4; index++)
        {
            uint fatSector = CfbUInt(bytes, checked(0x4C + (int)(sector / 128) * 4));
            sector = CfbUInt(bytes, checked(CfbSectorOffset(fatSector) + (int)(sector % 128) * 4));
        }
        return checked(CfbSectorOffset(sector) + (int)(entryId % 4) * 128);
    }

    private static byte[] OleBodyBytes(int length) => CreateOleCompoundBytes(root =>
    {
        using CfbStream body = root.CreateStream("Body");
        body.Write(new byte[length]);
    });

    private static bool IsMalformedOle(FileAnalysis file) =>
        (file.Limits & InspectionLimit.Structure) != 0 &&
        (HasOleFinding(file, "ole-structure-unparsed") ||
         HasOleFinding(file, "ole-stream-read-error") ||
         HasOleFinding(file, "ole-stream-size-mismatch")) &&
        !HasOleFinding(file, "ole-content-time");

    private static bool TestOleCorruptChainsFailClosed() =>
        WithFixtureDirectory(directory =>
        {
            foreach (int size in new[] { 256, 8192 })
            {
                byte[] original = OleBodyBytes(size);
                string path = Path.Combine(directory, "chain.dat");
                File.WriteAllBytes(path, original);
                FileAnalysis control = Inspect(path).Files.Single();
                if (control.Limits != InspectionLimit.None || control.ArchiveContentScannedBytes != size) return false;
                uint firstSector = CfbUInt(original, FirstCfbBodyEntry(original) + 0x74);
                uint tableSector = size < 4096
                    ? CfbUInt(original, 0x3C)
                    : CfbUInt(original, checked(0x4C + (int)(firstSector / 128) * 4));
                int link = checked(CfbSectorOffset(tableSector) + (int)(firstSector % 128) * 4);
                foreach (uint next in new[] { UInt32.MaxValue, firstSector })
                {
                    byte[] corrupt = (byte[])original.Clone();
                    SetCfbUInt(corrupt, link, next);
                    File.WriteAllBytes(path, corrupt);
                    if (!IsMalformedOle(Inspect(path).Files.Single())) return false;
                }
            }
            return true;
        });

    private static bool TestOleTruncatedBodyIsIncomplete() =>
        WithFixtureDirectory(directory =>
        {
            byte[] bytes = OleBodyBytes(8192);
            string path = Path.Combine(directory, "short-body.dat");
            File.WriteAllBytes(path, bytes);
            FileAnalysis control = Inspect(path).Files.Single();
            if (control.Limits != InspectionLimit.None || control.ArchiveContentScannedBytes != 8192) return false;
            File.WriteAllBytes(path, bytes.AsSpan(0, bytes.Length - 7).ToArray());
            FileAnalysis file = Inspect(path).Files.Single();
            // Core 3.3.0 rejects this partial final sector before yielding body bytes.
            // This proves truncated-input rejection, not the defensive short-EOF branch.
            return HasOleFinding(file, "ole-stream-read-error") &&
                   file.ArchiveContentScannedBytes == 0 &&
                   file.Limits == (InspectionLimit.Content | InspectionLimit.Structure);
        });

    // Synthetic reader tests target the production body-reading path, not CFB compatibility.
    // A real truncated CFB is separately tested above and rejected earlier by OpenMcdf.
    private sealed class DeclaredLengthStream(byte[] content, long declaredLength) : MemoryStream(content, writable: false)
    {
        public override long Length => declaredLength;
        public long BytesRead { get; private set; }
        public int ReadCalls { get; private set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ReadCalls++;
            int read = base.Read(buffer, offset, Math.Min(count, 3));
            BytesRead += read;
            return read;
        }
    }

    private static bool TestOleBodyLengthEvidence()
    {
        foreach (int actualLength in new[] { 0, 3, 4, 5 })
        {
            using var source = new DeclaredLengthStream(new byte[actualLength], 4);
            var file = new FileAnalysis();
            long charged = 0;
            FileInspector.ScanOleStreamBody(source, 8, file, static () => { },
                (_, _, read) => charged += read);
            bool mismatch = actualLength != 4;
            if (HasOleFinding(file, "ole-stream-size-mismatch") != mismatch ||
                HasOleFinding(file, "ole-stream-budget") || HasOleFinding(file, "ole-stream-read-error") ||
                file.Limits != (mismatch ? InspectionLimit.Content | InspectionLimit.Structure : InspectionLimit.None) ||
                file.ArchiveContentScannedBytes != actualLength || charged != actualLength || source.BytesRead != actualLength)
                return false;
        }
        return true;
    }

    private static bool TestOleBodyReaderHonorsByteLimit()
    {
        foreach (int length in new[] { 0, 8 })
            foreach (long limit in new long[] { 0, 4, 8, 9 })
            {
                using var source = new DeclaredLengthStream(new byte[length], length);
                var file = new FileAnalysis();
                long charged = 0;
                FileInspector.ScanOleStreamBody(source, limit, file, static () => { },
                    (_, _, read) => charged += read);
                long expected = Math.Min(length, limit);
                int expectedReadCalls = (int)((expected + 2) / 3) + (limit > length ? 1 : 0);
                bool limited = length > limit;
                if (source.BytesRead != expected || charged != expected || file.ArchiveContentScannedBytes != expected ||
                    source.ReadCalls != expectedReadCalls ||
                    HasOleFinding(file, "ole-stream-budget") != limited ||
                    file.Limits != (limited ? InspectionLimit.Content | InspectionLimit.Structure : InspectionLimit.None))
                    return false;
            }
        return true;
    }

    private static bool TestOleBodyCancellationPropagates()
    {
        using var source = new DeclaredLengthStream(new byte[8], 8);
        using var cancellation = new CancellationTokenSource();
        var file = new FileAnalysis();
        try
        {
            FileInspector.ScanOleStreamBody(source, 8, file, cancellation.Token.ThrowIfCancellationRequested,
                (_, _, _) => cancellation.Cancel());
            return false;
        }
        catch (OperationCanceledException exception)
        {
            return exception.CancellationToken == cancellation.Token && source.BytesRead == 3 &&
                   file.ArchiveContentScannedBytes == 3 && file.Indicators.Count == 0;
        }
    }

    private static bool TestOleCorruptDirectoryIsLazy() =>
        WithFixtureDirectory(directory =>
        {
            byte[] bytes = OrdinaryOleBytes();
            // The first child points to itself as its left sibling.
            SetCfbUInt(bytes, FirstCfbBodyEntry(bytes) + 0x44, 1);
            using (var source = new MemoryStream(bytes, writable: false))
            using (var root = RootStorage.Open(source, StorageModeFlags.LeaveOpen | StorageModeFlags.StrictValidation))
            {
                IEnumerable<EntryInfo> entries = root.EnumerateEntries();
                bool rejected = false;
                try
                {
                    using IEnumerator<EntryInfo> cursor = entries.GetEnumerator();
                    _ = cursor.MoveNext();
                }
                catch (OpenMcdf.FileFormatException) { rejected = true; }
                if (!rejected) return false;
            }
            string path = Path.Combine(directory, "directory-cycle.dat");
            File.WriteAllBytes(path, bytes);
            return IsMalformedOle(Inspect(path).Files.Single());
        });

    private static bool TestOleCorruptDifatFailsClosed() =>
        WithFixtureDirectory(directory =>
        {
            const int size = 9 * 1024 * 1024;
            byte[] bytes = OleBodyBytes(size);
            // The normal body must actually require an external DIFAT; a tiny header-only
            // mutation would not prove that the affected FAT-sector enumeration was reached.
            if (CfbUInt(bytes, 0x2C) <= 109 || CfbUInt(bytes, 0x48) == 0) return false;
            string path = Path.Combine(directory, "difat.dat");
            File.WriteAllBytes(path, bytes);
            FileAnalysis control = Inspect(path).Files.Single();
            if (control.Limits != InspectionLimit.None || control.ArchiveContentScannedBytes != size) return false;
            SetCfbUInt(bytes, 0x44, checked((uint)(bytes.Length / 512 + 1)));
            File.WriteAllBytes(path, bytes);
            return IsMalformedOle(Inspect(path).Files.Single());
        });
}
