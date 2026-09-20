using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DestinyBlackBox;

internal enum DefenderQueryStage { Query, SecureProxy, Enumerate, Property }

/// <summary>Local, fixed SELECT queries only. No WMI methods, subscriptions, credentials or remote host input.</summary>
internal static class DefenderWmi
{
    private const string LocalNamespace = @"ROOT\Microsoft\Windows\Defender";
    private static readonly string[] ProtectionFields =
        ["AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled", "AntivirusSignatureLastUpdated"];
    private static readonly string[] HistoryFields =
        ["ThreatID", "InitialDetectionTime", "LastThreatStatusChangeTime", "ThreatStatusID", "ActionSuccess", "AdditionalActionsBitMask"];
    private static readonly string[] ExtendedFields =
        ["BehaviorMonitorEnabled", "IoavProtectionEnabled", "NISEnabled", "OnAccessProtectionEnabled",
            "IsTamperProtected", "DefenderSignaturesOutOfDate", "AMRunningMode"];

    internal static DefenderSnapshot Read(Action<DefenderSnapshot>? reportBasic = null)
    {
        var clock = Stopwatch.StartNew();
        DateTimeOffset observed = DateTimeOffset.UtcNow;
        bool initialized = false;
        DefenderConnectionStage stage = DefenderConnectionStage.Initialize;
        IWbemLocator? locator = null;
        IWbemServices? services = null;
        try
        {
            Marshal.ThrowExceptionForHR(CoInitializeEx(IntPtr.Zero, 0)); // dedicated MTA worker
            initialized = true;
            stage = DefenderConnectionStage.Activate;
            Guid classId = new("4590F811-1D3A-11D0-891F-00AA004B2E24");
            Guid interfaceId = typeof(IWbemLocator).GUID;
            Marshal.ThrowExceptionForHR(CoCreateInstance(ref classId, IntPtr.Zero, 1, ref interfaceId, out locator));
            stage = DefenderConnectionStage.Connect;
            // WBEM_FLAG_CONNECT_USE_MAX_WAIT: Windows bounds connection establishment at 120 s.
            // The caller returns after 10 s and refuses overlapping workers while this call finishes.
            Marshal.ThrowExceptionForHR(locator.ConnectServer(LocalNamespace, null, null, null, 0x80,
                null, IntPtr.Zero, out services));
            stage = DefenderConnectionStage.SecureProxy;
            SecureProxy(services);
            QueryResult status = Query(new NativeQueryCursor(services, "MSFT_MpComputerStatus", ProtectionFields),
                ProtectionFields, 1, () => clock.Elapsed);
            QueryResult history = Query(new NativeQueryCursor(services, "MSFT_MpThreatDetection", HistoryFields),
                HistoryFields, DefenderReader.MaxHistory, () => clock.Elapsed);
            DefenderSnapshot basic = Project(observed, status, history);
            reportBasic?.Invoke(basic);
            // Optional/newer provider fields cannot invalidate the original status/history queries.
            QueryResult extended = Query(new NativeQueryCursor(services, "MSFT_MpComputerStatus", ExtendedFields),
                ExtendedFields, 1, () => clock.Elapsed);
            return ProjectExtended(basic, extended);
        }
        catch (Exception error) { throw new DefenderConnectionException(stage, error); }
        finally
        {
            Release(services);
            Release(locator);
            if (initialized) CoUninitialize();
        }
    }

    internal sealed record QueryResult(DefenderReadState State, IReadOnlyList<object?[]> Rows,
        DefenderQueryStage? FailureStage = null, int? ErrorCode = null);

    internal static DefenderSnapshot ProjectExtended(DefenderSnapshot snapshot, QueryResult result)
    {
        DefenderReadState state = result.State;
        DefenderExtendedProtection? protection = null;
        if (result.Rows.Count == 1 && result.Rows[0].Length == ExtendedFields.Length)
        {
            object?[] row = result.Rows[0];
            string? mode = row[6] is string text && text is "Normal" or "Passive Mode" or "EDR Block Mode" or "Not running"
                ? text : null;
            protection = new(DefenderReader.Boolean(row[0]), DefenderReader.Boolean(row[1]), DefenderReader.Boolean(row[2]),
                DefenderReader.Boolean(row[3]), DefenderReader.Boolean(row[4]), DefenderReader.Boolean(row[5]), mode);
            if (state == DefenderReadState.Complete && !protection.ValuesKnown) state = DefenderReadState.Partial;
        }
        else if (state == DefenderReadState.Complete) state = DefenderReadState.InvalidData;
        return snapshot with
        {
            ExtendedProtection = protection,
            ExtendedProtectionState = state,
            ExtendedFailureStage = result.FailureStage,
            ExtendedErrorCode = result.ErrorCode
        };
    }

    internal static DefenderSnapshot Project(DateTimeOffset observed, QueryResult status, QueryResult history)
    {
        DefenderReadState statusState = status.State;
        DefenderReadState historyState = history.State;
        DefenderProtection? protection = null;
        if (status.Rows.Count == 1 && status.Rows[0].Length == ProtectionFields.Length)
        {
            object?[] row = status.Rows[0];
            protection = new(DefenderReader.Boolean(row[0]), DefenderReader.Boolean(row[1]),
                DefenderReader.Boolean(row[2]), DefenderReader.Timestamp(row[3]));
            if (statusState == DefenderReadState.Complete && (protection.ServiceEnabled is null ||
                protection.AntivirusEnabled is null || protection.RealTimeProtectionEnabled is null || protection.SignatureUpdated is null))
                statusState = DefenderReadState.Partial;
        }
        else if (statusState == DefenderReadState.Complete) statusState = DefenderReadState.InvalidData;

        var detections = new List<DefenderDetection>();
        foreach (object?[] row in history.Rows.Take(DefenderReader.MaxHistory))
        {
            if (row.Length != HistoryFields.Length) { historyState = DefenderReadState.Partial; continue; }
            var detection = new DefenderDetection(DefenderReader.NonnegativeInteger(row[0]), DefenderReader.Timestamp(row[1]),
                DefenderReader.Timestamp(row[2]), DefenderReader.Byte(row[3]), DefenderReader.Boolean(row[4]), DefenderReader.Unsigned(row[5]));
            detections.Add(detection);
            if (historyState == DefenderReadState.Complete && (detection.ThreatId is null || detection.DetectedAt is null ||
                detection.ChangedAt is null || detection.StatusId is null || detection.ActionSucceeded is null || detection.AdditionalActions is null))
                historyState = DefenderReadState.Partial;
        }
        if (history.Rows.Count > DefenderReader.MaxHistory) historyState = DefenderReadState.Partial;
        return new(observed, statusState, protection, historyState, detections.AsReadOnly())
        {
            ProtectionFailureStage = status.FailureStage,
            ProtectionErrorCode = status.ErrorCode,
            HistoryFailureStage = history.FailureStage,
            HistoryErrorCode = history.ErrorCode
        };
    }

    // The production loop owns the cursor and each returned row, including failure paths. Tests
    // substitute only the OS responses and clock; no runtime option replaces the native adapter.
    internal interface IQueryCursor : IDisposable
    {
        void Open();
        void Secure();
        int Next(int timeout, out IQueryRow? item, out uint returned);
    }

    internal interface IQueryRow : IDisposable
    {
        int Get(string name, out object? value);
    }

    internal static QueryResult Query(IQueryCursor cursor, string[] fields, int limit, Func<TimeSpan> elapsed)
    {
        var rows = new List<object?[]>();
        DefenderQueryStage stage = DefenderQueryStage.Query;
        try
        {
            CheckBudget(elapsed);
            cursor.Open();
            stage = DefenderQueryStage.SecureProxy;
            cursor.Secure();
            while (true)
            {
                CheckBudget(elapsed);
                IQueryRow? item = null;
                try
                {
                    stage = DefenderQueryStage.Enumerate;
                    int result = cursor.Next(200, out item, out uint returned);
                    Marshal.ThrowExceptionForHR(result);
                    CheckBudget(elapsed);
                    if (returned == 0 && result == 1) return new(DefenderReadState.Complete, rows);
                    if (returned == 0 && result == 0x40004) continue; // WBEM_S_TIMEDOUT is not EOF
                    if (returned != 1 || item is null) return new(DefenderReadState.InvalidData, rows);
                    if (rows.Count == limit) return new(DefenderReadState.Partial, rows);
                    var values = new object?[fields.Length];
                    stage = DefenderQueryStage.Property;
                    for (int index = 0; index < fields.Length; index++)
                    {
                        CheckBudget(elapsed);
                        int propertyResult = item.Get(fields[index], out object? value);
                        if (propertyResult != unchecked((int)0x80041002)) Marshal.ThrowExceptionForHR(propertyResult);
                        // A synchronous Get can cross the deadline, including the final property.
                        CheckBudget(elapsed);
                        if (propertyResult == unchecked((int)0x80041002)) continue; // missing is unknown
                        // Reject unexpected types/large strings before retaining provider values.
                        values[index] = value is bool or byte or sbyte or short or ushort or int or uint or long or ulong ||
                            value is string { Length: <= 25 } ? value : null;
                    }
                    rows.Add(values);
                    if (result == 1) return new(DefenderReadState.Complete, rows);
                }
                finally { item?.Dispose(); }
            }
        }
        catch (Exception error) { return new(DefenderReader.Classify(error), rows, stage, error.HResult); }
        finally { cursor.Dispose(); }
    }

    private static void CheckBudget(Func<TimeSpan> elapsed)
    {
        if (elapsed() >= DefenderReader.QueryBudget) throw new TimeoutException();
    }

    private sealed class NativeQueryCursor(IWbemServices services, string className, string[] fields) : IQueryCursor
    {
        private IEnumWbemClassObject? _results;

        // Both class names and every property originate from the private fixed literals above.
        public void Open() => Marshal.ThrowExceptionForHR(services.ExecQuery("WQL",
            $"SELECT {String.Join(',', fields)} FROM {className}",
            0x30, IntPtr.Zero, out _results)); // RETURN_IMMEDIATELY | FORWARD_ONLY

        public void Secure() => SecureProxy(_results!);

        public int Next(int timeout, out IQueryRow? item, out uint returned)
        {
            int result = _results!.Next(timeout, 1, out IWbemClassObject? nativeItem, out returned);
            // Preserve ownership even when Next returns a failure HRESULT along with an object.
            item = nativeItem is null ? null : new NativeQueryRow(nativeItem);
            return result;
        }

        public void Dispose()
        {
            Release(_results);
            _results = null;
        }
    }

    private sealed class NativeQueryRow(IWbemClassObject item) : IQueryRow
    {
        private IWbemClassObject? _item = item;

        public int Get(string name, out object? value) => _item!.Get(name, 0, out value, out _, out _);

        public void Dispose()
        {
            Release(_item);
            _item = null;
        }
    }

    // Preserve each interface's proxy pointer. Marshaling object as IUnknown would configure the
    // identity proxy, not necessarily the IWbemServices/IEnumWbemClassObject proxy used for calls.
    private static void SecureProxy(IWbemServices proxy) => Marshal.ThrowExceptionForHR(
        CoSetServiceProxyBlanket(proxy, 10, 0, IntPtr.Zero, 6, 3, IntPtr.Zero, 0));
    private static void SecureProxy(IEnumWbemClassObject proxy) => Marshal.ThrowExceptionForHR(
        CoSetEnumerationProxyBlanket(proxy, 10, 0, IntPtr.Zero, 6, 3, IntPtr.Zero, 0));

    private static void Release(object? value)
    {
        if (value is not null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value);
    }

    [DllImport("ole32.dll", ExactSpelling = true)]
    private static extern int CoInitializeEx(IntPtr reserved, uint flags);
    [DllImport("ole32.dll", ExactSpelling = true)]
    private static extern void CoUninitialize();
    [DllImport("ole32.dll", ExactSpelling = true)]
    private static extern int CoCreateInstance(ref Guid clsid, IntPtr outer, uint context, ref Guid iid,
        [MarshalAs(UnmanagedType.Interface)] out IWbemLocator locator);
    [DllImport("ole32.dll", EntryPoint = "CoSetProxyBlanket", ExactSpelling = true)]
    private static extern int CoSetServiceProxyBlanket([MarshalAs(UnmanagedType.Interface)] IWbemServices proxy,
        uint authentication, uint authorization, IntPtr principal, uint authenticationLevel,
        uint impersonationLevel, IntPtr identity, uint capabilities);
    [DllImport("ole32.dll", EntryPoint = "CoSetProxyBlanket", ExactSpelling = true)]
    private static extern int CoSetEnumerationProxyBlanket([MarshalAs(UnmanagedType.Interface)] IEnumWbemClassObject proxy,
        uint authentication, uint authorization, IntPtr principal, uint authenticationLevel,
        uint impersonationLevel, IntPtr identity, uint capabilities);

    // Native COM ABI prefix declarations, in Windows SDK wbemcli.h vtable order. Unused slots are
    // private padding, never called; mutating methods are deliberately not exposed by this adapter.
    [ComImport, Guid("DC12A687-737F-11CF-884D-00AA004B2E24"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IWbemLocator
    {
        [PreserveSig]
        int ConnectServer([MarshalAs(UnmanagedType.BStr)] string resource,
            [MarshalAs(UnmanagedType.BStr)] string? user, [MarshalAs(UnmanagedType.BStr)] string? password,
            [MarshalAs(UnmanagedType.BStr)] string? locale, int flags, [MarshalAs(UnmanagedType.BStr)] string? authority,
            IntPtr context, out IWbemServices services);
    }

    [ComImport, Guid("9556DC99-828C-11CF-A37E-00AA003240C7"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IWbemServices
    {
        void Slot01(); void Slot02(); void Slot03(); void Slot04(); void Slot05(); void Slot06();
        void Slot07(); void Slot08(); void Slot09(); void Slot10(); void Slot11(); void Slot12();
        void Slot13(); void Slot14(); void Slot15(); void Slot16(); void Slot17();
        [PreserveSig]
        int ExecQuery([MarshalAs(UnmanagedType.BStr)] string language,
            [MarshalAs(UnmanagedType.BStr)] string query, int flags, IntPtr context, out IEnumWbemClassObject results);
    }

    [ComImport, Guid("027947E1-D731-11CE-A357-000000000001"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IEnumWbemClassObject
    {
        void Reset();
        [PreserveSig] int Next(int timeout, uint count, out IWbemClassObject? item, out uint returned);
    }

    [ComImport, Guid("DC12A681-737F-11CF-884D-00AA004B2E24"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IWbemClassObject
    {
        void GetQualifierSet();
        [PreserveSig]
        int Get([MarshalAs(UnmanagedType.LPWStr)] string name, int flags,
            [MarshalAs(UnmanagedType.Struct)] out object? value, out int type, out int flavor);
    }
}
