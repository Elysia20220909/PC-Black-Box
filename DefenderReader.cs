using System.Globalization;
using System.Runtime.InteropServices;

namespace DestinyBlackBox;

internal enum DefenderConnectionStage { Initialize, Activate, Connect, SecureProxy }

internal sealed class DefenderConnectionException(DefenderConnectionStage stage, Exception cause)
    : Exception("The local Defender connection failed.", cause)
{
    internal DefenderConnectionStage Stage { get; } = stage;
}

internal sealed class DefenderReader
{
    internal const int MaxHistory = 256;
    internal static readonly TimeSpan QueryBudget = TimeSpan.FromSeconds(8);
    internal static readonly DefenderReader Shared = new(report => DefenderWmi.Read(report));
    private readonly Func<Action<DefenderSnapshot>, DefenderSnapshot> _read;
    private readonly object _gate = new();
    private Task<DefenderSnapshot>? _pending;

    internal DefenderReader(Func<DefenderSnapshot> read) : this(_ => read()) { }
    internal DefenderReader(Func<Action<DefenderSnapshot>, DefenderSnapshot> read) => _read = read;

    internal async Task<DefenderSnapshot> ReadAsync()
    {
        Task<DefenderSnapshot> pending;
        DefenderSnapshot? basic = null;
        lock (_gate)
        {
            // A timed-out COM call cannot safely be aborted. Keep at most one worker, even when
            // the user repeatedly refreshes. Never weaken the product's process/network guards.
            if (_pending is { IsCompleted: false }) return DefenderSnapshot.Empty(DefenderReadState.Busy);
            pending = _pending = Task.Factory.StartNew(() => ReadSafely(snapshot => Volatile.Write(ref basic, snapshot)), CancellationToken.None,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
        try { return await pending.WaitAsync(QueryBudget + TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
        catch (TimeoutException)
        {
            // Keep only this request's already collected basic status/history if the optional
            // native query stalls. The pending worker still blocks overlapping requests.
            return Volatile.Read(ref basic) is { } saved
                ? saved with { ExtendedProtectionState = DefenderReadState.Timeout }
                : DefenderSnapshot.Empty(DefenderReadState.Timeout);
        }
    }

    private DefenderSnapshot ReadSafely(Action<DefenderSnapshot> reportBasic)
    {
        try { return _read(reportBasic); }
        catch (DefenderConnectionException error)
        {
            return DefenderSnapshot.Empty(Classify(error.InnerException!)) with
            {
                ConnectionFailureStage = error.Stage,
                ConnectionErrorCode = error.InnerException!.HResult
            };
        }
        catch (Exception error) { return DefenderSnapshot.Empty(Classify(error)); }
    }

    internal static DefenderReadState Classify(Exception error) => error switch
    {
        UnauthorizedAccessException => DefenderReadState.AccessDenied,
        TimeoutException => DefenderReadState.Timeout,
        COMException when error.HResult is unchecked((int)0x80041003) or unchecked((int)0x80070005) => DefenderReadState.AccessDenied,
        _ => DefenderReadState.Unavailable
    };

    internal static bool? Boolean(object? value) => value is bool flag ? flag : null;
    internal static long? NonnegativeInteger(object? value) => value switch
    {
        byte number => number,
        ushort number => number,
        uint number => number,
        sbyte number when number >= 0 => number,
        short number when number >= 0 => number,
        int number when number >= 0 => number,
        long number when number >= 0 => number,
        ulong number when number <= long.MaxValue => (long)number,
        string text when text.Length is > 0 and <= 19 && text.All(Char.IsAsciiDigit) &&
            Int64.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long number) => number,
        _ => null
    };
    internal static byte? Byte(object? value) => NonnegativeInteger(value) is long number && number <= byte.MaxValue ? (byte)number : null;
    internal static uint? Unsigned(object? value) => NonnegativeInteger(value) is long number && number <= uint.MaxValue ? (uint)number : null;

    // CIM_DATETIME, not a culture-dependent date or an arbitrary provider string. Unknown/wildcard
    // dates remain unknown. Do not materialize provider text in reports or error messages.
    internal static DateTimeOffset? Timestamp(object? value)
    {
        if (value is not string text || text.Length != 25 || text[14] != '.' || text[21] is not ('+' or '-')) return null;
        if (!Int32.TryParse(text.AsSpan(22), NumberStyles.None, CultureInfo.InvariantCulture, out int offset) || offset > 840) return null;
        if (!DateTime.TryParseExact(text[..21], "yyyyMMddHHmmss.ffffff", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime date)) return null;
        try { return new DateTimeOffset(date, TimeSpan.FromMinutes(text[21] == '-' ? -offset : offset)); }
        catch (ArgumentException) { return null; }
    }
}
