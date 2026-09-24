using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace DestinyBlackBox;

internal sealed record IsolationToolPresence(string Tool, bool? RegistrationObserved, bool ProbeComplete);

internal sealed record IsolationPresenceSnapshot(DateTimeOffset ObservedAt, DefenderReadState State,
    IReadOnlyList<IsolationToolPresence> Tools)
{
    internal static IsolationPresenceSnapshot Empty(DefenderReadState state) => new(DateTimeOffset.UtcNow, state,
        [new("Sandboxie Plus", null, false), new("QEMU", null, false)]);

    internal JsonElement ToJsonElement() => JsonSerializer.SerializeToElement(new
    {
        observedAt = ObservedAt,
        retrievalState = State.ToString(),
        probeScope = "fixed-local-registry-keys-only",
        tools = Tools,
        executableAuthenticityVerified = false,
        isolationState = "not-verified",
        toolsLaunched = false
    });

    internal string ToDisplay(bool japanese)
    {
        var text = new StringBuilder();
        text.AppendLine(japanese ? "外部隔離ツール — 登録情報の手掛かりのみ" : "External isolation tools — registration hints only");
        text.AppendLine($"{ObservedAt:O} / {State}");
        foreach (IsolationToolPresence tool in Tools)
        {
            string hint = tool.RegistrationObserved switch
            {
                true => japanese ? "登録の手掛かりあり" : "registration hint observed",
                false => japanese ? "確認範囲では登録なし（未導入の断定ではありません）" : "no registration in checked locations; installation not ruled out",
                _ => japanese ? "不明" : "unknown"
            };
            text.AppendLine($"{tool.Tool}: {hint}; {(japanese ? "照会完了" : "probe complete")}={tool.ProbeComplete}");
        }
        text.AppendLine(japanese
            ? "固定のローカル登録キーだけを照会しました。残存・偽装された登録の可能性があり、ポータブル版は検出できないことがあります。"
            : "Only fixed local registration keys were queried; stale/spoofed registrations and undetected portable copies are possible.");
        text.AppendLine(japanese
            ? "実行ファイルの真正性・起動状態・隔離の有効性は未確認です。ツールや対象ファイルは起動していません。"
            : "Executable authenticity, running state and effective isolation are NOT verified. No tool or target was launched.");
        return text.ToString();
    }

    internal string WithDefenderJson(DefenderSnapshot defender)
    {
        using JsonDocument document = JsonDocument.Parse(defender.ToJson());
        return JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            readOnly = true,
            defender = document.RootElement,
            isolationTools = ToJsonElement(),
            isolationEstablished = false,
            malwareVerdict = "not-assessed"
        }, new JsonSerializerOptions { WriteIndented = true });
    }
}

internal sealed class IsolationToolReader(Func<IsolationPresenceSnapshot> read)
{
    internal static readonly IsolationToolReader Shared = new(ReadRegistry);
    internal static readonly TimeSpan QueryBudget = TimeSpan.FromSeconds(1);
    private readonly object _gate = new();
    private Task<IsolationPresenceSnapshot>? _pending;

    internal async Task<IsolationPresenceSnapshot> ReadAsync()
    {
        Task<IsolationPresenceSnapshot> pending;
        lock (_gate)
        {
            if (_pending is { IsCompleted: false }) return IsolationPresenceSnapshot.Empty(DefenderReadState.Busy);
            pending = _pending = Task.Factory.StartNew(() =>
            {
                try { return read(); }
                catch { return IsolationPresenceSnapshot.Empty(DefenderReadState.Unavailable); }
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
        try { return await pending.WaitAsync(QueryBudget + TimeSpan.FromSeconds(1)).ConfigureAwait(false); }
        catch (TimeoutException) { return IsolationPresenceSnapshot.Empty(DefenderReadState.Timeout); }
    }

    private static IsolationPresenceSnapshot ReadRegistry()
    {
        var clock = Stopwatch.StartNew();
        return Probe((hive, view, name) =>
        {
            using RegistryKey root = RegistryKey.OpenBaseKey(hive, view);
            using RegistryKey? key = root.OpenSubKey(name, writable: false);
            return key is not null;
        }, () => clock.Elapsed);
    }

    // No enumeration, registry values, installation paths, environment/PATH search, DLL load or
    // executable launch. A key's existence is only a hint, never a verified security capability.
    internal static IsolationPresenceSnapshot Probe(Func<RegistryHive, RegistryView, string, bool> exists, Func<TimeSpan> elapsed)
    {
        var tools = new List<IsolationToolPresence>();
        bool timedOut = false;
        foreach (string tool in new[] { "Sandboxie Plus", "QEMU" })
        {
            string[] keys = tool == "Sandboxie Plus"
                ? [@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sandboxie-Plus_is1"]
                : [@"SOFTWARE\QEMU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\QEMU"];
            bool observed = false;
            bool complete = true;
            foreach (RegistryHive hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
                foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                    foreach (string key in keys)
                    {
                        if (timedOut || elapsed() >= QueryBudget) { timedOut = true; complete = false; continue; }
                        try
                        {
                            bool found = exists(hive, view, key);
                            if (elapsed() >= QueryBudget) { timedOut = true; complete = false; continue; }
                            observed |= found;
                        }
                        catch { complete = false; }
                    }
            tools.Add(new(tool, observed ? true : complete ? false : null, complete));
        }
        DefenderReadState state = timedOut ? DefenderReadState.Timeout : tools.All(tool => tool.ProbeComplete)
            ? DefenderReadState.Complete : DefenderReadState.Partial;
        return new(DateTimeOffset.UtcNow, state, tools.AsReadOnly());
    }
}
