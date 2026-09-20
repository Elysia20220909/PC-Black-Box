using System.IO;
using System.IO.Pipes;
using System.Text;

namespace DestinyBlackBox;

internal static class DieSessionClient
{
    internal static async Task DisconnectProbeAsync(bool sendRequest, string target)
    {
        string name = Environment.GetEnvironmentVariable("PCBB_DIE_PIPE") ?? throw new IOException();
        using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await pipe.ConnectAsync(5000).ConfigureAwait(false);
        DiePipeProtocol.VerifyServer(pipe, UInt32.Parse(Environment.GetEnvironmentVariable("PCBB_DIE_SERVER")!, System.Globalization.CultureInfo.InvariantCulture));
        if (sendRequest) await DiePipeProtocol.WriteAsync(pipe, Encoding.UTF8.GetBytes(target), CancellationToken.None).ConfigureAwait(false);
    }

    internal static async Task AttachAsync(ScanResult result, string target, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        if (result.TargetWasDirectory) { result.DieStatus = "skipped-folder"; return; }
        if (result.Files.Count != 1 || result.Files[0].Size > 64L * 1024 * 1024) { result.DieStatus = "skipped-size-or-count"; return; }
        string? name = Environment.GetEnvironmentVariable("PCBB_DIE_PIPE");
        if (name is null || !name.StartsWith("PCBB.Die.", StringComparison.Ordinal) || name.Length > 100 ||
            !UInt32.TryParse(Environment.GetEnvironmentVariable("PCBB_DIE_SERVER"), out uint server))
        { result.DieStatus = "unavailable-use-integrated-launcher"; return; }
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            deadline.CancelAfter(TimeSpan.FromSeconds(90));
            using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(5000, deadline.Token).ConfigureAwait(false);
            DiePipeProtocol.VerifyServer(pipe, server);
            byte[] request = Encoding.UTF8.GetBytes(SecurityPolicy.ValidateTargetPath(target));
            if (request.Length > 32768) throw new InvalidDataException("Input path too long.");
            await DiePipeProtocol.WriteAsync(pipe, request, deadline.Token).ConfigureAwait(false);
            byte[] evidence = await DiePipeProtocol.ReadAsync(pipe, DieEvidence.MaxBytes, deadline.Token).ConfigureAwait(false);
            result.Die = DieEvidence.Parse(evidence, result);
            result.DieStatus = "complete";
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { throw; }
        catch { result.Die = null; result.DieStatus = "failed-or-timeout"; }
    }
}
