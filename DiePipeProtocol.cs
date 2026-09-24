using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DestinyBlackBox;

internal static class DiePipeProtocol
{
    internal const int MaxFrame = 1024 * 1024;
    internal static ReadOnlySpan<byte> ParserStarted => "pcbb-die-started-v1"u8;

    internal static async Task WriteAsync(Stream stream, byte[] payload, CancellationToken cancellation)
    {
        if (payload.Length == 0 || payload.Length > MaxFrame) throw new InvalidDataException("Invalid frame size.");
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellation).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellation).ConfigureAwait(false);
        await stream.FlushAsync(cancellation).ConfigureAwait(false);
    }

    internal static async Task<byte[]> ReadAsync(Stream stream, int maximum, CancellationToken cancellation)
    {
        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header, cancellation).ConfigureAwait(false);
        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > maximum || length > MaxFrame) throw new InvalidDataException("Invalid frame size.");
        byte[] data = new byte[length];
        await stream.ReadExactlyAsync(data, cancellation).ConfigureAwait(false);
        return data;
    }

    internal static void VerifyServer(NamedPipeClientStream pipe, uint expected)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint actual) || actual != expected)
            throw new IOException("Unexpected DiE server.");
    }

    internal static void VerifyClient(NamedPipeServerStream pipe, uint expected)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint actual) || actual != expected)
            throw new IOException("Unexpected DiE client.");
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
}
