# PC Black Box

PC Black Box is a Windows static-inspection tool for examining downloaded files and folders without executing them.

Its compact black, white, and yellow interface carries forward the at-a-glance operating style of Marathon Network Blocker. Administrator privileges are not requested.

## Setup

You need:

- Windows 10 or Windows 11
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Access to this private repository
- [GitHub CLI](https://cli.github.com/)

Run the following commands in PowerShell:

```powershell
gh auth login
gh repo clone Elysia20220909/PC-Black-Box
cd PC-Black-Box
dotnet restore
dotnet run --project .\Destiny2BlackBox.csproj
```

Skip `gh auth login` if GitHub CLI is already authenticated.

## Use

1. Start `PC Black Box.exe`.
2. Drop a file or folder onto the window, or use a selection button.
3. Select `INSPECT`.
4. Review prioritized findings under `OVERVIEW`, file-level evidence under `FILES`, and the sanitized report under `REPORT`.

Use `JA / EN` to switch languages. Only that language preference is stored in `%LOCALAPPDATA%\PCBlackBox\settings.json`.

## Productive review

- Search file names, types, signatures, signers, sources, and findings instantly from the `FILES` page.
- Filter by `HIGH`, `REVIEW`, `LOW`, or `CLEAR` while keeping the visible and total counts in view.
- Select a finding card on `OVERVIEW`, or focus it with Tab and press Enter / Space, to open the matching file evidence directly.
- Use `Ctrl+O` for a file, `Ctrl+Shift+O` for a folder, `Ctrl+F` to search, and `F5` or `Ctrl+Enter` to inspect.
- Use `Ctrl+1 / 2 / 3` for Overview, Files, and Report; press `Esc` to cancel an active inspection.

## What it inspects

- SHA-256
- Authenticode status and signer using only the local Windows trust cache, without online revocation requests
- Mark-of-the-Web (Internet Zone) and source host
- True format inferred from file magic
- Double extensions, right-to-left override characters, and extension mismatches
- PE architecture, product/company metadata, and entropy
- Static capability terms associated with downloads, persistence, Defender changes, process injection, deletion, and related behavior
- Executable content, macros, path traversal, and extreme compression ratios inside ZIP and Office packages

Folder inspection stops at 2,500 files, 10,000 directories, depth 128, 20,000 enumerated entries, eight million retained path characters, or 12 GB. ZIP metadata is capped at 10,000 entries, a 64 MiB central directory, and 4,096 bytes per central entry name; signature checks stop at 300 files. Reparse points are not followed.

## Assessment model

`CLEAR / LOW / REVIEW / HIGH` is a review priority, not a malware verdict or safety guarantee.

Legitimate administration scripts, installers, and compression tools can trigger warnings. Conversely, unknown code may show no static indicator. Combine this result with the expected purpose, download source, signature, and tools such as Windows Defender.

## Privacy and safety boundary

- The target is never launched.
- Files are not uploaded.
- No automatic network request is made.
- No process injection, game-memory access, or packet capture is performed.
- Files are not deleted, quarantined, moved, or repaired.
- Reports omit absolute paths, Windows user names, IP addresses, Steam IDs, and credentials.
- No external hash lookup or browser launch is available; inspection remains fully offline.

The design follows iOS-inspired security principles: least privilege, a closed data flow, explicit user actions, and fixed trust boundaries. It remains a conventional Windows desktop app and does not claim isolation equivalent to the iOS App Sandbox.

## Defense in depth

- Thirteen required controls are applied before application initialization and verified through OS and runtime responses. Inspection fails closed unless every control is verified.
- The OS blocks child processes, legacy extension points, non-system fonts, and native images from remote or Low-integrity locations.
- DEP, ASLR, Control Flow Guard, and SEHOP are mandatory, and invalid-handle use is made fatal.
- P/Invoke and normal DLL discovery are restricted to the application directory and System32; the current directory is excluded.
- Inspection files are opened through handles that do not follow reparse points and do not share writes or replacement while parsing.
- Every opened file and directory handle must resolve to the exact requested local path, blocking intermediate junction replacement.
- Volume identity and a 128-bit file ID are rechecked alongside length and timestamp to detect same-name replacement.
- The 12 GB folder limit is enforced again against cumulative stable-handle sizes, not only enumeration metadata.
- Parent directories deny delete sharing during enumeration and settings or report writes to block destination replacement.
- Every enumerated directory identity and write timestamp is revalidated after scanning; a mutation makes the folder result `PARTIAL`.
- EOCD, ZIP64 end records, central headers, counts, lengths, and boundaries are validated before the standard ZIP parser is constructed, rejecting fake end records and central-directory floods fail-closed.
- Capability matching uses the linear-time regular-expression engine with a time limit to resist crafted denial-of-service inputs.

The UI and reports expose the verified baseline as a count such as `13/13`. The trust boundaries and residual risks are recorded in [`THREAT_MODEL.md`](THREAT_MODEL.md).

These controls translate Apple's code-trust and strict-capability principles into defenses compatible with the current Windows/WPF design. They do not introduce AppContainer packaging or a signed distribution binary.

## Current limitations

- No dynamic behavior, sandbox execution, or live destination analysis.
- The WPF process is not an AppContainer and does not provide the same OS isolation as the iOS App Sandbox.
- 7-Zip and RAR are identified but not unpacked.
- Split ZIPs, encrypted central directories, and ambiguous multiple-EOCD layouts are not internally inspected and are reported.
- Capability terms inside script comments are still reported and require context.
- A `CLEAR` result does not guarantee safety.

The product has no NSA or equivalent external certification. “High assurance” here means layered, testable, fail-closed engineering based on public specifications.

## Build

```powershell
dotnet build .\Destiny2BlackBox.csproj -c Release
```

The app also supports non-interactive Markdown report generation:

```powershell
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --report "C:\path\to\target" ".\report.md"
```

The security baseline can be checked without reading a target:

```powershell
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --security-status
```

Search, filtering, sanitization, and the security baseline can be tested without a target file. The check also creates, safely replaces, and removes an isolated temporary report:

```powershell
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --self-test
```

## Repository policy

This is a private, source-only repository. Executables, installers, release archives, signing keys, local settings, packet captures, and generated reports are neither tracked nor distributed. Adding access or changing visibility requires the owner's explicit approval.
