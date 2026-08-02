# PC Black Box

PC Black Box is a Windows static-inspection tool for examining downloaded files and folders without executing them.

Its compact black, white, and yellow interface carries forward the at-a-glance operating style of Marathon Network Blocker. Administrator privileges are not requested.

## Use

1. Start `PC Black Box.exe`.
2. Drop a file or folder onto the window, or use a selection button.
3. Select `INSPECT`.
4. Review prioritized findings under `OVERVIEW`, file-level evidence under `FILES`, and the sanitized report under `REPORT`.

Use `JA / EN` to switch languages. Only that language preference is stored in `%LOCALAPPDATA%\PCBlackBox\settings.json`.

## What it inspects

- SHA-256
- Authenticode status and signer using only the local Windows trust cache, without online revocation requests
- Mark-of-the-Web (Internet Zone) and source host
- True format inferred from file magic
- Double extensions, right-to-left override characters, and extension mismatches
- PE architecture, product/company metadata, and entropy
- Static capability terms associated with downloads, persistence, Defender changes, process injection, deletion, and related behavior
- Executable content, macros, path traversal, and extreme compression ratios inside ZIP and Office packages

Safety limits are 2,500 files or 12 GB per folder, 10,000 ZIP entries, and 300 signature checks. Reparse points are not followed.

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

- Required Windows process mitigations block child-process creation at the OS boundary.
- Remote and Low-integrity native images are refused and System32 images are preferred. Inspection fails closed if these policies cannot be enabled.
- Inspection files are opened through handles that do not follow reparse points and do not share writes or replacement while parsing.
- Volume identity and a 128-bit file ID are rechecked alongside length and timestamp to detect same-name replacement.
- Capability matching uses the linear-time regular-expression engine with a time limit to resist crafted denial-of-service inputs.

These controls translate Apple's code-trust and strict-capability principles into defenses compatible with the current Windows/WPF design. They do not introduce AppContainer packaging or a signed distribution binary.

## Current limitations

- No dynamic behavior, sandbox execution, or live destination analysis.
- The WPF process is not an AppContainer and does not provide the same OS isolation as the iOS App Sandbox.
- 7-Zip and RAR are identified but not unpacked.
- Capability terms inside script comments are still reported and require context.
- A `CLEAR` result does not guarantee safety.

## Build

```powershell
dotnet build .\Destiny2BlackBox.csproj -c Release
```

The app also supports non-interactive Markdown report generation:

```powershell
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --report "C:\path\to\target" ".\report.md"
```

## Repository policy

This is a private, source-only repository. Executables, installers, release archives, signing keys, local settings, packet captures, and generated reports are neither tracked nor distributed. Adding access or changing visibility requires the owner's explicit approval.
