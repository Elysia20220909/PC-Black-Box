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
- `COPY SHA-256` and `COPY LOOKUP URL` in the file evidence pane only place text on the clipboard. The product never opens the URL and never connects; opening it is the operator's decision, and doing so discloses that hash to the service. The clipboard itself is outside this product: with Windows clipboard history enabled, the copied string is also retained by Windows and may sync to a Microsoft account.

## What it inspects

- SHA-256
- Authenticode status and signer using only the local Windows trust cache, without online revocation requests
- Mark-of-the-Web (Internet Zone) and source host
- True format inferred from file magic
- Double extensions, right-to-left override characters, and extension mismatches
- Windows shortcuts: the target, arguments, working directory, hidden-window and elevation flags, read from the shortcut structure without resolving or launching it
- OLE compound files (installers and legacy Office documents): recognized by content and read for strings, with the storage tree left unparsed and reported as incomplete
- PE architecture, product/company metadata, and entropy sampled from the first 8 MiB
- Streaming capability matching for scripts, Windows PE files, and PDFs within explicit limits, including downloads, persistence, Defender changes, process injection, deletion, and related behavior
- Prefixed data, internal double extensions, executable content, macros, path traversal, and extreme compression ratios inside ZIP and Office packages
- Capability terms such as downloads, persistence, Defender changes, and process injection in ZIP entries, including nested ZIPs inspected in memory to depth 3 without extracting them to disk

Folder inspection stops at 2,500 files, 10,000 directories, depth 128, 20,000 enumerated entries, eight million retained path characters, or 12 GB. Ordinary-file capability scanning is capped at 1 GiB and 60 seconds per file, and 4 GiB and 180 seconds per inspection. ZIP entry-content scanning is capped at 64 MiB per entry, 256 MiB across each top-level file and its nested ZIPs, and 1 GiB per inspection, with at most one extra sentinel byte per capped entry to prove that data continues. Compressed input is limited to 64 KiB reads, and the 30-second/top-level-ZIP and 120-second/inspection clocks are checked before and after each input read. They still cannot forcibly interrupt one local OS read or inflater step already in progress. If observed EOF cannot establish the total body size, the product reports bytes scanned but labels the total unknown instead of inventing a denominator. Nested ZIP inspection is capped at depth 3, 32 nested archives and 20,000 recursive entries per file, with at most 32 MiB buffered per nested archive and 128 MiB in aggregate. Each ZIP is capped at 10,000 entries, a 64 MiB central directory and ZIP64 terminal extension, and 4,096 bytes per central entry name; the top-level archive input is capped at 2 GiB and signature checks stop at 300 files. Reparse points are not followed. Any limit, read failure, or analysis timeout makes the result `INCOMPLETE`, never `CLEAR`.

## Assessment model

`CLEAR / LOW / REVIEW / HIGH` is review priority, while `COMPLETE / INCOMPLETE` describes inspection completeness. Known risk and unchecked scope are retained separately and can appear together, for example `HIGH+INCOMPLETE`. None is a malware verdict or safety guarantee.

Legitimate administration scripts, installers, and compression tools can trigger warnings. Conversely, unknown code may show no static indicator. Combine this result with the expected purpose, download source, signature, and tools such as Windows Defender.

## Privacy and safety boundary

- The target is never launched.
- Files are not uploaded.
- No automatic network request is made.
- No process injection, game-memory access, or packet capture is performed.
- Files are not deleted, quarantined, moved, or repaired.
- Reports omit **this machine’s** absolute paths, Windows user names, IP addresses, Steam IDs, and credentials. Strings held inside the target, such as a shortcut’s target and arguments, are shown as the evidence behind a finding.
- Treat the report itself as sensitive. It lists the inspected file names, the hosts they came from, and their digests, which identifies more than any single hash does. Generated reports are gitignored; read one before sharing it.
- No external hash lookup or browser launch is available; inspection remains fully offline.

The design follows iOS-inspired security principles: least privilege, a closed data flow, explicit user actions, and fixed trust boundaries. It remains a conventional Windows desktop app and does not claim isolation equivalent to the iOS App Sandbox.

## Defense in depth

- Sixteen required controls are applied before application initialization and verified through OS and runtime responses. Inspection fails closed unless every one of them is verified.
- A process DACL denies later same-user requests to read or write this process's memory, start a thread inside it, or duplicate its handles. An `OWNER RIGHTS` entry removes the owner's implicit DACL-change right. Task Manager-equivalent query and termination access remain available.
- The running process verifies that the standard .NET socket, name-resolution, HTTP, and related transport assemblies are absent; a later load terminates the process before the caller can use that transport.
- The OS blocks child processes, legacy extension points, non-system fonts, and native images from remote or Low-integrity locations.
- DEP, ASLR, Control Flow Guard, and SEHOP are mandatory, and invalid-handle use is made fatal.
- Heap corruption terminates the process instead of continuing in an allocator state an attacker can steer.
- P/Invoke and normal DLL discovery are restricted to the application directory and System32; the current directory is excluded.
- The hot reload metadata-update path and the EventSource tracing surface are disabled in the shipped runtime configuration.
- Inspection files are opened through handles that do not follow reparse points and do not share writes or replacement while parsing.
- Every opened file and directory handle must resolve to the exact requested local path, blocking intermediate junction replacement.
- Volume identity and a 128-bit file ID are rechecked alongside length and timestamp to detect same-name replacement.
- The 12 GB folder limit is enforced again against cumulative stable-handle sizes, not only enumeration metadata.
- Parent directories deny delete sharing during enumeration and settings or report writes to block destination replacement.
- Every enumerated directory identity and write timestamp is revalidated after scanning; a mutation makes the folder result `INCOMPLETE`.
- EOCD, ZIP64 end records, central headers, counts, lengths, and boundaries are validated before the standard ZIP parser is constructed, rejecting fake end records and central-directory floods fail-closed.
- Capability matching streams with overlapping chunks up to explicit byte and time budgets and uses the linear-time regular-expression engine with a time limit to resist crafted denial-of-service inputs. Reaching a budget before the end makes the result `INCOMPLETE`.

Four further defenses — redirection trust, security-domain isolation, page-combining disable, and speculative-store-bypass disable — are applied and read back where the OS build and the CPU offer them, alongside a read-only check of hardware-enforced shadow stacks (CET). Anything the platform does not offer is displayed as unavailable rather than quietly assumed.

The UI and reports expose the verified baseline as a count such as `16/16`, followed by the number of platform reinforcements active on that system. `--security-status` prints one line per control so the posture can be reviewed independently. The trust boundaries and residual risks, including the mitigations that were considered and deliberately rejected, are recorded in [`THREAT_MODEL.md`](THREAT_MODEL.md).

These controls translate Apple's code-trust and strict-capability principles into defenses compatible with the current Windows/WPF design. They do not introduce AppContainer packaging or a signed distribution binary.

## Current limitations

- No dynamic behavior, sandbox execution, or live destination analysis.
- The WPF process is not an AppContainer and does not provide the same OS isolation as the iOS App Sandbox.
- An administrator, a kernel-level component, or a compromised Windows trust store remains above this boundary. The process lockdown stops a same-user program, not a privileged one.
- The process DACL constrains access requested after it is installed; Windows cannot revoke a handle already held by the launcher or another process.
- Managed transport monitoring is not an OS-level network capability denial through AppContainer or Windows Filtering Platform. Native networking added in a future change could bypass it and is outside the accepted scope.
- 7-Zip and RAR are identified but not unpacked.
- ZIP entries are streamed for capability terms and never extracted to disk. Valid nested ZIPs are recursively opened within the limits even when their extension is hidden, if their structure can be established. This is neither a malware-signature engine nor a runtime sandbox.
- Nested 7-Zip, RAR, GZip, Cabinet, OLE and ISO content remains unopened. Malformed, encrypted, over-limit or unreadable nested ZIPs also remain unopened and make the result `INCOMPLETE`; prefixed bytes inside a nested ZIP remain explicitly unparsed.
- Ordinary ZIP and ZIP64 terminal records within the safety limit recover relative offsets through prefixed data, including ZIP64 records with extensible data, so the body can still be inspected. The prefix itself remains unparsed, so the result is `INCOMPLETE`. ZIP-like tails whose offsets cannot be recovered remain `INCOMPLETE` instead of falling back to an ordinary file.
- PDF, PE, script, and other primary formats can carry a trailing ZIP; both surfaces are inspected and reported as a polyglot. Central-directory body sizes are not trusted: direct entries are read to observed EOF, and a mismatch makes the result `INCOMPLETE`.
- Split ZIPs, encrypted central directories, and ambiguous multiple-EOCD layouts are not internally inspected and are reported.
- Capability terms inside script comments are still reported and require context.
- A `CLEAR` result does not guarantee safety.
- VirusTotal-style external reputation, multiple antivirus engines, cloud hash intelligence, and dynamic sandboxes are not included. The product goes as far as copying the SHA-256 and a lookup URL; the lookup itself happens elsewhere, at the operator’s hand.

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

Re-run the DACL, combined side-channel mitigation, and managed-transport FailFast checks from an external process. This creates local Release build output only, not a distribution artifact.

```powershell
pwsh -NoProfile -File .\tests\Test-RuntimeBoundaries.ps1
```

Search, filtering, sanitization, and the security baseline can be tested without a target file. The check also creates, safely replaces, and removes an isolated temporary report, and exercises the inspection path itself against fixtures it creates and removes: digest fidelity, script-capability findings, archive traversal reported without extraction, and an already-canceled inspection that reads nothing.

```powershell
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --self-test
```

## Repository policy

This is a private, source-only repository. Executables, installers, release archives, signing keys, local settings, packet captures, and generated reports are neither tracked nor distributed. Adding access or changing visibility requires the owner's explicit approval.
