# PC Black Box

[日本語](README.md) / [Changelog](CHANGELOG.md) / [Security policy](SECURITY.md) / [Threat model](THREAT_MODEL.md)

PC Black Box is a static inspection tool for checking downloaded files and folders on Windows before opening them.

It organizes evidence about a file's identity, signature, origin, internal structure, and capability-related text without executing, uploading, or modifying the target. Its result is neither a malware verdict nor proof of safety. Risk shows what deserves attention, while completeness shows how much of the target was actually examined.

> This repository is private and source-only. It provides no installer or distribution binary. Run it from source as a standard user; an elevated launch is refused before inspection.

## What it does / does not do

| What PC Black Box does | Boundary |
|---|---|
| Performs read-only static inspection of local files | Does not launch the target or load it as code |
| Prioritizes evidence from signatures, origin, formats, structures, and capability terms | Does not decide whether a file is malware |
| Creates local Markdown / JSON reports | Does not upload the file or report |
| Copies SHA-256 and an external lookup URL to the clipboard | Does not open the URL or communicate automatically |
| Preserves unexamined scope as `INCOMPLETE` | Does not assume that unread content is safe |
| Gives the operator evidence for a decision | Does not delete, quarantine, move, or repair files |

PC Black Box is not a dynamic sandbox, antivirus engine, or cloud reputation service. It is a conventional Windows desktop application and does not provide AppContainer or Windows Filtering Platform isolation at the operating-system level.

## Setup

You need:

- A Windows 11 release supported by [.NET 10](https://learn.microsoft.com/en-us/dotnet/core/install/windows#supported-versions), or a supported Windows 10 LTSC / Enterprise release
- The [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) with the latest servicing update
- Access to this private repository
- [GitHub CLI](https://cli.github.com/)

Run the following in a non-elevated PowerShell session. Do not use an administrator terminal.

```powershell
gh auth login
gh repo clone Elysia20220909/PC-Black-Box
cd PC-Black-Box
dotnet restore
dotnet run --project .\Destiny2BlackBox.csproj
```

If GitHub CLI is already authenticated, you can omit `gh auth login`. These commands build and start the private source locally; they do not download a packaged executable.

## Basic use

- Drop one file or folder onto the window, or use a selection button.
- Select `INSPECT`.
- Use `OVERVIEW` for the overall assessment and leading findings.
- Use `FILES` for signatures, origin, hashes, formats, and the evidence for each file.
- Use `REPORT` to preview the report, copy it, or save it as Markdown / JSON.
- Press `Esc` to stop an inspection in progress.

Use `JA / EN` to switch languages. The selected language is the only preference stored in `%LOCALAPPDATA%\PCBlackBox\settings.json`.

| Action | Key |
|---|---|
| Select a file | `Ctrl+O` |
| Select a folder | `Ctrl+Shift+O` |
| Search the file list | `Ctrl+F` |
| Start inspection | `F5` or `Ctrl+Enter` |
| Switch Overview / Files / Report | `Ctrl+1` / `Ctrl+2` / `Ctrl+3` |
| Switch display language | `Alt+L` |
| Stop inspection | `Esc` |

Select a finding card with the pointer, or focus it with Tab and press Enter / Space, to open its supporting file. The file list searches names, formats, signatures, signers, origin, and findings, and can be filtered by `HIGH / REVIEW / LOW / CLEAR`.

## What it inspects

| Area | What is examined | Important boundary |
|---|---|---|
| Digest | SHA-256 over the entire file | Independent of the capability-content scan budgets |
| Local trust | Authenticode status, signer, product, and company | Uses Windows `WinVerifyTrust` with revocation checks disabled and URL retrieval limited to the local cache; does not establish current online revocation status |
| Origin | Mark-of-the-Web Internet Zone and source host | Does not infer missing origin metadata |
| Actual format | Magic bytes, extension mismatch, and PE architecture | Does not trust the file name alone |
| Name deception | Double extensions, right-to-left controls, invisible characters, and trailing spaces or periods removed by Windows | Separates the displayed name from the effective extension |
| Windows shortcuts | Target, arguments, working directory, hidden launch, and elevation request | Reads the `.lnk` structure without resolving or launching it |
| PE / scripts / PDF | Capability terms related to downloading, persistence, Defender changes, process injection, hidden execution, deletion, and similar actions | Streams content only up to explicit byte and time budgets |
| OLE compound files | Recognizes the OLE format used by MSI / MSP / legacy Office files and scans strings in the raw bytes | Does not parse the storage tree, MSI tables, or VBA, so structure remains `INCOMPLETE` |
| ZIP / Office packages | Prefix data, polyglots, internal double extensions, active content, macros, traversal paths, extreme compression ratios, and declared-size versus observed-EOF differences | Validates boundaries before using the standard parser and never extracts entries to disk |
| Nested ZIPs | Recursively inspects valid ZIP structures, including ones hidden behind another extension | Holds them in memory and stops at depth 3; unsupported, malformed, encrypted, unreadable, or over-limit interiors remain `INCOMPLETE` |

PE entropy is calculated from the first 8 MiB. This does not mean that SHA-256 or capability scanning for supported formats stops after the first 8 MiB.

## Reading the assessment

PC Black Box evaluates risk and completeness independently.

### Risk

| Label | Score | Meaning |
|---|---:|---|
| `CLEAR` | 0 | No attention-worthy finding was found by the supported checks |
| `LOW` | 1–24 | A low-weight finding needs context |
| `REVIEW` | 25–59 | Evidence should be reviewed before execution |
| `HIGH` | 60–100 | Strong evidence deserves priority review while the target remains closed |

The score is a sum of finding weights used to order attention, not a probability of infection. Legitimate administration scripts, installers, and compression tools can produce warnings. Conversely, unknown code may leave no visible clue for static inspection.

### Completeness

| Aspect | Scope | Example cause of `INCOMPLETE` |
|---|---|---|
| Traversal | Whether every file in the selected target was reached | Enumeration limits, reparse points, or a directory changing during inspection |
| Digest | Whether every byte of a reached file contributed to SHA-256 | The file could not be opened safely or changed while being read |
| Capability content | Whether a supported format was scanned to its applicable boundary | Byte, elapsed-time, or match-time limits |
| Signature | Whether every applicable signature was checked | More than 300 signature candidates in one inspection |
| Structure | Whether the internal structure of ZIPs, shortcuts, and other containers was examined | An unreadable archive, malformed structure, or unparsed OLE interior |

`COMPLETE` means that every supported check finished within its safety boundaries. It does not mean the target is safe.

Known findings and unexamined scope remain visible together, producing labels such as `HIGH+INCOMPLETE`. If no risk finding exists but coverage is incomplete, the result is `INCOMPLETE` rather than `CLEAR`.

## Main inspection limits

The limits keep crafted inputs and very large folders from exhausting the inspector. Reaching any limit, encountering a read failure, or exceeding an analysis time boundary makes the affected scope `INCOMPLETE`; it is not shown as `CLEAR`.

### Folders / ordinary files

| Target | Limit |
|---|---:|
| Files | 2,500 |
| Directories | 10,000 |
| Directory depth | 128 |
| Enumerated entries | 20,000 |
| Retained path information | 8,388,608 characters |
| Total target size | 12 GB |
| Signature verification | 300 files per inspection |
| Capability-content scanning | 1 GiB per file / 4 GiB per inspection |
| Capability scan time | 60 seconds per file / 180 seconds per inspection |
| PE entropy | First 8 MiB |

Reparse points are not followed. Files and directories are checked through no-follow handles and final-path matching.

### Windows shortcuts

| Target | Limit |
|---|---:|
| Shortcut body read | 4 MiB |
| Each string | 8,192 characters |
| LinkInfo content extraction | 64 KiB |
| ExtraData | 64 blocks |

### ZIP / ZIP-based packages

| Target | Limit |
|---|---:|
| Top-level ZIP input | 2 GiB |
| Entry listing per ZIP | 10,000 entries |
| Central directory and ZIP64 terminal extensible data | 64 MiB |
| Central entry name / normalized path | 4,096 bytes / 2,048 characters |
| Entry-body scanning | 64 MiB per entry / 256 MiB across a top-level ZIP and its nested tree / 1 GiB per inspection |
| One compressed-input read | 64 KiB |
| Nested ZIPs | Depth 3 / 32 per file / 20,000 recursive entries |
| Nested ZIPs held in memory | 32 MiB each / 128 MiB per file |
| ZIP body scan time | 30 seconds per top-level ZIP / 120 seconds per inspection |

Only when needed to prove that a capped entry continues, the inspector reads at most one additional byte. Time limits are checked before and after each source read, but they cannot guarantee preemption of one local operating-system read or inflater call that is already running.

If observed EOF cannot establish the total eligible ZIP-body size, PC Black Box reports the scanned amount without guessing a denominator and displays the total as unknown. When a shared body budget is exhausted, the window, Markdown, and JSON retain the number of unread entry bodies and the subsets whose names declare active content or another container. This is a name-based inventory of unexamined scope, not proof of a body's format or safety.

## Privacy and safety boundary

- The target is not executed or loaded as code.
- Neither the target nor the report is uploaded.
- No automatic network communication or browser launch is performed.
- No process injection, game-memory reading, or packet capture is performed.
- Files are not deleted, quarantined, moved, or repaired.
- Reports exclude this environment's absolute paths, Windows user name, IP addresses, Steam ID, and credentials.

Strings stored inside the target, such as a shortcut target or its arguments, can appear in a report as evidence. Reports also list inspected file names, source hosts, and SHA-256 values, so treat the report itself as sensitive. Reports using the GUI default name or matching `reports/`, `pc-black-box-*.md`, `pc-black-box-*.json`, `*.report.md`, or `*.report.json` are excluded by `.gitignore`. An arbitrary name might not be excluded, so review every report before adding it to Git or sharing it.

`COPY SHA-256` and `COPY LOOKUP URL` only place text on the clipboard. PC Black Box neither opens the URL nor communicates with the service. If the operator opens that URL elsewhere, the SHA-256 is disclosed to VirusTotal. Windows also retains copied text when clipboard history is enabled and may synchronize it through a Microsoft account, depending on the system setting.

## Defense in depth

Inspection input is untrusted. Before normal application initialization, PC Black Box configures or verifies all sixteen required items in `SECURITY-BASELINE-2` and uses each available confirmation mechanism to decide whether the required posture is established. Inspection does not begin if any item cannot be confirmed.

| Layer | Main protections |
|---|---|
| Privilege | Refuses elevated launch and blocks child-process creation |
| Process | Uses a DACL to deny newly requested same-user memory read / write, thread creation, and handle duplication |
| Memory / control flow | Requires DEP, ASLR, Control Flow Guard, SEHOP, strict handle checking, and termination on heap corruption |
| DLL loading | Limits the default P/Invoke search to System32. Restricts normal DLL discovery to the application directory and System32, excluding the current directory, UNC, and Low-integrity images |
| Runtime | Disables the Hot Reload metadata-update path and EventSource tracing surface |
| Managed network boundary | Verifies that the fixed list of transport-capable standard .NET assemblies is absent and stops the process when a later load is detected |
| File I/O | Uses stable no-follow handles and rechecks final path, size, write time, volume number, and 128-bit file ID |
| Saving / traversal | Denies delete sharing on parent directories and rechecks directory IDs and write times after enumeration |
| Parsers | Preflights ZIP terminals and central directories, and bounds every count, length, input size, recursion path, and regular-expression evaluation |

Where the operating system and processor support them, PC Black Box also applies and reads back redirection trust, security-domain isolation, page-combining disablement, and speculative-store-bypass disablement. Hardware shadow-stack state is observed read-only. An unavailable reinforcement is reported as `unavailable` rather than assumed to be active.

The window and reports show the required baseline as `16/16` and then show the reinforcements active on that system. The complete control list, verification limits, residual boundaries, and rejected mitigations with their reasons are recorded in the [threat model](THREAT_MODEL.md).

The design adapts ideas about code trust and strict capability boundaries emphasized by Apple to protections available in the current Windows / WPF architecture. It does not provide iOS App Sandbox equivalence or certification by an external organization.

## Current limitations

- Inspection is static. It does not run a behavioral sandbox or measure runtime network destinations.
- The WPF process is not an AppContainer.
- An administrator, kernel compromise, modified Windows trust store, malicious firmware, and physical access are outside the protection boundary.
- The process DACL affects new access checks after lockdown. It cannot revoke a full-access handle retained by a launcher beforehand.
- Monitoring standard .NET transport assemblies is not operating-system-level capability removal through AppContainer or Windows Filtering Platform. Future native networking code could bypass it, so such a change is outside the accepted source scope.
- ZIP entries are scanned without disk extraction, and valid nested ZIPs are recursively examined within shared budgets. This is neither a malware-signature engine nor a runtime sandbox.
- Nested 7-Zip / RAR / GZip / Cabinet / OLE / ISO content, malformed ZIPs, encrypted nested ZIPs, and over-limit or unreadable nested ZIPs are not opened and remain `INCOMPLETE`.
- A bounded prefixed ZIP / ZIP64 payload is recovered and inspected, but the prefix remains unparsed and therefore `INCOMPLETE`.
- A ZIP polyglot with PDF / PE / script or another primary format keeps both inspection surfaces. Declared entry-body sizes are not trusted; a difference from observed EOF is reported as `INCOMPLETE`.
- Split ZIPs, encrypted central directories, and ambiguous multiple EOCD records are warned about without internal inspection.
- Comments in scripts can match capability terms, so every finding needs context.
- VirusTotal and other external reputation sources, multiple antivirus engines, cloud-known hashes, and dynamic analysis are not included.
- `CLEAR` does not guarantee safety.

Claims such as “NSA-grade” would imply certification that this product does not have. Here, hardening means layered controls based on public specifications and a fail-closed design that refuses to inspect when its required posture cannot be verified.

## Development and verification

Run every command in a non-elevated PowerShell session. An elevated launch is refused with a dedicated message and exit code 1.

Release build:

```powershell
dotnet build .\Destiny2BlackBox.csproj -c Release
```

Generate a Markdown report without opening the window:

```powershell
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --report "C:\path\to\target" ".\inspection.report.md"
```

Print the current security posture without reading a target:

```powershell
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --security-status
```

Verify search, filtering, sanitization, the baseline, and inspection paths with temporary fixtures created and removed by the product:

```powershell
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --self-test
```

Verify the DACL, platform reinforcements, and network-assembly FailFast behavior from an external process:

```powershell
pwsh -NoProfile -File .\tests\Test-RuntimeBoundaries.ps1
```

| Gate | Required result |
|---|---|
| Release build | 0 warnings / 0 errors |
| `--security-status` | `enforced=true controls=16/16` |
| `--self-test` | `PC_BLACK_BOX_SELF_TEST passed=true` |
| `Test-RuntimeBoundaries.ps1` | `PC_BLACK_BOX_RUNTIME_BOUNDARY_TEST passed=true` |

`--self-test` creates its own temporary folder and fixtures and removes them when it finishes. Local build output is created under `bin/` and is not registered as a distribution artifact.

## Related documents

- [CHANGELOG.md](CHANGELOG.md) — implementation changes by version
- [SECURITY.md](SECURITY.md) — security policy and reporting process
- [THREAT_MODEL.md](THREAT_MODEL.md) — trust boundaries, required controls, verification gates, and residual limits
- [AGENTS.md](AGENTS.md) — collaboration rules for this repository
- [README.md](README.md) — Japanese documentation

## Repository policy

This repository is private and source-only. Executables, installers, distribution ZIPs, signing keys, local settings, packet captures, and generated reports are neither committed nor distributed.

Adding access, making the repository public, packaging, signing, releasing, or merging requires the owner's explicit approval.
