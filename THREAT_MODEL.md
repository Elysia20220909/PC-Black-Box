# Threat model

## Security objective

PC Black Box gives the owner prioritized evidence about an untrusted local download without executing it, uploading it, or changing it. A result is not a malware verdict. The primary objective is to keep inspection itself from becoming a path to code execution, data disclosure, or silent evidence corruption.

## Trust boundaries

| Boundary | Trusted | Untrusted |
|---|---|---|
| Application | Signed source history and the running managed code | Selected file names, bytes, metadata, archive entries, and signer text |
| Operating system | Windows process-mitigation state read back through Kernel32 | Paths on network, device, alternate-stream, or reparse namespaces |
| Archive runtime | The serviced .NET runtime and its native `System.IO.Compression.Native.dll` loaded through restricted DLL discovery | Every compressed byte presented to the inflater |
| OLE parser | OpenMcdf 3.4.0 core, resolved through the repository NuGet configuration and lock file | CFB headers, storage trees, FAT/DIFAT/miniFAT links, and stream bodies |
| Output | Sanitized in-memory result and exclusively created local report | Existing report files, reparse destinations, absolute paths, and control characters |
| Network | No network function is required for inspection | Remote reputation, cloud scanning, download, upload, and browser launch |

## Required invariants

- The target is never launched, loaded as code, repaired, moved, quarantined, or deleted.
- Inspection does not continue unless every required control in `SECURITY-BASELINE-2` is enforced.
- The process holds none of the standard .NET network-transport assemblies used by this source tree; loading one terminates it.
- After lockdown, new same-user access requests cannot read or write this process's memory, start a thread in it, or duplicate its handles.
- Parsing uses a stable no-follow handle with no write or delete sharing.
- File identity is checked again after parsing and before a result is trusted.
- Directory identity and write time are checked after enumeration and again after file inspection.
- All loops, input sizes, filesystem entries, directory depth, retained paths, archive metadata, signature checks, text lengths, and regular-expression evaluation are bounded.
- ZIP central-directory structure must pass bounded preflight before the standard archive parser can allocate entry objects.
- ZIP entry bodies are read only through bounded streams and are never extracted to disk; declared size is reconciled with observed EOF. Valid nested ZIPs are recursively inspected in memory under shared depth, count, byte, entry, and time budgets, while unsupported, malformed, unread, or over-limit containers remain explicitly incomplete.
- Top-level OLE uses a non-writable view of the existing inspection handle and strict parser validation. Lazy traversal is limited to 10,000 entries and storage depth 32; each stream is limited to 64 MiB, each file to 256 MiB, and the scan to 1 GiB of structured body reads. Parser errors, regex timeouts, and unread declared bodies retain explicit incomplete coverage. Inputs are not extracted or written back.
- OLE and ZIP share one structured-inspection clock per file (30 seconds) and cumulative scan time (120 seconds). Limits are cooperative: a synchronous OS read or parser operation already in progress cannot be forcibly interrupted by these guards. The existing ZIP coverage fields count only ZIP body bytes; OLE reads consume the shared budget separately.
- VBA macro bodies and Windows Installer tables/actions are not decoded. Recognized VBA names and any top-level OLE with an MSI/MSP extension retain incomplete structure. Name evidence does not identify every renamed installer, encrypted payload, or embedded format; the synthetic fixtures are not a real-world Office/MSI compatibility suite.
- Decompression may enter the framework's native inflater only after DLL discovery has excluded the target and current directory. Compressed input, expanded output, and elapsed time remain bounded at the managed edge; native inflater correctness is a trusted runtime dependency rather than a claim made by this source tree.
- Report target metadata uses display names and target-relative file paths, without adding the selected target's absolute path. Display names, source hosts, hashes, and input-held evidence remain and can identify a person or contain absolute paths; this is not report anonymization. Batch schema v2 removes `targets[].path`; target array order remains input order, including duplicate names and failed targets. Empty or drive-root display names use the fixed label `target`.
- No administrator privilege, UIAccess, external lookup, or child process is required. An elevated
  launch is refused rather than accommodated.

## Security baseline

`SECURITY-BASELINE-2` has two tiers. The required tier gates inspection: if any one of its controls
cannot be applied and read back, the application refuses to inspect anything. The reinforcement tier
depends on the OS build and the CPU; each item is applied and read back where the platform offers it,
and reported as `unavailable` where it does not. Reinforcements are displayed, never assumed.

### Required tier — sixteen controls, fail closed

1. Finite default regular-expression timeout.
2. Child-process creation blocked.
3. Remote and Low-integrity native images blocked; System32 preferred.
4. Permanent strict-handle checking.
5. Legacy extension points disabled.
6. Non-system font loading disabled.
7. DEP enabled permanently.
8. Bottom-up and high-entropy ASLR enabled.
9. Control Flow Guard enabled.
10. SEHOP enabled.
11. Default DLL discovery restricted to the application directory and System32.
12. Current directory removed from DLL discovery.
13. Critical-error dialogs disabled and verified.
14. Heap corruption terminates the process instead of continuing in an attacker-influenced allocator state.
15. No standard .NET network-transport assembly is loaded, and a later load of one terminates the process.
16. The process object's DACL denies newly requested memory read, memory write, thread creation, and
    handle duplication rights to same-user callers, including the implicit rights of the object owner.

### Reinforcement tier — four controls, applied where the platform allows

17. Redirection trust enforced: the process refuses to follow junctions and symbolic links planted by a
    lower-privilege writer. Requires Windows 10 21H2 or later.
18. Security-domain isolation and page-combining disabled, so inspected bytes in this address space are
    not shared with any process outside this security domain.
19. Speculative store bypass disabled.
20. Hardware-enforced shadow stacks (CET) observed as active. This cannot be switched on for a running
    process, so the observation remains read only. An inactive result keeps `state=unavailable` and
    distinguishes `reason=cpu-unsupported` (successful policy read and CPUID confirms missing hardware),
    `reason=query-failed` (policy read failed), and `reason=not-enabled` (readable policy with a clear
    enable flag, CPU support present or unknown). CPU-query failure is not evidence of non-support.
    These diagnostics do not change the required tier or the reinforcement counts.

### Verification limits within the baseline

- Both report writers reject destinations over or inside their selected targets. The batch API requires all original input paths, including failed inspections; unknown target type does not remove containment protection. Every comparison uses normalized paths and separator boundaries, including drive roots. All targets are checked before creating any output or temporary file.
- A batch target boundary must be a verifiable local-drive path. Its existing file/directory or nearest existing ancestor is checked with the no-follow reader and final-handle path matching. Ambiguous trailing dots/spaces, reparse points, and access/sharing failures stop the save. A missing target can still be reported when its boundary is verifiable and the destination is outside it. These checks do not prove every filesystem alias or atomically prevent concurrent replacement between validation and writing.
- Heap termination on corruption has no query API in Windows. The `HeapSetInformation` result is the
  only available confirmation; every other control in both tiers is read back from the kernel.
- The network control blocks the assemblies that can actually move bytes — sockets, MsQuic, the DNS
  resolver, HTTP, mail, ping, and WebSockets. The request-shaped layers above them
  (`System.Net.Requests`, `System.Net.WebClient`, `System.Net.ServicePoint`, `System.Net.Security`)
  are not blocked: they cannot transmit without the socket layer, and `System.Configuration` loads
  several of them while opening a purely local `app.config` during WPF startup.
- This managed-runtime control is intentionally narrower than an AppContainer or Windows Filtering
  Platform capability boundary. Native WinSock or HTTP P/Invoke added to this source could bypass it;
  such a change is outside the accepted repository scope and must fail review.
- ZIP decompression relies on the supported .NET runtime's native `System.IO.Compression.Native.dll`.
  The application verifies where native images may be loaded from and bounds every call around the
  inflater, but it cannot independently prove the memory safety of that runtime component. Applying .NET
  servicing updates is part of the deployment boundary.
- A process DACL affects later access checks. Windows does not revoke a full-access handle already
  returned to a launcher or held before lockdown, so a hostile launcher is outside this boundary.
- The inspection path refuses to run unless the required tier is enforced, and a standard test host
  cannot satisfy that: `vstest` reaches its runner over a socket, so the host has already loaded
  `System.Net.Sockets` and the managed-transport control reports `not-enforced` before the first test
  runs. Inspection behavior is therefore verified from `--self-test` inside the hardened product
  process instead of from an external unit-test host. Adding a test-only exemption to the baseline
  would make the enforced posture untrue of the process that ships, and is rejected for that reason.

## Adversaries considered

- A malicious download crafted to exploit format parsing, regular expressions, archive enumeration, Unicode display, signature handling, or integer boundaries.
- A local race that attempts to replace or rewrite a file during inspection.
- A local race that replaces an intermediate directory with a junction between validation and access.
- A local race that grows files after enumeration to exceed the cumulative read limit.
- A folder that uses empty, unreadable, or linked entries and extreme path depth to exhaust traversal resources.
- A ZIP that declares excessive entries or metadata, underreports central records, or embeds a fake EOCD to desynchronize parsers.
- A ZIP that prepends junk before the real payload, underreports an entry body as zero, hides active content behind a Windows-normalized double extension, overlaps another primary format, prefixes or deeply nests another ZIP, floods recursive containers, or places a capability term across a decompression-chunk boundary.
- A malformed compressed stream crafted to exercise the managed archive parser or its native inflater.
- A local low-integrity or network location attempting to inject a native image.
- A malicious working directory attempting DLL preloading.
- A same-user process that tries to read inspected bytes out of this process's memory, patch its code,
  start a thread inside it, or steal its open file handles.
- A same-user process that tries to rewrite this process's DACL by way of implicit owner rights.
- Any standard .NET code path that would give the process a managed network transport after startup.
- An accidental operator action that selects a network, device, alternate-stream, or linked path.

## Explicitly out of scope

- Kernel drivers, filesystem minifilters, real-time antivirus monitoring, memory scanning, behavioral sandboxing, cloud reputation, remediation, and enterprise policy enforcement.
- Protection against an administrator, kernel compromise, compromised Windows trust store, malicious firmware, or physical access.
- AppContainer isolation and an Authenticode-signed distribution binary. Those require a separately approved packaging and signing design; this repository stays source-only regardless of its visibility.
- Revocation of process handles acquired before the startup DACL is installed, and OS-level denial of arbitrary native networking.

## Mitigations considered and deliberately not applied

These are stronger than anything in the baseline and were rejected on evidence, not oversight. Each
would break the running product, and a control that cannot stay on is worse than an honest absence.

| Mitigation | Why it is not applied |
|---|---|
| Dynamic code prohibition (`ProcessDynamicCodePolicy`) | The CLR generates and executes code at runtime. Enabling it stops the process before the first window is drawn. It would require a NativeAOT build, which WPF does not support. |
| Microsoft-signed images only (`ProcessSignaturePolicy`) | Blocks every later non-Microsoft native image load. The application host itself is unsigned, and a self-contained publish would fail. It also converts any injected AV or IME hook into a crash rather than a refusal. |
| Win32k system-call disable (`ProcessSystemCallDisablePolicy`) | The process is a WPF desktop application and needs win32k for every window it draws. |
| Payload restriction / EAF, IAF, and ROP guards | Applied at process creation by policy, not reliably from inside a running .NET process, and unverifiable by read-back from where this baseline runs. |


## Verification gates

- Strict Release rebuild with current .NET analyzers, all security rules enabled, and warnings treated as errors.
- Restore the application with its checked-in lock file and repository NuGet configuration. Unexpected dependency changes or content hashes must fail locked restore. Check upstream security advisories as well as the NuGet audit, which can lag newly published findings; neither proves parser correctness or SDK/runtime provenance.
- Dependency audit must report no advisory at any severity, direct or transitive.
- Runtime `--security-status` result must be `enforced=true` with every required control present, and must
  print one `control=… tier=… state=…` line per control for independent review.
- An elevated launch must be refused before inspection, with `PC_BLACK_BOX_ELEVATION elevated=true
  refusing=true` on the command line and a non-zero exit code, while the posture it prints still reports
  `enforced=true` — the refusal is a privilege decision, not a failed control.
- A fail-closed startup dialog must name the required controls that did not verify, in either language,
  and must name nothing else: no reinforcement lines, no enforced controls, and no text from a target.
- An external same-user process must be denied `PROCESS_VM_READ`, `PROCESS_VM_WRITE`,
  `PROCESS_CREATE_THREAD`, and `PROCESS_DUP_HANDLE` against a running instance, while
  `PROCESS_QUERY_LIMITED_INFORMATION` still succeeds so the operator keeps Task Manager visibility.
- `tests/Test-RuntimeBoundaries.ps1` must reproduce that access check, read back the combined
  side-channel flags, and prove that loading `System.Net.Sockets` terminates a separate probe through
  the managed network guard. Its product-DLL test host passes the normal elevation and required-posture
  checks without creating a window; it does not verify GUI or EXE/apphost-specific startup behavior.
- Target-free `--self-test` must pass product query, sanitization, report, baseline, directory-budget, ZIP, ZIP64, and ambiguous-record checks.
- `--self-test` must also inspect fixtures it creates and removes itself, and confirm that a text file's
  reported digest matches the bytes on disk, that script capabilities beyond the first 8 MiB and archive
  traversal are reported without extraction, that bounded whitespace survives a content-chunk boundary,
  that an invalid archive promotes the production result to `INCOMPLETE`, that long display paths do not
  hide an active extension, that no archive entry escapes onto disk, and that an already-canceled inspection
  ends without reading the target.
- `--self-test` must recover a prefixed ZIP payload without extracting it, detect an internal double
  extension, retain a capability term that crosses a ZIP entry-content chunk boundary, recursively inspect
  a valid nested ZIP even when its entry name has no archive extension, and preserve its full logical path.
- `--self-test` must reject a fourth nested ZIP level, the thirty-third nested ZIP, an over-buffer nested
  ZIP, and a malformed named nested ZIP as `INCOMPLETE`, while proving that no nested entry is written beside the fixture.
- `--self-test` must scan an entry whose central directory declares zero bytes, preserve the primary PDF
  side of a PDF+ZIP polyglot, keep a malformed ZIP-like tail incomplete, recover both fixed and extensible-data
  prefixed ZIP64 records, keep disguised nested OLE/ISO/PE content incomplete, and never render an unknown
  archive-body total as fully covered. A lower-weight decoy entry must not suppress the same capability in
  a later active-content entry.
- `--self-test` must prove that a shortcut is judged by the command line inside it, that a shortcut whose
  declared sizes do not fit ends the walk and reports the result as `INCOMPLETE` rather than throwing, and
  that malformed OLE stays incomplete, that well-formed storage trees are walked, and that undecoded VBA
  or Installer tables retain incomplete structure. OLE fixtures also cover entry/depth/byte limits,
  shared ZIP/OLE budgets, regex/time failures, corrupt chains and directory trees, truncation, and cancellation.
- `--self-test` must prove the four completeness aspects stay apart: a container that was never opened
  limits structure alone while digest, content and signature remain complete, and a file that could not be
  opened limits all four without falsely claiming that traversal missed the file. It must also expose every
  archive entry left unread after a shared content budget ends, inventory active-content and container names
  within that tail, avoid calling an honestly named executable entry hidden, and require corroboration before
  a signed PE plus trailing ZIP receives danger weight.
- Live process mitigation flags must match the required policy bits.
- Regression fixtures must preserve signature, capability, hostile-archive, privacy, and path-boundary behavior.
- Report regressions must decode JSON before checking for selected-path leaks, preserve relative file paths and input-held evidence, and cover failed targets, duplicate names, drive roots, and the batch v2 field contract.
- Batch-write regressions must reject target-file replacement and output inside any selected folder before changing fixture contents or creating temporary files, including failed/unknown targets and overwrite mode. Outside destinations and similarly prefixed sibling directories must remain writable; normalized relative paths, casing, separators, and drive-root containment must be covered.
- Regression checks must preserve final-handle path matching, guarded directory writes, directory mutation detection, archive preflight, and cumulative observed-size limits.
- Secret scanning and tracked-artifact inspection must pass before a signed commit is pushed.
