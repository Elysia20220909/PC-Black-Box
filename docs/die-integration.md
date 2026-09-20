# DiE local integration

The integrated local package has one entry point: root `PC Black Box.exe`. This launcher starts the protected GUI in `app/` and services repeated DiE requests over a local named pipe. Selecting a single file and pressing Inspect in the GUI now runs the ordinary inspection followed by isolated DiE classification. Cancellation closes the request connection and cancels staging/parser work. Results or failure/skip status appear in the GUI and Markdown/JSON reports. No DiE subprocess is created by the protected main process.

The named pipe is first-instance/current-user-only and both peers verify the other process ID. Requests and responses have explicit frame limits. The helper serves only its own GUI child, one request at a time. Folder inspections and files over 64 MiB retain ordinary PC Black Box analysis, with an explicit DiE skip status. Starting the executable under `app/` directly does not establish a DiE session; start the root executable instead.

## Local use

Build both projects for development:

```powershell
dotnet build Destiny2BlackBox.csproj -c Release
dotnet build tools/DieBridge/DieBridge.csproj -c Release
```

From this checkout, run PowerShell 7:

```powershell
./scripts/Invoke-DieInspection.ps1 -InputFile C:/path/sample.txt -EngineArchive C:/path/die_win32_portable_3.21_x86.zip -ReportPath C:/path/new-report.md
```

The script remains available as the legacy one-shot path; replace `-ReportPath ...` with `-ShowWindow` for its one-shot GUI result viewer. The installed root launcher needs no script. Development verification does not launch the GUI. Existing reports are not overwritten.

The bridge accepts only the official 3.21 x86 portable ZIP with SHA-256 `7D7195F757C45F6B69364D167C9958FA60339D53876A87E4A1EDBCBF67D1E477`. It uses the binary inside that pinned archive, not the separately rebuilt DiE executable or mutable Downloads directory. It does not download an engine. This is not decompilation or a binary-reproducibility claim.

## Boundaries

- One regular local input file, at most 64 MiB. No directories, network paths, alternate streams, or reparse-point targets.
- Only diec.exe, Qt Core/Script, three VC runtime DLLs, and the main signature database are staged. Extra/custom databases point to an empty directory; recursive/deep/heuristic options are not enabled.
- The bridge applies and verifies the existing process-object lockdown before staging. It must retain child-creation capability; it does not claim the main application's full 16-control baseline.
- A unique temporary AppContainer profile has zero capabilities. Its token is checked before resuming the child. The Job Object permits one process, limits its memory to 256 MiB, and kills it on close. Parser deadline: 30 seconds. Each output stream: 512 KiB. JSON depth and record/label counts are bounded. There is no unsandboxed fallback.
- Temporary engine directories grant the container read/execute only. File handles deny write/delete while input, engine, database, and evidence are consumed. Engine directory ACLs additionally prevent new DLL/database planting; retained handles restore ACLs for cleanup.
- The original file is held read-only; the staged copy's SHA-256 is checked. The main process independently matches the evidence digest against its inspection. This detects mismatched inputs, not a malicious parser's lies. Imported data is always untrusted classification, never a malware or isolation verdict, and does not reduce the risk score.
- A temporary local profile and scratch directory are created and removed for each parser request. No firewall rules, certificate-store entries, system PATH or startup entries are changed. Cleanup failures are reported; abrupt termination or OS crash can leave temporary data. Session mode cleans up after each response. Legacy view mode retains input/evidence until the main window exits; legacy report mode has a two-minute main-process deadline.

AppContainer is not a VM. Kernel/admin compromise, pre-existing process handles, parser vulnerabilities, denial of service, and the correctness of Windows confinement remain outside the claims. Same-user manipulation before bridge startup is not eliminated. Full internet traffic tracing and an adversarial sandbox-escape audit are not performed.

## Verification

Product self-tests cover valid import, digest mismatch, missing digest coverage, multi-file rejection, oversized/malformed/trailing JSON, invalid labels, null detection records, and exclusion of unrelated nested metadata. `tests/DieSandboxProbe` builds a small local native probe: a reachable loopback listener is the positive control, sandbox connections are denied or time out without acceptance, writes to staged runtime are denied, excessive output is rejected, and a hanging child is terminated. This is scoped evidence, not proof that every network route is blocked.

Rebuild and run the probe with the existing MSVC Build Tools and .NET SDK:

```powershell
./tests/DieSandboxProbe/build-native.cmd
dotnet build tests/DieSandboxProbe/DieSandboxProbe.csproj -c Release
dotnet tests/DieSandboxProbe/bin/Release/net10.0-windows10.0.17763.0/DieSandboxProbe.dll tests/DieSandboxProbe/obj/probe.exe
```

Never rebuild the main application concurrently with its self-tests: the running DLL is locked. Runtime boundary checks must run after self-tests complete.

## Dependencies and distribution

No DiE/Qt binaries or signature database are committed. The user-approved local installation includes the pinned official ZIP and necessary first-party components, but is not uploaded or published. DiE and the signature repository have MIT notices; Qt and bundled native dependencies have separate terms. A complete redistribution review, matching Qt source/notices, native third-party inventory, and Microsoft runtime redistribution conditions remain unresolved. The existing Microsoft SDK recipient-consent issue is unchanged. Separate-process use does not settle licensing obligations.

References: [DiE 3.21 release](https://github.com/horsicq/DIE-engine/releases/tag/3.21), [Microsoft AppContainer setup](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer), [Qt open-source obligations](https://www.qt.io/development/open-source-lgpl-obligations).

The user approved local replacement of signed-build-831eb7f with a recoverable backup and signing first-party binaries with the existing self-signed certificate. DiE and third-party files are not re-signed. No push, merge or external publication is authorized. The old directory name does not identify the source revision.

## Local results (2026-09-20)

- Main Release build and bridge build: zero compiler warnings/errors on the successful final builds.
- Product self-test: 311 checks passed (297 existing plus 14 DiE checks).
- Main security status: all 16 required controls enforced; 3/4 platform reinforcements, user-shadow-stack unavailable.
- Runtime boundary test: 9 checks passed, including memory/thread/handle access denial and managed network guard termination.
- Native sandbox probe: controlled loopback connectivity denied/timed out, runtime-directory write denied, output overflow rejected, 30-second timeout terminated the child. Positive-control loopback connection outside the container succeeded.
- Directory-seal regression: an injected writable Everyone ACE was removed; same-user file planting failed after sealing. Final sandbox probe exited 0 with all six markers true.
- Independent read-only review found staging/process-protection/validation issues, which were repaired. The final bounded re-review found no remaining actionable P1/P2 in the reviewed fixes; this is not comprehensive security approval.
- Official DiE archive -> AppContainer parsing -> main SHA-256 validation -> integrated Markdown report: successful on a harmless plain-text fixture. GUI display was not exercised.
- NuGet advisory query for the main project, including transitive packages: no known vulnerable packages reported by the configured source. This does not cover Qt/native DiE components or prove absence of vulnerabilities.
- An initial runtime-gate rebuild failed because the independently running self-test held the DLL open. Sequential rerun succeeded; the failed run is not counted as a pass.

The results above record the first, one-shot integration milestone. Session-mode and deployment results are recorded in the installed BUILD-INFO.txt. The deployed binaries were built from the independent `agent/die-integration` checkout before its source changes were committed. External native parser fuzzing, all-format coverage, GUI operation, another-PC behavior and distribution clearance remain unverified.

## Integrated local deployment (2026-09-20)

The approved signed-build-831eb7f directory now contains the unified launcher, protected app/ payload and pinned engine/ archive. The previous nine-file directory was moved intact to signed-build-831eb7f-backup-20260920-die; every original file's SHA-256 was verified after the move. First-party EXE/DLL files (four) have valid signatures on this PC using the existing self-signed certificate, without a timestamp service. Third-party engine files were not re-signed.

Post-deployment verification passed: product self-test 314 checks; all 16 required controls; root signed EXE headless session with immediate disconnect, request disconnect, cancellation and two successful subsequent analyses; four valid signatures; deployed binary hashes matching the pre-deployment snapshot. Runtime boundary test passed nine checks. The native probe additionally verified cancellation after the parser process was resumed. The reviewed GUI pending-result publication and pipe reconnection defects were fixed; bounded independent re-review reported no remaining P1/P2 in those fixes.

The actual GUI was not opened or operated. The installed README-LOCAL.md documents single-file/64 MiB scope, runtime requirements, limitations and folder-level rollback. Nothing was uploaded or published. Source changes were uncommitted at the time of this deployment.
