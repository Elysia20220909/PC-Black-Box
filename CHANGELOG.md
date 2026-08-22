# Changelog

## 0.8.1 — 2026-08-22

- Stopped rewarding an attacker for breaking the shortcut parser. A LinkInfo block larger than the extraction cap is legal and trivial to pad, and it made the walk abandon every field that follows — so a shortcut running an encoded command scored lower than one that parsed cleanly. The walk now steps over an oversized block and keeps reading, the header-derived flags are recorded even when the command line cannot be recovered, and a failed parse of active content is scored at review weight instead of the floor.
- Applied the same rule to every container this product can name but cannot open. `RAR`, `7-Zip` and `GZip` were named and then silently skipped, so shipping a payload as `.7z` instead of `.zip` erased every archive finding and still reported `CLEAR` and complete. Those formats now report `container-unopened` and `INCOMPLETE`, and ISO 9660 and Cabinet images are recognized rather than passing as `Binary / unknown` — an ISO matters because Mark-of-the-Web does not reach the files inside it.

- Said what the clipboard actually is. The copy action leaves the process, but Windows clipboard history retains copied text and can sync it to a Microsoft account, and this product cannot read that setting reliably — so the confirmation and the README name it instead of implying the string stops at the clipboard.
- Ignored generated reports wherever they are saved, not only under `reports/`. A report lists inspected file names, source hosts, and digests, so it identifies more than any single hash; only the directory was covered before.

- Read Windows shortcuts instead of naming them. A `.lnk` was never opened: it sat outside the capability gate, so a shortcut wearing a document name and running `powershell -w hidden -enc <payload>` was reported as `LOW` and, worse, as a complete inspection. The command line is now recovered from the shortcut structure and judged like the script it is. The measured fixture moved from `LOW 18` to `HIGH 100`.
- Reserved the danger-level shortcut finding for a command line that also carries another signal — an encoded command, a hidden window, a download, a double extension, or a Mark-of-the-Web. Measured against the 72 shortcuts in this machine’s system Start Menu, the first rule called 6 legitimate developer tools dangerous; the corroborated rule calls none of them dangerous while the malicious-shaped fixture stays at `HIGH 100`.
- Added `encoded-command` and `hidden-window` capability patterns, so PowerShell’s abbreviated switches (`-e`, `-enc`, `-encodedcommand`) and hidden-window launches are matched wherever they appear, not only in shortcuts.
- Extended the double-extension check to `.lnk`, `.url`, `.msi`, `.iso`, `.img`, `.pif`, `.cpl` and the remaining script extensions; `invoice.pdf.lnk` previously passed it untouched.
- Recognized OLE compound files (MSI, MSP, legacy Office) by content rather than leaving them as `Binary / unknown`. Their strings are now scanned, and because their storage tree is not parsed they are reported `INCOMPLETE` instead of `CLEAR`. A 655 MB installer previously came back `CLEAR (0/100)` and `complete` after being read only to compute its digest.
- Reported what a shortcut would run in the window, the Markdown report, and the JSON, so the finding carries its evidence.
- Corrected the privacy statement: the report omits this machine’s paths and identifiers, while strings found inside the target are shown as evidence.

## 0.8.0 — 2026-08-21

- Replaced the first-8-MiB capability sample with bounded streaming for scripts, Windows PE files, and PDFs. Chunk overlap preserves indicators that cross a read boundary, while explicit 1-GiB/file, 4-GiB/inspection, 60-second/file, and 180-second/inspection budgets fail closed as `INCOMPLETE`; SHA-256 remains a separate whole-file pass. The byte budgets govern coverage at a measured ~50 MiB/s, so an ordinary folder of installers is inspected in full instead of exhausting the budget partway.
- Made any per-file inspection limit promote the overall result to `INCOMPLETE`; an incomplete traversal can no longer present itself as `CLEAR` in the window, Markdown, or JSON report.
- Added explicit report evidence for SHA-256 bytes read and capability-pattern bytes scanned, plus a self-test fixture whose indicator appears beyond the former 8-MiB boundary.
- Advanced the JSON report schema to v3 with separate `risk`, `completeness`, and combined `assessment` fields, so a known `HIGH` cannot be hidden by `INCOMPLETE`.
- Added a `COPY LOOKUP URL` action beside `COPY SHA-256`, built only from a revalidated SHA-256, so an operator can carry a digest to an external service without the product itself gaining any network path. The message states what opening the URL would disclose.
- Replaced the stale hard-coded window version with the executing assembly version and documented that entropy remains an 8-MiB sample while archive entry bodies remain outside the static parser.

## 0.7.3 — 2026-08-15

- Named the required controls that failed in the startup dialog, in the operator's own language, instead of reporting only that "the baseline" could not be verified. The previous wording sent the reader looking for a fault in their machine rather than at the single control that was missing.
- Added a self-test that proves the process-owner comparison distinguishes the token's default owner from the user SID. Under an ordinary token the two are the same value, so nothing in a normal run could tell the corrected comparison from the mistaken one.
- Locked the failure and refusal wording to fixed control identifiers in both languages, so a dialog shown at startup can never carry inspected data.

## 0.7.2 — 2026-08-15

- Refused an elevated launch outright, with its own message instead of a generic baseline failure. Inspecting untrusted bytes never needs a token that can rewrite the machine, so startup, the command-line modes, and the direct scanner entry each decline before reading anything.
- Compared the process object's read-back owner against the token's own default owner rather than the user SID. An elevated token names the Administrators group, which previously reported a correctly applied DACL as unenforced and stopped the application through the wrong door.
- Extended the target-free self-test to certify that the process it is running in is not elevated.

## 0.7.1 — 2026-08-12

- Extended the target-free self-test to cover the inspection path itself: digest fidelity on an ordinary text file, script-capability findings, archive traversal and active content reported without extraction, and an already-canceled inspection that reads nothing. Each check builds and removes its own temporary fixture.
- Locked the documented score bands and clamp, the active-content extension match, and the report guarantees that keep absolute paths out and sanitize table cells.
- Recorded why these checks run inside the hardened product process: a standard test host reaches its runner over a socket, so the managed-transport control cannot be enforced there and the inspection path refuses to run.

## 0.7.0 — 2026-08-11

- Replaced the 13-control baseline with `SECURITY-BASELINE-2`: sixteen required controls that gate inspection and four platform reinforcements that are applied where the OS and CPU allow and reported as unavailable where they do not.
- Locked down newly requested same-user process access to memory, thread creation, and handle duplication; an `OWNER RIGHTS` entry removes the implicit owner right that could rewrite the DACL. Pre-existing handles remain an explicit Windows boundary.
- Made the standard .NET network-transport surface a checked property: listed transport assemblies may not be loaded, while documentation now distinguishes this guard from OS-level AppContainer or WFP isolation.
- Enabled heap termination on corruption, redirection trust, security-domain isolation, page-combining disable, and speculative-store-bypass disable, and reported hardware shadow-stack state.
- Disabled the hot reload metadata-update path and the EventSource tracing surface in the shipped runtime configuration.
- Enabled all .NET security analyzer rules as build errors and made any dependency advisory, at any severity, fail the build.
- Extended `--security-status` to distinguish unsupported reinforcements from failed enforcement, and the self-test to verify the exact process DACL, combined side-channel flags, live managed-transport absence, and the transport list in both directions.
- Added a source-only external runtime-boundary test for same-user process access, combined side-channel flags, and the managed network guard's FailFast path.
- Documented the mitigations that were considered and deliberately rejected, with the reason each would break the running product.

## 0.6.0 — 2026-08-08

- Reject oversized, malformed, split, or ambiguous ZIP central directories before constructing the standard archive parser.
- Bound ZIP metadata to 10,000 entries, 64 MiB of central-directory data, and 4,096 bytes per central entry name.
- Bound folder traversal by directory count, depth, total enumerated entries, and retained path metadata in addition to file count and bytes.
- Snapshot every enumerated directory and mark the result partial if folder contents change before inspection completes.
- Extend the target-free self-test with ZIP, ZIP64, fake-end-record, entry-flood, directory, enumeration, and path-budget boundaries.

## 0.5.1 — 2026-08-04

- Verify that every opened file and directory handle resolves to the exact requested local path.
- Hold no-delete directory guards while enumerating targets and writing settings or reports.
- Enforce the 12 GB folder limit against stable, handle-observed file sizes instead of relying only on enumeration metadata.
- Extend the target-free self-test with cumulative-size boundaries and guarded report-replacement checks.

## 0.5.0 — 2026-08-03

- Added instant file search across names, types, signatures, signers, sources, and findings.
- Added `HIGH`, `REVIEW`, `LOW`, and `CLEAR` filters with visible result counts.
- Made finding cards open the matching file evidence directly by pointer or keyboard.
- Added discoverable keyboard shortcuts and visible keyboard-focus states.
- Localized file-detail labels and made clipboard failures non-fatal.
- Improved pixel alignment and empty-filter states without changing the offline security boundary.
- Added a target-free product self-test for query, sanitization, reporting, and enforced security controls.

## 0.4.0 — 2026-08-02

- Added a fail-closed 13-control process security baseline with OS and runtime verification.
- Added strict handle checks, legacy extension-point blocking, non-system-font blocking, and hardened DLL discovery.
- Required DEP, high-entropy ASLR, Control Flow Guard, and SEHOP before any target can be inspected.
- Added a safe security-status command and embedded the verified posture in Markdown and JSON reports.
- Added a written threat model and made strict analyzer, overflow, and deterministic build settings project defaults.
- Embedded a project-owned multi-resolution Windows icon in the executable and WPF window.

## 0.1.0 — 2026-07-31

- Initial Windows WPF release.
- Added file and bounded folder inspection without target execution.
- Added SHA-256, Authenticode, Mark-of-the-Web, magic-byte, entropy, PE, script-capability, PDF, and ZIP/Office checks.
- Added transparent risk evidence, sanitized Markdown/JSON reports, and explicit hash-only reputation lookup.
- Added Japanese and English UI and documentation.
