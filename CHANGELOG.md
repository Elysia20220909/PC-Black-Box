# Changelog

## Unreleased

- Corrected OLE body coverage at the exact byte limit without reading beyond the budget. A fully observed logical stream is no longer marked incomplete solely because an extra EOF read did not fit; short EOF still marks both content and structure incomplete.
- Added real CFB fixtures around the 64 MiB stream boundary and synthetic production-reader tests for declared-length mismatches, short reads, zero/exact/over-limit budgets, and cancellation propagation.
- Made the hosted-account removal check fail on lookup errors instead of treating them as proof of absence. Added non-mutating regression tests for absence, a remaining account, and failed or partial enumeration.
- Kept OLE regex timeouts inside the per-file inspection boundary, recording incomplete content and structure instead of aborting the scan.
- Marked top-level MSI/MSP tables as undecoded even without a literal CustomAction stream name. Ordinary non-installer OLE files retain their existing completeness rules.
- Replaced eager OLE entry materialization with bounded lazy traversal, reconciled observed stream EOF with the declared length, and shared one file clock across OLE and trailing ZIP inspection.
- Added target-free OLE regression fixtures for normal input preservation, installer names, regex failure, shared byte/time budgets, depth and entry boundaries, and corrupt directory/FAT/miniFAT/DIFAT structures.
- Locked NuGet package versions and content hashes, restricted package sources, and added Windows build, formatting, advisory, and headless runtime gates. CI uses a disposable standard user without weakening the product's administrator-launch refusal; no distribution artifacts are created or uploaded.

## 0.13.0 — 2026-09-07

- Opened the OLE compound-file storage tree instead of stopping at the container name. A top-level MSI or legacy Office file is walked under the same byte and time budgets as ZIP entry bodies, using a read-only view of the already-open inspection stream. Nothing is extracted, launched, or written back.
- Recorded VBA and MSI CustomAction names as findings. Those streams are capability-scanned as bytes; the macro body and installer tables themselves stay undecoded, so the structure aspect remains `INCOMPLETE`. A well-formed tree no longer emits `ole-structure-unparsed`.
- Kept a malformed OLE header (magic plus strings, no valid FAT) fail-closed as `ole-structure-unparsed` and `INCOMPLETE`. Nested OLE inside a ZIP is still unopened. Added OpenMcdf 3.3.0 as the first PackageReference; net10.0 brings no transitive packages.

## 0.12.0 — 2026-08-24

- Promoted an exhausted ZIP-body budget from a prose-only warning to structured tail inventory. The window, Markdown, and JSON now retain the entry bodies left after that budget and the subsets whose names declare active content or another container.
- Kept the classification deliberately name-based: it preserves actionable metadata without claiming that an unread body was identified or safe. Aggregate and per-file evidence are both emitted, and the JSON schema is now v7.
- Extended the production byte-boundary fixture so one extreme-ratio container-named body and one active-content-named body remain after the 256-MiB budget. The regression keeps budget exhaustion ahead of skip policies, then verifies both counts through the model, warning, Markdown, and JSON surfaces.

## 0.11.0 — 2026-08-24

- Split incomplete coverage into traversal, digest, capability-content, signature, and structure aspects in the window, Markdown, JSON, and per-file inventory. A limit and its operator-facing reason are now recorded together.
- Kept traversal independent from a file that was reached but could not be read, so the report names the missing file aspects without falsely claiming that folder discovery failed.
- Preserved evidence when archive-content budgets run out by reporting the number of entry bodies left unread and the container-named entries among them, instead of silently dropping the tail of that ZIP layer.
- Reserved the hidden-executable-body finding for a PE body whose entry name does not already declare active content, while retaining ordinary active-entry counting for honestly named executables.
- Kept a validly signed self-extracting PE at informational polyglot weight even when it carries the normal Internet Zone mark of a download; another danger-level indicator is required to escalate it.
- Documented the native .NET decompression component that receives untrusted deflate data and retained the bounded-read, fail-closed parser boundary. The JSON schema is now v6.

## 0.10.0 — 2026-08-23

- Added bounded recursive inspection for valid ZIP and ZIP-based package entries. Nested archives are held only in memory, never extracted or launched, and are recognized from either a ZIP-family name or a validated local-header/end-record pair.
- Shared one fail-closed budget across the full archive tree: depth 3, 32 nested archives, 20,000 recursive entries, 32 MiB per nested archive, 128 MiB of nested buffers, 256 MiB of entry bodies and 30 seconds per top-level archive. Existing 1-GiB/120-second inspection-wide limits remain in force.
- Kept unsupported, malformed, unreadable and over-limit nested content honest. RAR, 7-Zip, GZip, Cabinet, OLE and ISO interiors remain unopened; any unexamined interior preserves `INCOMPLETE` and an unknown archive-body denominator. A valid prefixed nested ZIP is still inspected, while its prefix is reported as unparsed.
- Carried logical evidence paths such as `payload.dat!payload.ps1` through capability findings and added nested archive count, inner-entry count, maximum depth and inspected nested bytes to the window, Markdown and JSON reports. The JSON schema is now v5.
- Replaced the old “nested ZIP is always unopened” fixture with target-free checks for disguised, misnamed and prefixed valid nested ZIPs, cross-level active-content accounting, depth, count and byte boundaries, malformed nested data, full recursive coverage, and the continued absence of extracted files. The product self-test now contains 88 checks.

## 0.9.0 — 2026-08-22

- Stopped treating bytes before a ZIP payload as a type-evasion win. For ordinary ZIP and bounded ZIP64 terminal records, including records with extensible data, the physical record position and its relative offset recover the payload start; bounded preflight and the standard parser then operate through a read-only offset view. The archive body is still inspected, while the prefix itself is reported as unparsed and keeps the result `INCOMPLETE`. No entry is extracted or launched.
- Kept the primary format and ZIP structure separate. PDF, PE, script, OLE, or another recognized format with a valid trailing ZIP now has both surfaces inspected and reports `archive-polyglot`; a ZIP-like terminal record that cannot be validated reports `invalid-embedded-archive` instead of falling back to a complete ordinary file.
- Extended archive-name inspection to catch document-looking double extensions such as `invoice.pdf.ps1`, including names whose executable extension is followed by Windows-trimmed spaces or dots.
- Added bounded streaming over every direct ZIP entry body, including entries whose central directory declares zero bytes or names them as directories. Actual EOF is observed independently of the declaration; a mismatch reports `archive-entry-size-mismatch` and `INCOMPLETE`. Active content is inspected first, and chunk overlap preserves capability terms across reads.
- Capability findings retain the strongest matching context across entries, so a low-weight marker in a decoy PDF or binary cannot suppress the same capability in a later script.
- The body budgets are 64 MiB per entry, 256 MiB per ZIP, and 1 GiB per inspection, plus at most one sentinel byte when a capped entry must be proven to continue. Compressed input reads are capped at 64 KiB and guarded by the 30-second/ZIP and 120-second/inspection clocks before and after each source read; one already-running local OS read or inflater step remains non-preemptible. Extreme declared expansion ratios are not opened.
- Made nested containers honest, even when their extension is removed or inert bytes precede their signature. Nested ZIP/RAR/7-Zip/GZip/Cabinet/OLE/ISO and disguised PE bodies stay `INCOMPLETE`; their direct bytes can be scanned, but their own structure is not recursively parsed.
- Stopped mistaking an EOCD-shaped byte sequence inside a nested entry for a second terminal record. Only candidates whose declared comment reaches the actual file end are considered; an appended fake terminal record still fails the central-directory boundary checks.
- Added honest ZIP body coverage, polyglot state, and prefix evidence to the window, Markdown, and JSON, advanced the JSON schema to v4, and report an unknown denominator whenever observed EOF cannot establish the total. Harmless underreported-size, PDF+ZIP, malformed-tail, fixed and extensible-data prefixed-ZIP64, disguised nested-container, Windows-name-normalization, and chunk-boundary self-tests lock the new paths.

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
