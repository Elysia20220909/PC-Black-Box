# Changelog

## 0.8.0 — 2026-08-21

- Replaced the first-8-MiB capability sample with bounded streaming for scripts, Windows PE files, and PDFs. Chunk overlap preserves indicators that cross a read boundary, while explicit 256-MiB/file, 512-MiB/inspection, 30-second/file, and 60-second/inspection budgets fail closed as `INCOMPLETE`; SHA-256 remains a separate whole-file pass.
- Made any per-file inspection limit promote the overall result to `INCOMPLETE`; an incomplete traversal can no longer present itself as `CLEAR` in the window, Markdown, or JSON report.
- Added explicit report evidence for SHA-256 bytes read and capability-pattern bytes scanned, plus a self-test fixture whose indicator appears beyond the former 8-MiB boundary.
- Advanced the JSON report schema to v3 with separate `risk`, `completeness`, and combined `assessment` fields, so a known `HIGH` cannot be hidden by `INCOMPLETE`.
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
