# Changelog

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
