# Changelog

## 0.4.0 — 2026-08-02

- Added a fail-closed 13-control process security baseline with OS and runtime verification.
- Added strict handle checks, legacy extension-point blocking, non-system-font blocking, and hardened DLL discovery.
- Required DEP, high-entropy ASLR, Control Flow Guard, and SEHOP before any target can be inspected.
- Added a safe security-status command and embedded the verified posture in Markdown and JSON reports.
- Added a written threat model and made strict analyzer, overflow, and deterministic build settings project defaults.

## 0.1.0 — 2026-07-31

- Initial Windows WPF release.
- Added file and bounded folder inspection without target execution.
- Added SHA-256, Authenticode, Mark-of-the-Web, magic-byte, entropy, PE, script-capability, PDF, and ZIP/Office checks.
- Added transparent risk evidence, sanitized Markdown/JSON reports, and explicit hash-only reputation lookup.
- Added Japanese and English UI and documentation.
