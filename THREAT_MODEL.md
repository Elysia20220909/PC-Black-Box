# Threat model

## Security objective

PC Black Box gives the owner prioritized evidence about an untrusted local download without executing it, uploading it, or changing it. A result is not a malware verdict. The primary objective is to keep inspection itself from becoming a path to code execution, data disclosure, or silent evidence corruption.

## Trust boundaries

| Boundary | Trusted | Untrusted |
|---|---|---|
| Application | Signed source history and the running managed code | Selected file names, bytes, metadata, archive entries, and signer text |
| Operating system | Windows process-mitigation state read back through Kernel32 | Paths on network, device, alternate-stream, or reparse namespaces |
| Output | Sanitized in-memory result and exclusively created local report | Existing report files, reparse destinations, absolute paths, and control characters |
| Network | No network function is required for inspection | Remote reputation, cloud scanning, download, upload, and browser launch |

## Required invariants

- The target is never launched, loaded as code, repaired, moved, quarantined, or deleted.
- Inspection does not continue unless every control in `SECURITY-BASELINE-1` is enforced.
- Parsing uses a stable no-follow handle with no write or delete sharing.
- File identity is checked again after parsing and before a result is trusted.
- All loops, input sizes, archive entry counts, signature checks, text lengths, and regular-expression evaluation are bounded.
- Reports exclude absolute paths and personal identifiers and are never written inside the inspected target.
- No administrator privilege, UIAccess, external lookup, or child process is required.

## Security baseline

`SECURITY-BASELINE-1` requires thirteen independently checked controls:

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

## Adversaries considered

- A malicious download crafted to exploit format parsing, regular expressions, archive enumeration, Unicode display, signature handling, or integer boundaries.
- A local race that attempts to replace or rewrite a file during inspection.
- A local low-integrity or network location attempting to inject a native image.
- A malicious working directory attempting DLL preloading.
- An accidental operator action that selects a network, device, alternate-stream, or linked path.

## Explicitly out of scope

- Kernel drivers, filesystem minifilters, real-time antivirus monitoring, memory scanning, behavioral sandboxing, cloud reputation, remediation, and enterprise policy enforcement.
- Protection against an administrator, kernel compromise, compromised Windows trust store, malicious firmware, or physical access.
- AppContainer isolation and an Authenticode-signed distribution binary. Those require a separately approved packaging and signing design; this repository remains private and source-only.

## Verification gates

- Strict Release rebuild with current .NET analyzers and warnings treated as errors.
- Runtime `--security-status` result must be `enforced=true` with every required control present.
- Live process mitigation flags must match the required policy bits.
- Regression fixtures must preserve signature, capability, hostile-archive, privacy, and path-boundary behavior.
- Secret scanning and tracked-artifact inspection must pass before a signed commit is pushed.
