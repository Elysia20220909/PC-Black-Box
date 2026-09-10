# Security policy

StillLens is the planned new name for PC Black Box. The application and executable names have not changed. This policy describes the existing PC Black Box security boundaries; a name transition does not add protection or certification.

The repository is public, and a PC Black Box preview is published through GitHub Releases. This documentation revision includes [custom application terms](LICENSE) permitting noncommercial personal use and private modification, but prohibiting commercial use and redistribution. Third-party terms remain separate. Application of these terms to the published ZIP and SDK recipient agreement remain unresolved; availability is not distribution clearance. See [usage and distribution status](docs/distribution-status.md). The source tree must not contain release binaries or private artifacts.

The detailed boundary below describes main 0.12.0 at `2278b0f`. The published 0.13.0-preview.1 comes from `831eb7f` in PR #19, not main. Consult that commit's source and release evidence for version-specific behavior. Passing tests on that preview do not validate another version or computer.

## Reporting

Rechecked on 2026-09-10: Discussions is enabled, while Issues and GitHub private vulnerability reporting remain disabled. Discussions is public and must not be used to disclose vulnerabilities or sensitive information. This is a dated status, not a promise about future availability. The contact below can be used to request a secure reporting method; it is not a verified vulnerability-intake channel.

Do not disclose suspected vulnerabilities in public issues, pull requests, discussions, or social media. Use GitHub's private vulnerability reporting only when a "Report a vulnerability" option is available on this repository's Security page. The presence of this document does not mean that the reporting feature is enabled.

For trials and general bugs, contact [ChloeFlora23047120947120@protonmail.com](mailto:ChloeFlora23047120947120@protonmail.com). If private vulnerability reporting is unavailable, use this address only to request a secure reporting method, without sending vulnerability details or attachments first. Delivery and a secure intake process have not been verified. Wait for confirmation before sharing sensitive evidence; do not use a public issue or pull request as a fallback. No response time is guaranteed.

Include only the minimum evidence needed to reproduce the issue. Never attach credentials, raw packet captures, private download URLs, personal paths, or unredacted reports.

一般の不具合は上記アドレスへ連絡できます。初回はバージョン、Windowsの版、症状と再現手順だけを送り、実際の調査対象や未編集のレポートは添付しないでください。脆弱性の可能性がある場合は詳細を送らず、安全な受け渡し方法を先に確認してください。メールの到達性と安全な受付手順は未確認で、返信時期は保証しません。

## Repository boundary

- Release executables, installers, archives, signing keys, local settings, captures, and generated inspection reports must not be committed.
- The tool performs static inspection and does not guarantee that a file is safe.
- Changes that add execution, upload, packet capture, memory inspection, automatic routing, or security-control bypass are outside the accepted scope.
- Write access, collaborator permissions, and repository visibility changes require the owner's explicit approval. Viewing the source does not grant write access or permission to distribute binaries.

## Hardened application boundary

- The process runs as the current user and never requests elevation or UIAccess.
- An elevated launch is refused before anything is inspected. The window explains that the tool does not run with administrator rights, the command-line modes emit `PC_BLACK_BOX_ELEVATION elevated=true refusing=true` ahead of the posture lines, and the direct scanner entry throws. Inspecting untrusted bytes under a token that can rewrite the machine is a privilege the task never needs.
- Inspection accepts one local fixed, removable, or RAM-drive target at a time. Network, device, alternate-data-stream, and reparse-point paths are rejected.
- Signature verification uses the local Windows trust cache without online revocation retrieval.
- Reports require an existing local destination, cannot overlap the inspected target, and are written with exclusive access and a durable flush.
- New target selection discards the previous result to prevent stale evidence from being exported.
- A module initializer applies the required security baseline before WPF application initialization. Startup and direct scanner entry both fail closed unless all required controls are verified.
- When startup does fail closed, the dialog names the required controls that did not verify, in the operator's own language. The names come from the fixed baseline list and the posture summary, so a message shown before any target is opened cannot carry inspected data.
- Windows blocks child-process creation, legacy extension points, non-system fonts, remote native images, and Low-integrity native images for the process.
- DEP, high-entropy ASLR, Control Flow Guard, and SEHOP are required and read back from the running process.
- Strict handle checks are permanent; DLL discovery excludes the current directory and is restricted to the application directory and System32.
- Heap corruption terminates the process rather than continuing in an allocator state an attacker can steer.
- The process object's DACL is replaced at startup so later same-user access requests cannot read or write its memory, create a thread in it, or duplicate its handles. An `OWNER RIGHTS` entry removes the owner's implicit DACL-change right. The read-back owner is compared against the token's own default owner, which is not always the user SID, so a correctly applied DACL is never reported as unenforced. Query-limited, synchronize, read-control, and terminate access remain available. Handles obtained before lockdown cannot be revoked.
- Standard .NET network-transport assemblies are absent, and a later load terminates the process before the caller can use one. This managed-runtime invariant is not an AppContainer or Windows Filtering Platform capability denial for arbitrary native code.
- Where the platform offers them, the process additionally enforces redirection trust, security-domain isolation, page-combining disable, and speculative-store-bypass disable, and reports whether hardware-enforced shadow stacks are active. Unsupported controls are `unavailable`; supported controls that fail enforcement are `not-enforced` rather than being silently relabeled.
- Hot reload metadata updates and the EventSource tracing surface are disabled in the shipped runtime configuration.
- Serious operating-system errors are returned to the app instead of opening modal error dialogs that could stall unattended inspection.
- Inspection uses no-follow file handles and rechecks the volume plus 128-bit file identity after parsing.
- Opened file and directory handles must resolve to the exact requested DOS path.
- Directory guards deny delete sharing during enumeration and settings or report writes.
- Folder byte limits are rechecked against cumulative stable-handle sizes before hashing each file.
- Folder traversal has independent limits for files, directories, depth, all enumerated entries, retained path metadata, and stable-handle bytes.
- Enumerated directories are snapshotted and revalidated after file inspection; identity or write-time changes make the result partial.
- ZIP EOCD, ZIP64, central-directory records, entry count, metadata size, name length, and exact terminal boundary are checked before `ZipArchive` allocation.
- For an ordinary ZIP or a bounded ZIP64 record with prepended bytes, including a ZIP64 record with extensible data, the payload start is derived from physical terminal-record positions and relative offsets instead of trusting the first local-header signature. The prefix remains unparsed and therefore makes the result incomplete.
- Primary file type and trailing ZIP structure are tracked separately, so a PDF/PE/script polyglot has both surfaces inspected. A ZIP-like terminal record that fails validation remains incomplete.
- Direct ZIP entry bodies are decompressed only through bounded in-memory streams and never extracted. The scanner probes actual EOF independently of central-directory size declarations, and any mismatch or unread remainder is incomplete.
- ZIP body decompression crosses into the serviced .NET runtime's native `System.IO.Compression.Native.dll`. Restricted DLL discovery prevents the target or current directory from supplying that component, while bounded wrappers cap compressed reads, expanded bytes, and elapsed time. The native inflater's correctness remains an explicit trusted dependency, so the host must keep its supported .NET runtime patched.
- Byte limits are hard apart from one documented sentinel byte per capped entry. Compressed source reads are limited to 64 KiB and guarded by the time and cancellation checks before and after each read. One local OS read or inflater step already executing still cannot be forcibly interrupted.
- If the observed EOF cannot establish the total entry-body size, reports expose the scanned byte count and an unknown total; they never render a guessed denominator as fully covered.
- Split, encrypted-central-directory, oversized, malformed, or multiple-EOCD ZIP layouts fail closed rather than receiving a clean result.
- Untrusted capability text is evaluated with the non-backtracking regular-expression engine and a finite timeout.

These controls apply iOS-inspired least-privilege and closed-data-flow principles. They do not make a WPF process equivalent to the iOS App Sandbox and are not an absolute security guarantee.

## Primary references

- [Apple Platform Security: App security overview](https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/web)
- [Microsoft: Process mitigation policy enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-process_mitigation_policy)
- [Microsoft: Child-process mitigation policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_process_mitigation_child_process_policy)
- [Microsoft: Image-load mitigation policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_image_load_policy)
- [Microsoft: Strict-handle-check policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_strict_handle_check_policy)
- [Microsoft: Legacy extension-point policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_extension_point_disable_policy)
- [Microsoft: Non-system-font policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_font_disable_policy)
- [Microsoft: Restricting the default DLL search](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories)
- [Microsoft: Removing the current directory from DLL search](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setdlldirectoryw)
- [Microsoft: Process error mode](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode)
- [Microsoft: Redirection-trust policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_redirection_trust_policy)
- [Microsoft: Side-channel-isolation policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_side_channel_isolation_policy)
- [Microsoft: User-shadow-stack policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_user_shadow_stack_policy)
- [Microsoft: Heap termination on corruption](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapsetinformation)
- [Microsoft: Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Microsoft: Setting security on a kernel object](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setkernelobjectsecurity)
- [Microsoft: `OWNER RIGHTS` and implicit owner access](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings)
- [Microsoft: `CreateFileW` and `FILE_FLAG_OPEN_REPARSE_POINT`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Microsoft: File identity from an open handle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information)
- [.NET: Regular-expression options and non-backtracking mode](https://learn.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-options)
- [.NET: Backtracking and finite match timeouts](https://learn.microsoft.com/en-us/dotnet/standard/base-types/backtracking-in-regular-expressions)
- [PKWARE: ZIP File Format Specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [.NET runtime source: `ZipArchive`](https://source.dot.net/System.IO.Compression/System/IO/Compression/ZipArchive.cs.html)
- [Microsoft Security Development Lifecycle](https://learn.microsoft.com/en-us/compliance/assurance/assurance-microsoft-security-development-lifecycle)
