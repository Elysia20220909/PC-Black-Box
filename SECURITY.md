# Security policy

PC Black Box is maintained as a private, source-only repository.

## Reporting

Do not disclose suspected vulnerabilities in public issues, discussions, or social media. Report them privately to the repository owner using GitHub's private security-advisory channel when it is available.

Include only the minimum evidence needed to reproduce the issue. Never attach credentials, raw packet captures, private download URLs, personal paths, or unredacted reports.

## Repository boundary

- Release executables, installers, archives, signing keys, local settings, captures, and generated inspection reports must not be committed.
- The tool performs static inspection and does not guarantee that a file is safe.
- Changes that add execution, upload, packet capture, memory inspection, automatic routing, or security-control bypass are outside the accepted scope.
- Access remains owner-only unless the owner explicitly approves a narrowly scoped collaborator.

## Hardened application boundary

- The process runs as the current user and never requests elevation or UIAccess.
- Inspection accepts one local fixed, removable, or RAM-drive target at a time. Network, device, alternate-data-stream, and reparse-point paths are rejected.
- Signature verification uses the local Windows trust cache without online revocation retrieval.
- Reports require an existing local destination, cannot overlap the inspected target, and are written with exclusive access and a durable flush.
- New target selection discards the previous result to prevent stale evidence from being exported.
- Startup fails closed unless Windows blocks child-process creation, remote native images, and Low-integrity native images for the process.
- Inspection uses no-follow file handles and rechecks the volume plus 128-bit file identity after parsing.
- Untrusted capability text is evaluated with the non-backtracking regular-expression engine and a finite timeout.

These controls apply iOS-inspired least-privilege and closed-data-flow principles. They do not make a WPF process equivalent to the iOS App Sandbox and are not an absolute security guarantee.

## Primary references

- [Apple Platform Security: App security overview](https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/web)
- [Microsoft: Process mitigation policy enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-process_mitigation_policy)
- [Microsoft: Child-process mitigation policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_process_mitigation_child_process_policy)
- [Microsoft: Image-load mitigation policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_image_load_policy)
- [Microsoft: `CreateFileW` and `FILE_FLAG_OPEN_REPARSE_POINT`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Microsoft: File identity from an open handle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information)
- [.NET: Regular-expression options and non-backtracking mode](https://learn.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-options)
- [.NET: Backtracking and finite match timeouts](https://learn.microsoft.com/en-us/dotnet/standard/base-types/backtracking-in-regular-expressions)
