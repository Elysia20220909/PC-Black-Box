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
- A module initializer applies the required security baseline before WPF application initialization. Startup and direct scanner entry both fail closed unless all controls are verified.
- Windows blocks child-process creation, legacy extension points, non-system fonts, remote native images, and Low-integrity native images for the process.
- DEP, high-entropy ASLR, Control Flow Guard, and SEHOP are required and read back from the running process.
- Strict handle checks are permanent; DLL discovery excludes the current directory and is restricted to the application directory and System32.
- Serious operating-system errors are returned to the app instead of opening modal error dialogs that could stall unattended inspection.
- Inspection uses no-follow file handles and rechecks the volume plus 128-bit file identity after parsing.
- Opened file and directory handles must resolve to the exact requested DOS path.
- Directory guards deny delete sharing during enumeration and settings or report writes.
- Folder byte limits are rechecked against cumulative stable-handle sizes before hashing each file.
- Folder traversal has independent limits for files, directories, depth, all enumerated entries, retained path metadata, and stable-handle bytes.
- Enumerated directories are snapshotted and revalidated after file inspection; identity or write-time changes make the result partial.
- ZIP EOCD, ZIP64, central-directory records, entry count, metadata size, name length, and exact terminal boundary are checked before `ZipArchive` allocation.
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
- [Microsoft: `CreateFileW` and `FILE_FLAG_OPEN_REPARSE_POINT`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Microsoft: File identity from an open handle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information)
- [.NET: Regular-expression options and non-backtracking mode](https://learn.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-options)
- [.NET: Backtracking and finite match timeouts](https://learn.microsoft.com/en-us/dotnet/standard/base-types/backtracking-in-regular-expressions)
- [PKWARE: ZIP File Format Specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [.NET runtime source: `ZipArchive`](https://source.dot.net/System.IO.Compression/System/IO/Compression/ZipArchive.cs.html)
- [Microsoft Security Development Lifecycle](https://learn.microsoft.com/en-us/compliance/assurance/assurance-microsoft-security-development-lifecycle)
