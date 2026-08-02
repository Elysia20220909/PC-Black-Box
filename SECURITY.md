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

These controls apply iOS-inspired least-privilege and closed-data-flow principles. They do not make a WPF process equivalent to the iOS App Sandbox and are not an absolute security guarantee.
