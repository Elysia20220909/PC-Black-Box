# StillLens

Inspect files without running or uploading them.

ファイルを動かさず、手掛かりを見る。

[日本語](README.md) / [Published preview](https://github.com/Elysia20220909/PC-Black-Box/releases/tag/v0.13.0-preview.1) / [Usage and distribution status](docs/distribution-status.md) / [Security policy](SECURITY.md)

StillLens is the planned new name for PC Black Box, a Windows file inspection tool. It organizes signatures, origin metadata, actual file formats, and attention-worthy features locally without executing or uploading the target. It shows evidence and unexamined scope rather than certifying safety.

> The published application is still named PC Black Box. The repository URL, executable names, and settings location have not changed. The application in this documentation revision has [custom terms](LICENSE): noncommercial personal use and private modification are permitted; commercial use and paid or free redistribution are prohibited. Third-party components retain their own terms. Application of these terms to the published ZIP and recipient agreement for Microsoft SDK components remain unresolved. Availability for download does not establish that all general-distribution conditions have been met. Read the [current status](docs/distribution-status.md) first.

## When it helps

- Check the signature and origin of a downloaded file before opening it.
- Examine an extension mismatch or a shortcut's target without launching it.
- Distinguish evidence found inside a ZIP from content that could not be examined.

It does not replace antivirus software, a dynamic sandbox, or a cloud reputation service. Neither `CLEAR` nor `COMPLETE` proves that a file is safe. The tool does not execute, delete, quarantine, or repair the target.

## Find the published build

[PC Black Box v0.13.0-preview.1](https://github.com/Elysia20220909/PC-Black-Box/releases/tag/v0.13.0-preview.1) contains:

- `PC-Black-Box-v0.13.0-preview.1-win-x64.zip`
- `PC-Black-Box-v0.13.0-preview.1-win-x64.zip.sha256`

These instructions are for testers whose permission to use the build has been confirmed. They do not establish a new license.

### Requirements

- An x64 edition of [Windows supported by .NET 10](https://learn.microsoft.com/en-us/dotnet/core/install/windows#supported-versions). Windows 10 support is limited to the listed LTSC / Enterprise releases.
- A serviced [x64 .NET 10 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/10.0). The ZIP does not include the runtime. Running the application does not require the SDK.
- Run the application as a standard user. Elevated startup is refused.

### Verify before starting

- Download the ZIP and SHA-256 file, then compare the ZIP's hash. If the downloaded names are unchanged, run these commands in their directory:

  ~~~powershell
  Get-FileHash -LiteralPath '.\PC-Black-Box-v0.13.0-preview.1-win-x64.zip' -Algorithm SHA256
  Get-Content -LiteralPath '.\PC-Black-Box-v0.13.0-preview.1-win-x64.zip.sha256'
  ~~~

- Extract the entire ZIP and keep the EXE, DLLs, readme, and license documents together. Do not copy the EXE on its own.
- Review the included README and third-party notices, then start `PC Black Box.exe` as a standard user.

The EXE and application DLL use a self-signed developer certificate. A matching hash establishes correspondence with the checked file, not software safety or a trusted publisher. Trust on another PC and the absence of SmartScreen warnings are not guaranteed. Do not add a certificate to a trust store or disable Windows protection simply to suppress a warning.

## Basic use

- Select a file or folder and choose `INSPECT`.
- Read findings and completeness in `OVERVIEW`, then examine evidence in `FILES`.
- Use `REPORT` to save Markdown / JSON locally if needed. Press `Esc` to stop.

Use `JA / EN` to switch languages. Settings remain in `%LOCALAPPDATA%\PCBlackBox\settings.json`. See the [detailed controls and shortcuts](docs/reference-main.en.md#basic-use).

The target and report are not sent automatically. Reports can nevertheless contain file names, origin hosts, hashes, and strings stored inside the target. Review them before sharing. Opening a copied lookup URL in a browser discloses the hash to the external service; clipboard history and synchronization also depend on Windows settings.

## Source and preview are different versions

Keep batch output outside every input target. Saving over or inside any target, including a failed inspection, is rejected before an output or temporary file is created. Missing targets can still be reported outside their verifiable boundaries; ambiguous or unverifiable target paths stop the entire save.

Current batch JSON uses `pc-black-box-batch-report-v2`. It removes `targets[].path`, which exposed the selected absolute target path. `targets[].target` is a display name and `targets[].result.files[].path` is relative to that target. Array order matches input order, including duplicate names; empty or drive-root names use `target`. External consumers reading the v1 `path` field must be updated. Paths and personal information in input-held evidence remain; reports are not anonymized.

This working revision selectively ports OLE traversal while preserving the current main's batch CLI, shadow-stack diagnostics, and headless verification. It pins the corrected OpenMcdf 3.4.0. VBA bodies and Installer table semantics are not decoded and retain incomplete structure. The table below records historical versions; consult the [threat model](THREAT_MODEL.md) for current limits and [third-party notices](THIRD-PARTY-NOTICES.md) for dependency provenance.

This mapping was checked on 2026-09-10. Recheck tags and commits for later updates.

| Scope | Source commit | Important distinction |
|---|---|---|
| main 0.12.0, the base for this documentation change | `2278b0f` | Does not parse OLE storage trees. The [technical reference](docs/reference-main.en.md) describes this version |
| PC Black Box 0.13.0-preview.1 | `831eb7f` | Built from PR #19, not merged into main. Refer to [that version's source](https://github.com/Elysia20220909/PC-Black-Box/tree/831eb7fba4e2c7eb0a434d5e3a2240a0ee3a0c97) |

During preview preparation, the extracted DLL passed 111 self-tests, 16/16 required controls, and nine runtime-boundary checks. These results belong to that preview on the tested host, not to main or another computer. Interactive GUI use and startup on another PC remain unverified.

## For developers

Confirm the applicable usage and modification terms, then review the source and dependencies before building. Development requires [Git](https://git-scm.com/downloads) and the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0). These commands obtain main; they are not instructions for reproducing the published preview.

~~~powershell
git clone --branch main https://github.com/Elysia20220909/PC-Black-Box.git
cd PC-Black-Box
dotnet restore .\Destiny2BlackBox.csproj
dotnet build .\Destiny2BlackBox.csproj -c Release --no-restore
~~~

Cloning the private repository requires access and existing GitHub authentication. `dotnet restore` uses the network for dependencies and vulnerability information; this is separate from the application's no-upload handling of inspected files.

See [contribution guidance](CONTRIBUTING.md) for current verification and CLI reports. The [development reference](docs/reference-main.en.md#development-and-verification) describes the historical revision and its older GUI-based boundary test. The current boundary test is headless. A local build does not replace a published artifact or an installed application.

## Feedback and documentation

Contact for trials and general bugs: [ChloeFlora23047120947120@protonmail.com](mailto:ChloeFlora23047120947120@protonmail.com). In the first message, send only the application version, Windows version, symptoms, and reproduction steps. Do not attach inspected files, raw reports, credentials, or personal paths. Mailbox delivery has not been verified, and no response time is guaranteed.

Rechecked on 2026-09-10: [Discussions](https://github.com/Elysia20220909/PC-Black-Box/discussions) is enabled for general usage questions. Issues and GitHub private vulnerability reporting remain disabled. Do not post vulnerabilities or sensitive information in public channels, including Discussions. Follow [SECURITY.md](SECURITY.md) and confirm a secure transfer method before sending details.

- [Code of conduct](CODE_OF_CONDUCT.md) / [Support and reporting](SUPPORT.md)
- [Usage and distribution status](docs/distribution-status.md)
- [Controls, inspection scope, and limits](docs/reference-main.en.md)
- [Changelog](CHANGELOG.md) / [Threat model](THREAT_MODEL.md)
- [Contributing](CONTRIBUTING.md) / [Collaboration rules](AGENTS.md)

A name transition does not change inspection capabilities, safety boundaries, or license permissions. Executables, distribution ZIPs, signing keys, personal settings, and generated reports must not be committed with the source.
