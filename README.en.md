# PC Black Box

PC Black Box is a Windows tool for inspecting downloaded files and folders without running them.

It checks SHA-256, digital signatures, download origin, true file type, scripts, and ZIP contents. The interface supports Japanese and English.

## Setup

You need:

- Windows 10 or Windows 11
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Access to this private repository
- GitHub CLI

Run these commands in PowerShell:

```powershell
gh auth login
gh repo clone Elysia20220909/PC-Black-Box
cd PC-Black-Box
dotnet restore
dotnet run --project .\Destiny2BlackBox.csproj
```

Skip `gh auth login` if GitHub CLI is already signed in.

## Use

- Drop a file or folder onto the window, or use a selection button.
- Select `INSPECT`.
- Open `OVERVIEW` for the assessment, `FILES` for details, and `REPORT` for a reusable summary.
- Use `JA / EN` to change the display language.

## Understanding the result

`CLEAR / LOW / REVIEW / HIGH` is a review priority. It is not a malware verdict or a safety guarantee.

For `REVIEW` or `HIGH`, also check the signature, download source, expected purpose, and Windows Defender result.

## Safety and privacy

- The target is not launched.
- Files are not uploaded.
- No automatic network request, memory inspection, or packet capture is performed.
- Files are not deleted, quarantined, or repaired.
- Reports omit absolute paths, user names, IP addresses, Steam IDs, and credentials.

The VirusTotal hash lookup opens a browser only after confirmation. Its URL contains the SHA-256, not the file itself.

## Development commands

Build the project:

```powershell
dotnet build .\Destiny2BlackBox.csproj -c Release
```

Create a Markdown report without opening the window:

```powershell
dotnet ".\bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll" --report "C:\path\to\target" ".\report.md"
```

## Repository policy

This is a private, source-only repository. Executables, installers, release archives, signing keys, local settings, packet captures, and generated reports are neither tracked nor distributed.
