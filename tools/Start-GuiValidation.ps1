#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string] $RunRoot, [switch] $Launch)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $repo 'tools/Obfuscation.Common.ps1')
$RunRoot = Assert-LocalPlainPath $RunRoot
$manifest = Get-Content -LiteralPath (Get-ContainedPath $RunRoot 'manifest.json') -Raw | ConvertFrom-Json
foreach ($file in $manifest.files) {
    $path = Get-ContainedPath $RunRoot $file.path
    if ((Get-FileHash -LiteralPath $path).Hash -cne $file.sha256) { throw "Validation input changed: $($file.path)" }
}
foreach ($file in $manifest.oldFiles) {
    $path = Get-ContainedPath $manifest.oldRoot $file.path
    if ((Get-FileHash -LiteralPath $path).Hash -cne $file.sha256) { throw 'Old installation baseline changed; inspect before proceeding.' }
}
$settingsHash = if (Test-Path -LiteralPath $manifest.settingsPath) { (Get-FileHash -LiteralPath (Assert-LocalPlainPath $manifest.settingsPath)).Hash } else { $null }
if ($settingsHash -cne $manifest.settingsSha256) { throw 'Shared settings changed; inspect before proceeding.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if ([Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use a non-elevated PowerShell session.' }
} finally { $identity.Dispose() }
$dotnet = (Get-Command dotnet.exe -CommandType Application -ErrorAction Stop).Source
$null = Assert-LocalPlainPath $dotnet
$runtimes = & $dotnet --list-runtimes
if ($LASTEXITCODE -ne 0 -or !($runtimes -match '^Microsoft.WindowsDesktop.App 10\.')) { throw '.NET 10 Windows Desktop runtime is required.' }
"VALIDATION_INPUTS passed=true files=$($manifest.files.Count) head=$($manifest.head)"
if (!$Launch) { 'GUI not launched. Run explicitly with -Launch for the manual GUI check.'; return }
$run = Get-ContainedPath $RunRoot ('logs/run-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $run
Write-NewUtf8File (Join-Path $run 'started.json') (@{ head=$manifest.head; startedUtc=[DateTime]::UtcNow.ToString('o'); dotnet=$dotnet; status='starting'; logScope='Bridge stdout/stderr; GUI child logs are not guaranteed' } | ConvertTo-Json)
$start = [Diagnostics.ProcessStartInfo]::new($dotnet)
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.WorkingDirectory = Join-Path $RunRoot 'runtime'
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.ArgumentList.Add((Join-Path $RunRoot 'runtime/DieBridge.dll'))
$child = $null
$stdout = $null
$stderr = $null
try {
    $stdout = [IO.File]::Open((Join-Path $run 'bridge.stdout.log'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    $stderr = [IO.File]::Open((Join-Path $run 'bridge.stderr.log'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    $child = [Diagnostics.Process]::Start($start)
    Write-NewUtf8File (Join-Path $run 'process.json') (@{ bridgePid=$child.Id; startedUtc=$child.StartTime.ToUniversalTime().ToString('o') } | ConvertTo-Json)
    $outputCopy = $child.StandardOutput.BaseStream.CopyToAsync($stdout)
    $errorCopy = $child.StandardError.BaseStream.CopyToAsync($stderr)
    Write-Host "Manual GUI session; close PC Black Box normally when finished. Keep this PowerShell session open. Logs: $run"
    $child.WaitForExit()
    $outputCopy.GetAwaiter().GetResult()
    $errorCopy.GetAwaiter().GetResult()
    Write-NewUtf8File (Join-Path $run 'finished.json') (@{ finishedUtc=[DateTime]::UtcNow.ToString('o'); bridgeExitCode=$child.ExitCode; guiChecks='Not inferred from exit code; record manually' } | ConvertTo-Json)
    Write-Host "Bridge exit code: $($child.ExitCode). This does not certify GUI correctness."
} catch {
    Write-NewUtf8File (Join-Path $run 'launcher-error.txt') $_.Exception.ToString()
    throw
} finally {
    if ($stdout) { $stdout.Dispose() }
    if ($stderr) { $stderr.Dispose() }
    if ($child) { $child.Dispose() }
}
