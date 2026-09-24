#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string] $EngineArchive)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $root 'tools/Obfuscation.Common.ps1')
$archive = Assert-LocalPlainPath $EngineArchive
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -cne '7D7195F757C45F6B69364D167C9958FA60339D53876A87E4A1EDBCBF67D1E477') {
    throw 'The integration gate requires the pinned official 3.21 archive.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if ([Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run DiE gates without elevation.'
    }
    $userSid = $identity.User
}
finally { $identity.Dispose() }

$framework = 'net10.0-windows10.0.17763.0'
$appOutput = Join-Path $root "bin/Release/$framework"
$bridgeOutput = Join-Path $root "tools/DieBridge/bin/Release/$framework"
$probe = Join-Path $root "tests/DieSandboxProbe/bin/Release/$framework/DieSandboxProbe.dll"
$native = Join-Path $root 'tests/DieSandboxProbe/obj/probe.exe'
foreach ($required in @((Join-Path $appOutput 'PC Black Box.dll'), (Join-Path $bridgeOutput 'DieBridge.dll'), $probe, $native)) {
    $null = Assert-LocalPlainPath $required
    if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw 'Build all DiE gate inputs first.' }
}

function Get-SourceSnapshot {
    $head = & git -c "safe.directory=$root" -C $root rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Cannot identify source revision.' }
    # Documentation can record results afterwards; fingerprint all non-documentation
    # inputs, including untracked source/configuration, rather than claiming HEAD alone was tested.
    $paths = @(& git -c "safe.directory=$root" -C $root ls-files --cached --others --exclude-standard |
        Where-Object { $_ -notlike 'docs/*' -and $_ -notmatch '(?i)\.md$' } | Sort-Object -Unique)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate source inputs.' }
    $manifest = foreach ($relative in $paths) {
        $path = Get-ContainedPath $root $relative
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Source snapshot contains a missing file.' }
        $relative + ':' + (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    $dirty = [bool](& git -c "safe.directory=$root" -C $root status --porcelain)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot identify source status.' }
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($manifest -join "`n"))))
    return "PCBB_SOURCE_SNAPSHOT head=$head dirty=$($dirty.ToString().ToLowerInvariant()) codeSha256=$digest"
}

function Invoke-HeadlessDotnet([string[]] $Arguments, [int] $DeadlineSeconds) {
    $start = [Diagnostics.ProcessStartInfo]::new((Get-Command dotnet -CommandType Application).Source)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $child = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        if (!$child.WaitForExit($DeadlineSeconds * 1000)) {
            $child.Kill($true)
            $child.WaitForExit()
            throw 'A headless DiE gate exceeded its deadline.'
        }
        $output = $stdout.GetAwaiter().GetResult()
        $errors = $stderr.GetAwaiter().GetResult()
        if ($output) { Write-Host $output.TrimEnd() }
        if ($errors) { Write-Host $errors.TrimEnd() }
        if ($child.ExitCode -ne 0) { throw "A headless DiE gate failed: exit=$($child.ExitCode)." }
        return $output
    }
    finally {
        if (!$child.HasExited) { $child.Kill($true); $child.WaitForExit() }
        $child.Dispose()
    }
}

$before = Get-SourceSnapshot
$before
foreach ($binaryInput in @((Join-Path $appOutput 'PC Black Box.dll'), (Join-Path $bridgeOutput 'DieBridge.dll'), $probe, $native)) {
    "PCBB_BUILD_INPUT name=$([IO.Path]::GetFileName($binaryInput)) sha256=$((Get-FileHash -LiteralPath $binaryInput -Algorithm SHA256).Hash)"
}
$scratchParent = Assert-LocalPlainPath ([IO.Path]::GetTempPath())
$scratch = Join-Path $scratchParent ('PCBB-DieGate-' + [Guid]::NewGuid().ToString('N'))
# This layout is a private, temporary test fixture, not a release/package output.
$null = New-Item -ItemType Directory -Path $scratch
try {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($userSid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $scratch -AclObject $acl
    $null = New-Item -ItemType Directory -Path (Join-Path $scratch 'app'), (Join-Path $scratch 'engine')
    foreach ($directory in @($bridgeOutput, $appOutput)) {
        $destination = if ($directory -eq $appOutput) { Join-Path $scratch 'app' } else { $scratch }
        foreach ($file in Get-ChildItem -LiteralPath $directory -File) {
            $null = Assert-LocalPlainPath $file.FullName
            [IO.File]::Copy($file.FullName, (Join-Path $destination $file.Name), $false)
        }
    }
    [IO.File]::Copy($archive, (Join-Path $scratch 'engine/die_win32_portable_3.21_x86.zip'), $false)
    $sample = Join-Path $scratch 'sample.txt'
    Write-NewUtf8File $sample 'Harmless PC Black Box integration test fixture.'
    $probeOutput = Invoke-HeadlessDotnet @($probe, $native) 120
    foreach ($marker in @('PCBB_DIE_CLEANUP_TEST passed=true', 'PCBB_SANDBOX_PROBE passed=true')) {
        if (!$probeOutput.Contains($marker, [StringComparison]::Ordinal)) { throw 'A native/cleanup gate success marker is missing.' }
    }
    $sessionOutput = Invoke-HeadlessDotnet @((Join-Path $scratch 'DieBridge.dll'), '--session-test', $sample, (Join-Path $scratch 'session.report.md')) 270
    if (!$sessionOutput.Contains('PCBB_DIE_SESSION passed=true disconnectBeforeRequest=true disconnectAfterStart=true cancellationAfterStart=true repeatedRequests=2 cleanup=true controls=16/16', [StringComparison]::Ordinal)) {
        throw 'The session did not demonstrate all reconnect/cancellation/cleanup checks.'
    }
    if (!$sessionOutput.Contains('PCBB_DIE_SESSION_CLEANUP requests=4 attention=0', [StringComparison]::Ordinal)) {
        throw 'Cleanup was not acknowledged for all four requests, including disconnect/cancellation.'
    }
    $after = Get-SourceSnapshot
    if ($before -cne $after) { throw 'Source changed during verification; the results cannot be attributed to this snapshot.' }
}
finally {
    $resolved = Assert-LocalPlainPath $scratch
    if (![IO.Path]::GetDirectoryName($resolved).Equals([IO.Path]::TrimEndingDirectorySeparator($scratchParent), [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -cnotmatch '^PCBB-DieGate-[0-9a-f]{32}$') { throw 'Unexpected cleanup target.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
'PCBB_DIE_INTEGRATION passed=true fixtureRemoved=true'
