#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')][string] $RunId,
    [Parameter(Mandatory)][string] $OldRoot,
    [Parameter(Mandatory)][string] $EngineArchive,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string] $ExpectedHead,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $AppSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $BridgeSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $repo 'tools/Obfuscation.Common.ps1')
$expectedHead = $ExpectedHead.ToLowerInvariant()
$runRoot = Get-ContainedPath $repo "obj/gui-validation/$RunId"
if (Test-Path -LiteralPath $runRoot) { throw 'Run already exists; nothing was overwritten.' }
$head = & git -C $repo rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $head -cne $expectedHead) { throw 'Unexpected source revision.' }
$dirty = & git -C $repo status --porcelain
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect source status.' }
# Supplied hashes identify build inputs; record dirty state without claiming build provenance.
$runtime = Get-ContainedPath $runRoot 'runtime'
if (Test-Path -LiteralPath $runtime) { throw 'Runtime already exists; nothing was overwritten.' }
$old = Assert-LocalPlainPath $OldRoot
$oldPrefix = [IO.Path]::TrimEndingDirectorySeparator($old) + [IO.Path]::DirectorySeparatorChar
if ($runRoot.Equals([IO.Path]::TrimEndingDirectorySeparator($old), [StringComparison]::OrdinalIgnoreCase) -or
    $runRoot.StartsWith($oldPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Validation output must not be inside the old installation.'
}
if (!(Test-Path -LiteralPath (Join-Path $old 'PC Black Box.exe') -PathType Leaf)) { throw 'Old launcher is missing.' }
$framework = 'net10.0-windows10.0.17763.0'
$app = Get-ContainedPath $repo "bin/Release/$framework"
$bridge = Get-ContainedPath $repo "tools/DieBridge/bin/Release/$framework"
$archive = Assert-LocalPlainPath $EngineArchive
$expected = @{
    (Join-Path $app 'PC Black Box.dll') = $AppSha256.ToUpperInvariant()
    (Join-Path $bridge 'DieBridge.dll') = $BridgeSha256.ToUpperInvariant()
    $archive = '7D7195F757C45F6B69364D167C9958FA60339D53876A87E4A1EDBCBF67D1E477'
}
foreach ($path in $expected.Keys) {
    $null = Assert-LocalPlainPath $path
    if ((Get-FileHash -LiteralPath $path).Hash -cne $expected[$path]) { throw 'Previously verified input changed.' }
}
function Get-OldSnapshot {
    @(Get-ChildItem -LiteralPath $old -File -Recurse | Sort-Object FullName | ForEach-Object {
        $null = Assert-LocalPlainPath $_.FullName
        [ordered]@{ path = [IO.Path]::GetRelativePath($old, $_.FullName); sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash }
    })
}
$oldBefore = Get-OldSnapshot
$settings = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'PCBlackBox/settings.json'
$settingsBefore = if (Test-Path -LiteralPath $settings) { (Get-FileHash -LiteralPath (Assert-LocalPlainPath $settings)).Hash } else { $null }
$null = New-Item -ItemType Directory -Path $runRoot
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity.User, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $runRoot -AclObject $acl
} finally { $identity.Dispose() }
foreach ($folder in @('runtime/app','runtime/engine','samples/folder','logs','reports')) {
    $null = New-Item -ItemType Directory -Path (Get-ContainedPath $runRoot $folder)
}
$files = [Collections.Generic.List[object]]::new()
foreach ($source in @($bridge, $app)) {
    foreach ($file in Get-ChildItem -LiteralPath $source -File) {
        $null = Assert-LocalPlainPath $file.FullName
        $relative = if ($source -eq $app) { 'runtime/app/' + $file.Name } else { 'runtime/' + $file.Name }
        $destination = Get-ContainedPath $runRoot $relative
        [IO.File]::Copy($file.FullName, $destination, $false)
        $hash = (Get-FileHash -LiteralPath $file.FullName).Hash
        if ((Get-FileHash -LiteralPath $destination).Hash -cne $hash) { throw 'Copy verification failed.' }
        if ($expected.ContainsKey($file.FullName) -and $hash -cne $expected[$file.FullName]) {
            throw 'Pinned DLL changed during preparation.'
        }
        $files.Add([ordered]@{ path=$relative; sha256=$hash })
    }
}
$archiveRelative = 'runtime/engine/die_win32_portable_3.21_x86.zip'
[IO.File]::Copy($archive, (Get-ContainedPath $runRoot $archiveRelative), $false)
if ((Get-FileHash -LiteralPath (Get-ContainedPath $runRoot $archiveRelative)).Hash -cne $expected[$archive]) { throw 'Archive copy verification failed.' }
$files.Add([ordered]@{ path=$archiveRelative; sha256=$expected[$archive] })
Write-NewUtf8File (Get-ContainedPath $runRoot 'samples/first.txt') 'Harmless first GUI inspection sample. Identifier: FIRST.'
Write-NewUtf8File (Get-ContainedPath $runRoot 'samples/second.txt') 'Harmless second GUI inspection sample. Identifier: SECOND.'
Write-NewUtf8File (Get-ContainedPath $runRoot 'samples/folder/note.txt') 'Harmless folder inspection sample.'
$oldAfter = Get-OldSnapshot
if (($oldBefore | ConvertTo-Json -Depth 4 -Compress) -cne ($oldAfter | ConvertTo-Json -Depth 4 -Compress)) { throw 'Old installation changed during preparation.' }
$settingsAfter = if (Test-Path -LiteralPath $settings) { (Get-FileHash -LiteralPath $settings).Hash } else { $null }
if ($settingsBefore -cne $settingsAfter) { throw 'Settings changed during preparation.' }
$manifest = [ordered]@{
    head=$expectedHead; sourceDirty=[bool]$dirty; createdUtc=[DateTime]::UtcNow.ToString('o'); purpose='Private local manual GUI validation; not a distribution package'
    guiTested=$false; launched=$false; files=$files.ToArray(); oldRoot=$old; oldFiles=$oldBefore
    settingsPath=$settings; settingsSha256=$settingsBefore
}
Write-NewUtf8File (Join-Path $runRoot 'manifest.json') ($manifest | ConvertTo-Json -Depth 6)
'PREPARATION passed=true copiedFiles=' + $files.Count + ' oldFilesUnchanged=' + $oldBefore.Count + ' settingsUnchanged=true guiLaunched=false'
