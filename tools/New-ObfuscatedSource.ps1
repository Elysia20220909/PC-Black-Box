#requires -Version 7.0
[CmdletBinding(PositionalBinding = $false)]
param(
    [string] $SourceRoot = (Split-Path $PSScriptRoot -Parent),
    [string] $RunId = ('source-' + [Guid]::NewGuid().ToString('N'))
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Obfuscation.Common.ps1')
$SourceRoot = Assert-LocalPlainPath $SourceRoot
$layoutPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'obfuscation/source-layout.json'
$layout = Get-Content -LiteralPath $layoutPath -Raw | ConvertFrom-Json
if ($layout.schemaVersion -ne 2) { throw 'Unsupported source layout version.' }

# A reviewed allowlist prevents copying settings, Git history, reports, or future dependencies.
$projectName = 'Destiny2BlackBox.csproj'
$inputs = @($layout.renamedSources) + @($layout.preservedFiles) + @($projectName)
# Keep existing terms without importing the different LICENSE introduced on main later.
foreach ($notice in $layout.optionalNotices) {
    $noticePath = Get-ContainedPath $SourceRoot $notice
    if (Test-Path -LiteralPath $noticePath -PathType Leaf) { $inputs += $notice }
}
if (@($inputs | Sort-Object -Unique).Count -ne $inputs.Count) { throw 'Duplicate source input.' }
foreach ($relativePath in $inputs) {
    $path = Get-ContainedPath $SourceRoot $relativePath
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required source input is missing: $relativePath" }
}
[xml] $project = Get-Content -LiteralPath (Join-Path $SourceRoot $projectName) -Raw
$version = $project.SelectSingleNode('/Project/PropertyGroup/Version')
if ($null -eq $version -or $version.InnerText -cne $layout.applicationVersion) {
    throw "Source version must be $($layout.applicationVersion); a different baseline needs a separate profile."
}
$expectedCode = @($inputs | Where-Object { $_.EndsWith('.cs', [StringComparison]::OrdinalIgnoreCase) } | Sort-Object)
# Keep the traversal tied to the reviewed project, not just a silent hard-coded skip.
# If the compile model changes, review it before copying anything.
$removals = @($project.SelectNodes('/Project/ItemGroup/Compile/@Remove') | ForEach-Object { $_.Value.Replace('\', '/') } | Sort-Object)
if ($removals.Count -ne 2 -or (Compare-Object @('tests/**/*.cs', 'tools/**/*.cs') $removals) -or
    $project.SelectNodes('/Project/ItemGroup/Compile[@Include or @Update or @Condition] | /Project/ItemGroup[@Condition]/Compile | /Project/Import | /Project/Target').Count -ne 0 -or
    $project.SelectNodes('/Project/PropertyGroup/EnableDefaultCompileItems | /Project/PropertyGroup/DefaultItemExcludes | /Project/PropertyGroup/DefaultExcludesInProjectFolder').Count -ne 0) {
    throw 'Project compile exclusions changed; review the source inventory policy first.'
}
$codePaths = [Collections.Generic.List[string]]::new()
$directories = [Collections.Generic.Queue[string]]::new()
$directories.Enqueue($SourceRoot)
while ($directories.Count -gt 0) {
    $directory = $directories.Dequeue()
    $null = Assert-LocalPlainPath $directory
    foreach ($file in Get-ChildItem -LiteralPath $directory -Filter '*.cs' -File -Force) {
        $codePaths.Add([IO.Path]::GetRelativePath($SourceRoot, $file.FullName).Replace('\', '/'))
    }
    foreach ($child in Get-ChildItem -LiteralPath $directory -Directory -Force) {
        # Match this project's known top-level generated/test exclusions, not arbitrary subfolders.
        if ($directory -eq $SourceRoot -and $child.Name -in @('.git', 'bin', 'obj', 'tests', 'tools')) { continue }
        $directories.Enqueue($child.FullName)
    }
}
$actualCode = @($codePaths | Sort-Object)
if (Compare-Object $expectedCode $actualCode) { throw 'C# inventory changed; review the source allowlist first.' }

$runRoot = New-ObfuscationRun $SourceRoot $RunId
$copyRoot = Join-Path $runRoot 'source'
$privateRoot = Join-Path $runRoot 'private'
$null = New-Item -ItemType Directory -Path $copyRoot, $privateRoot
$mapping = [Collections.Generic.List[object]]::new()
foreach ($relativePath in $inputs) {
    $destination = $relativePath
    if ($relativePath -in $layout.renamedSources) {
        # Independent random identifiers; not a reversible hash of the original filename.
        $destination = 's/' + [Guid]::NewGuid().ToString('N') + '/' + [Guid]::NewGuid().ToString('N') + '.cs'
    }
    elseif ($relativePath -eq $projectName) { $destination = 'Application.csproj' }
    $inputPath = Get-ContainedPath $SourceRoot $relativePath
    $outputPath = Get-ContainedPath $copyRoot $destination
    $before = (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash
    $null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($outputPath)) -Force
    [IO.File]::Copy($inputPath, $outputPath, $false)
    $after = (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash
    $copied = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
    if ($before -ne $after -or $before -ne $copied) { throw 'A source changed during copying; this run is incomplete.' }
    $mapping.Add([ordered]@{ original = $relativePath; transformed = $destination; sha256 = $copied })
}

# The map is outside source/, and obj/ is ignored by Git and excluded by the SDK's source glob.
# This marker is written last. A directory without it is an incomplete run, never a publishable copy.
$mapPath = Join-Path $privateRoot 'source.obfuscation-map.json'
Write-NewUtf8File $mapPath (ConvertTo-Json -Depth 5 -InputObject ([ordered]@{
    schemaVersion = 1
    complete = $true
    scope = 'source-paths-only; contents and public history are not hidden'
    files = $mapping.ToArray()
}))
[pscustomobject]@{ SourceDirectory = $copyRoot; MappingFile = $mapPath; FileCount = $mapping.Count }
