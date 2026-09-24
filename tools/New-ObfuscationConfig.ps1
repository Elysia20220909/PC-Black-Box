#requires -Version 7.0
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string] $AssemblyPath,
    [Parameter(Mandatory)][string[]] $ResolutionDirectory,
    [string] $SourceRoot = (Split-Path $PSScriptRoot -Parent),
    [string] $RunId = ('config-' + [Guid]::NewGuid().ToString('N'))
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Obfuscation.Common.ps1')
$SourceRoot = Assert-LocalPlainPath $SourceRoot
$assembly = Assert-LocalPlainPath $AssemblyPath
if (!(Test-Path -LiteralPath $assembly -PathType Leaf) -or [IO.Path]::GetFileName($assembly) -cne 'PC Black Box.dll') {
    throw 'Supply the locally built PC Black Box.dll; arbitrary inputs are not supported.'
}
$layout = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'obfuscation/source-layout.json') -Raw | ConvertFrom-Json
if ($layout.schemaVersion -ne 2) { throw 'Unsupported source layout version.' }
if ([Diagnostics.FileVersionInfo]::GetVersionInfo($assembly).FileVersion -cne $layout.fileVersion) {
    throw "Assembly file version must be $($layout.fileVersion); do not mix baseline versions."
}
$searchPaths = @($ResolutionDirectory | ForEach-Object {
    $path = Assert-LocalPlainPath $_
    if (!(Test-Path -LiteralPath $path -PathType Container)) { throw 'A reference resolution directory is missing.' }
    $path
})
if ($searchPaths.Count -eq 0) { throw 'Explicit .NET and WPF reference directories are required.' }

$runRoot = New-ObfuscationRun $SourceRoot $RunId
$privateRoot = Join-Path $runRoot 'private'
$null = New-Item -ItemType Directory -Path $privateRoot
$config = [xml]'<Obfuscator />'
$settings = [ordered]@{
    InPath = [IO.Path]::GetDirectoryName($assembly)
    OutPath = (Join-Path $runRoot 'binary-test-output')
    LogFile = (Join-Path $privateRoot 'binary.obfuscation-map.xml')
    XmlMapping = 'true'
    KeepPublicApi = 'true'
    HidePrivateApi = 'true'
    RenameProperties = 'false'
    RenameEvents = 'false'
    HideStrings = 'false'
    OptimizeMethods = 'false'
    SuppressIldasm = 'false'
    SkipGenerated = 'true'
    SkipSpecialName = 'true'
}
foreach ($entry in $settings.GetEnumerator()) {
    $element = $config.CreateElement('Var')
    $element.SetAttribute('name', $entry.Key)
    $element.SetAttribute('value', $entry.Value)
    $null = $config.DocumentElement.AppendChild($element)
}
foreach ($path in $searchPaths) {
    $element = $config.CreateElement('AssemblySearchPath')
    $element.SetAttribute('path', $path)
    $null = $config.DocumentElement.AppendChild($element)
}
$module = $config.CreateElement('Module')
$module.SetAttribute('file', $assembly)
$null = $config.DocumentElement.AppendChild($module)

# Allow renaming only inside the two parsers. Keep UI, JSON models, P/Invoke,
# bootstrap, guards, and every unreviewed/new type unchanged. No third-party modules.
$skip = $config.CreateElement('SkipType')
$skip.SetAttribute('name', '^(?!DestinyBlackBox\.(FileInspector|ShortcutInspector)$).*')
foreach ($attribute in @('skipMethods', 'skipFields', 'skipProperties', 'skipEvents', 'skipStringHiding')) {
    $skip.SetAttribute($attribute, 'true')
}
$null = $module.AppendChild($skip)
$configPath = Join-Path $privateRoot 'obfuscar.xml'
Write-NewUtf8File $configPath $config.OuterXml
[pscustomobject]@{
    ConfigurationFile = $configPath
    Status = 'configuration-only; engine compatibility and binary transformation NOT verified'
}
