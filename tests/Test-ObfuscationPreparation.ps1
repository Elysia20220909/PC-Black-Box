#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string] $AssemblyPath)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'tools/Obfuscation.Common.ps1')
$sourceTool = Join-Path $root 'tools/New-ObfuscatedSource.ps1'
$configTool = Join-Path $root 'tools/New-ObfuscationConfig.ps1'
$script:checks = 0
function Assert-True([bool] $Condition, [string] $Message) {
    if (!$Condition) { throw $Message }
    $script:checks++
}
function Assert-Rejected([scriptblock] $Operation, [string] $Expected) {
    $message = $null
    try { & $Operation | Out-Null } catch { $message = $_.Exception.Message }
    Assert-True ($null -ne $message -and $message.Contains($Expected)) "Expected rejection: $Expected"
}

$runId = 'test-' + [Guid]::NewGuid().ToString('N')
$first = & $sourceTool -RunId $runId
$map = Get-Content -LiteralPath $first.MappingFile -Raw | ConvertFrom-Json
Assert-True $map.complete 'The completed mapping marker was not written.'
Assert-True ($first.FileCount -eq 24) 'Unexpected source-only input count.'
Assert-True (!$first.MappingFile.StartsWith($first.SourceDirectory + [IO.Path]::DirectorySeparatorChar)) 'The private map leaked into source/.'
foreach ($entry in $map.files) {
    $original = Join-Path $root $entry.original
    $transformed = Join-Path $first.SourceDirectory $entry.transformed
    Assert-True ((Get-FileHash -LiteralPath $original).Hash -eq $entry.sha256) 'The original source was modified.'
    Assert-True ((Get-FileHash -LiteralPath $transformed).Hash -eq $entry.sha256) 'Source content changed in the copy.'
}
$renamed = @($map.files | Where-Object { $_.transformed -match '^s/' })
Assert-True ($renamed.Count -eq 16) 'Not all reviewed source paths were renamed.'
Assert-True (@($renamed | Where-Object { $_.transformed -cnotmatch '^s/[0-9a-f]{32}/[0-9a-f]{32}\.cs$' }).Count -eq 0) 'A path still describes its responsibility.'
$copiedFiles = @(Get-ChildItem -LiteralPath $first.SourceDirectory -Recurse -File -Force)
Assert-True ($copiedFiles.Count -eq $map.files.Count) 'An unlisted file was copied.'
Assert-True (@($copiedFiles | Where-Object { $_.Extension -in @('.dll', '.exe', '.pdb', '.json', '.ps1') }).Count -eq 0) 'Unexpected metadata or binary in the source-only copy.'
Assert-True (Test-Path -LiteralPath (Join-Path $first.SourceDirectory 'LICENSE')) 'License notice omitted.'
Assert-True (Test-Path -LiteralPath (Join-Path $first.SourceDirectory 'App.xaml')) 'WPF entry point moved.'
Assert-True (Test-Path -LiteralPath (Join-Path $first.SourceDirectory 'MainWindow.xaml.cs')) 'WPF code-behind moved.'
$ignored = & git -C $root check-ignore -- $first.MappingFile
Assert-True ($LASTEXITCODE -eq 0 -and $null -ne $ignored) 'Private mapping is not ignored by Git.'
$second = & $sourceTool -RunId ($runId + '-second')
$secondMap = Get-Content -LiteralPath $second.MappingFile -Raw | ConvertFrom-Json
Assert-True ($map.files[0].transformed -ne $secondMap.files[0].transformed) 'Independent runs reused an identifier.'
Assert-Rejected { & $sourceTool -RunId $runId } 'already exists'
Assert-Rejected { & $sourceTool -RunId '../escape' } 'RunId must'

# Negative controls use only our generated copy, never the maintained sources.
$fixtureRoot = Join-Path (Split-Path $first.SourceDirectory -Parent) 'fixture'
$rootFixture = Join-Path (Split-Path $first.SourceDirectory -Parent) 'root-fixture'
foreach ($fixture in @($fixtureRoot, $rootFixture)) {
    $null = New-Item -ItemType Directory -Path $fixture
    foreach ($entry in $map.files) {
        $path = Join-Path $fixture $entry.original
        $null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($path)) -Force
        [IO.File]::Copy((Join-Path $root $entry.original), $path, $false)
    }
}
$extraDirectory = Join-Path $fixtureRoot 'Extra'
$null = New-Item -ItemType Directory -Path $extraDirectory
Write-NewUtf8File (Join-Path $extraDirectory 'Added.cs') '// nested source must fail closed'
Assert-Rejected { & $sourceTool -SourceRoot $fixtureRoot } 'inventory changed'
Write-NewUtf8File (Join-Path $rootFixture 'Unexpected.cs') '// independent root source must fail closed'
Assert-Rejected { & $sourceTool -SourceRoot $rootFixture } 'inventory changed'
$junction = Join-Path (Split-Path $first.SourceDirectory -Parent) 'linked-source'
$null = New-Item -ItemType Junction -Path $junction -Target $fixtureRoot
Assert-Rejected { & $sourceTool -SourceRoot $junction } 'Reparse points'
Assert-Rejected { Get-ContainedPath $root '../escape.cs' } 'escapes'
Assert-Rejected { Get-ContainedPath $root 'file.cs:stream' } 'alternate data stream'
Assert-Rejected { New-ObfuscationRun -SourceRoot $first.SourceDirectory -RunId 'wrong-root' } 'maintained application project'
Assert-Rejected { & $sourceTool 'unexpected-positional-argument' } 'positional parameter'
Assert-Rejected { Assert-FixedLocalDrive ([IO.DriveType]::Network) } 'fixed local drive'
Assert-Rejected { Assert-FixedLocalDrive ([IO.DriveType]::Unknown) } 'fixed local drive'
Assert-Rejected { Assert-FixedLocalDrive ([IO.DriveType]::NoRootDirectory) } 'fixed local drive'
Assert-Rejected { Assert-LocalPlainPath '\\example.invalid\share\source' } 'Network paths'

$result = & $configTool -AssemblyPath $AssemblyPath -ResolutionDirectory ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($AssemblyPath))) -RunId ($runId + '-config')
[xml] $config = Get-Content -LiteralPath $result.ConfigurationFile -Raw
$settings = @{}
foreach ($variable in $config.Obfuscator.Var) { $settings[$variable.name] = $variable.value }
Assert-True ($settings.KeepPublicApi -eq 'true' -and $settings.HidePrivateApi -eq 'true') 'Public contract protection changed.'
Assert-True ($settings.RenameProperties -eq 'false' -and $settings.RenameEvents -eq 'false') 'JSON or binding names may be renamed.'
Assert-True ($settings.HideStrings -eq 'false' -and $settings.OptimizeMethods -eq 'false') 'Runtime transformations were enabled.'
Assert-True ($settings.SkipGenerated -eq 'true' -and $settings.SkipSpecialName -eq 'true') 'Compiler-generated code is not protected.'
Assert-True ([IO.Path]::IsPathFullyQualified($settings.InPath) -and [IO.Path]::IsPathFullyQualified($settings.OutPath) -and [IO.Path]::IsPathFullyQualified($settings.LogFile)) 'Configuration contains relative paths.'
Assert-True (!(Test-Path -LiteralPath $settings.OutPath)) 'Binary output was created while generating configuration.'
Assert-True ($config.Obfuscator.Module.file -eq [IO.Path]::GetFullPath($AssemblyPath)) 'Input module changed.'
$skip = $config.Obfuscator.Module.SkipType
foreach ($type in @('App', 'MainWindow', 'FileAnalysis', 'ReportBuilder', 'SettingsStore', 'OfflineSignatureVerifier', 'SecureFileReader', 'ProcessSecurityBootstrap', 'WindowsProcessHardening', 'NetworkIsolationGuard', 'NewUnreviewedType')) {
    Assert-True ([regex]::IsMatch("DestinyBlackBox.$type", $skip.name)) "Excluded type can be renamed: $type"
}
Assert-True (![regex]::IsMatch('DestinyBlackBox.FileInspector', $skip.name)) 'File inspector not selected.'
Assert-True (![regex]::IsMatch('DestinyBlackBox.ShortcutInspector', $skip.name)) 'Shortcut inspector not selected.'
Assert-True ([regex]::IsMatch('DestinyBlackBox.FileInspector/BoundedReadStream', $skip.name)) 'A nested type escaped conservative exclusion.'
Assert-True ([regex]::IsMatch('DestinyBlackBox.FileInspector/NewUnreviewedType', $skip.name)) 'An unreviewed nested type escaped exclusion.'
foreach ($attribute in @('skipMethods', 'skipFields', 'skipProperties', 'skipEvents', 'skipStringHiding')) {
    Assert-True ($skip.GetAttribute($attribute) -eq 'true') "Exclusion misses $attribute"
}
Assert-Rejected { & $configTool -AssemblyPath (Join-Path $root 'missing.dll') -ResolutionDirectory $root } 'locally built'
Assert-Rejected { & $configTool -AssemblyPath $AssemblyPath -ResolutionDirectory (Join-Path $root 'missing-references') } 'directory is missing'

[pscustomobject]@{
    Passed = $true
    Checks = $script:checks
    SourceDirectory = $first.SourceDirectory
    ConfigurationFile = $result.ConfigurationFile
    BinaryObfuscationExecuted = $false
}
