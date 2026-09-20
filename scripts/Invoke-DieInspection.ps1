#Requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'Report')]
param(
    [Parameter(Mandatory)][string]$InputFile,
    [Parameter(Mandatory)][string]$EngineArchive,
    [Parameter(Mandatory, ParameterSetName = 'Report')][string]$ReportPath,
    [Parameter(Mandatory, ParameterSetName = 'View')][switch]$ShowWindow
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$framework = 'net10.0-windows10.0.17763.0'
$bridge = Join-Path $repository "tools\DieBridge\bin\Release\$framework\DieBridge.dll"
$app = Join-Path $repository "bin\Release\$framework\PC Black Box.dll"
if (!(Test-Path -LiteralPath $bridge) -or !(Test-Path -LiteralPath $app)) {
    throw 'Build Destiny2BlackBox.csproj and tools/DieBridge/DieBridge.csproj in Release first.'
}
$mode = if ($ShowWindow) { '--view' } else { '--report' }
$destination = if ($ShowWindow) { 'unused' } else { [IO.Path]::GetFullPath($ReportPath) }
& dotnet $bridge $mode ([IO.Path]::GetFullPath($EngineArchive)) ([IO.Path]::GetFullPath($InputFile)) $app $destination
if ($LASTEXITCODE -ne 0) { throw "DiE integration failed (exit $LASTEXITCODE)." }
