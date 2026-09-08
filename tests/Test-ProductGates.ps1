#Requires -Version 7.0
[CmdletBinding()]
param([string] $TemporaryDirectory)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($TemporaryDirectory)
{
    # Explicitly avoid inheriting an administrator-only TEMP on a hosted runner.
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted')
    {
        throw 'A CI temporary directory is accepted only on a GitHub-hosted runner.'
    }
    $env:TEMP = [IO.Path]::GetFullPath($TemporaryDirectory)
    $env:TMP = $env:TEMP
}
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$assembly = Join-Path $repositoryRoot 'bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll'

& (Join-Path $PSScriptRoot 'Test-HostedAccountCleanup.ps1')

function Invoke-CheckedProduct {
    param([Parameter(Mandatory)][string] $Mode)
    $output = @(& dotnet $assembly $Mode)
    $code = $LASTEXITCODE
    $output | Write-Output
    if ($code -ne 0)
    {
        $output | ForEach-Object { [Console]::Error.WriteLine($_) }
        throw "Product gate $Mode failed with exit code $code."
    }
}

$status = @(Invoke-CheckedProduct '--security-status')
$status | Write-Output
if (-not ($status -match '^PC_BLACK_BOX_SECURITY .* enforced=true controls=16/16 ') -or
    @($status -match '^control=\S+ tier=required state=enforced$').Count -ne 16 -or
    ($status -match '^control=\S+ tier=required state=(?!enforced$)'))
{
    throw 'The complete sixteen-control baseline was not demonstrated.'
}
$selfTest = @(Invoke-CheckedProduct '--self-test')
$selfTest | Write-Output
if (-not ($selfTest -match '^PC_BLACK_BOX_SELF_TEST passed=true checks=\d+$'))
{
    throw 'The product self-test success marker is missing.'
}
& (Join-Path $PSScriptRoot 'Test-RuntimeBoundaries.ps1') -NoBuild
