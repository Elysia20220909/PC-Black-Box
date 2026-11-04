#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Verification.Runtime.ps1')
$checks = 0

function Assert-Rejected {
    param([scriptblock] $Action, [string] $Reason)

    $rejected = $false
    try { & $Action | Out-Null }
    catch
    {
        # Errors must contain only the fixed reason, never the rejected output or a personal path.
        if ($_.Exception.Message -cne $Reason) { throw 'unexpected-runtime-error' }
        $rejected = $true
    }
    if (-not $rejected) { throw 'invalid-runtime-accepted' }
}

foreach ($version in @('10.0.13', '10.0.0.1'))
{
    foreach ($architecture in @('x86', 'x64', 'arm', 'arm64'))
    {
        $actual = ConvertFrom-RuntimeStatus "PC_BLACK_BOX_RUNTIME version=$version processArchitecture=$architecture"
        if ($actual.version -cne $version -or $actual.processArchitecture -cne $architecture -or $actual.Count -ne 2)
        {
            throw 'runtime-roundtrip-failed'
        }
        $checks++
    }
}

$valid = 'PC_BLACK_BOX_RUNTIME version=10.0.13 processArchitecture=x64'
foreach ($output in @(
    "$valid`nPC_BLACK_BOX_SECURITY profile=SECURITY-BASELINE-2 enforced=true controls=16/16`n",
    "$valid`r`nPC_BLACK_BOX_SELF_TEST passed=true checks=134`r`n",
    "PC_BLACK_BOX_BOUNDARY_ARTIFACT sha256=synthetic`n$valid`nPC_BLACK_BOX_RUNTIME_BOUNDARY_TEST passed=true checks=9`n"
))
{
    $actual = ConvertFrom-RuntimeStatus $output
    $decoded = $actual | ConvertTo-Json | ConvertFrom-Json -AsHashtable
    if ($decoded.Count -ne 2 -or $decoded.version -cne '10.0.13' -or $decoded.processArchitecture -cne 'x64')
    {
        throw 'runtime-json-contract-failed'
    }
    $checks++
}

foreach ($output in @(
    '',
    'PC_BLACK_BOX_SELF_TEST passed=true checks=134',
    '10.0.402',
    'Microsoft.NETCore.App 10.0.13 [C:\Users\Synthetic\.dotnet\shared]',
    'PC_BLACK_BOX_RUNTIME',
    "$valid`n$valid",
    "$valid`r`nPC_BLACK_BOX_RUNTIME version=10.0.14 processArchitecture=x64",
    "$valid`nPC_BLACK_BOX_RUNTIME malformed=true",
    "$valid`n PC_BLACK_BOX_RUNTIME version=10.0.13 processArchitecture=x64",
    " $valid",
    "$valid ",
    'pc_black_box_runtime version=10.0.13 processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version= processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version=10.0 processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version=10.0.13.1.2 processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version=10.0.13-preview.1 processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version=10.0.-1 processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version=010.0.13 processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version=10.0.9999999999 processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version=１０.0.13 processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version=C:\Users\Synthetic\private processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version=10.0.13 processArchitecture=',
    'PC_BLACK_BOX_RUNTIME version=10.0.13 processArchitecture=X64',
    'PC_BLACK_BOX_RUNTIME version=10.0.13 processArchitecture=unknown',
    'PC_BLACK_BOX_RUNTIME version=10.0.13 osArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME processArchitecture=x64 version=10.0.13',
    "$valid path=C:\Users\Synthetic\private",
    "$valid token=synthetic-secret",
    "$valid processArchitecture=arm64",
    "PC_BLACK_BOX_RUNTIME version=10.0.13`nprocessArchitecture=x64",
    "$valid`rprivate",
    ($valid + [char]0)
))
{
    Assert-Rejected { ConvertFrom-RuntimeStatus $output } 'runtime-metadata-invalid'
    $checks++
}

$expected = ConvertFrom-RuntimeStatus $valid
Assert-SameRuntime (ConvertFrom-RuntimeStatus $valid) $expected
$checks++
foreach ($different in @(
    'PC_BLACK_BOX_RUNTIME version=10.0.14 processArchitecture=x64',
    'PC_BLACK_BOX_RUNTIME version=10.0.13 processArchitecture=arm64',
    'PC_BLACK_BOX_RUNTIME version=11.0.0 processArchitecture=x86'
))
{
    $actual = ConvertFrom-RuntimeStatus $different
    Assert-Rejected { Assert-SameRuntime $actual $expected } 'runtime-metadata-mismatch'
    # Comparing must not overwrite the actual observation with the earlier stage's values.
    if ($actual.version -ceq $expected.version -and $actual.processArchitecture -ceq $expected.processArchitecture)
    {
        throw 'runtime-observation-overwritten'
    }
    $checks++
}

"PC_BLACK_BOX_RUNTIME_METADATA_TEST passed=true checks=$checks"
