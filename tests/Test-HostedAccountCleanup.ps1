#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$helper = Join-Path $PSScriptRoot 'HostedAccountCleanup.ps1'
$targetSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-9999')
$checks = 0
foreach ($scenario in @('absent', 'present', 'query-error', 'partial-query-error'))
{
    $state = @{ Calls = 0; Confirmed = $false }
    $succeeded = $false
    $failure = $null
    try
    {
        # The function shadows the Windows cmdlet only inside this child scope. No account
        # is created, removed, or queried on the machine running these regression tests.
        & {
            function Get-LocalUser {
                [CmdletBinding()]
                param([Security.Principal.SecurityIdentifier] $SID)

                $state.Calls++
                if ($PSBoundParameters.ContainsKey('SID') -or
                    -not $PSBoundParameters.ContainsKey('ErrorAction') -or
                    $PSBoundParameters['ErrorAction'] -ne [Management.Automation.ActionPreference]::Stop)
                {
                    throw 'Cleanup must enumerate accounts with explicit ErrorAction Stop.'
                }
                switch ($scenario)
                {
                    'absent' {
                        if ($null -eq $SID)
                        {
                            [pscustomobject]@{ SID = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-9998') }
                        }
                    }
                    'present' { [pscustomobject]@{ SID = $targetSid } }
                    'query-error' { Write-Error 'Synthetic account lookup failure.' }
                    'partial-query-error' {
                        if ($null -eq $SID)
                        {
                            [pscustomobject]@{ SID = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-9998') }
                        }
                        Write-Error 'Synthetic partial account lookup failure.'
                    }
                }
            }
            . $helper
            Assert-HostedAccountAbsent -Sid $targetSid
            $state.Confirmed = $true
        }
        $succeeded = $true
    }
    catch { $failure = $_.Exception.Message }
    $expected = $scenario -eq 'absent'
    $expectedFailure = switch ($scenario)
    {
        'absent' { $null }
        'present' { 'The temporary CI account was not removed.' }
        'query-error' { 'Synthetic account lookup failure.' }
        'partial-query-error' { 'Synthetic partial account lookup failure.' }
    }
    if ($state.Calls -ne 1 -or $succeeded -ne $expected -or $state.Confirmed -ne $expected -or $failure -ne $expectedFailure)
    {
        throw "Account-cleanup regression failed: scenario=$scenario succeeded=$succeeded confirmed=$($state.Confirmed)."
    }
    $checks++
}
"PC_BLACK_BOX_ACCOUNT_CLEANUP_TEST passed=true checks=$checks"
