#Requires -Version 7.0

function Assert-HostedAccountAbsent {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Security.Principal.SecurityIdentifier] $Sid)

    # Enumerate successfully before testing absence. A targeted lookup reports a missing
    # SID as an error; suppressing it would also hide genuine account-database failures.
    $accounts = @(Get-LocalUser -ErrorAction Stop)
    if ($accounts | Where-Object { $_.SID -eq $Sid })
    {
        throw 'The temporary CI account was not removed.'
    }
}
