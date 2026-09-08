#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Account creation is confined to GitHub's disposable hosted VM, never a developer PC.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows')
{
    throw 'This helper is restricted to a disposable GitHub-hosted Windows runner.'
}
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    throw 'The hosted setup process must be elevated; the product test process must not be.'
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$assembly = Join-Path $repositoryRoot 'bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll'

# Negative control: verify the unmodified product still rejects this elevated runner.
$refusal = @(& dotnet $assembly --security-status 2>&1)
$refusalExit = $LASTEXITCODE
if ($refusalExit -eq 0 -or -not ($refusal -match 'PC_BLACK_BOX_ELEVATION elevated=true refusing=true'))
{
    throw 'The elevated-launch refusal was not demonstrated.'
}
'ELEVATION_REFUSAL verified=true'

$accountName = 'PcbTest' + [Guid]::NewGuid().ToString('N').Substring(0, 10)
$password = ConvertTo-SecureString ('Pcb!9' + [Convert]::ToHexString(
    [Security.Cryptography.RandomNumberGenerator]::GetBytes(32))) -AsPlainText -Force
$account = $null
$child = $null
$logDirectory = Join-Path $env:RUNNER_TEMP $accountName
try
{
    $account = New-LocalUser -Name $accountName -Password $password -AccountNeverExpires -Description 'Disposable PC Black Box CI tests'
    # Resolve Users by SID so the VM language does not determine group membership.
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $users -Member $account
    [void](New-Item -ItemType Directory -Path $logDirectory)
    $acl = Get-Acl -LiteralPath $logDirectory
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $account.SID, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $logDirectory -AclObject $acl

    $credential = [Management.Automation.PSCredential]::new(".\$accountName", $password)
    $stdout = Join-Path $logDirectory 'stdout.txt'
    $stderr = Join-Path $logDirectory 'stderr.txt'
    $shell = (Get-Command pwsh -CommandType Application).Source
    $gate = Join-Path $PSScriptRoot 'Test-ProductGates.ps1'
    $launch = @{
        FilePath = $shell
        Credential = $credential
        LoadUserProfile = $true
        ArgumentList = ('-NoProfile -NonInteractive -File "{0}" -TemporaryDirectory "{1}"' -f $gate, $logDirectory)
        WorkingDirectory = $repositoryRoot
        WindowStyle = 'Hidden'
        RedirectStandardOutput = $stdout
        RedirectStandardError = $stderr
        PassThru = $true
    }
    $child = Start-Process @launch
    if (-not $child.WaitForExit(900000))
    {
        $child.Kill($true)
        throw 'The non-administrator runtime gates exceeded fifteen minutes.'
    }
    $child.WaitForExit()
    Get-Content -LiteralPath $stdout
    Get-Content -LiteralPath $stderr
    if ($child.ExitCode -ne 0) { throw 'The non-administrator runtime gates failed.' }
}
finally
{
    try
    {
        if ($null -ne $child)
        {
            try
            {
                if (-not $child.HasExited) { $child.Kill($true); $child.WaitForExit() }
            }
            finally { $child.Dispose() }
        }
    }
    finally
    {
        try
        {
            if ($null -ne $account)
            {
                Remove-LocalUser -SID $account.SID
                if (Get-LocalUser -SID $account.SID -ErrorAction SilentlyContinue)
                {
                    throw 'The temporary CI account was not removed.'
                }
                'TEMPORARY_ACCOUNT removed=true'
            }
        }
        finally { $password.Dispose() }
    }
    # Logs remain on the disposable VM for the current job only; no artifact upload is configured.
}
