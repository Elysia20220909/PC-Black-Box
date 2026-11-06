#Requires -Version 7.0

[CmdletBinding()]
param(
    [ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedApplicationSha256,
    [string] $DotNetPath,
    # The hosted standard-user session cannot write build output, so CI builds the probe beforehand.
    [switch] $NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot 'Verification.Runtime.ps1')

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$applicationProject = Join-Path $repositoryRoot 'Destiny2BlackBox.csproj'
$probeProject = Join-Path $PSScriptRoot 'RuntimeBoundaryProbe\RuntimeBoundaryProbe.csproj'
$targetFramework = 'net10.0-windows10.0.17763.0'
$applicationOutput = Join-Path $repositoryRoot "bin\Release\$targetFramework"
$probeOutput = Join-Path $PSScriptRoot "RuntimeBoundaryProbe\bin\Release\$targetFramework"
$applicationAssembly = Join-Path $applicationOutput 'PC Black Box.dll'
$probeAssembly = Join-Path $probeOutput 'PCBlackBox.RuntimeBoundaryProbe.dll'

if (-not $DotNetPath)
{
    $candidates = [Collections.Generic.List[string]]::new()
    $command = Get-Command dotnet -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) { $candidates.Add([IO.Path]::GetFullPath($command.Source)) }
    $userDotNet = Join-Path $env:USERPROFILE '.dotnet\dotnet.exe'
    $candidates.Add([IO.Path]::GetFullPath($userDotNet))
    foreach ($candidate in $candidates)
    {
        if (-not [IO.File]::Exists($candidate) -or [IO.Path]::GetFileName($candidate) -ine 'dotnet.exe') { continue }
        $versionStart = [Diagnostics.ProcessStartInfo]::new($candidate)
        $versionStart.WorkingDirectory = $repositoryRoot
        $versionStart.UseShellExecute = $false
        $versionStart.CreateNoWindow = $true
        $versionStart.RedirectStandardInput = $true
        $versionStart.RedirectStandardOutput = $true
        $versionStart.RedirectStandardError = $true
        $versionStart.ArgumentList.Add('--version')
        $versionProcess = [Diagnostics.Process]::new()
        $versionProcess.StartInfo = $versionStart
        $versionStarted = $false
        try
        {
            try { $versionStarted = $versionProcess.Start() } catch { continue }
            if (-not $versionStarted) { continue }
            $versionProcess.StandardInput.Close()
            $versionOutput = $versionProcess.StandardOutput.ReadToEndAsync()
            $versionError = $versionProcess.StandardError.ReadToEndAsync()
            if (-not $versionProcess.WaitForExit(30000)) { throw 'SDK version query timed out.' }
            if (-not $versionOutput.Wait(5000) -or -not $versionError.Wait(5000)) { throw 'SDK version query output timed out.' }
            $version = [regex]::Match($versionOutput.Result.Trim(), '^(?<major>\d+)\.\d+\.\d+([-.][A-Za-z0-9.-]+)?$')
            if ($versionProcess.ExitCode -eq 0 -and $version.Success -and [int]$version.Groups['major'].Value -ge 10)
            {
                $DotNetPath = $candidate
                break
            }
        }
        finally
        {
            try
            {
                if ($versionStarted -and -not $versionProcess.HasExited)
                {
                    try { $versionProcess.Kill($true) }
                    catch { if (-not $versionProcess.HasExited) { throw } }
                    if (-not $versionProcess.WaitForExit(5000)) { throw 'SDK version query cleanup timed out.' }
                }
            }
            finally { $versionProcess.Dispose() }
        }
    }
    if (-not $DotNetPath) { throw 'A .NET SDK 10 or later was not found.' }
}
$DotNetPath = [IO.Path]::GetFullPath($DotNetPath)
if (-not [IO.File]::Exists($DotNetPath) -or [IO.Path]::GetFileName($DotNetPath) -ine 'dotnet.exe')
{
    throw 'A dotnet.exe path is required.'
}

function Invoke-DotNetBuild {
    param([Parameter(Mandatory)][string] $Project)

    Push-Location -LiteralPath $repositoryRoot
    try
    {
        & $DotNetPath build $Project -c Release --no-incremental --disable-build-servers -warnaserror '-p:UseSharedCompilation=false'
        if ($LASTEXITCODE -ne 0)
        {
            throw "Release build failed."
        }
    }
    finally { Pop-Location }
}

function Add-NativeProbeType {
    if ('PcBlackBox.RuntimeBoundary.NativeMethods' -as [type])
    {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace PcBlackBox.RuntimeBoundary
{
    public static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetProcessMitigationPolicy(
            IntPtr process,
            int mitigationPolicy,
            out uint buffer,
            UIntPtr length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        public static extern uint GetErrorMode();

        [DllImport("kernel32.dll")]
        public static extern uint SetErrorMode(uint mode);
    }
}
'@
}

function Open-TestProcess {
    param(
        [Parameter(Mandatory)][uint32] $ProcessId,
        [Parameter(Mandatory)][uint32] $Access
    )

    $handle = [PcBlackBox.RuntimeBoundary.NativeMethods]::OpenProcess($Access, $false, $ProcessId)
    $lastError = [Runtime.InteropServices.Marshal]::GetLastPInvokeError()
    [pscustomobject]@{
        Handle = $handle
        Allowed = $handle -ne [IntPtr]::Zero
        Win32Error = $lastError
    }
}

function Close-TestHandle {
    param([Parameter(Mandatory)][IntPtr] $Handle)

    if ($Handle -ne [IntPtr]::Zero)
    {
        [void][PcBlackBox.RuntimeBoundary.NativeMethods]::CloseHandle($Handle)
    }
}

function Start-HeadlessProcess {
    param([Parameter(Mandatory)][Diagnostics.ProcessStartInfo] $StartInfo)

    # Child processes inherit this process-only error mode. Restore the test runner's previous
    # value immediately after launch; the deliberate network FailFast must not display a dialog.
    $originalMode = [PcBlackBox.RuntimeBoundary.NativeMethods]::GetErrorMode()
    try
    {
        [void][PcBlackBox.RuntimeBoundary.NativeMethods]::SetErrorMode($originalMode -bor [uint32]0x0003)
        if (([PcBlackBox.RuntimeBoundary.NativeMethods]::GetErrorMode() -band [uint32]0x0003) -ne [uint32]0x0003)
        {
            throw 'Could not set the child process error mode.'
        }

        $process = [Diagnostics.Process]::Start($StartInfo)
        if ($null -eq $process) { throw 'Could not start the test process.' }
        return $process
    }
    finally
    {
        [void][PcBlackBox.RuntimeBoundary.NativeMethods]::SetErrorMode($originalMode)
    }
}

function Stop-TestProcess {
    param([Parameter(Mandatory)][Diagnostics.Process] $Process)

    try
    {
        if (-not $Process.HasExited)
        {
            try { $Process.Kill() }
            catch { if (-not $Process.HasExited) { throw } }
        }
        if (-not $Process.WaitForExit(5000))
        {
            throw 'The owned test process did not exit during cleanup.'
        }
    }
    finally
    {
        $Process.Dispose()
    }
}

if (-not $NoBuild)
{
    Invoke-DotNetBuild -Project $applicationProject
    Invoke-DotNetBuild -Project $probeProject
}

foreach ($requiredPath in @($applicationAssembly, $probeAssembly))
{
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf))
    {
        throw "A required local build output is missing."
    }
}

$applicationSha256 = (Get-FileHash -LiteralPath $applicationAssembly -Algorithm SHA256).Hash
if ($ExpectedApplicationSha256 -and $applicationSha256 -cne $ExpectedApplicationSha256.ToUpperInvariant())
{
    throw 'The rebuilt application does not match the expected SHA-256.'
}
"PC_BLACK_BOX_BOUNDARY_ARTIFACT sha256=$applicationSha256"

Add-NativeProbeType
$checks = 0
$start = [Diagnostics.ProcessStartInfo]::new($DotNetPath)
$start.WorkingDirectory = $repositoryRoot
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.ArgumentList.Add($applicationAssembly)
$start.ArgumentList.Add('--runtime-boundary-test-host')
$target = Start-HeadlessProcess -StartInfo $start
$targetFailure = $null
try
{
    $targetError = $target.StandardError.ReadToEndAsync()
    $runtimeLine = $target.StandardOutput.ReadLineAsync()
    if (-not $runtimeLine.Wait(10000)) { throw 'runtime-metadata-timeout' }
    $runtime = ConvertFrom-RuntimeStatus $runtimeLine.Result
    $ready = $target.StandardOutput.ReadLineAsync()
    if (-not $ready.Wait(10000) -or $ready.Result -cne 'PC_BLACK_BOX_RUNTIME_BOUNDARY_HOST ready=true' -or $target.HasExited)
    {
        throw 'The headless application did not complete its security checks and become ready.'
    }
    $targetOutput = $target.StandardOutput.ReadToEndAsync()
    # Only forward validated product metadata, never the probe's or PowerShell's own runtime.
    "PC_BLACK_BOX_RUNTIME version=$($runtime.version) processArchitecture=$($runtime.processArchitecture)"

    $accessTests = @(
        [pscustomobject]@{ Name = 'PROCESS_VM_READ'; Mask = [uint32]0x0010; Expected = $false },
        [pscustomobject]@{ Name = 'PROCESS_VM_WRITE'; Mask = [uint32]0x0020; Expected = $false },
        [pscustomobject]@{ Name = 'PROCESS_CREATE_THREAD'; Mask = [uint32]0x0002; Expected = $false },
        [pscustomobject]@{ Name = 'PROCESS_DUP_HANDLE'; Mask = [uint32]0x0040; Expected = $false },
        [pscustomobject]@{ Name = 'PROCESS_ALL_ACCESS'; Mask = [uint32]0x001FFFFF; Expected = $false },
        [pscustomobject]@{ Name = 'PROCESS_QUERY_LIMITED_INFORMATION'; Mask = [uint32]0x1000; Expected = $true },
        [pscustomobject]@{ Name = 'PROCESS_TERMINATE'; Mask = [uint32]0x0001; Expected = $true }
    )

    foreach ($test in $accessTests)
    {
        $result = Open-TestProcess -ProcessId ([uint32]$target.Id) -Access $test.Mask
        try
        {
            if ($result.Allowed -ne $test.Expected)
            {
                throw "$($test.Name) returned an unexpected access decision."
            }
            if (-not $test.Expected -and $result.Win32Error -ne 5)
            {
                throw "$($test.Name) failed without ERROR_ACCESS_DENIED."
            }

            $checks++
            "ACCESS name=$($test.Name) allowed=$($result.Allowed.ToString().ToLowerInvariant()) win32=$($result.Win32Error)"
        }
        finally
        {
            Close-TestHandle -Handle $result.Handle
        }
    }

    $query = Open-TestProcess -ProcessId ([uint32]$target.Id) -Access ([uint32]0x1000)
    if (-not $query.Allowed)
    {
        throw "The side-channel mitigation policy could not be queried."
    }
    try
    {
        [uint32]$sideChannelFlags = 0
        $queried = [PcBlackBox.RuntimeBoundary.NativeMethods]::GetProcessMitigationPolicy(
            $query.Handle,
            14,
            [ref]$sideChannelFlags,
            [UIntPtr]4)
        if (-not $queried -or ($sideChannelFlags -band [uint32]0x0000000E) -ne [uint32]0x0000000E)
        {
            throw "The combined side-channel mitigation flags were not preserved."
        }

        $checks++
        "MITIGATION policy=side-channel flags=0x$($sideChannelFlags.ToString('X8'))"
    }
    finally
    {
        Close-TestHandle -Handle $query.Handle
    }

    $target.StandardInput.WriteLine('release')
    $target.StandardInput.Close()
    if (-not $target.WaitForExit(10000))
    {
        throw 'The headless application did not exit after release.'
    }
    if ($target.ExitCode -ne 0 -or $targetError.Result.Length -ne 0 -or $targetOutput.Result.Length -ne 0)
    {
        throw 'The headless application did not exit cleanly.'
    }
}
catch
{
    $targetFailure = $_
    throw
}
finally
{
    try { Stop-TestProcess -Process $target }
    catch
    {
        if ($null -ne $targetFailure) { Write-Warning "Original boundary test failure: $($targetFailure.Exception.Message)" }
        throw
    }
}

$probe = $null
$probeFailure = $null
try
{
    $probeStart = [Diagnostics.ProcessStartInfo]::new($DotNetPath)
    $probeStart.WorkingDirectory = $repositoryRoot
    $probeStart.UseShellExecute = $false
    $probeStart.CreateNoWindow = $true
    $probeStart.RedirectStandardOutput = $true
    $probeStart.RedirectStandardError = $true
    $probeStart.ArgumentList.Add($probeAssembly)
    $probeStart.ArgumentList.Add('--network-transport')
    $probeStart.ArgumentList.Add($applicationAssembly)
    $probe = Start-HeadlessProcess -StartInfo $probeStart
    $probeOutput = $probe.StandardOutput.ReadToEndAsync()
    $probeError = $probe.StandardError.ReadToEndAsync()
    if (-not $probe.WaitForExit(15000))
    {
        throw 'The network-guard probe timed out.'
    }

    if ($probe.ExitCode -eq 0 -or $probe.ExitCode -eq 86)
    {
        throw "The managed network transport load was not terminated."
    }
    if (-not $probeError.Result.Contains('PC Black Box blocked a network transport (System.Net.Sockets)', [StringComparison]::Ordinal))
    {
        throw "The probe failed without the expected network-guard evidence."
    }

    $checks++
    "NETWORK_GUARD assembly=System.Net.Sockets terminated=true exit=$($probe.ExitCode)"
}
catch
{
    $probeFailure = $_
    throw
}
finally
{
    if ($null -ne $probe)
    {
        try { Stop-TestProcess -Process $probe }
        catch
        {
            if ($null -ne $probeFailure) { Write-Warning "Original network probe failure: $($probeFailure.Exception.Message)" }
            throw
        }
    }
}

if ((Get-FileHash -LiteralPath $applicationAssembly -Algorithm SHA256).Hash -cne $applicationSha256)
{
    throw 'The application assembly changed during the boundary test.'
}
"PC_BLACK_BOX_RUNTIME_BOUNDARY_TEST passed=true checks=$checks"
