#Requires -Version 7.0

[CmdletBinding()]
param([switch] $NoBuild)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$applicationProject = Join-Path $repositoryRoot 'Destiny2BlackBox.csproj'
$probeProject = Join-Path $PSScriptRoot 'RuntimeBoundaryProbe\RuntimeBoundaryProbe.csproj'
$targetFramework = 'net10.0-windows10.0.17763.0'
$applicationOutput = Join-Path $repositoryRoot "bin\Release\$targetFramework"
$probeOutput = Join-Path $PSScriptRoot "RuntimeBoundaryProbe\bin\Release\$targetFramework"
$applicationExecutable = Join-Path $applicationOutput 'PC Black Box.exe'
$applicationAssembly = Join-Path $applicationOutput 'PC Black Box.dll'
$probeAssembly = Join-Path $probeOutput 'PCBlackBox.RuntimeBoundaryProbe.dll'

function Invoke-DotNetBuild {
    param([Parameter(Mandatory)][string] $Project)

    & dotnet build $Project -c Release --no-incremental
    if ($LASTEXITCODE -ne 0)
    {
        throw "Release build failed."
    }
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

if (-not $NoBuild)
{
    Invoke-DotNetBuild -Project $applicationProject
    Invoke-DotNetBuild -Project $probeProject
}

foreach ($requiredPath in @($applicationExecutable, $applicationAssembly, $probeAssembly))
{
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf))
    {
        throw "A required local build output is missing."
    }
}

Add-NativeProbeType
$checks = 0
$start = [Diagnostics.ProcessStartInfo]::new('dotnet')
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.ArgumentList.Add($probeAssembly)
$start.ArgumentList.Add('--hold')
$start.ArgumentList.Add($applicationAssembly)
$target = [Diagnostics.Process]::Start($start)
try
{
    $ready = $target.StandardOutput.ReadLineAsync()
    if (-not $ready.Wait(10000) -or $ready.Result -ne 'BOUNDARY_PROBE_READY' -or $target.HasExited)
    {
        throw "The headless production-boundary probe did not become ready."
    }

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
}
finally
{
    if (-not $target.HasExited)
    {
        $target.Kill()
        [void]$target.WaitForExit(5000)
    }
    $target.Dispose()
}

$token = [Guid]::NewGuid().ToString('N')
$standardOutput = Join-Path ([IO.Path]::GetTempPath()) "PCBlackBox-$token.stdout.txt"
$standardError = Join-Path ([IO.Path]::GetTempPath()) "PCBlackBox-$token.stderr.txt"
$probe = $null
try
{
    $probeArguments = '"{0}" --network-transport "{1}"' -f $probeAssembly, $applicationAssembly
    $probe = Start-Process `
        -FilePath 'dotnet' `
        -ArgumentList $probeArguments `
        -RedirectStandardOutput $standardOutput `
        -RedirectStandardError $standardError `
        -WindowStyle Hidden `
        -Wait `
        -PassThru

    $probeError = if (Test-Path -LiteralPath $standardError)
    {
        Get-Content -Raw -LiteralPath $standardError
    }
    else
    {
        [String]::Empty
    }

    if ($probe.ExitCode -eq 0 -or $probe.ExitCode -eq 86)
    {
        throw "The managed network transport load was not terminated."
    }
    if (-not $probeError.Contains('PC Black Box blocked a network transport (System.Net.Sockets)', [StringComparison]::Ordinal))
    {
        throw "The probe failed without the expected network-guard evidence."
    }

    $checks++
    "NETWORK_GUARD assembly=System.Net.Sockets terminated=true exit=$($probe.ExitCode)"
}
finally
{
    if ($null -ne $probe)
    {
        $probe.Dispose()
    }
    foreach ($temporaryFile in @($standardOutput, $standardError))
    {
        if (Test-Path -LiteralPath $temporaryFile -PathType Leaf)
        {
            Remove-Item -LiteralPath $temporaryFile -Force
        }
    }
}

"PC_BLACK_BOX_RUNTIME_BOUNDARY_TEST passed=true checks=$checks"
