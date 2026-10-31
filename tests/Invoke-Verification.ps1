#Requires -Version 7.0
[CmdletBinding()]
param([string] $DotNetPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $repositoryRoot 'Destiny2BlackBox.csproj'
$assembly = Join-Path $repositoryRoot 'bin\Release\net10.0-windows10.0.17763.0\PC Black Box.dll'
$boundaryScript = Join-Path $PSScriptRoot 'Test-RuntimeBoundaries.ps1'
$recordDirectory = Join-Path $repositoryRoot ('bin\validation\runs\' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N'))
$recordPath = Join-Path $recordDirectory 'summary.json'
$outputDirectories = @('bin', 'obj', 'tests\RuntimeBoundaryProbe\bin', 'tests\RuntimeBoundaryProbe\obj') |
    ForEach-Object { [IO.Path]::GetFullPath((Join-Path $repositoryRoot $_)) }

function Assert-SafeOutputPaths {
    # Check existing ancestors before creating the record, and inspect existing output trees before
    # a build can follow a junction or symlink. Concurrent replacement is outside this check's scope.
    foreach ($path in @($recordDirectory) + $outputDirectories)
    {
        $directory = [IO.DirectoryInfo]::new($path)
        while ($null -ne $directory)
        {
            if ([IO.File]::Exists($directory.FullName)) { throw 'output-path-not-directory' }
            if ([IO.Directory]::Exists($directory.FullName) -and
                (([IO.File]::GetAttributes($directory.FullName) -band [IO.FileAttributes]::ReparsePoint) -ne 0))
            {
                throw 'output-reparse-point'
            }
            $directory = $directory.Parent
        }
    }
    $pending = [Collections.Generic.Stack[string]]::new()
    foreach ($path in $outputDirectories) { if ([IO.Directory]::Exists($path)) { $pending.Push($path) } }
    while ($pending.Count -gt 0)
    {
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($pending.Pop()))
        {
            $attributes = [IO.File]::GetAttributes($entry)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'output-reparse-point' }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $pending.Push($entry) }
        }
    }
}

function Invoke-Child {
    param(
        [Parameter(Mandatory)][string] $Executable,
        [Parameter(Mandatory)][string[]] $Arguments,
        [Parameter(Mandatory)][int] $TimeoutMilliseconds
    )

    $start = [Diagnostics.ProcessStartInfo]::new($Executable)
    $start.WorkingDirectory = $repositoryRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $started = $false
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try
    {
        try { if (-not $process.Start()) { throw 'process-start-failed' } }
        catch { throw 'process-start-failed' }
        $started = $true
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds))
        {
            throw 'process-timeout'
        }
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000))
        {
            throw 'process-output-timeout'
        }
        $watch.Stop()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            DurationMs = $watch.ElapsedMilliseconds
            Stdout = $stdout.Result
            Stderr = $stderr.Result
        }
    }
    finally
    {
        try
        {
            if ($started -and -not $process.HasExited)
            {
                try { $process.Kill($true) }
                catch { if (-not $process.HasExited) { throw } }
                if (-not $process.WaitForExit(5000)) { throw 'process-cleanup-timeout' }
            }
        }
        finally { $process.Dispose() }
    }
}

function Get-SourceSnapshot {
    # Include ignored files as well: an ignored .cs or build configuration can still be compiled.
    # Only repository metadata and the two projects' generated output directories are excluded.
    $pending = [Collections.Generic.Stack[string]]::new()
    $files = [Collections.Generic.List[string]]::new()
    $excluded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in @('bin', 'obj', 'tests\RuntimeBoundaryProbe\bin', 'tests\RuntimeBoundaryProbe\obj'))
    {
        [void]$excluded.Add([IO.Path]::GetFullPath((Join-Path $repositoryRoot $path)))
    }
    $pending.Push($repositoryRoot)
    while ($pending.Count -gt 0)
    {
        $directory = $pending.Pop()
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($directory))
        {
            $name = [IO.Path]::GetFileName($entry)
            if ($name -ieq '.git') { continue }
            $attributes = [IO.File]::GetAttributes($entry)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'source-reparse-point' }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0 -and $excluded.Contains([IO.Path]::GetFullPath($entry))) { continue }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $pending.Push($entry) }
            else { $files.Add([IO.Path]::GetRelativePath($repositoryRoot, $entry)) }
        }
    }
    [string[]]$paths = $files.ToArray()
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $manifest = [Text.StringBuilder]::new()
    foreach ($path in $paths)
    {
        $fullPath = Join-Path $repositoryRoot $path
        $hash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash
        [void]$manifest.Append($path.Length).Append(':').Append($path).Append(':').Append($hash).Append([char]10)
    }
    # These inherited settings can affect both the root and nested projects.
    $parent = [IO.Directory]::GetParent($repositoryRoot)
    $level = 0
    while ($null -ne $parent)
    {
        foreach ($name in @('Directory.Build.props', 'Directory.Build.targets', 'Directory.Packages.props', 'global.json', 'NuGet.Config'))
        {
            $path = Join-Path $parent.FullName $name
            $hash = if ([IO.File]::Exists($path)) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } else { 'MISSING' }
            [void]$manifest.Append('parent:').Append($level).Append(':').Append($name).Append(':').Append($hash).Append([char]10)
        }
        $parent = $parent.Parent
        $level++
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($manifest.ToString())
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
}

function Get-RuntimeArtifactHashes {
    $directory = [IO.Path]::GetDirectoryName($assembly)
    $names = @([IO.Directory]::EnumerateFiles($directory, '*.dll') |
        ForEach-Object { [IO.Path]::GetFileName($_) }) + @('PC Black Box.deps.json', 'PC Black Box.runtimeconfig.json')
    $hashes = [ordered]@{}
    foreach ($name in ($names | Sort-Object))
    {
        $path = Join-Path $directory $name
        if (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'output-reparse-point' }
        $hashes[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    return $hashes
}

function Assert-Inputs {
    param([string] $SourceSha256, [string] $AssemblySha256, [Collections.IDictionary] $ArtifactHashes)

    if ((Get-SourceSnapshot) -cne $SourceSha256) { throw 'source-changed' }
    if ((Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash -cne $AssemblySha256) { throw 'assembly-changed' }
    $current = Get-RuntimeArtifactHashes
    if ($current.Count -ne $ArtifactHashes.Count) { throw 'runtime-artifacts-changed' }
    foreach ($name in $ArtifactHashes.Keys)
    {
        if (-not $current.Contains($name) -or $current[$name] -cne $ArtifactHashes[$name])
        {
            throw 'runtime-artifacts-changed'
        }
    }
}

function Assert-SecurityStatus {
    param([string] $Output)

    $summaryMatches = [regex]::Matches($Output, '(?m)^PC_BLACK_BOX_SECURITY profile=SECURITY-BASELINE-2 enforced=true controls=16/16(?: .*)?\r?$')
    if ($summaryMatches.Count -ne 1 -or $Output -match '(?m)^control=.*\bstate=not-enforced(?:\s|$)')
    {
        throw 'security-status-invalid'
    }
    $requiredNames = @(
        'regex-timeout', 'child-process-block', 'image-load-boundary', 'strict-handle-checks',
        'legacy-extension-points', 'non-system-fonts', 'dep', 'aslr', 'control-flow-guard', 'sehop',
        'dll-search-boundary', 'current-directory-dll-search', 'critical-error-mode',
        'heap-terminate-on-corruption', 'managed-network-transport-absent', 'process-object-lockdown'
    )
    $required = [regex]::Matches($Output, '(?m)^control=([a-z0-9-]+) tier=required state=enforced\r?$')
    if ($required.Count -ne $requiredNames.Count) { throw 'security-controls-invalid' }
    $observedNames = @($required | ForEach-Object { $_.Groups[1].Value })
    foreach ($name in $requiredNames)
    {
        if (@($observedNames | Where-Object { $_ -ceq $name }).Count -ne 1) { throw 'security-controls-invalid' }
    }
}

$stages = [ordered]@{
    build = [ordered]@{ status = 'not-run'; exitCode = $null; durationMs = $null; error = $null }
    security = [ordered]@{ status = 'not-run'; exitCode = $null; durationMs = $null; error = $null; required = $null; reinforcements = $null; shadowStack = $null }
    selfTest = [ordered]@{ status = 'not-run'; exitCode = $null; durationMs = $null; error = $null; checks = $null; failedCheck = $null; failedMethod = $null }
    boundary = [ordered]@{ status = 'not-run'; exitCode = $null; durationMs = $null; error = $null; checks = $null }
}
$summary = [ordered]@{
    schemaVersion = 1
    startedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    completedUtc = $null
    outcome = 'failed'
    error = $null
    baseCommit = $null
    workingTreeDirty = $null
    sourceSnapshotSha256 = $null
    sdkVersion = $null
    assemblySha256 = $null
    runtimeArtifactHashes = $null
    stages = $stages
}
$activeStage = 'preflight'
$reason = 'preflight-failed'
$savedPath = $env:PATH
$exitCode = 1

try
{
    Assert-SafeOutputPaths
    [void][IO.Directory]::CreateDirectory($recordDirectory)
    Assert-SafeOutputPaths
}
catch
{
    $recordError = if ($_.Exception.Message -cin @('output-reparse-point', 'output-path-not-directory')) { $_.Exception.Message } else { 'record-directory' }
    [Console]::Error.WriteLine("PC_BLACK_BOX_VERIFICATION failed reason=$recordError")
    exit 1
}

try
{
    if (-not $IsWindows) { throw 'windows-required' }
    $candidates = [Collections.Generic.List[string]]::new()
    if ($DotNetPath)
    {
        $candidates.Add([IO.Path]::GetFullPath($DotNetPath))
    }
    else
    {
        $dotnetCommand = Get-Command dotnet -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $dotnetCommand) { $candidates.Add([IO.Path]::GetFullPath($dotnetCommand.Source)) }
        $candidates.Add([IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.dotnet\dotnet.exe')))
    }
    $selectedDotNet = $null
    $foundExecutable = $false
    foreach ($candidate in $candidates)
    {
        if (-not [IO.File]::Exists($candidate) -or [IO.Path]::GetFileName($candidate) -ine 'dotnet.exe') { continue }
        $foundExecutable = $true
        try { $version = Invoke-Child $candidate @('--version') 30000 }
        catch { if ($_.Exception.Message -eq 'process-start-failed') { continue }; throw }
        $versionMatch = [regex]::Match($version.Stdout.Trim(), '^(?<major>\d+)\.\d+\.\d+([-.][A-Za-z0-9.-]+)?$')
        if ($version.ExitCode -eq 0 -and $versionMatch.Success -and [int]$versionMatch.Groups['major'].Value -ge 10)
        {
            $selectedDotNet = $candidate
            $summary.sdkVersion = $version.Stdout.Trim()
            break
        }
    }
    if ($null -eq $selectedDotNet)
    {
        $reason = if ($foundExecutable) { 'sdk-version-failed' } else { 'dotnet-not-found' }
        throw $reason
    }
    $DotNetPath = $selectedDotNet
    $git = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $shell = Join-Path $PSHOME 'pwsh.exe'
    if (-not [IO.File]::Exists($shell)) { throw 'powershell-not-found' }
    $env:PATH = [IO.Path]::GetDirectoryName($DotNetPath) + [IO.Path]::PathSeparator + $savedPath

    $commit = Invoke-Child $git.Source @('rev-parse', 'HEAD') 30000
    if ($commit.ExitCode -ne 0 -or $commit.Stdout.Trim() -notmatch '^[0-9a-f]{40,64}$') { throw 'commit-query-failed' }
    $summary.baseCommit = $commit.Stdout.Trim()
    $status = Invoke-Child $git.Source @('status', '--porcelain=v1', '-z', '--untracked-files=all') 30000
    if ($status.ExitCode -ne 0) { throw 'worktree-query-failed' }
    $summary.workingTreeDirty = $status.Stdout.Length -ne 0
    $summary.sourceSnapshotSha256 = Get-SourceSnapshot

    $activeStage = 'build'
    $stages.build.status = 'running'
    Assert-SafeOutputPaths
    $reason = 'build-failed'
    $build = Invoke-Child $DotNetPath @('build', $project, '-c', 'Release', '--no-incremental', '--disable-build-servers', '-warnaserror', '-p:UseSharedCompilation=false', '--verbosity', 'minimal') 240000
    $stages.build.exitCode = $build.ExitCode
    $stages.build.durationMs = $build.DurationMs
    if ($build.ExitCode -ne 0) { throw $reason }
    $summary.assemblySha256 = (Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash
    $summary.runtimeArtifactHashes = Get-RuntimeArtifactHashes
    $reason = 'build-inputs-changed'
    Assert-Inputs $summary.sourceSnapshotSha256 $summary.assemblySha256 $summary.runtimeArtifactHashes
    $stages.build.status = 'passed'

    $activeStage = 'security'
    $stages.security.status = 'running'
    $reason = 'security-process-failed'
    $security = Invoke-Child $DotNetPath @($assembly, '--security-status') 60000
    $stages.security.exitCode = $security.ExitCode
    $stages.security.durationMs = $security.DurationMs
    if ($security.ExitCode -ne 0 -or $security.Stderr.Length -ne 0) { throw $reason }
    $reason = 'security-result-invalid'
    Assert-SecurityStatus $security.Stdout
    $reinforcements = [regex]::Matches($security.Stdout, '(?m)^control=([a-z0-9-]+) tier=reinforcement state=(enforced|unavailable)(?: reason=([a-z-]+))?\r?$')
    $reinforcementSummary = [regex]::Matches($security.Stdout, '(?m)^PC_BLACK_BOX_SECURITY .* reinforcements=([0-4])/4\r?$')
    $reinforcementNames = @('redirection-trust', 'security-domain-isolation', 'speculative-store-bypass', 'user-shadow-stack')
    if ($reinforcements.Count -ne 4 -or $reinforcementSummary.Count -ne 1) { throw $reason }
    foreach ($name in $reinforcementNames)
    {
        if (@($reinforcements | Where-Object { $_.Groups[1].Value -ceq $name }).Count -ne 1) { throw $reason }
    }
    $enforcedCount = @($reinforcements | Where-Object { $_.Groups[2].Value -ceq 'enforced' }).Count
    if ($enforcedCount -ne [int]$reinforcementSummary[0].Groups[1].Value) { throw $reason }
    $shadow = @($reinforcements | Where-Object { $_.Groups[1].Value -ceq 'user-shadow-stack' })[0]
    if ($shadow.Groups[3].Success -and $shadow.Groups[3].Value -cnotin @('cpu-unsupported', 'query-failed', 'not-enabled')) { throw $reason }
    $stages.security.required = '16/16'
    $stages.security.reinforcements = "$enforcedCount/4"
    $stages.security.shadowStack = [ordered]@{ state = $shadow.Groups[2].Value; reason = if ($shadow.Groups[3].Success) { $shadow.Groups[3].Value } else { $null } }
    $reason = 'security-inputs-changed'
    Assert-Inputs $summary.sourceSnapshotSha256 $summary.assemblySha256 $summary.runtimeArtifactHashes
    $stages.security.status = 'passed'

    $activeStage = 'selfTest'
    $stages.selfTest.status = 'running'
    $reason = 'self-test-process-failed'
    $self = Invoke-Child $DotNetPath @($assembly, '--self-test') 180000
    $stages.selfTest.exitCode = $self.ExitCode
    $stages.selfTest.durationMs = $self.DurationMs
    $failure = [regex]::Match($self.Stderr, '(?m)^SELF_TEST_FAILED check=([0-9]{1,6}) expression=(Test[A-Za-z0-9_]{1,100})\(\)\r?$')
    if ($failure.Success)
    {
        $stages.selfTest.failedCheck = [int]$failure.Groups[1].Value
        $stages.selfTest.failedMethod = $failure.Groups[2].Value
    }
    if ($self.ExitCode -ne 0 -or $self.Stderr.Length -ne 0) { throw $reason }
    $reason = 'self-test-result-invalid'
    $selfMatches = [regex]::Matches($self.Stdout, '(?m)^PC_BLACK_BOX_SELF_TEST passed=true checks=([1-9][0-9]*)\r?$')
    if ($selfMatches.Count -ne 1) { throw $reason }
    $stages.selfTest.checks = [int]$selfMatches[0].Groups[1].Value
    $reason = 'self-test-inputs-changed'
    Assert-Inputs $summary.sourceSnapshotSha256 $summary.assemblySha256 $summary.runtimeArtifactHashes
    $stages.selfTest.status = 'passed'

    $activeStage = 'boundary'
    $stages.boundary.status = 'running'
    Assert-SafeOutputPaths
    $reason = 'boundary-process-failed'
    $boundary = Invoke-Child $shell @('-NoProfile', '-NonInteractive', '-File', $boundaryScript, '-ExpectedApplicationSha256', $summary.assemblySha256, '-DotNetPath', $DotNetPath) 300000
    $stages.boundary.exitCode = $boundary.ExitCode
    $stages.boundary.durationMs = $boundary.DurationMs
    if ($boundary.ExitCode -ne 0 -or $boundary.Stderr.Length -ne 0) { throw $reason }
    $reason = 'boundary-result-invalid'
    $artifactPattern = '(?m)^PC_BLACK_BOX_BOUNDARY_ARTIFACT sha256=' + $summary.assemblySha256 + '\r?$'
    $markers = [regex]::Matches($boundary.Stdout, '(?m)^PC_BLACK_BOX_RUNTIME_BOUNDARY_TEST passed=true checks=9\r?$')
    if ([regex]::Matches($boundary.Stdout, $artifactPattern).Count -ne 1 -or $markers.Count -ne 1) { throw $reason }
    $stages.boundary.checks = 9
    $reason = 'boundary-inputs-changed'
    Assert-Inputs $summary.sourceSnapshotSha256 $summary.assemblySha256 $summary.runtimeArtifactHashes
    $stages.boundary.status = 'passed'

    $summary.outcome = 'passed'
    $reason = $null
    $exitCode = 0
}
catch
{
    $knownReasons = @('process-start-failed', 'process-timeout', 'process-output-timeout', 'process-cleanup-timeout',
        'source-changed', 'assembly-changed', 'runtime-artifacts-changed', 'windows-required', 'powershell-not-found', 'sdk-version-failed',
        'commit-query-failed', 'worktree-query-failed', 'source-reparse-point', 'output-reparse-point', 'output-path-not-directory',
        'security-status-invalid', 'security-controls-invalid')
    if ($_.Exception.Message -cin $knownReasons) { $reason = $_.Exception.Message }
    if ($activeStage -ne 'preflight' -and $stages[$activeStage].status -eq 'running')
    {
        $stages[$activeStage].status = 'failed'
        $stages[$activeStage].error = $reason
    }
    $summary.error = $reason
}
finally
{
    $env:PATH = $savedPath
    $summary.completedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    try
    {
        Assert-SafeOutputPaths
        [IO.File]::WriteAllText($recordPath, ($summary | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    }
    catch
    {
        $exitCode = 1
        $reason = if ($_.Exception.Message -cin @('output-reparse-point', 'output-path-not-directory')) { $_.Exception.Message } else { 'record-write' }
        [Console]::Error.WriteLine("PC_BLACK_BOX_VERIFICATION failed reason=$reason")
    }
}

if ($exitCode -eq 0)
{
    "PC_BLACK_BOX_VERIFICATION passed=true record=$recordPath"
}
else
{
    [Console]::Error.WriteLine("PC_BLACK_BOX_VERIFICATION passed=false stage=$activeStage reason=$reason record=$recordPath")
}
exit $exitCode
