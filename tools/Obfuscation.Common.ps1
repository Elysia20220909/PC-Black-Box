#requires -Version 7.0
Set-StrictMode -Version Latest

function Assert-FixedLocalDrive {
    param([IO.DriveType] $DriveType)
    if ($DriveType -ne [IO.DriveType]::Fixed) {
        throw 'A fixed local drive is required; mapped network drives are not supported.'
    }
}

function Assert-LocalPlainPath {
    param([Parameter(Mandatory)][string] $Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith('\\', [StringComparison]::Ordinal)) {
        throw 'Network paths are not supported.'
    }
    # Check the drive before inspecting files: a mapped drive can hide a network share.
    Assert-FixedLocalDrive ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($fullPath)).DriveType)
    $cursor = $fullPath
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Reparse points are not supported.'
            }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    return $fullPath
}

function Get-ContainedPath {
    param([string] $Root, [string] $RelativePath)

    if ([IO.Path]::IsPathRooted($RelativePath) -or $RelativePath.Contains(':')) {
        throw 'A relative path without an alternate data stream is required.'
    }
    $rootPath = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Root))
    $path = [IO.Path]::GetFullPath([IO.Path]::Combine($rootPath, $RelativePath))
    if (!$path.StartsWith($rootPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The path escapes its allowed directory.'
    }
    return Assert-LocalPlainPath $path
}

function New-ObfuscationRun {
    param([string] $SourceRoot, [string] $RunId)

    $project = Get-ContainedPath $SourceRoot 'Destiny2BlackBox.csproj'
    if (!(Test-Path -LiteralPath $project -PathType Leaf)) {
        throw 'SourceRoot must contain the maintained application project.'
    }
    if ($RunId -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$') {
        throw 'RunId must contain only letters, digits, underscores, or hyphens (1-64 characters).'
    }
    $runRoot = Get-ContainedPath $SourceRoot "obj/structure-obfuscation/$RunId"
    if (Test-Path -LiteralPath $runRoot) { throw 'RunId already exists; no files were overwritten.' }
    $parent = [IO.Path]::GetDirectoryName($runRoot)
    $null = New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop
    $null = New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop
    return $runRoot
}

function Write-NewUtf8File {
    param([string] $Path, [string] $Content)

    $null = Assert-LocalPlainPath $Path
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally { $stream.Dispose() }
}
