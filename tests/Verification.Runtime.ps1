# Shared output contract for the product's headless verification modes. No process is launched here.
function ConvertFrom-RuntimeStatus {
    param([AllowEmptyString()][string] $Output)

    $lines = @($Output -split '\r?\n' | Where-Object {
        $_.TrimStart() -cmatch '\APC_BLACK_BOX_RUNTIME(?:\s|\z)'
    })
    if ($lines.Count -ne 1) { throw 'runtime-metadata-invalid' }

    # Environment.Version is numeric; no SDK labels, framework paths, or arbitrary text is accepted.
    $number = '(?:0|[1-9][0-9]{0,8})'
    $pattern = '\APC_BLACK_BOX_RUNTIME version=(?<version>' + $number + '\.' + $number + '\.' + $number +
        '(?:\.' + $number + ')?) processArchitecture=(?<architecture>x86|x64|arm|arm64)\z'
    $match = [regex]::Match($lines[0], $pattern)
    if (-not $match.Success) { throw 'runtime-metadata-invalid' }

    return [ordered]@{
        version = $match.Groups['version'].Value
        processArchitecture = $match.Groups['architecture'].Value
    }
}

function Assert-SameRuntime {
    param(
        [Parameter(Mandatory)][Collections.IDictionary] $Actual,
        [Parameter(Mandatory)][Collections.IDictionary] $Expected
    )

    if ($Actual.version -cne $Expected.version -or $Actual.processArchitecture -cne $Expected.processArchitecture)
    {
        throw 'runtime-metadata-mismatch'
    }
}
