#!/usr/bin/env pwsh
# Fails the build if any C# source line exceeds the configured column limit.
# Runs on all platforms via `pwsh`. Tabs are expanded to 4 columns for measurement.

[CmdletBinding()]
param(
    [int]$MaxLength = 100,
    [string[]]$Roots = @('src', 'tests', 'samples')
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$violations = New-Object System.Collections.Generic.List[string]

foreach ($root in $Roots)
{
    $rootPath = Join-Path $repoRoot $root
    if (-not (Test-Path $rootPath))
    {
        continue
    }

    $files = Get-ChildItem -Path $rootPath -Recurse -Filter *.cs |
        Where-Object { $_.FullName -notmatch '[\\/](obj|bin)[\\/]' }

    foreach ($file in $files)
    {
        $lineNo = 0
        foreach ($line in [System.IO.File]::ReadAllLines($file.FullName))
        {
            $lineNo++
            $expanded = $line -replace "`t", '    '
            if ($expanded.Length -gt $MaxLength)
            {
                $rel = $file.FullName.Substring($repoRoot.Length).TrimStart('\', '/')
                $violations.Add(("{0}:{1}: {2} columns" -f $rel, $lineNo, $expanded.Length))
            }
        }
    }
}

if ($violations.Count -gt 0)
{
    Write-Host "Line-length violations (> $MaxLength columns):" -ForegroundColor Red
    foreach ($v in $violations)
    {
        Write-Host "  $v"
    }
    exit 1
}

Write-Host "Line-length check passed (max $MaxLength columns)." -ForegroundColor Green
