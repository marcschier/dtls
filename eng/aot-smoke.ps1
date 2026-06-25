#!/usr/bin/env pwsh
# Copyright (c) marcschier. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
# Smoke test for the NativeAOT-published samples. Until the DTLS handshake engine is
# complete, this runs each sample's `--selftest` mode, which exercises the implemented
# transport layer end to end and exits 0 on success. It validates that the library and
# samples publish and run correctly as native AOT binaries on each platform.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Rid
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Get-PublishedExecutable([string]$sampleName)
{
    $publishDir = Join-Path $repoRoot `
        "samples/$sampleName/bin/Release/net10.0/$Rid/publish"
    $exe = Join-Path $publishDir $sampleName
    if ($IsWindows)
    {
        $exe += '.exe'
    }
    if (-not (Test-Path $exe))
    {
        throw "Published executable not found: $exe"
    }
    return $exe
}

function Invoke-SelfTest([string]$sampleName)
{
    $exe = Get-PublishedExecutable $sampleName
    Write-Host "Running $sampleName --selftest..."
    $process = Start-Process -FilePath $exe -ArgumentList @('--selftest') -PassThru -Wait
    if ($process.ExitCode -ne 0)
    {
        throw "$sampleName --selftest failed with exit code $($process.ExitCode)."
    }
}

Invoke-SelfTest 'Dtls.EchoServer'
Invoke-SelfTest 'Dtls.EchoClient'
Write-Host "AOT smoke test passed." -ForegroundColor Green
