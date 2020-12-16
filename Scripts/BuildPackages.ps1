<#
.SYNOPSIS
    Build packages from compiled dlls.
.PARAMETER Configuration
    The build configuration: Release or Debug. Default=Release
#>

[CmdletBinding()]
param(
    [string]
    [ValidateSet("Debug", "Release")]
    $Configuration="Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

$ScriptName = $([io.Path]::GetFileNameWithoutExtension($PSCommandPath))
$RepoRoot = $(Resolve-Path $PSScriptRoot\..).Path

function Exit-WithFailureMessage($scriptName, $message) {
    Write-Information "${scriptName}: $message"
    Write-Information "$scriptName FAILED."
    exit 1
}

dotnet pack "$RepoRoot\src\SarifPatternMatcher.sln"  --no-build --configuration $Configuration --force 
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Pack of SarifPatternMatcher.sln failed."
}

Write-Information "$ScriptName SUCCEEDED."