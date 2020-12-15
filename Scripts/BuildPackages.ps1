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

dotnet pack "$RepoRoot\src\Plugins\BannedApi\BannedApi.csproj" --no-build --configuration $Configuration --force --include-symbols
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Pack of BannedApi failed."
}

dotnet pack "$RepoRoot\src\Plugins\PlaintextSecrets\PlaintextSecrets.csproj" --no-build --configuration $Configuration --force --include-symbols
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Pack of PlaintextSecrets failed."
}

dotnet pack "$RepoRoot\src\RE2.Managed\RE2.Managed.csproj" --no-build --configuration $Configuration --force --include-symbols
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Pack of RE2.Managed failed."
}

dotnet pack "$RepoRoot\src\String8\String8.csproj" --no-build --configuration $Configuration --force --include-symbols
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Pack of String8 failed."
}

dotnet pack "$RepoRoot\src\SarifPatternMatcher\SarifPatternMatcher.csproj" --no-build --configuration $Configuration --force --include-symbols
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Pack of SarifPatternMatcher failed."
}

dotnet pack "$RepoRoot\src\SarifPatternMatcher.Cli\SarifPatternMatcher.Cli.csproj" --no-build --configuration $Configuration --force --include-symbols
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Pack of SarifPatternMatcher.Cli failed."
}


Write-Information "$ScriptName SUCCEEDED."