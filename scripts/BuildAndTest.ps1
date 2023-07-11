<#
.SYNOPSIS
    Build, test, and package the sarif-pattern-matcher.
.DESCRIPTION
    Builds the sarif-pattern-matcher for multiple target frameworks, runs the tests, and creates
    NuGet packages.
.PARAMETER Configuration
    The build configuration: Release or Debug. Default=Release
.PARAMETER NoBuild
    Do not build.
.PARAMETER NoTest
    Do not run tests.
.PARAMETER NoFormat
    Do not format files based on dotnet-format tool.
.PARAMETER EnableCoverage
    Enable CodeCoverage.
#>

[CmdletBinding()]
param(
    [string]
    [ValidateSet("Debug", "Release")]
    $Configuration="Release",

    [switch]
    $NoBuild,

    [switch]
    $NoTest,
    
    [switch]
    $NoFormat,

    [switch]
    $EnableCoverage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
$NonWindowsOptions = @{}

$ScriptName = $([io.Path]::GetFileNameWithoutExtension($PSCommandPath))
$RepoRoot = $(Resolve-Path $PSScriptRoot\..).Path

function Exit-WithFailureMessage($scriptName, $message) {
    Write-Information "${scriptName}: $message"
    Write-Information "$scriptName FAILED."
    exit 1
}

Write-Information "Retrieving submodules..."
git submodule update --init --recursive

If (Test-Path "..\bld") {
    Write-Information "Deleting old build..."
    Remove-Item -Path ..\bld -Recurse -Force -Confirm:$false
}

if (-not $NoBuild) {    
    Write-Information "Building Sarif.Sdk"	
    & $RepoRoot\src\sarif-sdk\scripts\BuildAndTest.ps1 -NoBuild -NoTest -NoPublish -NoSigningDirectory -NoPackage -NoFormat
    if ($LASTEXITCODE -ne 0) {	
        Exit-WithFailureMessage $ScriptName "Build of sarif.sdk failed."	
    }    

    Write-Information $RepoRoot
    ls
    $RepoRoot = $(Resolve-Path $PSScriptRoot\..).Path
    Write-Information $RepoRoot
    ls
    
    Write-Information "Building SarifPatternMatcher.sln (dotnet)..."
    dotnet build $RepoRoot\src\SarifPatternMatcher.sln -c $Configuration -p:Deterministic=true
    if ($LASTEXITCODE -ne 0) {
        Exit-WithFailureMessage $ScriptName "Build of SarifPatternMatcher failed."
    }
}

if (-not $NoTest) {
    Write-Information "Running tests..."

    $CodeCoverageCommand = '--collect:"Code Coverage"'
    if (-not $EnableCoverage) {
        $CodeCoverageCommand = ""
    }
    if (-not $ENV:OS) {
        $NonWindowsOptions = @{ "-filter" = "WindowsOnly!=true" }
    }
    dotnet test $RepoRoot\src\SarifPatternMatcher.sln -c $Configuration --logger trx --no-build $CodeCoverageCommand --settings $RepoRoot\src\SarifPatternMatcher.runsettings /p:IncludeTestAssembly=false @NonWindowsOptions

    if ($LASTEXITCODE -ne 0) {
        Exit-WithFailureMessage $ScriptName "Test of SarifPatternMatcher failed."
    }
}

if (-not $NoFormat) {
    dotnet tool update --global dotnet-format --version 4.1.131201
    dotnet-format --folder --exclude .\src\sarif-sdk\
}

Write-Information "$ScriptName SUCCEEDED."