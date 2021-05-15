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

$ScriptName = $([io.Path]::GetFileNameWithoutExtension($PSCommandPath))
$RepoRoot = $(Resolve-Path $PSScriptRoot\..).Path

function Exit-WithFailureMessage($scriptName, $message) {
    Write-Information "${scriptName}: $message"
    Write-Information "$scriptName FAILED."
    exit 1
}

if (-not (Test-Path "$RepoRoot\Src\RE2.Native\re2\re2")) {
    Write-Information "Retrieving RE2 submodule..."
    git submodule init
    git submodule update
}

if (-not (Test-Path "$RepoRoot\Src\Sarif-Sdk")) {
    Write-Information "Retrieving Sarif-Sdk submodule..."
    git submodule init
    git submodule update
}

If (Test-Path "..\bld") {
    Write-Information "Deleting old build..."
    rd /s /q ..\bld
}

if (-not $NoBuild) {
    Write-Information "Building RE2.Native.sln (MSBuild)..."
    MSBuild "$RepoRoot\Src\RE2.Native.sln" /p:Configuration=$Configuration /p:Platform="Any CPU"
    
    Write-Information "Building Sarif.Sdk"	
    & $RepoRoot\Src\sarif-sdk\BuildAndTest.cmd -NoBuild -NoTest -NoPublish -NoSigningDirectory -NoPackage -NoFormat
    if ($LASTEXITCODE -ne 0) {	
        Exit-WithFailureMessage $ScriptName "Build of sarif.sdk failed."	
    }

    Write-Information "Building SarifPatternMatcher.sln (dotnet)..."
    dotnet build $RepoRoot\Src\SarifPatternMatcher.sln -c $Configuration -p:Deterministic=true
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

    dotnet test $RepoRoot\Src\SarifPatternMatcher.sln -c $Configuration --no-build $CodeCoverageCommand --settings $RepoRoot\Src\SarifPatternMatcher.runsettings /p:IncludeTestAssembly=false

    if ($LASTEXITCODE -ne 0) {
        Exit-WithFailureMessage $ScriptName "Test of SarifPatternMatcher failed."
    }
}

if (-not $NoFormat) {
    dotnet tool update --global dotnet-format --version 4.1.131201
    dotnet-format --folder --exclude .\src\sarif-sdk\
}

Write-Information "$ScriptName SUCCEEDED."