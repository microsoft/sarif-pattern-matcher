
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

Write-Information "Building RE2.Native.sln (MSBuild)..."
MSBuild "$RepoRoot\Src\RE2.Native.sln" /p:Configuration=Release /p:Platform="Any CPU"

Write-Information "Building Sarif.Sdk"
& $RepoRoot\Src\sarif-sdk\BuildAndTest.cmd -NoTest -NoPublish
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Build of sarif.sdk failed."
}

Write-Information "Building SarifPatternMatcher.sln (dotnet)..."
dotnet build $RepoRoot\Src\SarifPatternMatcher.sln -c Release -p:Deterministic=true
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Build of SarifPatternMatcher failed."
}

Write-Information "Packing SarifPatternMatcher.sln (dotnet)..."
dotnet pack $RepoRoot\Src\SarifPatternMatcher.sln -c Release --no-build
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Pack of SarifPatternMatcher failed."
}

Write-Information "Running tests..."
dotnet test $RepoRoot\Src\SarifPatternMatcher.sln -c Release --no-build --collect:"XPlat Code Coverage"
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Test of SarifPatternMatcher failed."
}

dotnet tool update --global dotnet-format --version 4.1.131201
dotnet-format --folder

Write-Information "$ScriptName SUCCEEDED."