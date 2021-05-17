nuget install Microsoft.CodeCoverage -version 16.8.3

$files = Get-ChildItem "bld\TestResults" -Filter "*.coverage" -Recurse

foreach ($file in $files)
{
    $command = 'microsoft.codecoverage.16.9.4\build\netstandard1.0\CodeCoverage\CodeCoverage.exe analyze /output:' + $file.DirectoryName + '\' + $file.Name + '.xml '+ $file.FullName
    Write-Host $command
    Invoke-Expression $command
}