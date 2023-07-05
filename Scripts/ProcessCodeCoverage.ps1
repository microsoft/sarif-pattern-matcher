nuget install Microsoft.CodeCoverage -version 16.10.0

$files = Get-ChildItem "Bld\TestResults" -Filter "*.coverage" -Recurse

foreach ($file in $files)
{
    $command = 'microsoft.codecoverage.16.10.0\build\netstandard1.0\CodeCoverage\CodeCoverage.exe analyze /output:' + $file.DirectoryName + '\' + $file.Name + '.xml '+ $file.FullName
    Write-Host $command
    Invoke-Expression $command
}