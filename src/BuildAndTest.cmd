@echo off

dotnet restore

dotnet build --no-restore --configuration Release

dotnet test --no-build --configuration Release
