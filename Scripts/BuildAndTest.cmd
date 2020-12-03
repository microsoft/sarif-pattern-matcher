@ECHO OFF
SET ExitCode=-1

PUSHD "%~dp0"
IF NOT "%ERRORLEVEL%"=="0" (
  ECHO - Error. Couldn't find tools. Build stopping.
  GOTO :End
)

IF NOT EXIST "..\Src\RE2.Native\re2\re2" (
  ECHO - Retrieving RE2 submodule...
  git submodule init
  git submodule update
)

IF NOT EXIST "..\Src\Sarif-Sdk" (
  ECHO - Retrieving Sarif-Sdk submodule...
  git submodule init
  git submodule update
)

:: IF NOT EXIST "Spam\Searchers" (
::   ECHO Retrieving Searchers submodule...
::   git submodule init
::   git submodule update
:: )

IF EXIST "..\bld" (
  ECHO - Deleting old build...
  rd /s /q ..\bld
)

ECHO - Building RE2.Native.sln (MSBuild)...
MSBuild "..\Src\RE2.Native.sln" /p:Configuration=Release /p:Platform="Any CPU"

ECHO - Building Sarif.Sdk
..\Src\sarif-sdk\BuildAndTest.cmd -NoTest

ECHO - Building SarifPatternMatcher.sln (dotnet)...
dotnet build ..\Src\SarifPatternMatcher.sln -c Release -p:Deterministic=true
IF NOT "%ERRORLEVEL%"=="0" (
  ECHO - Error. Build failed. Build stopping.
  GOTO :End
)

ECHO.
ECHO - Packing SarifPatternMatcher.sln (dotnet)...
dotnet pack ..\Src\SarifPatternMatcher.sln -c Release --no-build
IF NOT "%ERRORLEVEL%"=="0" (
  ECHO - Error. Published failed. Build stopping.
  GOTO :End
)

ECHO.
ECHO - Running tests...
dotnet test ..\Src\SarifPatternMatcher.sln -c Release --no-build --collect:"XPlat Code Coverage"
IF NOT "%ERRORLEVEL%"=="0" (
  ECHO Error. Tests failed. Build stopping.
  GOTO :End
)

dotnet tool update --global dotnet-format --version 4.1.131201
dotnet-format --folder

set ExitCode=0
:End
POPD
EXIT /B %ExitCode%
