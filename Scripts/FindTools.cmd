@ECHO OFF

IF NOT "%MSBuildPath%"=="" GOTO :FoundMSBuild
  SET MSBuildPath="%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe"
  IF EXIST "%MSBuildPath%" GOTO :FoundMSBuild

  PUSHD "%ProgramFiles(x86)%\Microsoft Visual Studio"
  FOR /F "delims=" %%D IN ('DIR /S /B MSBuild.exe') DO (
     SET MSBuildPath=%%D
  )
  POPD

  IF NOT EXIST "%MSBuildPath%" (
    ECHO Error: MSBuild.exe not found at "%MSBuildPath%".
    EXIT /B -1
  )
:FoundMSBuild

ECHO MSBuild: %MSBuildPath%
EXIT /B 0