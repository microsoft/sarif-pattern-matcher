To get RE2 building in Windows, you use CMake to generate vcxproj files from the 'CMakeLists.txt' file in the RE2 repo.

https://dfs-minded.com/build-integrate-re2-c-project-windows/ has the original instructions.

To Build on Windows:
-  Install CMAKE - https://cmake.org/download/
  - Run CMake GUI
    - 'Source Code': C:\Code\re2 (folder with CMakeLists.txt)
    - 'Build': C:\Code\re2\vs
    - Click 'Configure'. Pick Visual Studio 15 2017 x64.
    - Click 'Generate'
  - In Visual Studio, open and build 'C:\Code\re2\vs\RE2.sln'

To reference:
  - Copy and Edit re2.vcxproj.
    - Remove <ItemGroup> with <CustomBuild> section.
    - Remove <ItemGroup> with <ProjectReference> to ZERO_CHECK.vcxproj.
    - Find and Replace absolute paths with relative ones
  - Copy and edit re2.vcxproj.filters; find and replace absolute paths with relative ones
  - Add a new C++ console app.
    - Add re2.vcxproj as an Existing Project to the solution.
    - In your project, open project properties
      - References -> Add Reference to RE2.
      - C++ -> General -> 'Additional Include Directories'l add RE2 folder (with RE2.h)
    - Fix sources which include 're2/stringpiece.h' to no relative path ('stringpiece.h')

NOTE: Our RE2.vcxproj has other changes to de-duplicate settings and use more consistent output folders.