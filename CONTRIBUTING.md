# Contributing to sarif-pattern-matcher

## Development Environment

You can contribute to this project from a Windows, macOS or Linux machine.

On all platforms, the minimum requirements are:

* Git client and command line tools.
* .NET Core 3.1+ and .NET 6.0

### Windows

* Visual Studio 2019 or 2022(recommended), any edition
* In the Visual Studio Installer, install the following:
  * Workloads
    * .NET desktop development
    * Desktop development with C++
  * Individual components
    * C++ x64/x86 Spectre-mitigated libs (Latest)

## Style Guide

This project includes a
[`.editorconfig`](https://github.com/microsoft/sarif-pattern-matcher/blob/main/src/.editorconfig)
file which is supported by all the IDEs/editor mentioned above. It works with
the IDE/editor only and does not affect the actual build of the project.

## How to start

Clone the repository with the command:

```bat
git clone https://github.com/microsoft/sarif-pattern-matcher.git
```

Then, update the submodules:

```bat
git submodule update --init --recursive
```

To build the solution you can:

* Open `Developer Command Prompt for VS 2019` and run the following:

```bat
.\BuildAndTest.cmd
```

* Use Visual Studio:

1. Open the solution `Src\RE2.Native.sln` and build.
2. Open the solution `Src\SarifPatternMatcher.sln` and build.

## Troubleshooting First Commit
If you are having trouble with your first commit or push to the GitHub, first please confirm with your repository admin to ensure you have write permissions. 
Then remove and re-add all accounts in Visual Studio Account Settings Menu.