# From Zero to Bug Fix Hero
These steps assume you are an authorized contributor to this repository. If you are not already an authorized contributor, please fork the repo first and complete all steps off of your fork.

## Visual Studio
Install the latest version of Visual Studio with the minimum initial workloads:

  * Workloads
    * .NET desktop development
    * Desktop development with C++
  * Individual components
    * C++ x64/x86 Spectre-mitigated libs (Latest)

Additional setup guidance can be found in the [Contributing.md](https://github.com/microsoft/sarif-pattern-matcher/blob/main/CONTRIBUTING.md) documentation.

## Enlist in this Repo
1. From a developer cmd prompt execute the git clone operation:

    `git clone https://github.com/microsoft/sarif-pattern-matcher`

2. From the root folder of your new local copy, run BuildAndTest.exe. This will properly load all sub modules and double check all of your configurations/settings. Complete any recommended installs/upgrades (ie. install a newer sdk):

    `D:\repos\sarif-pattern-matcher> BuildAndTest.cmd`

    Note the folder where the sarif-pattern-matcher release can be found, you will need this later.

3. Create and checkout a new branch by executing the below from developer cmd prompt:

    `git checkout -b users/userName/example`

    Recommended branch naming guidelines: users/githubUserName/branchGoal.

4. Make sure that Sarif.PatternMatcher.Cli is set as the startup project (will appear bold in Visual Studio Solution Explorer menu).

## Debugging - Easy Mode
1. Identify an example of a secret to test for an established rule.
2. Locate the file corresponding to the rule in the `C:\<yourRepoDirectory>\sarif-pattern-matcher\Src\Plugins\Tests.Security\TestData\SecurePlaintextSecrets\Inputs\` folder.
3. Add your example to this folder.
4. Set a break point in the corresponding rule validator.
5. Debug the `SecurePlaintextSecrets_EndToEndFunctionalTests` to hit your breakpoint and continue as usual.

## Debugging - Expert Mode
1. Identify an example of a secret to test (ie. a false negative or false positive).
2. [Regex 101](https://regex101.com/) (recommended InPrivate browsing mode) can be used to validate the example matches a rule's regular expression (regex).
3. Create and save a text file somewhere easily accessible that contains just your example (ie. `D:\someDirectory\example.txt`). Using developer cmd prompt, navigate to the location of the sarif-pattern-matcher executable noted earlier. You will also need the location of the `SEC101.SecurePlaintextSecrets.json` file (`repoRootDirectory\Bld\bin\AnyCPU_Release\Security\netstandard2.1\SEC101.SecurePlaintextSecrets.json`). Note, this file will exist in multiple directories including the debug directory; this is an example that may be used.  Execute this command:

    `spam analyze D:\someDirectory\example.txt --search-definitions D:\sarif-pattern-matcher\Bld\bin\AnyCPU_Release\Security\netstandard2.1\SEC101.SecurePlaintextSecrets.json`
4. Set target to analyze:

    - From the Solution Explorer, right click on `Sarif.PatternMatcher.Cli`
    - Select `Properties` and then navigate to `Debug`
    - Visual Studio 2022: Click `Open debug launch profiles UI`

5. Set a break point in the rule to be investigated.

6. Begin debugging as usual.