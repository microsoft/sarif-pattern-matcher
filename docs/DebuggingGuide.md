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

## Enlist and build in this repo
1. From a developer cmd prompt execute one of the the following commands, depending on whether you work from a forked enlistment or not:

    `git clone https://github.com/microsoft/sarif-pattern-matcher`
    `git clone https://github.com/YOURGITHUBACCOUNT/sarif-pattern-matcher`

2. Run BuildAndTest.exe from the root of the enlistment. This will properly load all submodules and validate some machine configuration/settings. Complete any recommended installs/upgrades (e.g., to install a newer sdk):

    `D:\src\sarif-pattern-matcher> BuildAndTest.cmd`

3. Create a branch:

    `git checkout -b informative-branch-name`

## Debugging
0. Install the [VS SARIF viewer](https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer).

1. Identify an example of a secret to test (ie. a false negative or false positive). If you need a testable pattern just to explore the code base you can use the following (which is not an actual credential):
~~~
<add key="GitHubPat" value="dead885a8624460a855540c6592698d2f1812843" />
~~~

2. Create and save a text file somewhere easily accessible that contains the test pattern (e.g., in a file named `d:\testFiles\repro.txt`).

3. Create a response file (e.g., in a file named `d:\testFiles\SpamArguments.rsp`) that contains the following analysis arguments (it is fine for a response file to break its arguments across multiple lines, just as they are here). Note that in this example `d:\src\sarif-pattern-matcher\` refers to the root of the `sarif-pattern-enlistment`. The output location referenced here directs SARIF log file output to a special directory that the VS SARIF viewer extension watches. VS will automatically load and display any SARIF results written to this special location (i.e., a directory named `\.sarif\` that exists alongside the current VS solution file).

~~~
    --search-definitions "..\..\Security\netstandard2.1\SEC101.SecurePlaintextSecrets.json" 
    --output d:\src\spam8\src\.sarif\out.sarif
    --force --pretty-print
    d:\testFiles\repro.txt 
    --level Error;Warning;Note
    --dynamic-validation
~~~

4. Open the SLN file at `.\src\SarifPatternMatcher.sln`.

5. Configure the client tool to invoke the response file you created:

    - From the Solution Explorer, right click on `Sarif.PatternMatcher.Cli`
    - Select `Properties` and then navigate to `Debug`
    - [in Visual Studio 2022 only] Click `Open debug launch profiles UI`
    - Enter the following into the command-line arguments field: `analyze d:\testFiles\SpamArguments.rsp`

6. Open the rule file associated with the pattern, e.g., the file associated with the test pattern at `.\src\Plugins\Security\SecurePlaintextSecretsValidators\SEC101_006.GitHubPatValidator.cs`. Set a breakpoint in the `IsValidStaticHelper` override to verify whether the pattern is detect for the first, strictly static detection phase.

7. Set a breakpoint in the `IsValidDynamicHelper` override. If the static analysis phase finds a valid secret candidate, this helper should be called next (if the `--dynamic-analysis` argument is present on the command-line) in order to detect whether the secret is 'live' (and therefore exploitable). 

8. Start debugging by hitting `F5` or choosing `Start Debugging` from the Visual Studio `Debug` menu.