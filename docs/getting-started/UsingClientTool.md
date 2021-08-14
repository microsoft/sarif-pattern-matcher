# Using the client tool

## How to install

To start using the client tool, you will need:
1. Install [Sarif.PatternMatcher.Cli](https://www.nuget.org/packages/Sarif.PatternMatcher.Cli)
```bash
dotnet tool install --global Sarif.PatternMatcher.Cli --version x.y.z
```
2. Download [Sarif.PatternMatcher.Security](https://www.nuget.org/packages/Sarif.PatternMatcher.Security/)
```bash
nuget install Sarif.PatternMatcher.Security -Version x.y.z -OutputDirectory c:\folder-to-install-packages\
```

After completing the steps above, execute in the terminal (cmd/powershell):
```bash
> spam --help
Sarif Pattern Matcher Cli 1.4.0-alpha.198+840f9cbd87
c Microsoft Corporation. All rights reserved.

  analyze

  analyze-database

  validate

  help        Display more information on a specific command.

  version     Display version information.
```

For each verb, you can use `--help` to retrieve the arguments:
```bash
❯ spam analyze --help
```

Also, check in the `c:\folder-to-install-packages` if you can see the following structure:
```
c:\folder-to-install-packages
│───Sarif.PatternMatcher.Security.x.y.z
│   └───content
│       └───*.json
│       └───*.txt
│       └───*.dll
│   └───lib
│       └───*.dll
```

If you see that structure, copy the dll files from the `lib` folder to the `content` folder. With that, `*.json` and `*.dll` files should be in the same directory.

## How to execute the `analyze` command

The following command will analyze a folder using one json file, filtering some results and outputting to a file:

```bash
spam analyze c:\path-to-analyze\ --recurse --output c:\analysis.sarif --force --level "Error;Warning" --kind "Fail" --search-definitions PATH\SEC101.SecurePlaintextSecrets.json
```

- `analyze` the path `c:\path-to-analyze\` in recursive mode, which means that it will fetch all files and folders.
- `--output` the result of the analysis in the `c:"\analysis.sarif`.
- `--force` replace the file if exists.
- `--level` filter the results using `resultLevel` with `Error` or `Warning`.
- `--kind` filter the results using `resultKind` with `Fail`.
- `--search-definitions` will use the following rules to analyze.

The following command will analyze a folder using two json files, filtering some results, file size and path based on a regex. Also, it will execute the dynamic validation:

```bash
spam analyze c:\path-to-analyze\ --recurse --deny-regex "\\\.git\\\\" --output c:\temp\spam.sarif --force --level "Error;Note" --kind "Fail" --file-size 2048 --dynamic-validation --threads 8 --insert "RegionSnippets;ContextRegionSnippets" --search-definitions PATH\SEC101.SecurePlaintextSecrets.json;PATH\SEC101.SomeRule.json
```

- `analyze` the path `c:\path-to-analyze\` in recursive mode, which means that it will fetch all files and folders.
- `--deny-regex` filter out files that matches the regex.
- `--output` the result of the analysis in the `c:"\analysis.sarif`.
- `--force` replace the file if exists.
- `--level` filter the results using `resultLevel` with `Error` or `Note`.
- `--kind` filter the results using `resultKind` with `Fail`.
- `--file-size X` filters out files with size larger that X KB. The default value is 1024 KB.
- `--dynamic-validation` if a result is found, it will trigger a second step to validate dynamically the result (if the rule implements it).
- `--threads X` it will create X threads to parallelize the work. The default value is `Environment.ProcessorCount`.
- `--insert` if supplied, it will add more information to the output SARIF file.
- `--search-definitions` will use the following rules to analyze.

Obs.:
- `--level` can be `Error`, `Warning`, `Note`, or `None`. The full definition can be found in the [SARIF specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317648).
- `--kind` can be `None`, `NotApplicable`, `Pass`, `Fail`, `Review`, `Open`, or `Informational`. The full definition can be found in the [SARIF specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317647).

## How to execute the `analyze-database` command

The following command will analyze a database using one json file, filtering some results and outputting to a file:

```bash
spam analyze-database c:\temp\ --connection "Some connection string" --data-type SqlLite --target "SELECT * FROM some_database" --identity Id --output c:\analysis.sarif --force --level "Error;Warning" --kind "Fail" --search-definitions PATH\SEC101.SecurePlaintextSecrets.json
```

- `analyze-database` the database from the target.
- `--connection` the connection string to access the database.
- `--data-type` the type of the connection string.
- `--target` the query that will return rows to be analyze.
- `--identity` the identity column.
- `--output` the result of the analysis in the `c:"\analysis.sarif`.
- `--force` replace the file if exists.
- `--level` filter the results using `resultLevel` with `Error` or `Warning`.
- `--kind` filter the results using `resultKind` with `Fail`.
- `--search-definitions` will use the following rules to analyze.

Obs.: the first argument is a path that won't be used.

## How to view the results

Open the SARIF file using:
- [VSCode extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
- [VS extension](https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer)
- [Web viewer](https://microsoft.github.io/sarif-web-component/)

The viewer does not handle exceptions. With that, always take a look at `runs -> invocations -> toolExecutionNotifications` and check for the exceptions.
