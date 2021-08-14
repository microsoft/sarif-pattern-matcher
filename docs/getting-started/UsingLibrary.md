# Using the library

## How to install
To start using the client tool, you will need:
1. Install [Sarif.PatternMatcher](https://www.nuget.org/packages/Sarif.PatternMatcher)
```xml
<PackageReference Include="Sarif.PatternMatcher" Version="x.y.z" />
```
2. Install [Sarif.PatternMatcher.Security](https://www.nuget.org/packages/Sarif.PatternMatcher.Security/)
```xml
<PackageReference Include="Sarif.PatternMatcher.Security" Version="x.y.z" />
```

## How to execute
First, you will need to load the rules:
```csharp
string rulePath = "PATH where you can see .dll and .json";
var FileSystem = Sarif.FileSystem.Instance;
IEnumerable<string> regexDefinitions = FileSystem.DirectoryGetFiles(rulePath, "*.json");

// Load all rules from JSON. This also automatically loads any validations file that
// lives alongside the JSON. For a JSON file named PlaintextSecrets.json, the
// corresponding validations assembly is named PlaintextSecrets.dll (i.e., only the
// extension name changes from .json to .dll).
var skimmers = AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(FileSystem, regexDefinitions);
```

With the `skimmers`, we can prepare to call the analyzer:
```csharp
var sb = new StringBuilder();

using (var outputTextWriter = new StringWriter(sb))
using (var logger = new SarifLogger(
    outputTextWriter,
    LogFilePersistenceOptions.PrettyPrint,
    dataToInsert: OptionallyEmittedData.Hashes | OptionallyEmittedData.RegionSnippets | OptionallyEmittedData.ContextRegionSnippets | OptionallyEmittedData.ComprehensiveRegionProperties,
    levels: new List<FailureLevel> { FailureLevel.Error, FailureLevel.Warning, FailureLevel.Note, FailureLevel.None },
    kinds: new List<ResultKind> { ResultKind.Fail }))
{
    // Check next step.
}

SarifLog sarifLog = JsonConvert.DeserializeObject<SarifLog>(sb.ToString());
```

With the preparation, we can use this:
```csharp
// The analysis will disable skimmers that raise an exception. This
// hash set stores the disabled skimmers. When a skimmer is disabled,
// that catastrophic event is logged as a SARIF notification.
var disabledSkimmers = new HashSet<string>();

var context = new AnalyzeContext
{
    TargetUri = new Uri(filePath, UriKind.RelativeOrAbsolute),
    FileContents = text,
    Logger = logger,
    DynamicValidation = true,
};

using (context)
{
    IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, Skimmers, disabledSkimmers);
    AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers);
}
```

Below, a brief explanation of the `SarifLogger` properties used:
- `LogFilePersistenceOptions.PrettyPrint`: Indent persisted JSON for easy file viewing.
- `dataToInsert: `: it will add more information to the output SARIF file.
- `levels: `: it will filter the results using the `level` property from the result.
- `kinds: `: it will filter the results using the `resultKind` property from the result.

Below, a brief explanation of the `AnalyzeContext` properties used:
- `TargetUri`: file path that will be used to analyze.
- `FileContents`: file content of the `TargetUri`.
- `Logger`: use `SarifLogger` instance.
- `DynamicValidation`: if a result is found, it will trigger a second step to validate dynamically the result (if the rule implements it). The default value is `false`.

## How to view the results
Open the SARIF file using:
- [VSCode extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
- [VS extension](https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer)
