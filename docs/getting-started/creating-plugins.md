# Creating plugins

## Basic structure

A plugin contains the following structure:

- A `txt` file (**optional**): it will contain all the regular expressions.
- A `json` file (**required**): it will contain all definitions.
- A `targets` file (**required**): it will move all the required files to the output folder.

### Text file

The `txt` file contains all the regular expressions that will help with your plugin.

### Json file

The `json` file contains the following structure:

```json
{
  "ValidatorsAssemblyName": "name-of-the-assembly.dll",
  "SharedStringsFileName": "txt-file-to-read.txt",
  "Definitions": [
    {
      "Name": "DoNotExposePlaintextSecrets",
      "Id": "SEC101",
      "Level": "Warning",
      "FileNameDenyRegex": "$BinaryFiles",
      "Description": "Some Description.",
      "Message": "Some message {secretKind}.",
      "MatchExpressions": [
        {
          "Id": "SEC101/001",
          "Name": "DoNotExposePlaintextSecrets/regex-rule",
          "ContentsRegex": "$SEC101/001.regex-rule",
          "MessageArguments": { "secretKind": "some message argument" }
        }
      ]
    }
  ]
}
```

#### Definition structure

The `Definition` property has the following structure:

```json
{
  "Id": "'Id' shall contain a stable identifier for the rule.",
  "Name": "'Name' may contain an identifier that is understandable to an end user.",
  "HelpUri": "'HelpUri' may contain the absolute URI of the primary documentation for the reporting item.",
  "Message": "'Message' may contain the default message that will be used.",
  "Kind": "The kind, or 'ResultKind' that is associated with this rule (e.g., 'Pass', 'Open', 'Informational', 'NotApplicable', ''Review' or 'Fail').",
  "Level": "The severity, or SARIF 'FailureLevel' that is associated with this rule (e.g., 'Error', Warning' or 'Note').",
  "Description": "'Description' of the rule.",
  "FileNameDenyRegex": "Any files whose names match the 'FileNameDenyRegex' pattern will be added to a deny list (i.e., they won't be scanned).",
  "FileNameAllowRegex": "Any files whose names match the 'FileNameAllowRegex' will be added to an allow list (i.e., they will be scanned).",
  "MatchExpressions": "List of 'MatchExpression' objects."
}
```

#### MatchExpression Structure

The `MatchExpression` property has the following structure:

```json
{
  "Id": "'Id' shall contain a stable identifier for the rule.",
  "Name": "'Name' may contain an identifier that is understandable to an end user.",
  "HelpUri": "'HelpUri' may contain the absolute URI of the primary documentation for the reporting item.",
  "Message": "'Message' may contain the default message that will be used.",
  "Kind": "The kind, or 'ResultKind' that is associated with this rule (e.g., 'Pass', 'Open', 'Informational', 'NotApplicable', ''Review' or 'Fail').",
  "Level": "The severity, or SARIF 'FailureLevel' that is associated with this rule (e.g., 'Error', Warning' or 'Note').",
  "Description": "'Description' of the rule.",
  "FileNameDenyRegex": "Any files whose names match the 'FileNameDenyRegex' pattern will be added to a deny list (i.e., they won't be scanned).",
  "FileNameAllowRegex": "Any files whose names match the 'FileNameAllowRegex' will be added to an allow list (i.e., they will be scanned).",
  "ContentsRegex": "Regular expression or pointer to a regular expression in the txt file.",
  "IntrafileRegexes": "List of regular expressions or pointers to regular expressions in the txt file.",
  "SingleLineRegexes": "List of regular expressions or pointers to regular expressions in the txt file."
}
```

##### Difference between ContentsRegex vs IntrafileRegexes vs SingleLineRegexes

- ContentsRegex: is a simple regular expression.
- IntrafileRegexes: for each regular expression in the list it will run the regular expression. With that, you can bring together two parts that are far from each other.
- SingleLineRegexes: is a single line regular expression order insensitive. Based on the match of the first item, it will look for all the other parts in any order.

#### Validator

Each `MatchExpression` can be mapped to a validator.
Each validator can implement the following methods:

```csharp
public static IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
{
}

public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                             ref string message,
                                             Dictionary<string, string> options,
                                             ref ResultLevelKind resultLevelKind)
{
}
```

You can extend `ValidatorBase` to use the helpers that we already have. If that is the case, you will need to implement:

```csharp
protected override IEnumerable<ValidationResult> IsValidStaticHelper(Dictionary<string, FlexMatch> groups)
{
  // TODO: add your static analysis implementation.
}

protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                        ref string message,
                                                        Dictionary<string, string> options,
                                                        ref ResultLevelKind resultLevelKind)
{
  // TODO: add your dynamic analysis implementation.
}
```

### Targets file

The `targets` file contains all the instructions to move files during installation of the package.

## Examples

For examples, check the public repository:

- [txt file](https://github.com/microsoft/sarif-pattern-matcher/blob/main/Src/Plugins/Security/Security.SharedStrings.txt)
- [json file](https://github.com/microsoft/sarif-pattern-matcher/blob/main/Src/Plugins/Security/SEC101.SecurePlaintextSecrets.json)
- [targets file](https://github.com/microsoft/sarif-pattern-matcher/blob/main/Src/Plugins/Security/build/Sarif.PatternMatcher.Security.targets)
