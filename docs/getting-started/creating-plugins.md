# Creating plugins

## Basic structure

A plugin contains the following structure:

- A `txt` file (**optional**): it will contain all the regular expressions.
- A `json` file (**required**): it will contain all definitions.
- A `targets` file (**required**): it will move all the required files to the output folder.

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

## Examples

For examples, check the public repository:

- [sarif-pattern-matcher repository](https://github.com/microsoft/sarif-pattern-matcher/tree/main/Src/Plugins/Security)
