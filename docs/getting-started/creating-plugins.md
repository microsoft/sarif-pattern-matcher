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
public static string IsValidStatic(ref string matchedPattern,
                                   ref Dictionary<string, string> groups,
                                   ref string failureLevel,
                                   ref string fingerprint,
                                   ref string message)
{
}

public static string IsValidDynamic(ref string fingerprint, ref string message, ref Dictionary<string, string> options)
{
}
```

You can extend `ValidatorBase` to use the helpers that we already have. If that is the case, you will need to implement:
```csharp
protected override string IsValidStaticHelper(ref string matchedPattern,
                                              ref Dictionary<string, string> groups,
                                              ref string failureLevel,
                                              ref string fingerprintText,
                                              ref string message)
{
    return nameof(ValidationState.Unknown);
}

protected override string IsValidDynamicHelper(ref string fingerprintText,
                                               ref string message,
                                               ref Dictionary<string, string> options)
{
    return nameof(ValidationState.Unknown);
}
```

## Examples
For examples, check the public repository:
- [sarif-pattern-matcher repository](https://github.com/microsoft/sarif-pattern-matcher/tree/main/Src/Plugins/Security)
