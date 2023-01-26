// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Newtonsoft.Json;

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SecurePlaintextSecretsTests : EndToEndTests
    {
        public SecurePlaintextSecretsTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string RuleId => "SEC101";

        protected override string Framework => "netstandard2.1";

        protected override string TypeUnderTest => "SecurePlaintextSecrets";

        [Fact]
        public void SecurePlaintextSecrets_EndToEndFunctionalTests()
            => RunAllTests();

        [Fact]
        public void SecurePlaintextSecrets_VerifyAllValidatorsExist()
        {
            PatternInvariantTests.VerifyAllValidatorsExist(DefinitionsPath);
        }

        [Fact]
        public void VerifySkimmersdisabled()
        {
            // Testing the RuleStateEnabled = "Disabled" stub with PushInheritedData function by simulating a definitions.json file with associated sharedStrings.txt.
            // When a rule is enabled, its name starts with "Enabled"
            // When a rule is disabled, its name starts with "Disabled"

            var sharedStrings = new Dictionary<string, string>
            {
                { "$BinaryFiles", "(?i)\\.(?:bmp|dll|exe|gif|jpe?g|lock|pack|png|psd|tar\\.gz|tiff?|ttf|wmf|xcf|zip)$"},
                { "$SEC101/XX1.ExampleRule1", "EXAMPLERULE1REGEX" },
                { "$SEC101/XX2.ExampleRule2", "EXAMPLERULE2REGEX" },
                { "$SEC101/XX3.ExampleRule3", "EXAMPLERULE3REGEX" }
            };

            // generator to create this json output?!
            // could output json if test fails.

            string allEnabled = "{\r\n  \"ValidatorsAssemblyName\": \"Security.dll\",\r\n  \"SharedStringsFileName\": \"Security.SharedStrings.txt\",\r\n  \"Definitions\": [\r\n    {\r\n      \"Id\": \"SEC101\",\r\n      \"Name\": \"DoNotExposePlaintextSecrets\",\r\n      \"Level\": \"Warning\",\r\n      \"FileNameDenyRegex\": \"$BinaryFiles\",\r\n      \"Description\": \"Do not expose plaintext (or base64-encoded plaintext) secrets in versioned engineering content.\",\r\n      \"Message\": \"'{0:truncatedSecret}' is {1:validationPrefix}{2:encoding}{3:secretKind}{4:validationSuffix}{5:validatorMessage}.\",\r\n      \"MatchExpressions\": [\r\n        {\r\n          \"Id\": \"SEC101/XX1\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Enabled1\",\r\n          \"ContentsRegex\": \"$SEC101/XX1.ExampleRule1\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 1\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX2\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Enabled2\",\r\n          \"ContentsRegex\": \"$SEC101/XX2.ExampleRule2\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 2\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX3\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Enabled3\",\r\n          \"ContentsRegex\": \"$SEC101/XX3.ExampleRule3\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 3\" },\r\n        }\r\n      ]\r\n    }\r\n  ]\r\n}";
            string allDisabled = "{\r\n  \"ValidatorsAssemblyName\": \"Security.dll\",\r\n  \"SharedStringsFileName\": \"Security.SharedStrings.txt\",\r\n  \"Definitions\": [\r\n    {\r\n      \"Id\": \"SEC101\",\r\n      \"Name\": \"DoNotExposePlaintextSecrets\",\r\n      \"Level\": \"Warning\",\r\n      \"FileNameDenyRegex\": \"$BinaryFiles\",\r\n      \"Description\": \"Do not expose plaintext (or base64-encoded plaintext) secrets in versioned engineering content.\",\r\n      \"Message\": \"'{0:truncatedSecret}' is {1:validationPrefix}{2:encoding}{3:secretKind}{4:validationSuffix}{5:validatorMessage}.\",\r\n      \"MatchExpressions\": [\r\n        {\r\n          \"Id\": \"SEC101/XX1\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Disabled1\",\r\n          \"RuleEnabledState\": \"Disabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX1.ExampleRule1\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 1\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX2\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Disabled2\",\r\n          \"RuleEnabledState\": \"Disabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX2.ExampleRule2\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 2\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX3\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Disabled3\",\r\n          \"RuleEnabledState\": \"Disabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX3.ExampleRule3\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 3\" },\r\n        }\r\n      ]\r\n    }\r\n  ]\r\n}";

            // One rule has two match expressions, both of which are enabled. 3rd rule is disabled.
            string specialCase1 = "{\r\n  \"ValidatorsAssemblyName\": \"Security.dll\",\r\n  \"SharedStringsFileName\": \"Security.SharedStrings.txt\",\r\n  \"Definitions\": [\r\n    {\r\n      \"Id\": \"SEC101\",\r\n      \"Name\": \"DoNotExposePlaintextSecrets\",\r\n      \"Level\": \"Warning\",\r\n      \"FileNameDenyRegex\": \"$BinaryFiles\",\r\n      \"Description\": \"Do not expose plaintext (or base64-encoded plaintext) secrets in versioned engineering content.\",\r\n      \"Message\": \"'{0:truncatedSecret}' is {1:validationPrefix}{2:encoding}{3:secretKind}{4:validationSuffix}{5:validatorMessage}.\",\r\n      \"MatchExpressions\": [\r\n        {\r\n          \"Id\": \"SEC101/XX1\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Enabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX1.ExampleRule1\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 1\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX1\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Enabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX2.ExampleRule2\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 2\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX2\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Disabled3\",\r\n          \"RuleEnabledState\": \"Disabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX3.ExampleRule3\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 3\" },\r\n        }\r\n      ]\r\n    }\r\n  ]\r\n}";

            // One rule has two match expressions, one of which is disabled. 3rd rule is disabled.
            string specialCase2 = "{\r\n  \"ValidatorsAssemblyName\": \"Security.dll\",\r\n  \"SharedStringsFileName\": \"Security.SharedStrings.txt\",\r\n  \"Definitions\": [\r\n    {\r\n      \"Id\": \"SEC101\",\r\n      \"Name\": \"DoNotExposePlaintextSecrets\",\r\n      \"Level\": \"Warning\",\r\n      \"FileNameDenyRegex\": \"$BinaryFiles\",\r\n      \"Description\": \"Do not expose plaintext (or base64-encoded plaintext) secrets in versioned engineering content.\",\r\n      \"Message\": \"'{0:truncatedSecret}' is {1:validationPrefix}{2:encoding}{3:secretKind}{4:validationSuffix}{5:validatorMessage}.\",\r\n      \"MatchExpressions\": [\r\n        {\r\n          \"Id\": \"SEC101/XX1\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Enabled\",\r\n          \"RuleEnabledState\": \"Disabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX1.ExampleRule1\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 1\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX1\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Enabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX2.ExampleRule2\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 2\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX2\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Disabled3\",\r\n          \"RuleEnabledState\": \"Disabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX3.ExampleRule3\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 3\" },\r\n        }\r\n      ]\r\n    }\r\n  ]\r\n}";

            string oneDisabled = "{\r\n  \"ValidatorsAssemblyName\": \"Security.dll\",\r\n  \"SharedStringsFileName\": \"Security.SharedStrings.txt\",\r\n  \"Definitions\": [\r\n    {\r\n      \"Id\": \"SEC101\",\r\n      \"Name\": \"DoNotExposePlaintextSecrets\",\r\n      \"Level\": \"Warning\",\r\n      \"FileNameDenyRegex\": \"$BinaryFiles\",\r\n      \"Description\": \"Do not expose plaintext (or base64-encoded plaintext) secrets in versioned engineering content.\",\r\n      \"Message\": \"'{0:truncatedSecret}' is {1:validationPrefix}{2:encoding}{3:secretKind}{4:validationSuffix}{5:validatorMessage}.\",\r\n      \"MatchExpressions\": [\r\n        {\r\n          \"Id\": \"SEC101/XX1\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Enabled1\",\r\n          \"ContentsRegex\": \"$SEC101/XX1.ExampleRule1\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 1\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX2\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Disabled2\",\r\n          \"RuleEnabledState\": \"Disabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX2.ExampleRule2\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 2\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX3\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Enabled3\",\r\n          \"ContentsRegex\": \"$SEC101/XX3.ExampleRule3\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 3\" },\r\n        }\r\n      ]\r\n    }\r\n  ]\r\n}";

            string twoDisabled = "{\r\n  \"ValidatorsAssemblyName\": \"Security.dll\",\r\n  \"SharedStringsFileName\": \"Security.SharedStrings.txt\",\r\n  \"Definitions\": [\r\n    {\r\n      \"Id\": \"SEC101\",\r\n      \"Name\": \"DoNotExposePlaintextSecrets\",\r\n      \"Level\": \"Warning\",\r\n      \"FileNameDenyRegex\": \"$BinaryFiles\",\r\n      \"Description\": \"Do not expose plaintext (or base64-encoded plaintext) secrets in versioned engineering content.\",\r\n      \"Message\": \"'{0:truncatedSecret}' is {1:validationPrefix}{2:encoding}{3:secretKind}{4:validationSuffix}{5:validatorMessage}.\",\r\n      \"MatchExpressions\": [\r\n        {\r\n          \"Id\": \"SEC101/XX1\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Enabled1\",\r\n          \"ContentsRegex\": \"$SEC101/XX1.ExampleRule1\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 1\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX2\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Disabled2\",\r\n          \"RuleEnabledState\": \"Disabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX2.ExampleRule2\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 2\" },\r\n        },\r\n        {\r\n          \"Id\": \"SEC101/XX3\",\r\n          \"Name\": \"DoNotExposePlaintextSecrets/Disabled3\",\r\n          \"RuleEnabledState\": \"Disabled\",\r\n          \"ContentsRegex\": \"$SEC101/XX3.ExampleRule3\",\r\n          \"MessageArguments\": { \"secretKind\": \"example rule 3\" },\r\n        }\r\n      ]\r\n    }\r\n  ]\r\n}";


            SearchDefinitions definitions;
            List<Tuple<int, string>> testCases = new List<Tuple<int, string>>{
                new Tuple<int, string>(3, allEnabled),
                new Tuple<int, string>(0, allDisabled),
                new Tuple<int, string>(1, specialCase1),
                new Tuple<int, string>(1, specialCase2),
                new Tuple<int, string>(2, oneDisabled),
                new Tuple<int, string>(1, twoDisabled)
            };


            // stringbuilder implementation.

            foreach (var testCase in testCases)
            {
                definitions = JsonConvert.DeserializeObject<SearchDefinitions>(testCase.Item2);
                definitions = AnalyzeCommand.PushInheritedData(definitions, sharedStrings);

                Assert.True(definitions.Definitions.Count == testCase.Item1);
                foreach (var definition in definitions.Definitions)
                {
                    Assert.True(definition.Name.Contains("Enabled"));
                }
            }
        }


    }
}
