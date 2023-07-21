// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Moq;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ValidatingVisitorTests
    {
        //[Fact]
        public void ValidatingVisitor_ApplyDescriptorAttributeToValidators()
        {
            string directory = $@"D:\src\sarif-pattern-matcher\Src\Plugins\Security\";

            foreach (string file in Directory.GetFiles(directory, "SEC10*.cs", SearchOption.AllDirectories))
            {
                InjectDescriptorAttributeIntoFile(file);
            }
        }

        private void InjectDescriptorAttributeIntoFile(string file)
        {
            string ruleId = Path.GetFileName(file);
            ruleId = ruleId.Substring(0, "SEC101_001".Length);
            ruleId = ruleId.Replace("_", "/");

            string fileContents = File.ReadAllText(file).Trim();
            bool injected = false;
            using var sw = new StreamWriter(file);
            foreach (string line in fileContents.Split(Environment.NewLine))
            {
                if (line.StartsWith("    public class ") && !injected)
                {
                    sw.WriteLine($"    [ValidatorDescriptor(\"{ruleId}\")]");
                    injected = true;
                }
                sw.WriteLine(line);
            }
        }

        [Fact]
        public void ValidatingVisitor_ShouldOverrideAssetFingerprint()
        {
            for (int i = 0; i < s_validatingVisitorTestCases.Length; i++)
            {
                ValidatingVisitorTestCase testCase = s_validatingVisitorTestCases[i];
                Validate(testCase.Original, testCase.Expected);
            }
        }

        private void Validate(Fingerprint original, Fingerprint expected)
        {
            TestRuleValidator.OverrideIsValidDynamic = (ref Fingerprint fingerprint,
                                                        ref string message,
                                                        IDictionary<string, string> options,
                                                        ref ResultLevelKind resultLevelKind) =>
            {
                fingerprint.Id = "test";
                return ValidationState.Authorized;
            };

            string validatorAssemblyPath = $@"c:\{Guid.NewGuid()}.dll";
            string scanTargetExtension = Guid.NewGuid().ToString();

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileExists(validatorAssemblyPath)).Returns(true);
            mockFileSystem.Setup(x => x.AssemblyLoadFrom(validatorAssemblyPath)).Returns(this.GetType().Assembly);

            foreach (string ruleName in new[] { "TestRule", Guid.NewGuid().ToString() })
            {
                var validators = new ValidatorsCache(new string[] { validatorAssemblyPath },
                                                     fileSystem: mockFileSystem.Object);

                var validatingVisitor = new ValidatingVisitor(validators);
                validatingVisitor.VisitRun(new Run
                {
                    Tool = new Tool
                    {
                        Driver = new ToolComponent
                        {
                            Rules = new[]
                            {
                            new ReportingDescriptor
                            {
                                Id = SpamTestRule.TestRuleId,
                                Name = ruleName
                            }
                        }
                        }
                    }
                });

                var result = new Result
                {
                    RuleId = SpamTestRule.TestRuleId,
                    Fingerprints = new Dictionary<string, string>
                {
                    { SearchSkimmer.AssetFingerprintCurrent, original.GetAssetFingerprint() },
                    { SearchSkimmer.ValidationFingerprintCurrent, original.GetValidationFingerprint() },
                    { SearchSkimmer.SecretFingerprintCurrent, original.GetSecretFingerprint() },
                },
                    Message = new Message
                    {
                        Arguments = new List<string> { "", "", "", "", "", "" }
                    }
                };

                result = validatingVisitor.VisitResult(result);

                // AssetFingerprint should be updated.
                result.Fingerprints[SearchSkimmer.AssetFingerprintCurrent].Should().Be(expected.GetAssetFingerprint());

                // ValidationFingerprint should be the same as original.
                result.Fingerprints[SearchSkimmer.ValidationFingerprintCurrent].Should().Be(original.GetValidationFingerprint());
                result.Fingerprints[SearchSkimmer.SecretFingerprintCurrent].Should().Be(original.GetSecretFingerprint());
            }
        }

        private static readonly ValidatingVisitorTestCase[] s_validatingVisitorTestCases = new[]
        {
            new ValidatingVisitorTestCase
            {
                Original = new Fingerprint
                {
                    Secret = "secret",
                    Platform = nameof(AssetPlatform.GitHub),
                },
                Expected = new Fingerprint
                {
                    Id = "test",
                    Secret = "secret",
                    Platform = nameof(AssetPlatform.GitHub),
                },
                Title = "Simple override test."
            },
            new ValidatingVisitorTestCase
            {
                Original = new Fingerprint
                {
                    Secret = "secret[id=id]",
                    Platform = nameof(AssetPlatform.GitHub),
                },
                Expected = new Fingerprint
                {
                    Id = "test",
                    Secret = "secret[id=id]",
                    Platform = nameof(AssetPlatform.GitHub),
                },
                Title = "Broken square bracket fingerprint."
            }
        };

        internal struct ValidatingVisitorTestCase
        {
            public string Title;
            public Fingerprint Original;
            public Fingerprint Expected;
        }
    }
}
