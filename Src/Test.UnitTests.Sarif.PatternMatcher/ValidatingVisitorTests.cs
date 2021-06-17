﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Moq;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ValidatingVisitorTests
    {
        [Fact]
        public void ValidatingVisitor_ShouldOverrideAssetFingerprint()
        {
            TestRuleValidator.OverrideIsValidDynamic = (ref Fingerprint fingerprint,
                                                        ref string message,
                                                        Dictionary<string, string> options,
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

            var validators = new ValidatorsCache(
                new string[] { validatorAssemblyPath },
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
                                Id = "TestRule",
                                Name = "TestRule"
                            }
                        }
                    }
                }
            });

            const string validationFingerprint = "[secret=secret]";
            const string originalAssetFingerprint = "[platform=GitHub]";
            const string updatedAssetFingerprint = "[id=test][platform=GitHub]";

            var result = new Result
            {
                RuleId = "TestRule",
                Fingerprints = new Dictionary<string, string>
                {
                    { SearchSkimmer.AssetFingerprint, originalAssetFingerprint },
                    { SearchSkimmer.ValidationFingerprint, validationFingerprint }
                },
                Message = new Message
                {
                    Arguments = new List<string>
                    {
                        "secret…",
                        "a valid ",
                        "",
                        "legacy format GitHub personal access token",
                        "",
                        " (the compromised GitHub account is '[username](https://github.com/username)' which has access to the following orgs '[None]')"
                    }
                }
            };

            result = validatingVisitor.VisitResult(result);
            result.Fingerprints[SearchSkimmer.ValidationFingerprint].Should().Be(validationFingerprint);
            result.Fingerprints[SearchSkimmer.AssetFingerprint].Should().Be(updatedAssetFingerprint);
        }
    }
}
