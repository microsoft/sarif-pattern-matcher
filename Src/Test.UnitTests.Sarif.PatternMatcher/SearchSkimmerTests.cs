﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Moq;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SearchSkimmerTests
    {
        private const int DefaultMaxFileSizeInKilobytes = 10000;

        private static MatchExpression CreateGuidDetectingMatchExpression(
            string denyFileExtension = null,
            string allowFileExtension = null)
        {
            const string guidRegexText = "(?i)[0-9a-f]{8}[-]?([0-9a-f]{4}[-]?){3}[0-9a-f]{12}";

            return new MatchExpression
            {
                MatchLengthToDecode = Guid.NewGuid().ToString().Length,
                ContentsRegex = guidRegexText,
                FileNameDenyRegex = denyFileExtension != null ? $"(?i)\\.{denyFileExtension}$" : null,
                FileNameAllowRegex = allowFileExtension != null ? $"(?i)\\.{allowFileExtension}$" : null,
            };
        }

        private static MatchExpression CreateFileDetectingMatchExpression(string fileExtension)
        {
            string fileNameRegexText = $"(?i)\\.{fileExtension}$";

            return new MatchExpression
            {
                FileNameAllowRegex = fileNameRegexText
            };
        }

        [Fact]
        public void SearchSkimmer_RecoverValidatorMessage()
        {
            const string validationMessage = " (no validation occurred as it was not enabled. Pass '--dynamic-validation' on the command-line to validate this match)";
            string dynamicValidationMessage = SearchSkimmer.RecoverValidatorMessage(validationMessage);
            dynamicValidationMessage.Should().Be(validationMessage.Replace(" (", string.Empty).Replace(")", string.Empty));
        }

        [Fact]
        public void SearchSkimmer_DetectsBase64EncodedPattern()
        {
            MatchExpression expr = CreateGuidDetectingMatchExpression();
            SearchDefinition definition = CreateDefaultSearchDefinition(expr);

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileInfoLength(It.IsAny<string>())).Returns(10);

            string originalMessage = definition.Message;

            // We inject the well-known encoding name that reports with
            // 'plaintext' or 'base64-encoded' depending on how a match
            // was made.
            definition.Message = $"{{0:encoding}}:{definition.Message}";

            string scanTargetContents = definition.Id;

            byte[] bytes = Encoding.UTF8.GetBytes(scanTargetContents);
            string base64Encoded = Convert.ToBase64String(bytes);

            var logger = new TestLogger();

            var context = new AnalyzeContext
            {
                TargetUri = new Uri($"file:///c:/{definition.Name}.{definition.FileNameAllowRegex}"),
                FileContents = base64Encoded,
                Logger = logger,
                FileRegionsCache = new FileRegionsCache()
            };

            SearchSkimmer skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
            skimmer.Analyze(context);

            // Analyzing base64-encoded values with MatchLengthToDecode > 0 succeeds
            logger.Results.Count.Should().Be(1);
            logger.Results[0].RuleId.Should().Be(definition.Id);
            logger.Results[0].Level.Should().Be(definition.Level);
            logger.Results[0].GetMessageText(skimmer).Should().Be($"base64-encoded:{originalMessage}");

            // Analyzing base64-encoded values with MatchLengthToDecode == 0 fails
            definition.MatchExpressions[0].MatchLengthToDecode = 0;

            logger.Results.Clear();
            skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
            skimmer.Analyze(context);

            logger.Results.Count.Should().Be(0);

            // Analyzing plaintext values with MatchLengthToDecode > 0 succeeds
            context.FileContents = scanTargetContents;

            logger.Results.Clear();
            skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
            skimmer.Analyze(context);

            // But we should see a change in encoding information in message. Note
            // that when emitting plaintext matches, we elide this information
            // entirely (i.e., we only explicitly report 'base64-encoded' and
            // report nothing for plaintext).
            logger.Results.Count.Should().Be(1);
            logger.Results[0].RuleId.Should().Be(definition.Id);
            logger.Results[0].Level.Should().Be(definition.Level);
            logger.Results[0].GetMessageText(skimmer).Should().Be($":{originalMessage}");
        }

        [Fact]
        public void SearchSkimmer_DetectsFilePatternOnly()
        {
            string fileExtension = Guid.NewGuid().ToString();
            MatchExpression expr = CreateFileDetectingMatchExpression(fileExtension: fileExtension);
            SearchDefinition definition = CreateDefaultSearchDefinition(expr);

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileInfoLength(It.IsAny<string>())).Returns(10);

            var logger = new TestLogger();
            var context = new AnalyzeContext
            {
                TargetUri = new Uri($"file:///c:/{definition.Name}.Fake.{fileExtension}"),
                FileContents = definition.Id,
                Logger = logger
            };

            SearchSkimmer skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
            skimmer.Analyze(context);

            ValidateResultsAgainstDefinition(logger.Results, definition, skimmer);
        }

        [Fact]
        public void SearchSkimmer_NoDetectionWhenMatchIsEmpty()
        {
            var expression = new MatchExpression();
            SearchDefinition definition = CreateDefaultSearchDefinition(expression);

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileInfoLength(It.IsAny<string>())).Returns(10);

            var logger = new TestLogger();
            var context = new AnalyzeContext
            {
                TargetUri = new Uri($"file:///c:/{definition.Name}.Fake.asc"),
                FileContents = $"{ definition.Id}",
                Logger = logger
            };

            SearchSkimmer skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
            skimmer.Analyze(context);

            logger.Results.Should().BeNull();
        }

        [Fact]
        public void SearchSkimmer_DenyFileNameRegexFiltersProperly()
        {
            string scanTargetExtension = Guid.NewGuid().ToString();

            SearchDefinition definition = null;

            AnalyzeContext context =
                CreateGuidMatchingSkimmer(
                    scanTargetExtension: scanTargetExtension,
                    ref definition,
                    out SearchSkimmer skimmer,
                    allowFileExtension: null,
                    denyFileExtension: scanTargetExtension);

            AnalysisApplicability applicability = skimmer.CanAnalyze(context, out string reasonIfNotApplicable);
            applicability.Should().Be(AnalysisApplicability.NotApplicableToSpecifiedTarget);
            reasonIfNotApplicable.Should().Be(SpamResources.TargetDoesNotMeetFileNameCriteria);

            skimmer.Analyze(context);
            ((TestLogger)context.Logger).Results.Should().BeNull();
        }

        [Fact]
        public void SearchSkimmer_AllowFileNameRegexMatchesProperly()
        {
            string scanTargetExtension = Guid.NewGuid().ToString();

            SearchDefinition definition = null;

            AnalyzeContext context =
                CreateGuidMatchingSkimmer(
                    scanTargetExtension: scanTargetExtension,
                    ref definition,
                    out SearchSkimmer skimmer,
                    allowFileExtension: scanTargetExtension,
                    denyFileExtension: null);

            AnalysisApplicability applicability = skimmer.CanAnalyze(context, out string reasonIfNotApplicable);
            applicability.Should().Be(AnalysisApplicability.ApplicableToSpecifiedTarget);
            reasonIfNotApplicable.Should().BeNull();

            skimmer.Analyze(context);
            ValidateResultsAgainstDefinition(((TestLogger)context.Logger).Results, definition, skimmer);

            context.FileContents = null;
            ((TestLogger)context.Logger).Results.Clear();

            skimmer.Analyze(context);
            ValidateResultsAgainstDefinition(((TestLogger)context.Logger).Results, definition, skimmer);
        }

        private void ValidateResultsAgainstDefinition(IList<Result> results, SearchDefinition definition, SearchSkimmer skimmer)
        {
            results.Should().NotBeNull();
            results.Count.Should().Be(1);
            results[0].RuleId.Should().Be(definition.Id);
            results[0].Level.Should().Be(definition.Level);
            results[0].GetMessageText(skimmer).Should().Be($"{definition.Message}");
        }

        [Fact]
        public void SearchSkimmer_BothAllowAndDenyFileNameRegexFiltersProperly()
        {
            string scanTargetExtension = Guid.NewGuid().ToString();

            // Analysis should not occur unless the file name both matches
            // the allow regex, if present, and does not match the deny
            // regex, if present. So, if the file name matches both the
            // allow and deny regex, we should not analyze.

            SearchDefinition definition = null;

            AnalyzeContext context =
                CreateGuidMatchingSkimmer(
                    scanTargetExtension: scanTargetExtension,
                    ref definition,
                    out SearchSkimmer skimmer,
                    allowFileExtension: scanTargetExtension,
                    denyFileExtension: scanTargetExtension);

            skimmer.Analyze(context);

            ((TestLogger)context.Logger).Results.Should().BeNull();
        }

        [Fact]
        public void SearchSkimmer_ValidatorResultsAreProperlyPrioritized()
        {
            string validatorAssemblyPath = $@"c:\{Guid.NewGuid()}.dll";
            string scanTargetExtension = Guid.NewGuid().ToString();

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileExists(validatorAssemblyPath)).Returns(true);
            mockFileSystem.Setup(x => x.AssemblyLoadFrom(validatorAssemblyPath)).Returns(this.GetType().Assembly);

            var validators = new ValidatorsCache(
                new string[] { validatorAssemblyPath },
                fileSystem: mockFileSystem.Object);

            MatchExpression expression =
                CreateGuidDetectingMatchExpression(
                    allowFileExtension: scanTargetExtension);

            expression.ContentsRegex = "TestRule";

            SearchDefinition definition = CreateDefaultSearchDefinition(expression);

            // This Id will match us up with the TestRuleValidator type.
            definition.Id = "TestRule";
            definition.Name = "TestRule";

            AnalyzeContext context =
                CreateGuidMatchingSkimmer(
                    scanTargetExtension: scanTargetExtension,
                    ref definition,
                    out SearchSkimmer skimmer,
                    validators: validators);

            skimmer.Analyze(context);

            //((TestLogger)context.Logger).Results.Should().BeNull();
        }

        [Fact]
        public void SearchSkimmer_ValidatorResultsAreProperlyChangingFingerprintAfterDynamicValidation()
        {
            TestRuleValidator.OverrideIsValidStatic = (groups) =>
            {
                return new[] {
                    new ValidationResult
                    {
                        Fingerprint = new Fingerprint
                        {
                            Secret = "secret",
                            Platform = nameof(AssetPlatform.GitHub),
                        },
                        ValidationState = ValidationState.Unknown,
                    }
                };
            };

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

            var validators = new ValidatorsCache(
                new string[] { validatorAssemblyPath },
                fileSystem: mockFileSystem.Object);

            MatchExpression expression =
                CreateGuidDetectingMatchExpression(
                    allowFileExtension: scanTargetExtension);

            expression.ContentsRegex = "TestRule";

            SearchDefinition definition = CreateDefaultSearchDefinition(expression);

            // This Id will match us up with the TestRuleValidator type.
            definition.Id = "TestRule";
            definition.Name = "TestRule";

            AnalyzeContext context =
                CreateGuidMatchingSkimmer(
                    scanTargetExtension: scanTargetExtension,
                    ref definition,
                    out SearchSkimmer skimmer,
                    validators: validators);
            context.DynamicValidation = true;

            skimmer.Analyze(context);

            ((TestLogger)context.Logger).Results.Should().NotBeNull();
            Result result = ((TestLogger)context.Logger).Results[0];
            result.Fingerprints[SearchSkimmer.AssetFingerprintCurrent].Should().Be("{\"id\":\"test\",\"platform\":\"GitHub\"}");
            result.Fingerprints[SearchSkimmer.ValidationFingerprintCurrent].Should().Be("{\"id\":\"test\",\"secret\":\"secret\"}");
            result.Fingerprints[SearchSkimmer.SecretFingerprintCurrent].Should().Be("{\"secret\":\"secret\"}");
        }

        [Fact]
        public void SearchSkimmer_HelpUriShouldBePropagatedWhenExists()
        {
            const string defaultHelpUri = "https://github.com/microsoft/sarif-pattern-matcher";
            string[] testCases = new[]
            {
                null,
                "https://github.com/",
                "https://www.microsoft.com"
            };

            var sb = new StringBuilder();
            IRegex regexEngine = RE2Regex.Instance;
            foreach (string testCase in testCases)
            {
                var searchDefinition = new SearchDefinition
                {
                    HelpUri = testCase,
                    MatchExpressions = new List<MatchExpression>(),
                };

                var searchSkimmer = new SearchSkimmer(regexEngine, validators: null, searchDefinition);
                var reportingDescriptor = searchSkimmer as ReportingDescriptor;

                if (reportingDescriptor.HelpUri != searchSkimmer.HelpUri)
                {
                    sb.AppendLine($"The helpUri was expected to be equal to '{searchSkimmer.HelpUri}' but it was '{reportingDescriptor.HelpUri}'.");
                }

                if (testCase == null)
                {
                    if (searchSkimmer.HelpUri.OriginalString != defaultHelpUri)
                    {
                        sb.AppendLine($"It was expected to see '{defaultHelpUri}' but saw '{searchSkimmer.HelpUri.OriginalString}'.");
                    }
                }
                else
                {
                    if (testCase != searchSkimmer.HelpUri.OriginalString)
                    {
                        sb.AppendLine($"It was expected to see '{testCase}' but saw '{searchSkimmer.HelpUri.OriginalString}'.");
                    }
                }
            }

            sb.Length.Should().Be(0, sb.ToString());
        }

        [Fact]
        public void SearchSkimmer_ShouldThrowWhenRuleDoesNotHaveAnyRegularExpression()
        {
            string fileExtension = Guid.NewGuid().ToString();
            SearchDefinition definition = CreateDefaultSearchDefinition(new MatchExpression());
            definition.FileNameAllowRegex = string.Empty;

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileInfoLength(It.IsAny<string>())).Returns(10);

            var logger = new TestLogger();
            var context = new AnalyzeContext
            {
                TargetUri = new Uri($"file:///c:/{definition.Name}.Fake.{fileExtension}"),
                FileContents = definition.Id,
                Logger = logger
            };

            SearchSkimmer skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
            Exception exception = Record.Exception(() => skimmer.Analyze(context));
            exception.Should().NotBeNull();
            exception.GetType().Should().Be(typeof(InvalidOperationException));
        }

        [Fact]
        public void SearchSkimmer_ShouldNotEvaluateTooLargeFiles()
        {
            var testCases = new[]
            {
                new {
                    fileSize = long.MaxValue,
                    maxFileSize = (int)uint.MinValue + 1,
                },
                new {
                    fileSize = long.MaxValue,
                    maxFileSize = int.MaxValue,
                },
                new {
                    fileSize = (long)50000000,
                    maxFileSize = DefaultMaxFileSizeInKilobytes,
                },
            };

            foreach (var testCase in testCases)
            {
                var mockFileSystem = new Mock<IFileSystem>();

                mockFileSystem.Setup(x => x.FileInfoLength(It.IsAny<string>())).Returns(testCase.fileSize);

                mockFileSystem.Setup(x => x.FileReadAllText(It.IsAny<string>())).Returns(Guid.NewGuid().ToString());

                MatchExpression expr = CreateGuidDetectingMatchExpression();
                SearchDefinition definition = CreateDefaultSearchDefinition(expr);

                string filePath = $"file:///c:/{definition.Name}.{definition.FileNameAllowRegex}";
                var uri = new Uri(filePath);

                var logger = new TestLogger();

                var sb = new StringBuilder();

                for (int i = 0; i < 100; i++)
                {
                    sb.Append($"{Guid.NewGuid()};");
                }

                // `MaxFileSizeInKilobytes` is set, overriding the default value used by the `AnalyzeContext`.
                // `FileContents` is not set, so file size will be determined by checking the size of the target file,
                // via `_fileSystem.FileInfoLength()`.
                // Set breakpoints in `DoesTargetFileExceedSizeLimits()` in the `SearchSkimmer` class and both
                // references to observe the the origins and comparisons of these values.
                var context = new AnalyzeContext
                {
                    TargetUri = new Uri(filePath),
                    Logger = logger,
                    MaxFileSizeInKilobytes = testCase.maxFileSize
                };

                SearchSkimmer skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
                Exception exception = Record.Exception(() => skimmer.Analyze(context));
                exception.Should().BeNull();

                logger.Results.Should().BeNull();

                mockFileSystem.Verify(x => x.FileInfoLength(uri.LocalPath), Times.Once());
            }
        }

        [Fact]
        public void SearchSkimmer_SearchSkimmer_ShouldNotEvaluateFilesExceedingDefaultLimit()
        {
            // Length of files to be returned by the mocked file system. Will be divided by 1024 to convert to KB.
            int[] testCases = new int[]
            {
                int.MaxValue,
                1024 * (DefaultMaxFileSizeInKilobytes + 1)
            };

            foreach (int testCase in testCases)
            {
                var mockFileSystem = new Mock<IFileSystem>();

                mockFileSystem.Setup(x => x.FileInfoLength(It.IsAny<string>())).Returns(testCase);

                mockFileSystem.Setup(x => x.FileReadAllText(It.IsAny<string>())).Returns(Guid.NewGuid().ToString());

                MatchExpression expr = CreateGuidDetectingMatchExpression();
                SearchDefinition definition = CreateDefaultSearchDefinition(expr);

                string filePath = $"file:///c:/{definition.Name}.{definition.FileNameAllowRegex}";
                var uri = new Uri(filePath);

                var logger = new TestLogger();

                var sb = new StringBuilder();

                for (int i = 0; i < 100; i++)
                {
                    sb.Append($"{Guid.NewGuid()};");
                }

                // `MaxFileSizeInKilobytes` is not set; the default value defined in `AnalyzeContext.cs` will be used.
                // `FileContents` is not set, so file size will be determined by checking the size of the target file,
                // via `_fileSystem.FileInfoLength()`.
                // Set breakpoints in `DoesTargetFileExceedSizeLimits()` in the `SearchSkimmer` class and both
                // references to observe the the origins and comparisons of these values.
                var context = new AnalyzeContext
                {
                    TargetUri = new Uri(filePath),
                    Logger = logger
                };

                SearchSkimmer skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
                Exception exception = Record.Exception(() => skimmer.Analyze(context));
                exception.Should().BeNull();

                logger.Results.Should().BeNull();
            }
        }

        [Fact]
        public void SearchSkimmer_ShouldEvaluateFilesUnderLimit()
        {
            // `MaxFileSizeInKilobytes` values to test.
            int[] testCases = new int[]
            {
                (int)uint.MinValue + 1,
                10000,
                100000,
                1000000,
                1024 * (DefaultMaxFileSizeInKilobytes - 1),
                int.MaxValue,
            };

            foreach (int testCase in testCases)
            {
                var mockFileSystem = new Mock<IFileSystem>();

                MatchExpression expr = CreateGuidDetectingMatchExpression();
                SearchDefinition definition = CreateDefaultSearchDefinition(expr);

                string filePath = $"file:///c:/{definition.Name}.{definition.FileNameAllowRegex}";
                var uri = new Uri(filePath);

                var logger = new TestLogger();

                var sb = new StringBuilder();

                for (int i = 0; i < 100; i++)
                {
                    sb.Append($"{Guid.NewGuid()};");
                }

                // `MaxFileSizeInKilobytes` is set, overriding the default value used by the `AnalyzeContext`.
                // `FileContents` is set, so file size will be determined by the length of the string.
                // Set breakpoints in `DoesTargetFileExceedSizeLimits()` in the `SearchSkimmer` class and both
                // references to observe the the origins and comparisons of these values.
                var context = new AnalyzeContext
                {
                    TargetUri = new Uri(filePath),
                    Logger = logger,
                    MaxFileSizeInKilobytes = testCase,
                    FileContents = Guid.NewGuid().ToString()
                };

                SearchSkimmer skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
                Exception exception = Record.Exception(() => skimmer.Analyze(context));
                exception.Should().BeNull();

                logger.Results.Should().NotBeNullOrEmpty();
            }
        }

        [Fact]
        public void SearchSkimmer_ShouldEvaluateFilesUnderDefaultLimit()
        {
            // Length of files to be returned by the mocked file system.
            int[] testCases = new int[]
            {
                0,
                1,
                DefaultMaxFileSizeInKilobytes,
                100000,
                1000000,
                1024 * (DefaultMaxFileSizeInKilobytes - 1),
            };

            foreach (int testCase in testCases)
            {
                var mockFileSystem = new Mock<IFileSystem>();

                mockFileSystem.Setup(x => x.FileInfoLength(It.IsAny<string>())).Returns(testCase);

                mockFileSystem.Setup(x => x.FileReadAllText(It.IsAny<string>())).Returns(Guid.NewGuid().ToString());

                MatchExpression expr = CreateGuidDetectingMatchExpression();
                SearchDefinition definition = CreateDefaultSearchDefinition(expr);

                string filePath = $"file:///c:/{definition.Name}.{definition.FileNameAllowRegex}";
                var uri = new Uri(filePath);

                var logger = new TestLogger();

                var sb = new StringBuilder();

                for (int i = 0; i < 100; i++)
                {
                    sb.Append($"{Guid.NewGuid()};");
                }

                // `MaxFileSizeInKilobytes` is not set; the default value defined in `AnalyzeContext.cs` will be used.
                // `FileContents` is not set, so file size will be determined by checking the size of the target file,
                // via `_fileSystem.FileInfoLength()`.
                // Set breakpoints in `DoesTargetFileExceedSizeLimits()` in the `SearchSkimmer` class and both
                // references to observe the the origins and comparisons of these values.
                var context = new AnalyzeContext
                {
                    TargetUri = new Uri(filePath),
                    Logger = logger
                };

                SearchSkimmer skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
                Exception exception = Record.Exception(() => skimmer.Analyze(context));
                exception.Should().BeNull();

                logger.Results.Should().NotBeNullOrEmpty();
            }
        }

        [Fact]
        public void SearchSkimmer_ShouldLogIOExceptionIfFileNotFound()
        {
            MatchExpression expr = CreateGuidDetectingMatchExpression();
            SearchDefinition definition = CreateDefaultSearchDefinition(expr);
            IRegex regexEngine = RE2Regex.Instance;

            var searchDefinition = new SearchDefinition
            {
                HelpUri = "https://www.microsoft.com",
                MatchExpressions = new List<MatchExpression>(),
            };

            var searchSkimmer = new SearchSkimmer(regexEngine, validators: null, searchDefinition);
            var reportingDescriptor = searchSkimmer as ReportingDescriptor;

            var logger = new TestLogger();

            var context = new AnalyzeContext
            {
                TargetUri = new Uri($"file:///c:/{definition.Name}.{definition.FileNameAllowRegex}"),
                Logger = logger,
                MaxFileSizeInKilobytes = 1,
                Rule = reportingDescriptor
            };

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileReadAllText(It.IsAny<string>())).Throws(new FileNotFoundException());

            SearchSkimmer skimmer = CreateSkimmer(definition, fileSystem: mockFileSystem.Object);
            Exception exception = Record.Exception(() => skimmer.Analyze(context));
            exception.Should().BeNull();

            logger.ToolNotifications[0].Exception.Should().NotBeNull();
            logger.ToolNotifications[0].Exception.Kind.Should().Be(nameof(FileNotFoundException));
        }

        private AnalyzeContext CreateGuidMatchingSkimmer(
            string scanTargetExtension,
            ref SearchDefinition definition,
            out SearchSkimmer skimmer,
            string allowFileExtension = null,
            string denyFileExtension = null,
            ValidatorsCache validators = null)
        {
            MatchExpression expression =
                CreateGuidDetectingMatchExpression(
                    denyFileExtension: denyFileExtension,
                    allowFileExtension: allowFileExtension);

            definition ??= CreateDefaultSearchDefinition(expression);

            var logger = new TestLogger();

            var context = new AnalyzeContext
            {
                TargetUri = new Uri($"file:///c:/{definition.Name}.{definition.FileNameAllowRegex}.{scanTargetExtension}"),
                FileContents = definition.Id,
                Logger = logger,
                FileRegionsCache = new FileRegionsCache(),
            };

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileReadAllText(context.TargetUri.LocalPath)).Returns(definition.Id);

            skimmer = CreateSkimmer(
                definition,
                validators: validators,
                fileSystem: mockFileSystem.Object);

            return context;
        }

        private SearchSkimmer CreateSkimmer(
            SearchDefinition definition,
            IRegex engine = null,
            ValidatorsCache validators = null,
            IFileSystem fileSystem = null)
        {
            var definitions = new SearchDefinitions
            {
                Definitions = new List<SearchDefinition>(new[] { definition }),
            };

            definitions = AnalyzeCommand.PushInheritedData(definitions, sharedStrings: null);

            return new SearchSkimmer(
                engine: engine ?? RE2Regex.Instance,
                validators: validators,
                definition: definitions.Definitions[0],
                fileSystem: fileSystem);
        }

        private SearchDefinition CreateDefaultSearchDefinition(MatchExpression matchExpression)
        {
            return new SearchDefinition()
            {
                FileNameAllowRegex = Guid.NewGuid().ToString(),
                Description = Guid.NewGuid().ToString(),
                Id = Guid.NewGuid().ToString(),
                Level = FailureLevel.Error,
                MatchExpressions = new List<MatchExpression> { matchExpression },
                Message = Guid.NewGuid().ToString(),
                Name = Guid.NewGuid().ToString(),
            };
        }
    }
}
