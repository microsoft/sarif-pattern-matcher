// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.RE2.Managed;

using Moq;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SearchSkimmerTests
    {
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
        public void SearchSkimmer_DetectsBase64EncodedPattern()
        {
            MatchExpression expr = CreateGuidDetectingMatchExpression();
            SearchDefinition definition = CreateDefaultSearchDefinition(expr);

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
                Logger = logger
            };

            SearchSkimmer skimmer = CreateSkimmer(definition);
            skimmer.Analyze(context);

            // Analyzing base64-encoded values with MatchLengthToDecode > 0 succeeds
            logger.Results.Count.Should().Be(1);
            logger.Results[0].RuleId.Should().Be(definition.Id);
            logger.Results[0].Level.Should().Be(definition.Level);
            logger.Results[0].GetMessageText(skimmer).Should().Be($"base64-encoded:{originalMessage}");

            // Analyzing base64-encoded values with MatchLengthToDecode == 0 fails
            definition.MatchExpressions[0].MatchLengthToDecode = 0;

            logger.Results.Clear();
            skimmer = CreateSkimmer(definition);
            skimmer.Analyze(context);

            logger.Results.Count.Should().Be(0);

            // Analyzing plaintext values with MatchLengthToDecode > 0 succeeds
            context.FileContents = scanTargetContents;

            logger.Results.Clear();
            skimmer = CreateSkimmer(definition);
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

            string scanTargetContents = definition.Id;

            var logger = new TestLogger();

            var context = new AnalyzeContext
            {
                TargetUri = new Uri($"file:///c:/{definition.Name}.Fake.{fileExtension}"),
                FileContents = definition.Id,
                Logger = logger
            };

            SearchSkimmer skimmer = CreateSkimmer(definition);
            skimmer.Analyze(context);

            ValidateResultsAgainstDefinition(logger.Results, definition, skimmer);
        }

        [Fact]
        public void SearchSkimmer_NoDetectionWhenMatchIsEmpty()
        {
            MatchExpression expression = new MatchExpression();
            SearchDefinition definition = CreateDefaultSearchDefinition(expression);

            string scanTargetContents = definition.Id;

            var logger = new TestLogger();

            var context = new AnalyzeContext
            {
                TargetUri = new Uri($"file:///c:/{definition.Name}.Fake.asc"),
                FileContents = $"{ definition.Id}",
                Logger = logger
            };

            SearchSkimmer skimmer = CreateSkimmer(definition);
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

            AnalyzeContext context =
                CreateGuidMatchingSkimmer(
                    scanTargetExtension: scanTargetExtension,
                    ref definition,
                    out SearchSkimmer skimmer,
                    validators: validators);

            skimmer.Analyze(context);

            //((TestLogger)context.Logger).Results.Should().BeNull();
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
                    allowFileExtension: allowFileExtension,
                    denyFileExtension: denyFileExtension);

            definition ??= CreateDefaultSearchDefinition(expression);

            var logger = new TestLogger();

            var context = new AnalyzeContext
            {
                TargetUri = new Uri($"file:///c:/{definition.Name}.{definition.FileNameAllowRegex}.{scanTargetExtension}"),
                FileContents = definition.Id,
                Logger = logger
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
            FileRegionsCache fileRegionsCache = null,
            IFileSystem fileSystem = null)
        {
            AnalyzeCommand.PushInheritedData(definition, sharedStrings: null);

            return new SearchSkimmer(
                engine: engine ?? RE2Regex.Instance,
                validators: validators,
                fileRegionsCache: fileRegionsCache ?? new FileRegionsCache(),
                definition: definition,
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
