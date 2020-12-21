// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using FluentAssertions;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SearchSkimmerTests
    {
        private static MatchExpression CreateGuidDetectingMatchExpression(bool denyRegexEnabled = false)
        {
            const string guidRegexText = "(?i)[0-9a-f]{8}[-]?([0-9a-f]{4}[-]?){3}[0-9a-f]{12}";

            return new MatchExpression
            {
                MatchLengthToDecode = Guid.NewGuid().ToString().Length,
                ContentsRegex = guidRegexText,
                FileNameDenyRegex = denyRegexEnabled ? "(?i)\\.asc$" : ""
            };
        }

        private static MatchExpression CreateFileDetectingMatchExpression()
        {
            const string fileNameRegexText = "(?i)\\.asc$";

            return new MatchExpression
            {
                FileNameAllowRegex = fileNameRegexText
            };
        }

        private static MatchExpression CreateEmptyMatchExpression()
        {
            return new MatchExpression();
        }

        [Fact]
        public void DetectsBase64EncodedPattern()
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

            // But we should see a change in encoding information in message.
            logger.Results.Count.Should().Be(1);
            logger.Results[0].RuleId.Should().Be(definition.Id);
            logger.Results[0].Level.Should().Be(definition.Level);
            logger.Results[0].GetMessageText(skimmer).Should().Be($"plaintext:{originalMessage}");
        }

        [Fact]
        public void DetectsFilePatternOnly()
        {
            MatchExpression expr = CreateFileDetectingMatchExpression();
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
                TargetUri = new Uri($"file:///c:/{definition.Name}.Fake.asc"),
                FileContents = base64Encoded,
                Logger = logger
            };

            SearchSkimmer skimmer = CreateSkimmer(definition);
            skimmer.Analyze(context);

            // Analyzing base64-encoded values with MatchLengthToDecode > 0 succeeds
            logger.Results.Count.Should().Be(1);
            logger.Results[0].RuleId.Should().Be(definition.Id);
            logger.Results[0].Level.Should().Be(definition.Level);
            logger.Results[0].GetMessageText(skimmer).Should().Be($"plaintext:{originalMessage}");
        }

        [Fact]
        public void NoDetectionWhenMatchIsEmpty()
        {
            MatchExpression expr = CreateEmptyMatchExpression();
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
                TargetUri = new Uri($"file:///c:/{definition.Name}.Fake.asc"),
                FileContents = base64Encoded,
                Logger = logger
            };

            SearchSkimmer skimmer = CreateSkimmer(definition);
            skimmer.Analyze(context);

            logger.Results.Should().BeNull();
        }

        [Fact]
        public void NoDetectionWhenFileIsInDeny()
        {
            MatchExpression expr = CreateGuidDetectingMatchExpression(denyRegexEnabled: true);
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
                TargetUri = new Uri($"file:///c:/{definition.Name}.{definition.FileNameAllowRegex}.asc"),
                FileContents = base64Encoded,
                Logger = logger
            };

            SearchSkimmer skimmer = CreateSkimmer(definition);
            skimmer.Analyze(context);

            // Analyzing base64-encoded values with MatchLengthToDecode > 0 succeeds
            logger.Results.Should().BeNull();
        }

        private SearchSkimmer CreateSkimmer(SearchDefinition definition, IRegex engine = null, ValidatorsCache validators = null)
        {
            return new SearchSkimmer(
                engine: engine ?? RE2Regex.Instance,
                validators: validators,
                definition);
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
