//// Copyright (c) Microsoft. All rights reserved.
//// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//using System;
//using System.Collections.Generic;

//using FluentAssertions;

//using Microsoft.RE2.Managed;

//using Moq;

//using Xunit;

//namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
//{
//    public class ValidationResultTests
//    {
//        [Fact]
//        public void SearchSkimmer_ValidationResultsOverrideIndexAndLength()
//        {
//            // test using OverrideIndexTestValidator
//            string ruleName = "OverrideIndexTest";
//            string validatorAssemblyPath = $@"c:\{Guid.NewGuid()}.dll";
//            string scanTargetExtension = Guid.NewGuid().ToString();

//            var mockFileSystem = new Moq.Mock<IFileSystem>();
//            mockFileSystem.Setup(x => x.FileExists(validatorAssemblyPath)).Returns(true);
//            mockFileSystem.Setup(x => x.AssemblyLoadFrom(validatorAssemblyPath)).Returns(this.GetType().Assembly);

//            var validators = new ValidatorsCache(
//                new string[] { validatorAssemblyPath },
//                fileSystem: mockFileSystem.Object);

//            string regexStr = "(?im)^.*?(?P<refine>\\bTestTerm\\b).*?$";
//            string fileContent = "TestTerm Another-TEST-TERM";
//            MatchExpression expression =
//                CreateMatchExpression(
//                    regexStr,
//                    allowFileExtension: scanTargetExtension);

//            SearchDefinition definition = CreateSearchDefinition(ruleName, expression);

//            AnalyzeContext context =
//                CreateSkimmer(
//                    scanTargetExtension: scanTargetExtension,
//                    definition,
//                    out SearchSkimmer skimmer,
//                    fileContent,
//                    validators: validators);

//            skimmer.Analyze(context);

//            IList<Result> results = ((TestLogger)context.Logger).Results;
//            results.Should().NotBeNull();
//            results.Count.Should().Be(1);
//            results[0].Kind.Should().Be(ResultKind.Fail);
//            results[0].Level.Should().Be(FailureLevel.Warning);
//            results[0].Locations.Should().NotBeNull();
//            results[0].Locations.Count.Should().Be(1);
//            results[0].Locations[0].PhysicalLocation.Should().NotBeNull();
//            results[0].Locations[0].PhysicalLocation.Region.Should().NotBeNull();

//            // matchedPattern is "TestTerm Another-TEST-TERM"
//            // OverrideIndexTestValidator overrides index to 17 and length 9
//            // the snippet text should be "TEST-TERM"
//            Region region = results[0].Locations[0].PhysicalLocation.Region;
//            int index = 17;
//            region.CharOffset.Should().Be(index);
//            region.CharLength.Should().Be("TEST-TERM".Length);
//            region.StartColumn.Should().Be(index + 1);
//            region.EndColumn.Should().Be(index + 1 + "TEST-TERM".Length);
//            region.Snippet.Text.Should().Be("TEST-TERM");
//        }

//        [Fact]
//        public void SearchSkimmer_ValidatorDoesNotExist()
//        {
//            // without validator
//            string ruleName = "NonExistValidatorTest";
//            string validatorAssemblyPath = $@"c:\{Guid.NewGuid()}.dll";
//            string scanTargetExtension = Guid.NewGuid().ToString();

//            var mockFileSystem = new Moq.Mock<IFileSystem>();
//            mockFileSystem.Setup(x => x.FileExists(validatorAssemblyPath)).Returns(true);
//            mockFileSystem.Setup(x => x.AssemblyLoadFrom(validatorAssemblyPath)).Returns(this.GetType().Assembly);

//            var validators = new ValidatorsCache(
//                new string[] { validatorAssemblyPath },
//                fileSystem: mockFileSystem.Object);

//            string regexStr = "TestTerm";
//            string fileContent = "TestTerm Another-TestTerm";
//            MatchExpression expression =
//                CreateMatchExpression(
//                    regexStr,
//                    allowFileExtension: scanTargetExtension);

//            SearchDefinition definition = CreateSearchDefinition(ruleName, expression);

//            AnalyzeContext context =
//                CreateSkimmer(
//                    scanTargetExtension: scanTargetExtension,
//                    definition,
//                    out SearchSkimmer skimmer,
//                    fileContent,
//                    validators: validators);

//            skimmer.Analyze(context);

//            IList<Result> results = ((TestLogger)context.Logger).Results;
//            results.Should().NotBeNull();
//            results.Count.Should().Be(2);

//            // since validator doesn't exist, there should be 2 results:
//            // first result points to first "TestTerm" at index 0
//            // and second result points to second "TestTerm" at index 17
//            // in orginal text "TestTerm Another-TestTerm"

//            // verify first result
//            Result result = results[0];
//            result.Kind.Should().Be(ResultKind.Fail);
//            result.Level.Should().Be(FailureLevel.Error);
//            result.Locations.Should().NotBeNull();
//            result.Locations.Count.Should().Be(1);
//            result.Locations[0].PhysicalLocation.Should().NotBeNull();
//            result.Locations[0].PhysicalLocation.Region.Should().NotBeNull();

//            Region region = result.Locations[0].PhysicalLocation.Region;
//            int index = 0;
//            region.CharOffset.Should().Be(index);
//            region.CharLength.Should().Be("TestTerm".Length);
//            region.StartColumn.Should().Be(index + 1);
//            region.EndColumn.Should().Be(index + 1 + "TestTerm".Length);
//            region.Snippet.Text.Should().Be("TestTerm");

//            // verify second result
//            result = results[1];
//            result.Kind.Should().Be(ResultKind.Fail);
//            result.Level.Should().Be(FailureLevel.Error);
//            result.Locations.Should().NotBeNull();
//            result.Locations.Count.Should().Be(1);
//            result.Locations[0].PhysicalLocation.Should().NotBeNull();
//            result.Locations[0].PhysicalLocation.Region.Should().NotBeNull();

//            region = result.Locations[0].PhysicalLocation.Region;
//            index = 17;
//            region.CharOffset.Should().Be(index);
//            region.CharLength.Should().Be("TestTerm".Length);
//            region.StartColumn.Should().Be(index + 1);
//            region.EndColumn.Should().Be(index + 1 + "TestTerm".Length);
//            region.Snippet.Text.Should().Be("TestTerm");
//        }

//        [Fact]
//        public void SearchSkimmer_ValidatorDoesNotOverride()
//        {
//            // test using DoesNotOverrideTestValidator
//            string ruleName = "DoesNotOverrideTest";
//            string validatorAssemblyPath = $@"c:\{Guid.NewGuid()}.dll";
//            string scanTargetExtension = Guid.NewGuid().ToString();

//            var mockFileSystem = new Moq.Mock<IFileSystem>();
//            mockFileSystem.Setup(x => x.FileExists(validatorAssemblyPath)).Returns(true);
//            mockFileSystem.Setup(x => x.AssemblyLoadFrom(validatorAssemblyPath)).Returns(this.GetType().Assembly);

//            var validators = new ValidatorsCache(
//                new string[] { validatorAssemblyPath },
//                fileSystem: mockFileSystem.Object);

//            string regexStr = "TestTerm";
//            string fileContent = "TestTerm Another-TestTerm";
//            MatchExpression expression =
//                CreateMatchExpression(
//                    regexStr,
//                    allowFileExtension: scanTargetExtension);

//            SearchDefinition definition = CreateSearchDefinition(ruleName, expression);

//            AnalyzeContext context =
//                CreateSkimmer(
//                    scanTargetExtension: scanTargetExtension,
//                    definition,
//                    out SearchSkimmer skimmer,
//                    fileContent,
//                    validators: validators);

//            skimmer.Analyze(context);

//            IList<Result> results = ((TestLogger)context.Logger).Results;
//            results.Should().NotBeNull();
//            results.Count.Should().Be(2);

//            // validator doesn't override index and length, there should be 2 results:
//            // first result points to first "TestTerm" at index 0
//            // and second result points to second "TestTerm" at index 17
//            // in orginal text "TestTerm Another-TestTerm"

//            // verify first result
//            Result result = results[0];
//            result.Kind.Should().Be(ResultKind.Fail);
//            result.Level.Should().Be(FailureLevel.Note); // since validator returns ValidationState.Unknown
//            result.Locations.Should().NotBeNull();
//            result.Locations.Count.Should().Be(1);
//            result.Locations[0].PhysicalLocation.Should().NotBeNull();
//            result.Locations[0].PhysicalLocation.Region.Should().NotBeNull();

//            Region region = result.Locations[0].PhysicalLocation.Region;
//            int index = 0;
//            region.CharOffset.Should().Be(index);
//            region.CharLength.Should().Be("TestTerm".Length);
//            region.StartColumn.Should().Be(index + 1);
//            region.EndColumn.Should().Be(index + 1 + "TestTerm".Length);
//            region.Snippet.Text.Should().Be("TestTerm");

//            // verify second result
//            result = results[1];
//            result.Kind.Should().Be(ResultKind.Fail);
//            result.Level.Should().Be(FailureLevel.Note); // since validator returns ValidationState.Unknown
//            result.Locations.Should().NotBeNull();
//            result.Locations.Count.Should().Be(1);
//            result.Locations[0].PhysicalLocation.Should().NotBeNull();
//            result.Locations[0].PhysicalLocation.Region.Should().NotBeNull();

//            region = result.Locations[0].PhysicalLocation.Region;
//            index = 17;
//            region.CharOffset.Should().Be(index);
//            region.CharLength.Should().Be("TestTerm".Length);
//            region.StartColumn.Should().Be(index + 1);
//            region.EndColumn.Should().Be(index + 1 + "TestTerm".Length);
//            region.Snippet.Text.Should().Be("TestTerm");
//        }

//        [Fact]
//        public void SearchSkimmer_ValidationResult_VerifyResultKindLevel()
//        {
//            // test using VerifyResultKindLevelTestValidator
//            string ruleName = "VerifyResultKindLevelTest";
//            string validatorAssemblyPath = $@"c:\{Guid.NewGuid()}.dll";
//            string scanTargetExtension = Guid.NewGuid().ToString();

//            var mockFileSystem = new Moq.Mock<IFileSystem>();
//            mockFileSystem.Setup(x => x.FileExists(validatorAssemblyPath)).Returns(true);
//            mockFileSystem.Setup(x => x.AssemblyLoadFrom(validatorAssemblyPath)).Returns(this.GetType().Assembly);

//            var validators = new ValidatorsCache(
//                new string[] { validatorAssemblyPath },
//                fileSystem: mockFileSystem.Object);

//            string regexStr = "TestTerm";
//            string fileContent = "TestTerm";
//            MatchExpression expression =
//                CreateMatchExpression(
//                    regexStr,
//                    allowFileExtension: scanTargetExtension);

//            SearchDefinition definition = CreateSearchDefinition(ruleName, expression);

//            AnalyzeContext context =
//                CreateSkimmer(
//                    scanTargetExtension: scanTargetExtension,
//                    definition,
//                    out SearchSkimmer skimmer,
//                    fileContent,
//                    validators: validators);

//            skimmer.Analyze(context);

//            IList<Result> results = ((TestLogger)context.Logger).Results;
//            results.Should().NotBeNull();
//            results.Count.Should().Be(8);

//            // VerifyResultKindLevelTestValidator creates 8 results which ValidationState are
//            // Authorized / PasswordProtected / Unauthorized / Expired / UnknownHost /
//            // InvalidForConsultedAuthorities / Unknown / ValidatorNotFound
//            // check VerifyResultKindLevelTestValidator class for expected result level
//            results[0].Level.Should().Be(FailureLevel.Error);
//            results[1].Level.Should().Be(FailureLevel.Warning);
//            results[2].Level.Should().Be(FailureLevel.Note);
//            results[3].Level.Should().Be(FailureLevel.Note);
//            results[4].Level.Should().Be(FailureLevel.Note);
//            results[5].Level.Should().Be(FailureLevel.Note);
//            results[6].Level.Should().Be(FailureLevel.Note);
//            results[7].Level.Should().Be(FailureLevel.Note);
//        }

//        [Fact]
//        public void SearchSkimmer_ValidationResults_InvalidOverrideIndexAndLength()
//        {
//            // test using InvalidIndexLengthTestValidator
//            string ruleName = "InvalidIndexLengthTest";
//            string validatorAssemblyPath = $@"c:\{Guid.NewGuid()}.dll";
//            string scanTargetExtension = Guid.NewGuid().ToString();

//            var mockFileSystem = new Moq.Mock<IFileSystem>();
//            mockFileSystem.Setup(x => x.FileExists(validatorAssemblyPath)).Returns(true);
//            mockFileSystem.Setup(x => x.AssemblyLoadFrom(validatorAssemblyPath)).Returns(this.GetType().Assembly);

//            var validators = new ValidatorsCache(
//                new string[] { validatorAssemblyPath },
//                fileSystem: mockFileSystem.Object);

//            string regexStr = "(?im)^.*?(?P<refine>\\bTestTerm\\b).*?$";
//            string fileContent = "TestTerm Another-TEST-TERM";
//            MatchExpression expression =
//                CreateMatchExpression(
//                    regexStr,
//                    allowFileExtension: scanTargetExtension);

//            SearchDefinition definition = CreateSearchDefinition(ruleName, expression);

//            AnalyzeContext context =
//                CreateSkimmer(
//                    scanTargetExtension: scanTargetExtension,
//                    definition,
//                    out SearchSkimmer skimmer,
//                    fileContent,
//                    validators: validators);

//            skimmer.Analyze(context);

//            // InvalidIndexLengthTestValidator create 3 results with invalid override index and length
//            // check InvalidIndexLengthTestValidator class for expected results
//            IList<Result> results = ((TestLogger)context.Logger).Results;
//            results.Should().NotBeNull();
//            results.Count.Should().Be(3);

//            // 1st result overrides index to -1, the region is expected to be the full file content
//            // verify first result
//            Result result = results[0];
//            result.Kind.Should().Be(ResultKind.Fail);
//            result.Level.Should().Be(FailureLevel.Error);
//            result.Locations.Should().NotBeNull();
//            result.Locations.Count.Should().Be(1);
//            result.Locations[0].PhysicalLocation.Should().NotBeNull();
//            result.Locations[0].PhysicalLocation.Region.Should().NotBeNull();

//            Region region = result.Locations[0].PhysicalLocation.Region;
//            region.CharOffset.Should().Be(0);
//            region.CharLength.Should().Be(fileContent.Length);
//            region.StartColumn.Should().Be(1);
//            region.EndColumn.Should().Be(1 + fileContent.Length);
//            region.Snippet.Text.Should().Be(fileContent);

//            // 2nd result overrides index to 26, the region is expected to be the full file content
//            // verify second result
//            result = results[1];
//            result.Kind.Should().Be(ResultKind.Fail);
//            result.Level.Should().Be(FailureLevel.Error);
//            result.Locations.Should().NotBeNull();
//            result.Locations.Count.Should().Be(1);
//            result.Locations[0].PhysicalLocation.Should().NotBeNull();
//            result.Locations[0].PhysicalLocation.Region.Should().NotBeNull();

//            region = result.Locations[0].PhysicalLocation.Region;
//            region.CharOffset.Should().Be(0);
//            region.CharLength.Should().Be(fileContent.Length);
//            region.StartColumn.Should().Be(1);
//            region.EndColumn.Should().Be(1 + fileContent.Length);
//            region.Snippet.Text.Should().Be(fileContent);

//            // 3rd result overrides index to 17 and length to 100, the region is expected to be
//            // from the index (17) till end of file content
//            // verify third result
//            result = results[2];
//            result.Kind.Should().Be(ResultKind.Fail);
//            result.Level.Should().Be(FailureLevel.Error);
//            result.Locations.Should().NotBeNull();
//            result.Locations.Count.Should().Be(1);
//            result.Locations[0].PhysicalLocation.Should().NotBeNull();
//            result.Locations[0].PhysicalLocation.Region.Should().NotBeNull();

//            region = result.Locations[0].PhysicalLocation.Region;
//            int index = 17;
//            region.CharOffset.Should().Be(index);
//            region.CharLength.Should().Be("TEST-TERM".Length);
//            region.StartColumn.Should().Be(1 + index);
//            region.EndColumn.Should().Be(1 + index + "TEST-TERM".Length);
//            region.Snippet.Text.Should().Be("TEST-TERM");
//        }

//        private static MatchExpression CreateMatchExpression(
//            string regexString,
//            string denyFileExtension = null,
//            string allowFileExtension = null)
//        {
//            return new MatchExpression
//            {
//                MatchLengthToDecode = Guid.NewGuid().ToString().Length,
//                ContentsRegex = regexString,
//                FileNameDenyRegex = denyFileExtension != null ? $"(?i)\\.{denyFileExtension}$" : null,
//                FileNameAllowRegex = allowFileExtension != null ? $"(?i)\\.{allowFileExtension}$" : null,
//            };
//        }

//        private SearchDefinition CreateSearchDefinition(string ruleName, MatchExpression matchExpression)
//        {
//            return new SearchDefinition()
//            {
//                FileNameAllowRegex = Guid.NewGuid().ToString(),
//                Description = Guid.NewGuid().ToString(),
//                Id = Guid.NewGuid().ToString(),
//                Level = FailureLevel.Error,
//                MatchExpressions = new List<MatchExpression> { matchExpression },
//                Message = Guid.NewGuid().ToString(),
//                Name = ruleName,
//            };
//        }

//        private AnalyzeContext CreateSkimmer(
//            string scanTargetExtension,
//            SearchDefinition definition,
//            out SearchSkimmer skimmer,
//            string fileContent,
//            ValidatorsCache validators = null)
//        {

//            var logger = new TestLogger();

//            var context = new AnalyzeContext
//            {
//                TargetUri = new Uri($"file:///c:/{definition.Name}.{definition.FileNameAllowRegex}.{scanTargetExtension}"),
//                FileContents = fileContent,
//                Logger = logger
//            };

//            var mockFileSystem = new Mock<IFileSystem>();
//            mockFileSystem.Setup(x => x.FileReadAllText(context.TargetUri.LocalPath)).Returns(definition.Id);

//            skimmer = CreateSkimmer(
//                definition,
//                validators: validators,
//                fileSystem: mockFileSystem.Object);

//            return context;
//        }

//        private SearchSkimmer CreateSkimmer(
//            SearchDefinition definition,
//            IRegex engine = null,
//            ValidatorsCache validators = null,
//            FileRegionsCache fileRegionsCache = null,
//            IFileSystem fileSystem = null)
//        {
//            var definitions = new SearchDefinitions
//            {
//                Definitions = new List<SearchDefinition>(new[] { definition }),
//            };

//            definitions = AnalyzeCommand.PushInheritedData(definitions, sharedStrings: null);

//            return new SearchSkimmer(
//                engine: engine ?? RE2Regex.Instance,
//                validators: validators,
//                fileRegionsCache: fileRegionsCache ?? new FileRegionsCache(),
//                definition: definitions.Definitions[0],
//                fileSystem: fileSystem);
//        }
//    }
//}
