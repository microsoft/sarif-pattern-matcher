// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.RE2.Managed;
using Microsoft.Strings.Interop;

using Moq;

using Newtonsoft.Json;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class AnalyzeCommandTests
    {
        [Fact]
        public void AnalyzeCommand_SimpleAnalysis()
        {
            var regexList = new List<IRegex>
            {
                RE2Regex.Instance,
                DotNetRegex.Instance,
                CachedDotNetRegex.Instance,
            };

            foreach (IRegex regex in regexList)
            {
                AnalyzeCommand(regex);
            }
        }

        [Fact]
        public void AnalyzeFileCommand_SimpleAnalysis()
        {
            var regexList = new List<IRegex>
            {
                DotNetRegex.Instance,
                CachedDotNetRegex.Instance,
                RE2Regex.Instance
            };

            foreach (IRegex regex in regexList)
            {
                AnalyzeFileCommand(regex);
            }
        }

        [Fact]
        public void AnalyzeCommand_WithMessageId()
        {
            const string messageId = "NewId";
            var definitions = new SearchDefinitions()
            {
                Definitions = new List<SearchDefinition>(new[]
                            {
                    new SearchDefinition()
                    {
                        Name = "MinimalRule", Id = "Test1002",
                        Level = FailureLevel.Error, FileNameAllowRegex = "(?i)\\.test$",
                        Message = "A problem occurred in '{0:scanTarget}'.",
                        MatchExpressions = new List<MatchExpression>(new[]
                        {
                            new MatchExpression()
                            {
                                ContentsRegex = "foo",
                                MessageId = messageId,
                                Message = "Custom message."
                            }
                        })
                    }
                })
            };

            string definitionsText = JsonConvert.SerializeObject(definitions);

            string searchDefinitionsPath = Guid.NewGuid().ToString();

            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileReadAllText(searchDefinitionsPath)).Returns(definitionsText);

            // Acquire skimmers for searchers
            ISet<Skimmer<AnalyzeContext>> skimmers = PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                mockFileSystem.Object,
                new string[] { searchDefinitionsPath },
                RE2Regex.Instance);

            string scanTargetFileName = Path.Combine(@"C:\", Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";
            FlexString fixedFileContents = "bar bar bar";

            var context = new AnalyzeContext()
            {
                TargetUri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                FileContents = fileContents,
                Logger = testLogger
            };

            IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = PatternMatcher.AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, skimmers, disabledSkimmers);

            PatternMatcher.AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers);

            testLogger.Results.Should().NotBeNull();
            testLogger.Results.Count.Should().Be(2);

            foreach (Result result in testLogger.Results)
            {
                result.Level.Should().Be(FailureLevel.Error);
                result.Message.Id.Should().Be(messageId);
            }
        }

        [Fact]
        public void AnalyzeCommand_WithSubId()
        {
            const string subId = "NewId";
            var definitions = new SearchDefinitions()
            {
                Definitions = new List<SearchDefinition>(new[]
                {
                    new SearchDefinition()
                    {
                        Name = "MinimalRule", Id = "Test1002",
                        Level = FailureLevel.Error, FileNameAllowRegex = "(?i)\\.test$",
                        Message = "A problem occurred in '{0:scanTarget}'.",
                        MatchExpressions = new List<MatchExpression>(new[]
                        {
                            new MatchExpression()
                            {
                                SubId = subId,
                                ContentsRegex = "foo",
                                Message = "Custom message."
                            }
                        })
                    }
                })
            };

            string definitionsText = JsonConvert.SerializeObject(definitions);

            string searchDefinitionsPath = Guid.NewGuid().ToString();

            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileReadAllText(searchDefinitionsPath)).Returns(definitionsText);

            // Acquire skimmers for searchers
            ISet<Skimmer<AnalyzeContext>> skimmers = PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                mockFileSystem.Object,
                new string[] { searchDefinitionsPath },
                RE2Regex.Instance);

            string scanTargetFileName = Path.Combine(@"C:\", Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";
            FlexString fixedFileContents = "bar bar bar";

            var context = new AnalyzeContext()
            {
                TargetUri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                FileContents = fileContents,
                Logger = testLogger
            };

            IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = PatternMatcher.AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, skimmers, disabledSkimmers);

            PatternMatcher.AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers);

            testLogger.Results.Should().NotBeNull();
            testLogger.Results.Count.Should().Be(2);

            foreach (Result result in testLogger.Results)
            {
                result.Level.Should().Be(FailureLevel.Error);
                result.RuleId.Should().Be($"Test1002/{subId}");
            }
        }

        private static void AnalyzeCommand(IRegex engine)
        {
            var definitions = new SearchDefinitions()
            {
                Definitions = new List<SearchDefinition>(new[]
                            {
                    new SearchDefinition()
                    {
                        Name = "MinimalRule", Id = "Test1002",
                        Level = FailureLevel.Error, FileNameAllowRegex = "(?i)\\.test$",
                        Message = "A problem occurred in '{0:scanTarget}'.",
                        MatchExpressions = new List<MatchExpression>(new[]
                        {
                            new MatchExpression()
                            {
                                ContentsRegex = "foo",
                                Fixes = new Dictionary<string, SimpleFix>()
                                {
                                    {
                                        "convertToPublic", new SimpleFix()
                                        {
                                            Description = "Make class public.",
                                            Find = "foo",
                                            ReplaceWith = "bar"
                                        }
                                    }
                                }
                            }
                        })
                    }
                })
            };

            string definitionsText = JsonConvert.SerializeObject(definitions);

            string searchDefinitionsPath = Guid.NewGuid().ToString();

            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileReadAllText(searchDefinitionsPath)).Returns(definitionsText);

            // Acquire skimmers for searchers
            ISet<Skimmer<AnalyzeContext>> skimmers =
                PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                    mockFileSystem.Object,
                    new string[] { searchDefinitionsPath },
                    engine);

            string scanTargetFileName = Path.Combine(@"C:\", Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";
            FlexString fixedFileContents = "bar bar bar";

            var context = new AnalyzeContext()
            {
                TargetUri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                FileContents = fileContents,
                Logger = testLogger
            };

            IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = PatternMatcher.AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, skimmers, disabledSkimmers);

            PatternMatcher.AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers);

            testLogger.Results.Should().NotBeNull();
            testLogger.Results.Count.Should().Be(2);

            foreach (Result result in testLogger.Results)
            {
                result.Level.Should().Be(FailureLevel.Error);
                result.Message.Id.Should().Be("Default");
            }
        }

        private static void AnalyzeFileCommand(IRegex engine)
        {
            var definitions = new SearchDefinitions()
            {
                Definitions = new List<SearchDefinition>(new[]
                {
                    new SearchDefinition()
                    {
                        Name = "MinimalRule", Id = "Test1002",
                        Level = FailureLevel.Error, FileNameAllowRegex = "(?i)\\.test$",
                        Message = "A problem occurred in '{0:scanTarget}'.",
                        MatchExpressions = new List<MatchExpression>(new[]
                        {
                            new MatchExpression()
                        })
                    }
                })
            };

            string definitionsText = JsonConvert.SerializeObject(definitions);

            string searchDefinitionsPath = Guid.NewGuid().ToString();

            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileReadAllText(searchDefinitionsPath)).Returns(definitionsText);

            // Acquire skimmers for searchers
            ISet<Skimmer<AnalyzeContext>> skimmers =
                PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                    mockFileSystem.Object,
                    new string[] { searchDefinitionsPath },
                    engine);

            string scanTargetFileName = Path.Combine(Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";
            FlexString fixedFileContents = "bar bar bar";

            var context = new AnalyzeContext()
            {
                TargetUri = new Uri(scanTargetFileName, UriKind.Relative),
                FileContents = fileContents,
                Logger = testLogger
            };

            IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = PatternMatcher.AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, skimmers, disabledSkimmers);

            PatternMatcher.AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers);

            testLogger.Results.Should().NotBeNull();
            testLogger.Results.Count.Should().Be(1);

            foreach (Result result in testLogger.Results)
            {
                result.Level.Should().Be(FailureLevel.Error);
                result.Message.Id.Should().Be("Default");
            }
        }
    }
}
