// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

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

        [Fact]
        public void AnalyzeCommand_PushInheritedDataTest()
        {
            string guid = Guid.NewGuid().ToString();
            var searchDefinition = new SearchDefinition()
            {
                FileNameAllowRegex = guid,
                Description = guid,
                Id = guid,
                Level = FailureLevel.Error,
                MatchExpressions = new List<MatchExpression>(),
                Message = guid,
                Name = guid,
            };

            var testCases = new[]
            {
                new
                {
                    Id = "TEST001",
                    ContentsRegex =  (string)null,
                    Expected = (string)null,
                },
                new
                {
                    Id = "TEST002",
                    ContentsRegex =  string.Empty,
                    Expected = string.Empty,
                },
                new
                {
                    Id = "TEST003",
                    ContentsRegex = "(?!)\\bRegexString\\b",
                    Expected = "(?!)\\bRegexString\\b",
                },
                // this will throw exception if DEBUG macro defined
                //new
                //{
                //    Id = "TEST004",
                //    ContentsRegex = "$TEST.DoesNotExistString",
                //    Expected = "$TEST.DoesNotExistString",
                //},
                new
                {
                    Id = "TEST005",
                    ContentsRegex = "$TEST.RegexString1",
                    Expected = "(?!)\\bregex string 1\\b",
                },
                new
                {
                    Id = "TEST006",
                    ContentsRegex = "$TEST.RegexString2",
                    Expected = "(?!)\\bregex string 2\\b",
                },
                new
                {
                    Id = "TEST007",
                    ContentsRegex = "{$TEST.RegexString2}-[$TEST.RegexString1]",
                    Expected = "{(?!)\\bregex string 2\\b}-[(?!)\\bregex string 1\\b]",
                },
                new
                {
                    Id = "TEST008",
                    ContentsRegex = "This Is $TEST.RegexString1",
                    Expected = "This Is (?!)\\bregex string 1\\b",
                },
                new
                {
                    Id = "TEST009",
                    ContentsRegex = "$TEST.RegexString2 is here",
                    Expected = "(?!)\\bregex string 2\\b is here",
                },
                new
                {
                    Id = "TEST010",
                    ContentsRegex = "$TEST.RegexString111",
                    Expected = "This is not RegexString1",
                },
            };

            var sharedStrings = new Dictionary<string, string>()
            {
                { "$TEST.RegexString1", "(?!)\\bregex string 1\\b" },
                { "$TEST.RegexString2", "(?!)\\bregex string 2\\b" },
                { "$TEST.RegexString111", "This is not RegexString1" },
            };

            searchDefinition.MatchExpressions.AddRange(
                testCases.Select(t => new MatchExpression { SubId = t.Id, ContentsRegex = t.ContentsRegex }));

            var searchDefinitions = new SearchDefinitions()
            {
                Definitions = new List<SearchDefinition>() { searchDefinition }
            };

            searchDefinitions = PatternMatcher.AnalyzeCommand.PushInheritedData(searchDefinitions, sharedStrings);

            foreach (var test in testCases)
            {
                bool result;
                string actual = searchDefinitions.Definitions[0].MatchExpressions.First(m => m.SubId == test.Id).ContentsRegex;
                result = test.Expected == null ? actual == null : test.Expected.Equals(actual);
                result.Should().BeTrue();
            }
        }

        [Fact]
        public void AnalyzeCommand_PushInheritedDataShouldPropagateHelpUri()
        {
            var testCases = new[]
            {
                new
                {
                    SearchDefinitionHelpUri = "https://github.com",
                    MatchExpressionHelpUri = (string)null,
                    ExpectedHelpUri = "https://github.com",
                },
                new
                {
                    SearchDefinitionHelpUri = "https://github.com",
                    MatchExpressionHelpUri = "https://www.microsoft.com",
                    ExpectedHelpUri = "https://www.microsoft.com",
                },
                new
                {
                    SearchDefinitionHelpUri = (string)null,
                    MatchExpressionHelpUri = "https://www.microsoft.com",
                    ExpectedHelpUri = "https://www.microsoft.com",
                }
            };

            var sb = new StringBuilder();
            foreach (var testCase in testCases)
            {
                var definitions = new SearchDefinitions
                {
                    Definitions = new List<SearchDefinition>
                    {
                        new SearchDefinition
                        {
                            HelpUri = testCase.SearchDefinitionHelpUri,
                            MatchExpressions = new List<MatchExpression>
                            {
                                new MatchExpression
                                {
                                    Id = "Id0001",
                                    HelpUri = testCase.MatchExpressionHelpUri
                                }
                            }
                        },
                    }
                };

                SearchDefinitions transformedDefinition = PatternMatcher.AnalyzeCommand.PushInheritedData(definitions, new Dictionary<string, string>());
                string currentHelpUri = transformedDefinition.Definitions[0].HelpUri;
                if (currentHelpUri != testCase.ExpectedHelpUri)
                {
                    sb.AppendLine($"Push should be '{testCase.ExpectedHelpUri}' but found '{currentHelpUri}'.");
                }
            }

            sb.Length.Should().Be(0, sb.ToString());
        }

        [Fact]
        public void AnalyzeCommand_WithDeprecatedName()
        {
            const string messageId = "NewId";
            const string deprecatedName = "deprecated-rule-name";
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
                                Message = "Custom message.",
                                DeprecatedName = deprecatedName
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

            foreach (ReportingDescriptor rule in testLogger.Rules)
            {
                rule.DeprecatedNames.Should().NotBeNullOrEmpty();
                rule.DeprecatedNames[0].Should().Be(deprecatedName);
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
