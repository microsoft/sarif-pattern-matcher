// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

using CommandLine;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.CodeAnalysis.Sarif.Writers;
using Microsoft.RE2.Managed;
using Microsoft.Strings.Interop;

using Moq;

using Newtonsoft.Json;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class AnalyzeCommandTests
    {
        private static AnalyzeOptions CreateDefaultAnalyzeOptions()
        {
            var result = new AnalyzeOptions();
            Type analyzeOptionsType = typeof(AnalyzeOptions);

            foreach (PropertyInfo property in analyzeOptionsType.GetProperties())
            {
                var optionAttribute = (OptionAttribute)property.GetCustomAttribute(typeof(OptionAttribute));
                if (optionAttribute == null || optionAttribute.Default == null)
                {
                    continue;
                }

                property.SetValue(result, optionAttribute.Default);
            }
            return result;
        }

        [Fact]
        public void AnalyzeCommand_AnalyzeFromContextApiExample()
        {
            var logger = new TestLogger();
            var skimmers = new List<Skimmer<AnalyzeContext>>();
            skimmers.Add(new SpamTestRule());

            AnalyzeCommand.Analyze(context: new AnalyzeContext
            {
                Logger = logger,
                Skimmers = skimmers,
                TimeoutInMilliseconds = 1000,
                TargetUri = new Uri("c:\\FireOneWarning.txt"),
                FileContents = "Fire two results for: error error."
            });

            logger.Results.Count.Should().Be(3);
        }

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
                RunAnalyzeCommand(regex);
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

            string searchDefinitionsPath = Path.GetFullPath(Guid.NewGuid().ToString());

            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
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
                Logger = testLogger,
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

            string searchDefinitionsPath = Path.GetFullPath(Guid.NewGuid().ToString());

            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
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
                Logger = testLogger,
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
        public void AnalyzeCommand_RedactSensitiveData()
        {
            string secretText = nameof(secretText);

            var definitions = new SearchDefinitions()
            {
                Definitions = new List<SearchDefinition>(new[]
                {
                    new SearchDefinition()
                    {
                        Name = "SecretDetector", Id = "Test1009",
                        Level = FailureLevel.Error,
                        FileNameAllowRegex = "(?i)\\.test$",
                        Message = "Found sensitive data '{0:truncatedSecret}' in '{1:scanTarget}'.",
                        MatchExpressions = new List<MatchExpression>(new[]
                        {
                            new MatchExpression()
                            {
                                ContentsRegex = $"(?P<secret>{secretText})bar",
                            }
                        })
                    }
                })
            };

            string definitionsText = JsonConvert.SerializeObject(definitions);
            string searchDefinitionsPath = Path.GetFullPath(Guid.NewGuid().ToString());

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
            mockFileSystem.Setup(x => x.FileReadAllText(searchDefinitionsPath)).Returns(definitionsText);

            // Acquire skimmers for searchers.
            ISet<Skimmer<AnalyzeContext>> skimmers =
                PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(mockFileSystem.Object,
                                                                                 new string[] { searchDefinitionsPath },
                                                                                 RE2Regex.Instance);

            string scanTargetFileName = $"C:\\{Guid.NewGuid()}.test";
            FlexString fileContents = $"{secretText}bar1{Environment.NewLine} {secretText}bar2 {Environment.NewLine}3{secretText}bar";

            var sb = new StringBuilder();
            var writer = new StringWriter(sb);

            var logger = new SarifLogger(writer,
                                         LogFilePersistenceOptions.None,
                                         OptionallyEmittedData.All,
                                         closeWriterOnDispose: true);


            using var context = new AnalyzeContext()
            {
                Logger = logger,
                RedactSecrets = true,
                FileContents = fileContents,
                DataToInsert = OptionallyEmittedData.All,
                TargetUri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
            };

            var disabledSkimmers = new HashSet<string>();

            IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = PatternMatcher.AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, skimmers, disabledSkimmers);
            logger.AnalysisStarted();
            PatternMatcher.AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers);
            logger.AnalysisStopped(RuntimeConditions.None);
            logger.Dispose();

            // Test file contents:
            // foobar1\r\n foobar2 \r\n3foobar
            string sarifLogText = sb.ToString();
            SarifLog sarifLog = JsonConvert.DeserializeObject<SarifLog>(sarifLogText);
            sarifLog.Runs.Should().NotBeNullOrEmpty();
            sarifLog.Runs[0].Results.Should().NotBeNullOrEmpty();
            sarifLog.Runs[0].Results.Count.Should().Be(3);

            var fingerprint = new Fingerprint()
            {
                Secret = secretText
            };

            var redactedFingerprint = new Fingerprint()
            {
                Secret = secretText.Anonymize()
            };

            foreach (Result result in sarifLog.Runs[0].Results)
            {
                IDictionary<string, string> fingerprints = result.Fingerprints;

                // Make sure that redacted data hasn't snuck into the hash.
                fingerprints[SearchSkimmer.SecretHashSha256Current]
                    .Should().NotBe(redactedFingerprint.GetSecretHash());

                fingerprints[SearchSkimmer.ValidationFingerprintHashSha256Current]
                    .Should().NotBe(redactedFingerprint.GetValidationFingerprintHash());

                // Make sure that our hashes are constructed from the UNREDACTED data.
                fingerprints[SearchSkimmer.SecretHashSha256Current]
                    .Should().Be(fingerprint.GetSecretHash());

                fingerprints[SearchSkimmer.ValidationFingerprintHashSha256Current]
                    .Should().Be(fingerprint.GetValidationFingerprintHash());
            }


            sarifLogText.IndexOf($"{secretText}").Should().Be(-1, $"there should be no plaintext occurrence of '{secretText}'");
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
                        Level = FailureLevel.Error,
                        FileNameAllowRegex = "(?i)\\.test$",
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
            string searchDefinitionsPath = Path.GetFullPath(Guid.NewGuid().ToString());

            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
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
                Logger = testLogger,
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

        [Fact]
        public void AnalyzeCommand_SarifLogger_RegionSnippetValidation()
        {
            using var ms = new MemoryStream();
            using var writer = new StreamWriter(ms, Encoding.UTF8, 1024, leaveOpen: true);

            OptionallyEmittedData dataToInsert = OptionallyEmittedData.RegionSnippets | OptionallyEmittedData.ContextRegionSnippets | OptionallyEmittedData.ComprehensiveRegionProperties;

            var logger = new SarifLogger(writer,
                                         LogFilePersistenceOptions.None,
                                         dataToInsert,
                                         closeWriterOnDispose: false);

            using var context = new AnalyzeContext
            {
                TargetUri = new Uri($"/notreeindex/{Guid.NewGuid()}.test", UriKind.Relative),
                FileContents = "foo",
                Logger = logger,
                DataToInsert = dataToInsert,
                FileRegionsCache = new FileRegionsCache(),
            };

            var disabledSkimmers = new HashSet<string>();
            ISet<Skimmer<AnalyzeContext>> skimmers = CreateSkimmers(RE2Regex.Instance);
            IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = PatternMatcher.AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, skimmers, disabledSkimmers);

            logger.AnalysisStarted();
            FileRegionsCache.Instance.ClearCache();
            PatternMatcher.AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers);
            logger.AnalysisStopped(RuntimeConditions.None);

            logger.Dispose();
            writer.Flush();
            ms.Position = 0;

            var sarifLog = SarifLog.Load(ms);

            sarifLog.Runs[0].Results.Should().HaveCount(1);
            Result result = sarifLog.Runs[0].Results[0];

            PhysicalLocation physicalLocation = result.Locations[0].PhysicalLocation;
            physicalLocation.Region.Should().NotBeNull();
            physicalLocation.ContextRegion.Should().NotBeNull();
        }

        private static ISet<Skimmer<AnalyzeContext>> CreateSkimmers(IRegex engine)
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
            string searchDefinitionsPath = Path.GetFullPath(Guid.NewGuid().ToString());

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
            mockFileSystem.Setup(x => x.FileReadAllText(searchDefinitionsPath)).Returns(definitionsText);

            // Acquire skimmers for searchers
            return PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                    mockFileSystem.Object,
                    new string[] { searchDefinitionsPath },
                    engine);
        }

        private static void RunAnalyzeCommand(IRegex engine)
        {
            var testLogger = new TestLogger();
            ISet<Skimmer<AnalyzeContext>> skimmers = CreateSkimmers(engine);

            FlexString fileContents = "bar foo foo";
            string scanTargetFileName = Path.Combine(@"C:\", Guid.NewGuid().ToString() + ".test");

            AnalyzeCommand.Analyze(context: new AnalyzeContext
            {
                Logger = testLogger,
                Skimmers = skimmers,
                FileContents = fileContents,
                TimeoutInMilliseconds = 1000,
                TargetUri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
            });

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
            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            ISet<Skimmer<AnalyzeContext>> skimmers = CreateSkimmers(engine);

            string scanTargetFileName = Path.Combine(Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";
            FlexString fixedFileContents = "bar bar bar";

            var context = new AnalyzeContext()
            {
                TargetUri = new Uri(scanTargetFileName, UriKind.Relative),
                FileContents = fileContents,
                Logger = testLogger,
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
    }
}
