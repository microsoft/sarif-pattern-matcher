// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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
using Xunit.Sdk;

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
        public void AnalyzeCommand_SniffLiterals()
        {
            string contents = "foo";
            string contentsRegex = $"(?P<secret>{contents})";

            foreach (bool enableSniffLiterals in new[] { true, false })
            {
                string sniffThatFilters = $"{Guid.NewGuid()}";
                foreach (string sniffLiteral in new[] { "foo", "", sniffThatFilters, null })
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
                                        ContentsRegex = contentsRegex,
                                        SniffLiterals = new List<string>(new[] { sniffLiteral }),
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

                    string scanTargetFileName = Path.Combine(@"C:\", Guid.NewGuid().ToString() + ".test");
                    FlexString fileContents = $"{Guid.NewGuid} {contents} {contents}";
                    FlexString fixedFileContents = $" {Guid.NewGuid} {Guid.NewGuid} {Guid.NewGuid} ";

                    var stream = new MemoryStream(Encoding.Unicode.GetBytes(fileContents));
                    stream.Position = 0;
                    mockFileSystem.Setup(x => x.FileOpenRead(scanTargetFileName)).Returns(stream);

                    var target = new EnumeratedArtifact(FileSystem.Instance)
                    {
                        Uri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                        Contents = fileContents,
                    };

                    var context = new AnalyzeContext()
                    {
                        TargetsProvider = new ArtifactProvider(new[] { target }),
                        EnableSniffLiterals = enableSniffLiterals,
                        Logger = testLogger,
                    };

                    var options = new AnalyzeOptions
                    {
                        PluginFilePaths = new[] { searchDefinitionsPath }
                    };

                    var analyzeCommand = new AnalyzeCommand(fileSystem: mockFileSystem.Object);
                    int result = analyzeCommand.Run(options, ref context);
                    context.ValidateCommandExecution(result);

                    int resultCount = !enableSniffLiterals
                        ? 2
                        : sniffLiteral == sniffThatFilters ? 0 : 2;

                    if (resultCount > 0 || !enableSniffLiterals)
                    {
                        testLogger.Results.Should().NotBeNull();
                        testLogger.Results.Count.Should().Be(resultCount);
                    }
                    else
                    {
                        testLogger.Results.Should().BeNull();
                    }
                }
            }
        }

        [Trait(TestTraits.WindowsOnly, "true")]
        public void AnalyzeCommand_SniffRegex()
        {
            var inMemoryLogger = new MemoryStreamSarifLogger();
            var skimmers = new List<Skimmer<AnalyzeContext>> { new SpamTestRule() };

            var target = new EnumeratedArtifact(FileSystem.Instance)
            {
                Uri = new Uri(Path.Combine(Environment.CurrentDirectory, "c", "FireOneError.txt"), UriKind.Absolute),
                Contents = $"Will fire a single error due to the file name. ",
            };

            var context = new AnalyzeContext
            {
                Skimmers = skimmers,
                Logger = inMemoryLogger,
                SniffRegex = "Will fire", // Will match target contents above.
                TargetsProvider = new ArtifactProvider(new[] { target }),
                RegexEngine = RegexEngine.IronRE2
            };

            var command = new AnalyzeCommand();
            int result = command.Run(options: null, ref context);
            context.ValidateCommandExecution(result);

            var sarifLog = inMemoryLogger.ToSarifLog();
            sarifLog.Runs?[0]?.Results?.Count().Should().Be(1);

            inMemoryLogger = new MemoryStreamSarifLogger();
            context = new AnalyzeContext
            {
                Skimmers = skimmers,
                Logger = inMemoryLogger,
                SniffRegex = "Won't fire",
                TargetsProvider = new ArtifactProvider(new[] { target }),
                RegexEngine = RegexEngine.IronRE2
            };

            command = new AnalyzeCommand();
            result = command.Run(options: null, ref context);
            context.ValidateCommandExecution(result);

            sarifLog = inMemoryLogger.ToSarifLog();
            sarifLog.Runs?[0]?.Results?.Count().Should().Be(0);
        }

        [Fact(Skip = "Recent file regions cache change broke this test.")]
        public void AnalyzeCommand_InMemoryExceptionWhileAnalyzing()
        {
            OptionallyEmittedData toInsert = OptionallyEmittedData.Hashes;

            var inMemoryLogger = new MemoryStreamSarifLogger(dataToInsert: toInsert);

            var skimmers = new List<Skimmer<AnalyzeContext>> { new SpamTestRule() };

            var target = new EnumeratedArtifact(FileSystem.Instance)
            {
                Uri = new Uri("c:\\FireOneWarning.txt", UriKind.Absolute),
                Contents = $"Will fire a single warning due to the file name. " +
                           $"Will fire two errors due to this content: ' foo foo '.",
            };

            var context = new AnalyzeContext
            {
                Skimmers = skimmers,
                Logger = inMemoryLogger,
                DataToInsert = toInsert,
                TargetsProvider = new ArtifactProvider(new[] { target }),
            };

            context.Policy.SetProperty(TestRule.Behaviors, TestRuleBehaviors.RaiseExceptionInvokingAnalyze);

            var command = new AnalyzeCommand();

            int result = command.Run(options: null, ref context);
            context.RuntimeErrors.Fatal().Should().Be(RuntimeConditions.ExceptionInSkimmerAnalyze);
            result.Should().Be(CommandBase.FAILURE);

            var sarifLog = inMemoryLogger.ToSarifLog();

            // One artifact for the scan target, the other for the top
            // frame of the exception raised by the rule.
            sarifLog.Runs?[0].Artifacts.Should().HaveCount(2);

            // We generate 3 hash kinds by default for every artifact.
            sarifLog.Runs?[0].Artifacts[0].Hashes.Count.Should().Be(3);
            sarifLog.Runs?[0].Artifacts[1].Hashes.Count.Should().Be(3);
        }

        [Fact]
        public void AnalyzeCommand_TracesInMemory()
        {
            var testOutput = new StringBuilder();

            foreach (DefaultTraces trace in new[] { DefaultTraces.None, DefaultTraces.ScanTime, DefaultTraces.RuleScanTime, DefaultTraces.PeakWorkingSet })
            {
                foreach (Uri uri in new[] { new Uri(@"c:\doesnotexist.txt"), new Uri(@"doesnotexist.txt", UriKind.Relative) })
                {
                    var command = new TestMultithreadedAnalyzeCommand();

                    var options = new TestAnalyzeOptions
                    {
                        Trace = new[] { trace.ToString() },
                    };

                    var sarifOutput = new StringBuilder();
                    using var writer = new StringWriter(sarifOutput);

                    var logger = new SarifLogger(writer,
                                                 run: new Run { Tool = command.Tool },
                                                 levels: BaseLogger.ErrorWarningNote,
                                                 kinds: BaseLogger.Fail);

                    var target = new EnumeratedArtifact(FileSystem.Instance)
                    {
                        Uri = uri,
                        Contents = "Contents."
                    };

                    var context = new TestAnalysisContext
                    {
                        TargetsProvider = new ArtifactProvider(new[] { target }),
                        FailureLevels = BaseLogger.ErrorWarningNote,
                        ResultKinds = BaseLogger.Fail,
                        Logger = logger,
                    };

                    int result = command.Run(options, ref context);
                    context.ValidateCommandExecution(result);

                    SarifLog sarifLog = JsonConvert.DeserializeObject<SarifLog>(sarifOutput.ToString());

                    int validTargetsCount = 1;
                    AnalyzeCommandBaseTests.Validate(sarifLog.Runs?[0], trace, validTargetsCount, testOutput);
                }

                testOutput.Length.Should().Be(0, $"test cases failed : {Environment.NewLine}{testOutput}");
            }
        }

        [Fact(Skip = "Recent file regions cache change broke this test.")]
        public void AnalyzeCommandBase_InMemoryAnalysisGeneratesHashes()
        {
            string expiredSendGridSecret = "SG.LGS6i3i1RnijKO2MvTm9sg.99e5Sv0_K0-deaddeaddeaddeaddeaddead0123dead";
            HashData hashData = HashUtilities.ComputeHashesForText(expiredSendGridSecret);

            var target = new EnumeratedArtifact(FileSystem.Instance)
            {
                Uri = new Uri("Example.txt", UriKind.Relative),
                Contents = expiredSendGridSecret,
            };

            var options = new AnalyzeOptions
            {
                PluginFilePaths = new[] { "SEC101.SecurePlaintextSecrets.json" },
                Trace = new string[] { nameof(DefaultTraces.RuleScanTime) },
            };

            var analyzeCommand = new AnalyzeCommand();

            var sb = new StringBuilder();
            var writer = new StringWriter(sb);
            var run = new Run { Tool = analyzeCommand.Tool };
            var failureLevels = new FailureLevelSet(new[] { FailureLevel.Warning, FailureLevel.Note });

            var logger = new SarifLogger(writer,
                                         run: run,
                                         dataToInsert: OptionallyEmittedData.Hashes,
                                         levels: failureLevels,
                                         kinds: BaseLogger.Fail);

            var context = new AnalyzeContext
            {
                Logger = logger,
                Traces = new HashSet<string>(new[] { "RuleScanTime" }),
                TargetsProvider = new ArtifactProvider(new[] { target }),
                FailureLevels = failureLevels,
                ResultKinds = BaseLogger.Fail,
            };

            int result = analyzeCommand.Run(options, ref context);

            context.RuntimeExceptions?[0].InnerException.Should().BeNull();
            context.RuntimeExceptions?[0].Should().BeNull();
            context.RuntimeErrors.Fatal().Should().Be(0);

            result.Should().Be(CommandBase.SUCCESS);

            SarifLog sarifLog = JsonConvert.DeserializeObject<SarifLog>(sb.ToString());

            sarifLog.Runs?[0].Results.Should().NotBeNull();

            sarifLog.Runs[0].Artifacts.Should().NotBeNull();
            sarifLog.Runs[0].Artifacts[0].Hashes.Should().Equal(hashData.ToDictionary());

            sarifLog.Runs[0].Invocations?[0].ToolExecutionNotifications.Should().NotBeNull();
        }


        [Fact]
        public void AnalyzeCommand_AnalyzeFromContextNoRulesProvided()
        {
            var emptySkimmers = new List<Skimmer<AnalyzeContext>>();

            var target = new EnumeratedArtifact(FileSystem.Instance)
            {
                Uri = new Uri(@"c:\test.txt"),
                Contents = string.Empty
            };

            foreach (List<Skimmer<AnalyzeContext>> skimmers in new[] { null, emptySkimmers })
            {
                var context = new AnalyzeContext
                {
                    Logger = new TestMessageLogger(),
                    CurrentTarget = target,
                    Skimmers = skimmers,
                };

                new AnalyzeCommand().Run(options: null, ref context);
                context.RuntimeErrors.Should().Be(RuntimeConditions.NoRulesLoaded);
            }
        }

        [Fact]
        public void AnalyzeCommand_AnalyzeFromContext_CancelledExternallyMultithreaded()
        {
            CancelledExternallyHelper(iterations: 10, threads: 2);
        }

        [Fact]
        public void AnalyzeCommand_AnalyzeFromContext_CancelledExternallySinglethreaded()
        {
            CancelledExternallyHelper(iterations: 10, threads: 1);
        }

        private void CancelledExternallyHelper(int iterations, int threads)
        {
            using ZipArchive archive = CreateTestZipArchive();

            for (int i = 0; i < iterations; i++)
            {
                var logger = new TestMessageLogger();
                using ZipArchive archiveToAnalyze = CreateTestZipArchive();
                var skimmers = new List<Skimmer<AnalyzeContext>> { new SpamTestRule() };

                ArtifactProvider provider = (threads == 1)
                    ? (ArtifactProvider)new SinglethreadedZipArchiveArtifactProvider(archive, FileSystem.Instance)
                    : new MultithreadedZipArchiveArtifactProvider(archive, FileSystem.Instance);

                var ct = new CancellationTokenSource();
                ct.CancelAfter(TimeSpan.FromMilliseconds(10));

                var context = new AnalyzeContext
                {
                    Logger = logger,
                    Skimmers = skimmers,
                    CancellationToken = ct.Token,
                    Threads = threads,
                    TargetsProvider = provider,
                };

                // The rule will pause for 100 ms giving us time to cancel;
                context.Policy.SetProperty(TestRule.DelayInMilliseconds, 100);
                int result = new AnalyzeCommand().Run(options: null, ref context);

                context.RuntimeExceptions.Should().NotBeNull();
                context.RuntimeExceptions[0].Should().NotBeNull();
                context.RuntimeExceptions[0].GetType().Should().Be(typeof(ExitApplicationException<ExitReason>));
                context.RuntimeExceptions[0].InnerException.Should().NotBeNull();
                context.RuntimeExceptions[0].InnerException.GetType().Should().Be(typeof(TaskCanceledException));

                logger.ConfigurationNotifications.Should().NotBeNull();
                logger.ConfigurationNotifications.Count.Should().Be(1);
                logger.ConfigurationNotifications[0].Descriptor.Id.Should().Be("ERR999.AnalysisCanceled");

                context.RuntimeErrors.HasFlag(RuntimeConditions.AnalysisCanceled).Should().BeTrue();
                result.Should().Be(CommandBase.FAILURE);
            }
        }

        [Fact]
        public void AnalyzeCommand_AnalyzeFromContext_TimesOutMultithreaded()
        {
            TimesOutHelper(iterations: 10, threads: 2);
        }

        [Fact]
        public void AnalyzeCommand_AnalyzeFromContext_TimesOutSinglethreaded()
        {
            TimesOutHelper(iterations: 10, threads: 1);
        }

        private void TimesOutHelper(int iterations, int threads)
        {
            using ZipArchive archive = CreateTestZipArchive();

            for (int i = 0; i < iterations; i++)
            {
                var logger = new TestMessageLogger();
                var skimmers = new List<Skimmer<AnalyzeContext>> { new SpamTestRule() };

                ArtifactProvider provider = (threads == 1)
                    ? (ArtifactProvider)new SinglethreadedZipArchiveArtifactProvider(archive, FileSystem.Instance)
                    : new MultithreadedZipArchiveArtifactProvider(archive, FileSystem.Instance);

                var context = new AnalyzeContext
                {
                    Logger = logger,
                    Skimmers = skimmers,
                    Threads = threads,
                    TargetsProvider = provider,
                    TimeoutInMilliseconds = 15,
                };

                // The rule will pause for 100 ms, provoking our 5 ms timeout;
                context.Policy.SetProperty(TestRule.DelayInMilliseconds, 100);

                int result = new AnalyzeCommand().Run(options: null, ref context);
                context.RuntimeExceptions.Should().BeNull();
                (context.RuntimeErrors & RuntimeConditions.AnalysisTimedOut).Should().Be(RuntimeConditions.AnalysisTimedOut);
                result.Should().Be(CommandBase.FAILURE);
            }
        }

        [Fact]
        public void AnalyzeCommand_AnalyzeFromContext_RetrievedFromZippedContent()
        {
            var badlyBehavedRule = new BadlyBehavedRule();

            // Initialize a logger to receive callbacks for all results, notifications, etc.
            var logger = new TestMessageLogger();

            // Initialize and manage a set of skimmers to apply to every scan targets.
            var skimmers = new List<Skimmer<AnalyzeContext>>
            {
                new SpamTestRule(),
                badlyBehavedRule,
            };

            // Retrieve the zip archive with all scan targets.
            using ZipArchive archiveToAnalyze = CreateTestZipArchive();

            /* We will use a special zip archive enumerator below. But here's
             * how you could create a provider manually using a generic pattern.
             *
                var enumeratedArtifacts = new List<EnumeratedArtifact>();

                foreach (ZipArchiveEntry entry in archiveToAnalyze.Entries)
                {
                    enumeratedArtifacts.Add(new EnumeratedArtifact
                    {
                        Uri = new Uri(entry.FullName, UriKind.RelativeOrAbsolute),
                        Stream = entry.Open()
                    });
                }
                var unusedArtifactsProvider = new ArtifactProvider(enumeratedArtifacts);
            *
            */

            // Initialize an 'analyze command context' object that holds all config.
            var context = new AnalyzeContext
            {
                // Logger, rules and scan targets.
                Logger = logger,
                Skimmers = skimmers,
                TargetsProvider = new MultithreadedZipArchiveArtifactProvider(archiveToAnalyze, FileSystem.Instance),

                // Execution configuration.
                Threads = 20,
                TimeoutInMilliseconds = 1000 * 60 * 2,
                CancellationToken = default,

                // Optional configuration for enriching output.
                DataToInsert = OptionallyEmittedData.Hashes | OptionallyEmittedData.Guids,

                Traces = new StringSet(new[] { nameof(DefaultTraces.ScanTime) }),
            };

            // OPTIONAL: Turn off a badly behaved rule. You could
            //           also simply omit it from the skimmers set.
            PerLanguageOption<RuleEnabledState> ruleEnabledProperty =
                DefaultDriverOptions.CreateRuleSpecificOption(badlyBehavedRule, DefaultDriverOptions.RuleEnabled);

            context.Policy.SetProperty(ruleEnabledProperty, RuleEnabledState.Disabled);

            // Perform the analysis. 
            int result = CommandBase.FAILURE;
            try
            {
                result = new AnalyzeCommand().Run(options: null, ref context);
            }
            catch (Exception)
            {
                // This code path should never get hit. It indicates a catastrophic condition
                // in the scanner. We could log this and generate telemetry for creating 
                // a service incident here.
                false.Should().BeTrue();
            }

            context.RuntimeExceptions?[0].InnerException.Should().BeNull();
            context.RuntimeExceptions.Should().BeNull();

            // Config notifications relate specifically to how you've configured analysis.
            // The scanner will emit a notification for every disabled check.
            logger.ConfigurationNotifications.Should().NotBeNull();
            logger.ConfigurationNotifications.Count.Should().Be(1);
            logger.ConfigurationNotifications[0].Descriptor.Id.Should().Be("WRN999.RuleExplicitlyDisabled");

            // Rule disablement is also reflected as a bit in our return value.

            RuntimeConditions conditions =
                RuntimeConditions.RuleWasExplicitlyDisabled |
                RuntimeConditions.OneOrMoreWarningsFired |
                RuntimeConditions.OneOrMoreErrorsFired;

            context.RuntimeExceptions.Should().BeNull();
            context.RuntimeErrors.Should().Be(conditions);
            result.Should().Be(CommandBase.SUCCESS);

            /* Here's how it looks for an entirely clean run.
             * 
             *      context.RuntimeErrors.Should().Be(CommandBase.SUCCESS);
             *      
             */

            int expectedResultsCount = DEFAULT_TARGETS_COUNT + (DEFAULT_FOO_COUNT * ALL_TARGETS_COUNT);
            logger.Results.Count.Should().Be(expectedResultsCount);
        }

        // We create one each of scan targets named in a way to produce an error,
        // a warning, and a note. The default configuration enables errors/warnings only.
        private const int NOTE_TARGETS = 1;
        private const int WARN_TARGETS = 1;
        private const int ERROR_TARGETS = 1;
        private const int DEFAULT_TARGETS_COUNT = ERROR_TARGETS + WARN_TARGETS;
        private const int ALL_TARGETS_COUNT = ERROR_TARGETS + WARN_TARGETS + NOTE_TARGETS;

        // A default # of 'foo' tokens in each scan target, each of which will generate an error.
        private const int DEFAULT_FOO_COUNT = 2;

        private static ZipArchive CreateTestZipArchive(int fooInstancesPerTarget = DEFAULT_FOO_COUNT)
        {
            const string FOO = " foo ";

            var fooString = new StringBuilder();
            for (int i = 0; i < fooInstancesPerTarget; i++)
            {
                fooString.Append(FOO);
            }

            var stream = new MemoryStream();
            using (var populateArchive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
            {
                ZipArchiveEntry entry = populateArchive.CreateEntry("error.txt", CompressionLevel.NoCompression);
                using (var errorWriter = new StreamWriter(entry.Open()))
                {
                    errorWriter.WriteLine($"Generates an error and an error for each of : {fooString}");
                }

                ZipArchiveEntry warningEntry = populateArchive.CreateEntry("warning.txt", CompressionLevel.NoCompression);
                using (var warningWriter = new StreamWriter(warningEntry.Open()))
                {
                    warningWriter.WriteLine($"Generates a warning and an error for each of : {fooString}");
                }

                ZipArchiveEntry noteEntry = populateArchive.CreateEntry("note.txt", CompressionLevel.NoCompression);
                using (var noteWriter = new StreamWriter(noteEntry.Open()))
                {
                    noteWriter.WriteLine($"Generates a note and an error for each of : {fooString}");
                }
            }

            stream.Flush();
            stream.Position = 0;

            return new ZipArchive(stream, ZipArchiveMode.Read); ;
        }

        [Fact]
        public void AnalyzeCommand_AnalyzeFromContext_EnumeratedArtifact()
        {
            var logger = new TestMessageLogger();
            var skimmers = new List<Skimmer<AnalyzeContext>>
            {
                new SpamTestRule()
            };

            const string FOO = " foo ";
            string[] fooInstances = { FOO, FOO, FOO };
            string fooString = string.Join(' ', fooInstances);

            var artifacts = new EnumeratedArtifact[]
            {
                new EnumeratedArtifact(FileSystem.Instance)
                {
                    Uri = new Uri("c:\\FireOneWarning.txt", UriKind.Absolute),
                    Contents = $"Will fire a single warning due to the file name. " +
                           $"Will fire two errors due to this content: {fooString}.",
                }
            };

            var artifactProvider = new ArtifactProvider(artifacts);

            var context = new AnalyzeContext
            {
                Logger = logger,
                Skimmers = skimmers,
                TargetsProvider = artifactProvider,
            };

            int result = new AnalyzeCommand().Run(options: null, ref context);
            result.Should().Be(AnalyzeCommand.SUCCESS);
            context.RuntimeErrors.Should().Be(RuntimeConditions.OneOrMoreErrorsFired | RuntimeConditions.OneOrMoreWarningsFired);
            logger.Results.Count.Should().Be(artifacts.Length + fooInstances.Length);
        }

        [Fact]
        public void AnalyzeCommand_SimpleAnalysis()
        {
            List<IRegex> regexList;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                regexList = new List<IRegex>
                {
                    RE2Regex.Instance,
                    DotNetRegex.Instance,
                    CachedDotNetRegex.Instance,
                    IronRE2Regex.Instance,
                };
            }
            else
            {
                regexList = new List<IRegex>
                {
                    IronRE2Regex.Instance,
                };
            }

            foreach (IRegex regex in regexList)
            {
                RunAnalyzeCommand(regex);
            }
        }

        [Fact]
        public void AnalyzeFileCommand_SimpleAnalysis()
        {
            List<IRegex> regexList;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                regexList = new List<IRegex>
                {
                    RE2Regex.Instance,
                    DotNetRegex.Instance,
                    CachedDotNetRegex.Instance,
                    IronRE2Regex.Instance,
                };
            }
            else
            {
                regexList = new List<IRegex>
                {
                    IronRE2Regex.Instance,
                };
            }

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
            var tool = Tool.CreateFromAssemblyData();
            ISet<Skimmer<AnalyzeContext>> skimmers = PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                mockFileSystem.Object,
                new string[] { searchDefinitionsPath },
                tool,
                IronRE2Regex.Instance);

            string scanTargetFileName = Path.Combine(Environment.CurrentDirectory, "C", Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";
            FlexString fixedFileContents = "bar bar bar";

            var target = new EnumeratedArtifact(mockFileSystem.Object)
            {
                Uri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                Contents = fileContents,
            };

            var context = new AnalyzeContext()
            {
                CurrentTarget = target,
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

            var tool = Tool.CreateFromAssemblyData();

            // Acquire skimmers for searchers
            ISet<Skimmer<AnalyzeContext>> skimmers = PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                mockFileSystem.Object,
                new string[] { searchDefinitionsPath },
                tool,
                IronRE2Regex.Instance);

            string scanTargetFileName = Path.Combine(Environment.CurrentDirectory, "C", Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";
            FlexString fixedFileContents = "bar bar bar";

            var target = new EnumeratedArtifact(FileSystem.Instance)
            {
                Uri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                Contents = fileContents,
            };

            var context = new AnalyzeContext()
            {
                CurrentTarget = target,
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
                ExtensionName = "RedactSensitiveData",
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

            var run = new Run { Tool = Tool.CreateFromAssemblyData() };

            // Acquire skimmers for searchers.
            ISet<Skimmer<AnalyzeContext>> skimmers =
                PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(mockFileSystem.Object,
                                                                                 new string[] { searchDefinitionsPath },
                                                                                 run.Tool,
                                                                                 IronRE2Regex.Instance);

            string scanTargetFileName = $"C:\\{Guid.NewGuid()}.test";
            FlexString fileContents = $"{secretText}bar1{Environment.NewLine} {secretText}bar2 {Environment.NewLine}3{secretText}bar";

            var sb = new StringBuilder();
            var writer = new StringWriter(sb);

            var logger = new SarifLogger(writer,
                                         FilePersistenceOptions.None,
                                         OptionallyEmittedData.All,
                                         run: run,
                                         closeWriterOnDispose: true);

            var target = new EnumeratedArtifact(FileSystem.Instance)
            {
                Uri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                Contents = fileContents,
            };

            var context = new AnalyzeContext()
            {
                Logger = logger,
                RedactSecrets = true,
                DataToInsert = OptionallyEmittedData.All,
                CurrentTarget = target,
                Skimmers = skimmers,
                TargetsProvider = new ArtifactProvider(new[] { target }),
            };

            var disabledSkimmers = new HashSet<string>();

            var options = new AnalyzeOptions
            {
                PluginFilePaths = new string[] { },
            };

            int exitCode = new AnalyzeCommand().Run(options: options, ref context);

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

            var tool = Tool.CreateFromAssemblyData();

            // Acquire skimmers for searchers
            ISet<Skimmer<AnalyzeContext>> skimmers = PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                mockFileSystem.Object,
                new string[] { searchDefinitionsPath },
                tool,
                IronRE2Regex.Instance);

            string scanTargetFileName = Path.Combine(Environment.CurrentDirectory, "C", Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";
            FlexString fixedFileContents = "bar bar bar";

            var target = new EnumeratedArtifact(mockFileSystem.Object)
            {
                Uri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                Contents = fileContents,
            };

            var context = new AnalyzeContext()
            {
                CurrentTarget = target,
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

            var run = new Run { Tool = Tool.CreateFromAssemblyData() };

            var logger = new SarifLogger(writer,
                                         FilePersistenceOptions.None,
                                         dataToInsert,
                                         run: run,
                                         closeWriterOnDispose: false);

            var target = new EnumeratedArtifact(FileSystem.Instance)
            {
                Uri = new Uri($"/notreeindex/{Guid.NewGuid()}.test", UriKind.Relative),
                Contents = "foo",
            };

            using var context = new AnalyzeContext
            {
                Logger = logger,
                CurrentTarget = target,
                DataToInsert = dataToInsert,
                RegexEngine = RegexEngine.IronRE2,
            };

            var disabledSkimmers = new HashSet<string>();
            ISet<Skimmer<AnalyzeContext>> skimmers = CreateSkimmers(IronRE2Regex.Instance, run.Tool);
            IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = PatternMatcher.AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, skimmers, disabledSkimmers);

            logger.AnalysisStarted();
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

        private static ISet<Skimmer<AnalyzeContext>> CreateSkimmers(IRegex engine, Tool tool)
        {
            var definitions = new SearchDefinitions()
            {
                ExtensionName = "RulesForTesting",
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
            ISet<Skimmer<AnalyzeContext>> skimmers =
                PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                    mockFileSystem.Object,
                    new string[] { searchDefinitionsPath },
                    tool,
                    engine);

            return skimmers;
        }

        private static void RunAnalyzeCommand(IRegex engine)
        {
            var testLogger = new TestLogger();

            var tool = Tool.CreateFromAssemblyData();

            ISet<Skimmer<AnalyzeContext>> skimmers = CreateSkimmers(engine, tool);

            FlexString fileContents = "bar foo foo";
            string scanTargetFileName = Path.Combine(Environment.CurrentDirectory, "C", Guid.NewGuid().ToString() + ".test");

            var targetsProvider = new ArtifactProvider(new[] {
            new EnumeratedArtifact(FileSystem.Instance)
            {
                Uri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                Contents = fileContents,
            } });

            var context = new AnalyzeContext
            {
                Logger = testLogger,
                Skimmers = skimmers,
                TargetsProvider = targetsProvider,
                TimeoutInMilliseconds = int.MaxValue,
            };

            new AnalyzeCommand().Run(options: null, ref context);

            (context.RuntimeErrors & ~RuntimeConditions.Nonfatal).Should().Be(0);
            testLogger.Results.Should().NotBeNull();
            testLogger.Results.Count.Should().Be(2);

            foreach (Result result in testLogger.Results)
            {
                result.Level.Should().Be(FailureLevel.Error);
                result.Message.Id.Should().Be("Default");
            }
        }

        private static SearchDefinitions CreateFooFindingDefinitions()
        {
            var definitions = new SearchDefinitions()
            {
                ExtensionName = "FooFinding",
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
                            }
                        })
                    }
                })
            };

            return definitions;
        }

        private static void AnalyzeFileCommand(IRegex engine)
        {
            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            var tool = Tool.CreateFromAssemblyData();

            ISet<Skimmer<AnalyzeContext>> skimmers = CreateSkimmers(engine, tool);

            string scanTargetFileName = Path.Combine(Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";

            var target = new EnumeratedArtifact(FileSystem.Instance)
            {
                Uri = new Uri(scanTargetFileName, UriKind.Relative),
                Contents = fileContents,
            };

            var context = new AnalyzeContext()
            {
                CurrentTarget = target,
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

        private Mock<IFileSystem> CreateMockFileSystemForDefinitions(SearchDefinitions definitions, out string definitionsPath)
        {
            string definitionsText = JsonConvert.SerializeObject(definitions);
            string searchDefinitionsPath = Path.GetFullPath(Guid.NewGuid().ToString());

            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
            mockFileSystem.Setup(x => x.FileReadAllText(searchDefinitionsPath)).Returns(definitionsText);

            definitionsPath = searchDefinitionsPath;
            return mockFileSystem;
        }
    }
}
