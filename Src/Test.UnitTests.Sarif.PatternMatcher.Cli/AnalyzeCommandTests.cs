// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.Driver;

using Moq;

using Newtonsoft.Json;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    public class AnalyzeCommandTests
    {
        private const string SmallTargetName = "smallTarget.txt";
        private const string LargeTargetName = "largeTarget.txt";

        [Fact]
        public void AnalyzeCommand_NoArgumentsInvokesHelp()
        {
            string[] args = Array.Empty<string>();
            Program.ClearUnitTestData();
            int result = Program.Main(args);
            Program.GlobalContext.RuntimeExceptions.Should().BeNull();
            result.Should().Be(CommandBase.SUCCESS);
        }

        [Fact]
        public void AnalyzeCommand_DefinitionsArgumentIsRequired()
        {
            string[] args = new[]
            {
                    "analyze",
                    Guid.NewGuid().ToString(),
                    $"-o", Guid.NewGuid().ToString(),
            };

            Program.ClearUnitTestData();
            int result = Program.Main(args);
            Program.GlobalContext.RuntimeExceptions.Should().NotBeNull();
            var ex = (ExitApplicationException<ExitReason>)Program.GlobalContext.RuntimeExceptions[0];
            ex.ExitReason.Should().Be(ExitReason.NoRulesLoaded);
            result.Should().Be(CommandBase.FAILURE);
        }

        [Fact]
        public void AnalyzeCommand_SingleLineRuleBasic()
        {
            string definitionsText = GetSingleLineRuleDefinition();

            string fileContents = "unused leading space  \r\n" +
                                  " id1 host1 secret1    \r\n" +
                                  " id2 secret2 host2    \r\n" +
                                  " host3 id3 secret3    \r\n" +
                                  " host4 secret3 id4    \r\n" +
                                  " secret5 id5 host5    \r\n" +
                                  " secret6 host6 id6    \r\n" +
                                  "unused trailing space \r\n";

            SarifLog sarifLog = RunAnalyzeCommand(definitionsText, fileContents);
            sarifLog.Should().NotBeNull();

            sarifLog.Runs?[0].Invocations[0].ToolExecutionNotifications.Should().BeNull();
            sarifLog.Runs?[0].Results?.Count.Should().Be(6);

            for (int i = 0; i < sarifLog.Runs[0].Results.Count; i++)
            {
                // Start line is 1-indexed. Add another line to
                // account for the 'unused leading space' line.
                int startLine = i + 2;

                Result result = sarifLog.Runs[0].Results[i];
                Region region = result.Locations?[0].PhysicalLocation?.Region;
                region.Should().NotBeNull();

                int matchLength = "secret1".Length;

                region.EndColumn.Should().Be(region.StartColumn + matchLength);

                region.StartLine.Should().Be(startLine);
                region.EndLine.Should().Be(startLine);
            }
        }

        [Fact]
        public void AnalyzeCommand_IntrafileBasic()
        {
            string definitionsText = GetIntrafileRuleDefinition();

            string fileContents = "unused leading space  \r\n" +
                                  " secret1              \r\n" +
                                  " host1                \r\n" +
                                  " id1                  \r\n" +
                                  " secret2              \r\n" +
                                  "unused trailing space \r\n";

            SarifLog sarifLog = RunAnalyzeCommand(definitionsText, fileContents);
            sarifLog.Should().NotBeNull();
            sarifLog.Runs?[0].Results?.Count.Should().Be(2);

            Result result = sarifLog.Runs[0].Results[0];
            Region region = result.Locations?[0].PhysicalLocation?.Region;
            region.Should().NotBeNull();
            region?.StartLine.Should().Be(2);
            region?.EndLine.Should().Be(2);

            // This is a special check to ensure that our matches don't
            // include region information that derives from unnamed groups,
            // e.g., groups["1].
            region.StartColumn.Should().Be(2);

            result = sarifLog.Runs[0].Results[1];
            region = result.Locations?[0].PhysicalLocation?.Region;
            region.Should().NotBeNull();
            region?.StartLine.Should().Be(5);
            region?.EndLine.Should().Be(5);
            region.StartColumn.Should().Be(2);
        }

        [Fact]
        public void AnalyzeCommand_ShouldAnalyzeTargetWithinSizeLimit()
        {
            var testCases = new[] {
                new {
                    largeFileSize = long.MaxValue,
                    maxFileSize = 1,
                    expectedResult = 2,
                },
                new {
                    largeFileSize = (long)2000,
                    maxFileSize = 1,
                    expectedResult = 2
                },
                new {
                    largeFileSize = long.MaxValue,
                    maxFileSize = int.MaxValue,
                    expectedResult = 2
                },
                new {
                    largeFileSize = (long)ulong.MinValue,
                    maxFileSize = 1,
                    expectedResult = 2
                },
                new {
                    largeFileSize = (long)ulong.MinValue + 1,
                    maxFileSize = 2000,
                    expectedResult = 4
                },
                new {
                    largeFileSize = (long)ulong.MinValue,
                    maxFileSize = int.MaxValue,
                    expectedResult = 2
                },
                new {
                    largeFileSize = (long)1024,
                    maxFileSize = int.MaxValue,
                    expectedResult = 4
                },
            };

            foreach (var testCase in testCases)
            {
                RuntimeConditions runtimeConditions =
                    testCase.expectedResult != 4
                        ? RuntimeConditions.OneOrMoreFilesSkippedDueToExceedingSizeLimits
                        : RuntimeConditions.None;


                if (runtimeConditions == RuntimeConditions.OneOrMoreFilesSkippedDueToExceedingSizeLimits)
                {
                    if (testCase.largeFileSize == 0)
                    {
                        runtimeConditions = RuntimeConditions.OneOrMoreEmptyFilesSkipped;
                    }
                }

                SarifLog logFile =
                    RunAnalyzeCommandWithFileSizeLimits(maxFileSizeInKilobytes: testCase.maxFileSize,
                                                        testCase.largeFileSize,
                                                        runtimeConditions);


                logFile.Runs.Count.Should().Be(1);
                logFile.Runs[0].Results.Count.Should().Be(testCase.expectedResult);
            }
        }

        [Fact]
        public void AnalyzeCommand_ShouldProduceResultsForTargetsInFileSizeRange()
        {
            string rootDirectory = @"e:\repros";
            string smallTargetPath = Path.Combine(rootDirectory, SmallTargetName);
            string largeTargetPath = Path.Combine(rootDirectory, LargeTargetName);

            string definitionsText = GetIntrafileRuleDefinition();

            string fileContents = "unused leading space  \r\n" +
                                  " secret1              \r\n" +
                                  " host1                \r\n" +
                                  " id1                  \r\n" +
                                  " secret2              \r\n" +
                                  "unused trailing space \r\n";

            SarifLog sarifLogWithLargeFileExcluded = RunAnalyzeCommandWithFileSizeLimits(
                maxFileSizeInKilobytes: 1024,
                largeFileSizeInBytes: long.MaxValue,
                RuntimeConditions.OneOrMoreFilesSkippedDueToExceedingSizeLimits);

            sarifLogWithLargeFileExcluded.Should().NotBeNull();
            sarifLogWithLargeFileExcluded.Runs?[0].Results?.Count.Should().Be(2);
            sarifLogWithLargeFileExcluded.Runs?[0].Artifacts?.Count.Should().Be(2);
            sarifLogWithLargeFileExcluded.Runs[0].Results
                .Where(r => r.Locations[0].PhysicalLocation.ArtifactLocation.Uri.LocalPath.EndsWith(SmallTargetName))
                .Count().Should().Be(2);

            SarifLog sarifLogWithLargeFileIncluded = RunAnalyzeCommandWithFileSizeLimits(
                maxFileSizeInKilobytes: 1,
                largeFileSizeInBytes: 1,
                RuntimeConditions.None);

            sarifLogWithLargeFileIncluded.Should().NotBeNull();
            sarifLogWithLargeFileIncluded.Runs?[0].Results?.Count.Should().Be(4);
            sarifLogWithLargeFileIncluded.Runs[0].Artifacts.Count.Should().Be(3);

            Assert.True(string.Equals(sarifLogWithLargeFileIncluded.Runs[0].Artifacts[0].Location.Uri, smallTargetPath) ||
                string.Equals(sarifLogWithLargeFileIncluded.Runs[0].Artifacts[0].Location.Uri, largeTargetPath));

            Assert.True(string.Equals(sarifLogWithLargeFileIncluded.Runs[0].Artifacts[1].Location.Uri, smallTargetPath) ||
                string.Equals(sarifLogWithLargeFileIncluded.Runs[0].Artifacts[1].Location.Uri, largeTargetPath));

            SarifLog sarifLogOnlySmallFile = RunAnalyzeCommand(
                definitionsText,
                fileContents);

            sarifLogOnlySmallFile.Runs[0].Results
                .Where(r => r.Locations[0].PhysicalLocation.ArtifactLocation.Uri.LocalPath.EndsWith(SmallTargetName))
                .Count().Should().Be(2);
        }

        [Fact]
        public void AnalyzeCommand_ShouldErrorOutForConflictingFileSizeOptions()
        {
            int maxFileSizeInKilobytes = 1;
            int fileSizeInKilobytes = 2;

            string rootDirectory = @"e:\repros";
            string smallTargetPath = Path.Combine(rootDirectory, SmallTargetName);
            string largeTargetPath = Path.Combine(rootDirectory, LargeTargetName);
            string searchDefinitionsPath = @$"c:\{Guid.NewGuid()}.json";

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.DirectoryExists(rootDirectory)).Returns(true);
            mockFileSystem.Setup(x => x.DirectoryEnumerateFiles(rootDirectory,
                                                                SmallTargetName,
                                                                It.IsAny<SearchOption>()))
                                                                    .Returns(new[] { smallTargetPath });
            mockFileSystem.Setup(x => x.DirectoryEnumerateFiles(rootDirectory,
                                                                LargeTargetName,
                                                                It.IsAny<SearchOption>()))
                                                                    .Returns(new[] { largeTargetPath });

            // Search definitions location and loading
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);

            // Shared strings location and loading
            mockFileSystem.Setup(x => x.FileReadAllLines(It.IsAny<string>()))
                .Returns<string>((path) => GetSharedStrings());

            Program.ClearUnitTestData();
            Program.GlobalContext = new AnalyzeContext
            {
                FileSystem = mockFileSystem.Object
            };

            string tempFileName = Path.GetTempFileName();
            string sarifLogFileName = $"{tempFileName}.sarif";

            string[] args = new[]
            {
                "analyze",
                largeTargetPath,
                smallTargetPath,
                $"-p", searchDefinitionsPath,
                $"-o", sarifLogFileName,
                $"--file-size-in-kb", fileSizeInKilobytes.ToString(),
                $"--max-file-size-in-kb", maxFileSizeInKilobytes.ToString(),
            };

            int result = Program.Main(args);
            result.Should().Be(1);
        }


        [Fact]
        public void AnalyzeCommand_FailureLevelShouldBeDefaultUnlessDynamicallyValidated()
        {
            var sb = new StringBuilder();

            var testCases = new[] {
                new {
                    failureLevelConfiguredInDefinitionsJson = FailureLevel.Note,
                    dynamicValidationEnabledOnCommandLine = false,
                    expectedFailureLevelIfNoValidatorsExist = FailureLevel.Note,
                    expectedFailureLevelIfOnlyStaticValidatorExists = FailureLevel.Note,
                    expectedFailureLevelIfStaticAndDynamicValidatorExists = FailureLevel.Warning
                },
                new {
                    failureLevelConfiguredInDefinitionsJson = FailureLevel.Warning,
                    dynamicValidationEnabledOnCommandLine = false,
                    expectedFailureLevelIfNoValidatorsExist = FailureLevel.Warning,
                    expectedFailureLevelIfOnlyStaticValidatorExists = FailureLevel.Warning,
                    expectedFailureLevelIfStaticAndDynamicValidatorExists = FailureLevel.Warning
                },
                new {
                    failureLevelConfiguredInDefinitionsJson = FailureLevel.Error,
                    dynamicValidationEnabledOnCommandLine = false,
                    expectedFailureLevelIfNoValidatorsExist = FailureLevel.Error,
                    expectedFailureLevelIfOnlyStaticValidatorExists = FailureLevel.Error,
                    expectedFailureLevelIfStaticAndDynamicValidatorExists = FailureLevel.Warning
                },
                new {
                    failureLevelConfiguredInDefinitionsJson = FailureLevel.Note,
                    dynamicValidationEnabledOnCommandLine = true,
                    expectedFailureLevelIfNoValidatorsExist = FailureLevel.Note,
                    expectedFailureLevelIfOnlyStaticValidatorExists = FailureLevel.Note,
                    expectedFailureLevelIfStaticAndDynamicValidatorExists = FailureLevel.Error
                },
                new {
                    failureLevelConfiguredInDefinitionsJson = FailureLevel.Warning,
                    dynamicValidationEnabledOnCommandLine = true,
                    expectedFailureLevelIfNoValidatorsExist = FailureLevel.Warning,
                    expectedFailureLevelIfOnlyStaticValidatorExists = FailureLevel.Warning,
                    expectedFailureLevelIfStaticAndDynamicValidatorExists = FailureLevel.Error
                },
                new {
                    failureLevelConfiguredInDefinitionsJson = FailureLevel.Error,
                    dynamicValidationEnabledOnCommandLine = true,
                    expectedFailureLevelIfNoValidatorsExist = FailureLevel.Error,
                    expectedFailureLevelIfOnlyStaticValidatorExists = FailureLevel.Error,
                    expectedFailureLevelIfStaticAndDynamicValidatorExists = FailureLevel.Error
                }
            };

            foreach (var testCase in testCases)
            {
                string definitionsText =
                    GetSingleLineRuleDefinitionFailureLevel(testCase.failureLevelConfiguredInDefinitionsJson);

                string testScenarioName = "NoValidatorsExistForMatchExpression";
                SarifLog sarifLog = RunAnalyzeCommandWithDynamicValidation(
                    definitionsText,
                    testScenarioName,
                    testCase.dynamicValidationEnabledOnCommandLine);

                sb = CompareActualAndExpectedFailureLevel(
                    testCase.expectedFailureLevelIfNoValidatorsExist,
                    sarifLog,
                    testScenarioName,
                    testCase.dynamicValidationEnabledOnCommandLine,
                    sb);

                testScenarioName = "StaticValidatorExistsForMatchExpression";
                sarifLog = RunAnalyzeCommandWithDynamicValidation(
                    definitionsText,
                    testScenarioName,
                    testCase.dynamicValidationEnabledOnCommandLine);

                sb = CompareActualAndExpectedFailureLevel(
                    testCase.expectedFailureLevelIfOnlyStaticValidatorExists,
                    sarifLog,
                    testScenarioName,
                    testCase.dynamicValidationEnabledOnCommandLine,
                    sb);

                testScenarioName = "StaticAndDynamicValidatorsExistForMatchExpression";
                sarifLog = RunAnalyzeCommandWithDynamicValidation(
                    definitionsText,
                    testScenarioName,
                    testCase.dynamicValidationEnabledOnCommandLine);

                sb = CompareActualAndExpectedFailureLevel(
                    testCase.expectedFailureLevelIfStaticAndDynamicValidatorExists,
                    sarifLog,
                    testScenarioName,
                    testCase.dynamicValidationEnabledOnCommandLine,
                    sb);
            }

            string result = sb.ToString();
            result.Length.Should().Be(0, because: result);
        }

        private SarifLog RunAnalyzeCommand(string definitionsText, string fileContents)
        {
            string rootDirectory = @"e:\repros";
            string scanTargetName = SmallTargetName;
            string scanTargetPath = Path.Combine(rootDirectory, scanTargetName);
            string searchDefinitionsPath = @$"c:\{Guid.NewGuid()}.json";


            var fvi = FileVersionInfo.GetVersionInfo(this.GetType().Assembly.Location);

            var mockFileSystem = new Mock<IFileSystem>();

            mockFileSystem.Setup(x => x.FileInfoLength(It.IsAny<string>())).Returns(1025);
            mockFileSystem.Setup(x => x.FileVersionInfoGetVersionInfo(It.IsAny<string>())).Returns(fvi);
            mockFileSystem.Setup(x => x.DirectoryExists(rootDirectory)).Returns(true);
            mockFileSystem.Setup(x => x.DirectoryEnumerateFiles(rootDirectory,
                                                                scanTargetName,
                                                                It.IsAny<SearchOption>()))
                                                                    .Returns(new[] { scanTargetPath });

            // Search definitions location and loading
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
            mockFileSystem.Setup(x => x.FileReadAllText(It.IsAny<string>()))
                .Returns<string>((path) => path == scanTargetPath ?
                                          fileContents :
                                          definitionsText);

            // Shared strings location and loading
            mockFileSystem.Setup(x => x.FileReadAllLines(It.IsAny<string>()))
                .Returns<string>((path) => GetSharedStrings());

            mockFileSystem.Setup(x => x.FileInfoLength(SmallTargetName)).Returns(fileContents.Length);

            Program.ClearUnitTestData();
            Program.GlobalContext = new AnalyzeContext
            {
                FileSystem = mockFileSystem.Object
            };

            string tempFileName = Path.GetTempFileName();
            string sarifLogFileName = $"{tempFileName}.sarif";
            SarifLog sarifLog = null;

            try
            {
                string[] args = new[]
                {
                    "analyze",
                    scanTargetPath,
                    $"-p", searchDefinitionsPath,
                    $"-o", sarifLogFileName,
                };

                Program.ClearUnitTestData();
                Program.GlobalContext = new AnalyzeContext
                {
                    FileSystem = mockFileSystem.Object
                };

                int result = Program.Main(args);
                Program.GlobalContext.RuntimeExceptions?[0].Should().BeNull();
                Program.GlobalContext.RuntimeErrors.Should().Be(0);
                result.Should().Be(0);

                sarifLog = JsonConvert.DeserializeObject<SarifLog>(File.ReadAllText(sarifLogFileName));
            }
            finally
            {
                if (File.Exists(tempFileName))
                {
                    File.Delete(tempFileName);
                }

                if (File.Exists(sarifLogFileName))
                {
                    File.Delete(sarifLogFileName);
                }
            }

            return sarifLog;
        }

        private SarifLog RunAnalyzeCommandWithFileSizeLimits(int maxFileSizeInKilobytes,
                                                             long largeFileSizeInBytes,
                                                             RuntimeConditions runtimeConditions = RuntimeConditions.None)
        {
            string definitionsText = GetIntrafileRuleDefinition();

            string smallFileContents = "unused leading space  \r\n" +
                                       " secret1              \r\n" +
                                       " host1                \r\n" +
                                       " id1                  \r\n" +
                                       " secret2              \r\n" +
                                       "unused trailing space \r\n";

            string rootDirectory = @"e:\repros";
            string smallTargetPath = Path.Combine(rootDirectory, SmallTargetName);
            string largeTargetPath = Path.Combine(rootDirectory, LargeTargetName);
            string searchDefinitionsPath = @$"c:\{Guid.NewGuid()}.json";

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.DirectoryExists(rootDirectory)).Returns(true);
            mockFileSystem.Setup(x => x.DirectoryEnumerateFiles(rootDirectory,
                                                                SmallTargetName,
                                                                It.IsAny<SearchOption>()))
                                                                    .Returns(new[] { smallTargetPath });
            mockFileSystem.Setup(x => x.DirectoryEnumerateFiles(rootDirectory,
                                                                LargeTargetName,
                                                                It.IsAny<SearchOption>()))
                                                                    .Returns(new[] { largeTargetPath });

            // Search definitions location and loading
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
            mockFileSystem.Setup(x => x.FileReadAllText(It.IsAny<string>()))
                .Returns<string>((path) => (path == smallTargetPath || path == largeTargetPath)
                        ? smallFileContents
                        : definitionsText);

            // Shared strings location and loading
            mockFileSystem.Setup(x => x.FileReadAllLines(It.IsAny<string>()))
                .Returns<string>((path) => GetSharedStrings());

            string defaultConfigFilePath = Path.GetDirectoryName(typeof(CommandBase).Assembly.Location);
            defaultConfigFilePath = Path.Combine(defaultConfigFilePath, "default.configuration.xml");

            mockFileSystem.Setup(x => x.FileExists(defaultConfigFilePath))
                .Returns(true);

            mockFileSystem.Setup(x => x.FileInfoLength(smallTargetPath)).Returns(smallFileContents.Length);
            mockFileSystem.Setup(x => x.FileInfoLength(largeTargetPath)).Returns(largeFileSizeInBytes);

            Program.ClearUnitTestData();
            Program.GlobalContext = new AnalyzeContext
            {
                FileSystem = mockFileSystem.Object
            };

            string tempFileName = Path.GetTempFileName();
            string sarifLogFileName = $"{tempFileName}.sarif";
            SarifLog sarifLog = null;

            try
            {
                string[] args;

                args = new[]
                {
                        "analyze",
                        largeTargetPath,
                        smallTargetPath,
                        "--insert", "Hashes",
                        "-p", searchDefinitionsPath,
                        "-o", sarifLogFileName,
                        "--max-file-size-in-kb", maxFileSizeInKilobytes.ToString(),
                };

                Program.ClearUnitTestData();
                Program.GlobalContext = new AnalyzeContext
                {
                    FileSystem = mockFileSystem.Object
                };

                int result = Program.Main(args);
                File.Exists(sarifLogFileName).Should().BeTrue();
                sarifLog = JsonConvert.DeserializeObject<SarifLog>(File.ReadAllText(sarifLogFileName));
                sarifLog.Runs[0].Invocations?[0].ToolExecutionNotifications.Should().BeNull();

                Program.GlobalContext.RuntimeErrors.Should().Be(runtimeConditions);
                result.Should().Be(CommandBase.SUCCESS);
            }
            finally
            {
                if (File.Exists(tempFileName))
                {
                    File.Delete(tempFileName);
                }

                if (File.Exists(sarifLogFileName))
                {
                    File.Delete(sarifLogFileName);
                }
            }

            return sarifLog;
        }

        private SarifLog RunAnalyzeCommandWithDynamicValidation(string definitionsText,
                                                                string fileContents,
                                                                bool runDynamicValidation)
        {
            string sarifOutput;
            string rootDirectory = @"e:\repros";
            string scanTargetName = SmallTargetName;
            string scanTargetPath = Path.Combine(rootDirectory, scanTargetName);
            string searchDefinitionsPath = @$"c:\{Guid.NewGuid()}.json";
            string currentDirectory = Directory.GetCurrentDirectory();
            string dllLocation = Path.Combine(currentDirectory, "Test.UnitTests.Sarif.PatternMatcher.Cli.dll");

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.DirectoryExists(rootDirectory)).Returns(true);
            mockFileSystem.Setup(x => x.DirectoryEnumerateFiles(rootDirectory,
                                                                scanTargetName,
                                                                It.IsAny<SearchOption>()))
                                                                    .Returns(new[] { scanTargetPath });

            // Search definitions location and loading
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
            mockFileSystem.Setup(x => x.FileReadAllText(It.IsAny<string>()))
                .Returns<string>((path) => path == scanTargetPath ?
                      fileContents :
                      definitionsText);

            // Shared strings location and loading
            mockFileSystem.Setup(x => x.FileReadAllLines(It.IsAny<string>()))
                .Returns<string>((path) => GetSharedStrings());

            mockFileSystem.Setup(x => x.FileWriteAllText(It.IsAny<string>(), It.IsAny<string>()))
                .Callback(new Action<string, string>((path, logText) => sarifOutput = logText));

            mockFileSystem.Setup(x => x.FileInfoLength(scanTargetPath)).Returns(fileContents.Length);
            mockFileSystem.Setup(x => x.FileExists(@$"c:\Test.UnitTests.Sarif.PatternMatcher.Cli.dll")).Returns(true);
            mockFileSystem.Setup(x => x.AssemblyLoadFrom(It.IsAny<string>())).Returns(Assembly.LoadFrom(dllLocation));

            Program.ClearUnitTestData();
            Program.GlobalContext = new AnalyzeContext
            {
                FileSystem = mockFileSystem.Object
            };

            string tempFileName = Path.GetTempFileName();
            string sarifLogFileName = $"{tempFileName}.sarif";
            SarifLog sarifLog = null;
            string levels = "Error;Warning;Note";

            // Arguments to run static analysis only.
            string[] staticArgs = new[]
                {
                    "analyze",
                    scanTargetPath,
                    $"-p", searchDefinitionsPath,
                    $"-o", sarifLogFileName,
                    "--level", levels,
                    "--rich-return-code"
                };

            // Arguments to run static and dynamic analysis.
            string[] dynamicArgs = new[]
                {
                    "analyze",
                    scanTargetPath,
                    $"-p", searchDefinitionsPath,
                    $"-o", sarifLogFileName,
                    "--level", levels,
                    "--dynamic-validation",
                    "true",
                    "--rich-return-code",
                };

            try
            {
                string[] args = runDynamicValidation ? dynamicArgs : staticArgs;

                int result = Program.Main(args);
                (Program.GlobalContext.RuntimeErrors & ~RuntimeConditions.Nonfatal).Should().Be(0);
                sarifLog = JsonConvert.DeserializeObject<SarifLog>(File.ReadAllText(sarifLogFileName));
                result.Should().Be(0);
            }
            finally
            {
                if (File.Exists(tempFileName))
                {
                    File.Delete(tempFileName);
                }

                if (File.Exists(sarifLogFileName))
                {
                    File.Delete(sarifLogFileName);
                }
            }

            return sarifLog;
        }

        private static StringBuilder CompareActualAndExpectedFailureLevel(
            FailureLevel expectedFailureLevel,
            SarifLog sarifLog,
            string validationScenario,
            bool isDynamicAnalysis,
            StringBuilder stringBuilder)
        {
            stringBuilder ??= new StringBuilder();

            string testScenarioMode = isDynamicAnalysis ?
                    "with dynamic validation enabled" :
                    "without dynamic validation enabled";

            if (sarifLog == null)
            {
                string message = $"SARIF result should not be null for `{validationScenario}` test scenario {testScenarioMode}.";
                stringBuilder = StringBuilderFormatAndAppendNewLine(message, stringBuilder);
            }
            else if (sarifLog.Runs[0].Results?.Count > 0 == false)
            {
                string message = $"No results observed for `{validationScenario}` test scenario {testScenarioMode}.";
                stringBuilder = StringBuilderFormatAndAppendNewLine(message, stringBuilder);
            }
            else if (sarifLog.Runs[0].Results[0].Level != expectedFailureLevel)
            {
                string message = $"Expected `FailureLevel` to be `{expectedFailureLevel}` but found " +
                    $"`{sarifLog.Runs[0]?.Results[0]?.Level}` for `{validationScenario}` test scenario {testScenarioMode}.";

                stringBuilder = StringBuilderFormatAndAppendNewLine(message, stringBuilder);
            }

            return stringBuilder;

        }

        private static StringBuilder StringBuilderFormatAndAppendNewLine(string data, StringBuilder stringBuilder)
        {
            stringBuilder ??= new StringBuilder();

            if (stringBuilder.Length == 0)
            {
                stringBuilder.AppendLine("asserted condition(s) failed:");
            }

            stringBuilder.AppendLine(data);

            return stringBuilder;
        }

        private string[] GetSharedStrings()
        {
            string stringsLocation = this.GetType().Assembly.Location;
            stringsLocation = Path.GetDirectoryName(stringsLocation);
            stringsLocation = Path.Combine(stringsLocation, "SharedStrings.Txt");
            return File.ReadAllLines(stringsLocation);
        }

        private static List<string> GetMultipartRuleRegexes()
        {
            return new List<string>()
            {
                "$MultipartRegexesId",
                "(x|y)?(?P<host>host[0-9])",
                "(x|y)?(?P<secret>secret[0-9])"
            };
        }

        private static string GetIntrafileRuleDefinition()
        {
            string assemblyName = typeof(AnalyzeCommandTests).Assembly.Location;
            assemblyName = Path.GetFileName(assemblyName);
            var definitions = new SearchDefinitions()
            {
                ValidatorsAssemblyName = assemblyName,
                SharedStringsFileName = "SharedStrings.txt",
                ExtensionName = "IntrafileRules",
                Definitions = new List<SearchDefinition>(new[]
                {
                    new SearchDefinition()
                    {
                        Name = "IntrafileRule", Id = "Intrafile1001",
                        Level = FailureLevel.Error,
                        Message = "A problem occurred in '{0:scanTarget}'.",
                        MatchExpressions = new List<MatchExpression>(new[]
                        {
                            new MatchExpression()
                            {
                                IntrafileRegexes = GetMultipartRuleRegexes(),
                            }
                        })
                    }
                })
            };

            return JsonConvert.SerializeObject(definitions);
        }

        private static string GetSingleLineRuleDefinition()
        {
            string assemblyName = typeof(AnalyzeCommandTests).Assembly.Location;
            assemblyName = Path.GetFileName(assemblyName);
            var definitions = new SearchDefinitions()
            {
                ValidatorsAssemblyName = assemblyName,
                SharedStringsFileName = "SharedStrings.txt",
                ExtensionName = "SingleLineDefinition",
                Definitions = new List<SearchDefinition>(new[]
                {

                    new SearchDefinition()
                    {
                        Name = "SingleLineRule", Id = "SingleLine1001",
                        Level = FailureLevel.Error,
                        Message = "A problem occurred in '{0:scanTarget}'.",
                        MatchExpressions = new List<MatchExpression>(new[]
                        {
                            new MatchExpression()
                            {
                                SingleLineRegexes = GetMultipartRuleRegexes(),
                            }
                        })
                    }
                })
            };

            return JsonConvert.SerializeObject(definitions);
        }

        private static string GetSingleLineRuleDefinitionFailureLevel(FailureLevel level)
        {
            string assemblyName = typeof(AnalyzeCommandTests).Assembly.Location;
            assemblyName = Path.GetFileName(assemblyName);
            var definitions = new SearchDefinitions()
            {
                ValidatorsAssemblyName = assemblyName,
                SharedStringsFileName = "SharedStrings.txt",
                ExtensionName = "SingleLineDefinition",

                Definitions = new List<SearchDefinition>(new[]
                {
                    new SearchDefinition()
                    {
                        Name = "FailureLevelTest", Id = "TEST001",
                        Level = level,
                        Message = "A problem occurred in '{0:scanTarget}'.",
                        Description = "Failure Level Testing Rules",
                        MatchExpressions = new List<MatchExpression>(new[]
                        {
                            new MatchExpression()
                            {
                                Id = "TEST001/001",
                                Name ="NoValidatorsExistForMatchExpression",
                                ContentsRegex = "NoValidatorsExistForMatchExpression",
                            },
                            new MatchExpression()
                            {
                                Id = "TEST001/002",
                                Name ="StaticValidatorExistsForMatchExpression",
                                ContentsRegex = "StaticValidatorExistsForMatchExpression",
                            },
                            new MatchExpression()
                            {
                                Id = "TEST001/003",
                                Name ="StaticAndDynamicValidatorsExistForMatchExpression",
                                ContentsRegex = "StaticAndDynamicValidatorsExistForMatchExpression",
                            }
                        })
                    }
                })
            };

            return JsonConvert.SerializeObject(definitions);
        }

        // We create one each of scan targets named in a way to produce an error,
        // a warning, and a note. The default configuration enables errors/warnings only.
        private const int NOTE_TARGETS = 1;
        private const int WARN_TARGETS = 1;
        private const int ERROR_TARGETS = 1;
#pragma warning disable IDE0051 // Remove unused private members
        private const int DEFAULT_TARGETS_COUNT = ERROR_TARGETS + WARN_TARGETS;
        private const int ALL_TARGETS_COUNT = ERROR_TARGETS + WARN_TARGETS + NOTE_TARGETS;
#pragma warning restore IDE0051 // Remove unused private members

        // A default # of 'foo' tokens in each scan target, each of which will generate an error.
        private const int DEFAULT_FOO_COUNT = 2;

#pragma warning disable IDE0051 // Remove unused private members
        private static ZipArchive CreateTestZipArchive(int fooInstancesPerTarget = DEFAULT_FOO_COUNT)
#pragma warning restore IDE0051 // Remove unused private members
        {
            const string FOO = " foo ";

            var fooString = new StringBuilder();
            for (int i = 0; i < fooInstancesPerTarget; i++)
            {
                fooString.Append(FOO);
            }

            var stream = new MemoryStream();
            using (var populateArchive = new ZipArchive(stream, ZipArchiveMode.Update, leaveOpen: true))
            {
                ZipArchiveEntry entry = populateArchive.CreateEntry("error.txt");
                using var errorWriter = new StreamWriter(entry.Open());
                errorWriter.WriteLine($"Generates an error and an error for each of : {fooString}");

                ZipArchiveEntry warningEntry = populateArchive.CreateEntry("warning.txt");
                using var warningWriter = new StreamWriter(warningEntry.Open());
                warningWriter.WriteLine($"Generates a warning and an error for each of : {fooString}");

                ZipArchiveEntry noteEntry = populateArchive.CreateEntry("note.txt");
                using var noteWriter = new StreamWriter(noteEntry.Open());
                noteWriter.WriteLine($"Generates a note and an error for each of : {fooString}");
            }

            stream.Position = 0;
            return new ZipArchive(stream, ZipArchiveMode.Read); ;
        }

    }
}
