﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;

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
            result.Should().Be(CommandBase.FAILURE);

            // This validation is sufficient because the null check for an
            // instantiated analyze command verifies that we failed the 
            // CommandLine parsing code and error out before attempting
            // analysis.
            Program.InstantiatedAnalyzeCommand.Should().BeNull();
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
                    fileSize = long.MaxValue,
                    maxFileSize = 1,
                    expectedResult = 2
                },
                new {
                    fileSize = (long)2000,
                    maxFileSize = 1,
                    expectedResult = 2
                },
                new {
                    fileSize = long.MaxValue,
                    maxFileSize = int.MaxValue,
                    expectedResult = 2
                },
                new {
                    fileSize = (long)ulong.MinValue,
                    maxFileSize = 1,
                    expectedResult = 4
                },
                new {
                    fileSize = (long)ulong.MinValue,
                    maxFileSize = 2000,
                    expectedResult = 4
                },
                new {
                    fileSize = (long)ulong.MinValue,
                    maxFileSize = int.MaxValue,
                    expectedResult = 4
                },
                new {
                    fileSize = (long)1024,
                    maxFileSize = int.MaxValue,
                    expectedResult = 4
                },
            };

            foreach (var testCase in testCases)
            {
                SarifLog logFile = RunAnalyzeCommandWithFileSizeLimits(
                    maxFileSizeInKilobytes: testCase.maxFileSize,
                    fileSizeInBytes: testCase.fileSize);

                SarifLog obsoleteOptionLogFile = RunAnalyzeCommandWithFileSizeLimits(
                    maxFileSizeInKilobytes: testCase.maxFileSize,
                    fileSizeInBytes: testCase.fileSize,
                    shouldUseObsoleteOption: true);

                logFile.Runs.Count.Should().Be(1);
                logFile.Runs[0].Results.Count.Should().Be(testCase.expectedResult);
                obsoleteOptionLogFile.Runs.Count.Should().Be(1);
                obsoleteOptionLogFile.Runs[0].Results.Count.Should().Be(testCase.expectedResult);
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
                fileSizeInBytes: long.MaxValue);

            SarifLog sarifLogWithLargeFileIncluded = RunAnalyzeCommandWithFileSizeLimits(
                maxFileSizeInKilobytes: 1024,
                fileSizeInBytes: 0);

            SarifLog sarifLogOnlySmallFile = RunAnalyzeCommand(
                definitionsText,
                fileContents);

            sarifLogWithLargeFileExcluded.Should().NotBeNull();
            sarifLogWithLargeFileExcluded.Runs?[0].Results?.Count.Should().Be(2);
            sarifLogWithLargeFileIncluded.Should().NotBeNull();
            sarifLogWithLargeFileIncluded.Runs?[0].Results?.Count.Should().Be(4);
            sarifLogWithLargeFileIncluded.Runs[0].Artifacts.Count.Should().Be(2);

            Assert.True(string.Equals(sarifLogWithLargeFileIncluded.Runs[0].Artifacts[0].Location.Uri, smallTargetPath) ||
                string.Equals(sarifLogWithLargeFileIncluded.Runs[0].Artifacts[0].Location.Uri, largeTargetPath));

            Assert.True(string.Equals(sarifLogWithLargeFileIncluded.Runs[0].Artifacts[1].Location.Uri, smallTargetPath) ||
                string.Equals(sarifLogWithLargeFileIncluded.Runs[0].Artifacts[1].Location.Uri, largeTargetPath));

            sarifLogWithLargeFileExcluded.Runs[0].Results[0].Locations.Should()
                .BeEquivalentTo(sarifLogOnlySmallFile.Runs[0].Results[0].Locations);

            sarifLogWithLargeFileExcluded.Runs[0].Results[1].Locations.Should()
                .BeEquivalentTo(sarifLogOnlySmallFile.Runs[0].Results[1].Locations);

            sarifLogWithLargeFileExcluded.Runs[0].Artifacts.Count.Should().Be(1);

            Assert.True(string.Equals(sarifLogWithLargeFileExcluded.Runs[0].Artifacts[0].Location.Uri, smallTargetPath) &&
                !string.Equals(sarifLogWithLargeFileExcluded.Runs[0].Artifacts[0].Location.Uri, largeTargetPath));
        }

        [Fact]
        public void AnalyzeCommand_ShouldThrowExceptionForConflictingFileSizeOptions()
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
                .Returns<string>((path) => { return GetSharedStrings(); });

            Program.FileSystem = mockFileSystem.Object;

            string tempFileName = Path.GetTempFileName();
            string sarifLogFileName = $"{tempFileName}.sarif";

            string[] args = new[]
            {
                "analyze",
                largeTargetPath,
                smallTargetPath,
                $"-d", searchDefinitionsPath,
                $"-o", sarifLogFileName,
                $"--file-size-in-kb", fileSizeInKilobytes.ToString(),
                $"--max-file-size-in-kb", maxFileSizeInKilobytes.ToString(),
            };

            int result = Program.Main(args);
            result.Should().Be(1);

            Program.InstantiatedAnalyzeCommand.Should().NotBeNull();
        }

        private SarifLog RunAnalyzeCommand(string definitionsText, string fileContents)
        {
            string sarifOutput;
            string rootDirectory = @"e:\repros";
            string scanTargetName = SmallTargetName;
            string scanTargetPath = Path.Combine(rootDirectory, scanTargetName);
            string searchDefinitionsPath = @$"c:\{Guid.NewGuid()}.json";

            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.DirectoryExists(rootDirectory)).Returns(true);
            mockFileSystem.Setup(x => x.DirectoryEnumerateFiles(rootDirectory,
                                                                scanTargetName,
                                                                It.IsAny<SearchOption>()))
                                                                    .Returns(new[] { scanTargetPath });

            // Search definitions location and loading
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
            mockFileSystem.Setup(x => x.FileReadAllText(It.IsAny<string>()))
                .Returns<string>((path) =>
                                    {
                                        return path == scanTargetPath ?
                                          fileContents :
                                          definitionsText;
                                    });

            // Shared strings location and loading
            mockFileSystem.Setup(x => x.FileReadAllLines(It.IsAny<string>()))
                .Returns<string>((path) => { return GetSharedStrings(); });

            mockFileSystem.Setup(x => x.FileWriteAllText(It.IsAny<string>(), It.IsAny<string>()))
                .Callback(new Action<string, string>((path, logText) => { sarifOutput = logText; }));

            mockFileSystem.Setup(x => x.FileInfoLength(SmallTargetName)).Returns(fileContents.Length);

            Program.FileSystem = mockFileSystem.Object;

            string tempFileName = Path.GetTempFileName();
            string sarifLogFileName = $"{tempFileName}.sarif";
            SarifLog sarifLog = null;

            try
            {
                string[] args = new[]
                {
                    "analyze",
                    scanTargetPath,
                    $"-d", searchDefinitionsPath,
                    $"-o", sarifLogFileName,
                };

                int result = Program.Main(args);
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

        private SarifLog RunAnalyzeCommandWithFileSizeLimits(
            int maxFileSizeInKilobytes,
            long fileSizeInBytes,
            bool shouldUseObsoleteOption = false)
        {
            string definitionsText = GetIntrafileRuleDefinition();

            string fileContents = "unused leading space  \r\n" +
                                  " secret1              \r\n" +
                                  " host1                \r\n" +
                                  " id1                  \r\n" +
                                  " secret2              \r\n" +
                                  "unused trailing space \r\n";
            string sarifOutput;
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
                .Returns<string>((path) =>
                {
                    return (path == smallTargetPath || path == largeTargetPath) ?
                      fileContents :
                      definitionsText;
                });

            // Shared strings location and loading
            mockFileSystem.Setup(x => x.FileReadAllLines(It.IsAny<string>()))
                .Returns<string>((path) => { return GetSharedStrings(); });

            mockFileSystem.Setup(x => x.FileWriteAllText(It.IsAny<string>(), It.IsAny<string>()))
                .Callback(new Action<string, string>((path, logText) => { sarifOutput = logText; }));

            mockFileSystem.Setup(x => x.FileInfoLength(smallTargetPath)).Returns(fileContents.Length);
            mockFileSystem.Setup(x => x.FileInfoLength(largeTargetPath)).Returns(fileSizeInBytes);

            Program.FileSystem = mockFileSystem.Object;

            string tempFileName = Path.GetTempFileName();
            string sarifLogFileName = $"{tempFileName}.sarif";
            SarifLog sarifLog = null;

            try
            {
                string[] args;
                if (shouldUseObsoleteOption)
                {
                    args = new[]
                    {
                        "analyze",
                        largeTargetPath,
                        smallTargetPath,
                        $"-d", searchDefinitionsPath,
                        $"-o", sarifLogFileName,
                        $"--file-size-in-kb", maxFileSizeInKilobytes.ToString(),
                    };
                }
                else
                {
                    args = new[]
                    {
                        "analyze",
                        largeTargetPath,
                        smallTargetPath,
                        $"-d", searchDefinitionsPath,
                        $"-o", sarifLogFileName,
                        $"--max-file-size-in-kb", maxFileSizeInKilobytes.ToString(),
                        };
                }

                int result = Program.Main(args);
                result.Should().Be(CommandBase.SUCCESS);

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
    }
}
