// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;

using FluentAssertions;

using Moq;

using Newtonsoft.Json;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    public class AnalyzeCommandTests
    {
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

        private SarifLog RunAnalyzeCommand(string definitionsText, string fileContents)
        {
            string sarifOutput;
            string rootDirectory = @"e:\repros";
            string scanTargetName = $"test.txt";
            string scanTargetPath = @$"{rootDirectory}\{scanTargetName}";
            string searchDefinitionsPath = @$"c:\{Guid.NewGuid()}.json";

            var mockFileSystem = new Mock<IFileSystem>();

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
                    $"-o", sarifLogFileName
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
