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
        public void AnalyzeCommand_IntrafileBasic()
        {
            string definitionsText = GetIntrafileRuleDefinition();

            string fileContents = "unused leading space" + Environment.NewLine +
                                  "secret1" + Environment.NewLine +
                                  "host1" + Environment.NewLine +
                                  "id1" + Environment.NewLine +
                                  "unused trailing space";

            SarifLog sarifLog = RunAnalyzeCommand(definitionsText, fileContents);
            sarifLog.Should().NotBeNull();
            sarifLog.Runs?[0].Results?.Count.Should().Be(1);

            Result result = sarifLog.Runs?[0].Results?[0];

            result.Should().NotBeNull();
            result.Locations?[0].PhysicalLocation?.Region?.StartLine.Should().Be(2);
            result.Locations?[0].PhysicalLocation?.Region?.EndLine.Should().Be(4);
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

            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);

            mockFileSystem.Setup(x => x.FileReadAllText(It.IsAny<string>()))
                .Returns<string>((path) =>
                                    {
                                        return path == scanTargetPath ?
                                          fileContents :
                                          definitionsText;
                                    });

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

        private static string GetIntrafileRuleDefinition()
        {
            var definitions = new SearchDefinitions()
            {
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
                                IntrafileRegexes = new List<string>()
                                {
                                    "(?P<id>id[0-9])",
                                    "(?P<host>host[0-9])",
                                    "(?P<secret>secret[0-9])"
                                },
                            }
                        })
                    }
                })
            };

            return JsonConvert.SerializeObject(definitions);
        }
    }
}
