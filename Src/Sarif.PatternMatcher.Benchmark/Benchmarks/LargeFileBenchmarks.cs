// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using Moq;

using Newtonsoft.Json;

using Sarif.PatternMatcher.Benchmark;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Benchmark.Benchmarks
{
    public class LargeFileBenchmarks : BenchmarksBase
    {
        public int Run(LargeFileOptions _)
        {
            BenchmarkRunner.Run<LargeFileBenchmarks>();
            return 0;
        }

        private string searchDefinitionsPath;
        private Mock<IFileSystem> fileSystemMock;
        private List<EnumeratedArtifact> scanTargets;
        private SearchDefinitions searchDefinitions;

        [Params(100)]
        public int scanTargetSizeInMegabytes;

        [GlobalSetup]
        public void Setup()
        {
            searchDefinitions = CreateDefinitions(100);

            (string, Mock<IFileSystem>) result = PrepareFileSystemMock();
            searchDefinitionsPath = result.Item1;
            fileSystemMock = result.Item2;

            scanTargets = GenerateScanTargets(fileSystemMock.Object, scanTargetSizeInMegabytes);
        }

        //[Benchmark]
        public void AnalyzeCommand_SimpleAnalysisDotNetRegex()
        {
            AnalyzeCommand(RegexEngine.DotNet);
        }

        [Benchmark]
        public void AnalyzeCommand_SimpleAnalysisCachedDotNetRegex()
        {
            AnalyzeCommand(RegexEngine.CachedDotNet);
        }

        [Benchmark]
        public void AnalyzeCommand_SimpleAnalysisRE2()
        {
            AnalyzeCommand(RegexEngine.RE2);
        }

        //[Benchmark]
        public void AnalyzeCommand_SimpleAnalysisIronRE2()
        {
            AnalyzeCommand(RegexEngine.IronRE2);
        }

        private static SearchDefinitions CreateDefinitions(int count)
        {
            var searchDefinitions = new SearchDefinitions()
            {
                Definitions = new List<SearchDefinition>(count)
            };

            var random = new Random();
            for (int i = 0; i < count; i++)
            {
                searchDefinitions.Definitions.Add(new SearchDefinition()
                {
                    Name = "MinimalRule",
                    Id = $"Test100{random.Next(count)}",
                    Level = FailureLevel.Error,
                    FileNameAllowRegex = "(?i)\\.test$",
                    Message = "A problem occurred in '{0:scanTarget}'.",
                    MatchExpressions = new List<MatchExpression>(new[]
                    {
                        new MatchExpression() { ContentsRegex = $"{Guid.NewGuid()}", Fixes = new Dictionary<string, SimpleFix>()
                        {
                            { "convertToPublic", new SimpleFix() { Description = "Make class public.", Find = "foo", ReplaceWith = "bar" } }
                        } }
                    })
                });
            }

            return searchDefinitions;
        }

        private (string, Mock<IFileSystem>) PrepareFileSystemMock()
        {
            string searchDefinitionsPath = Guid.NewGuid().ToString();
            string fullSearchDefinitionsPath = $"{System.Environment.CurrentDirectory}{Path.DirectorySeparatorChar}{searchDefinitionsPath}";
            string definitionsText = JsonConvert.SerializeObject(searchDefinitions);
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileReadAllText(fullSearchDefinitionsPath)).Returns(definitionsText);
            mockFileSystem.Setup(x => x.DirectoryExists(It.IsAny<string>())).Returns(true);
            mockFileSystem.Setup(x => x.FileExists(searchDefinitionsPath)).Returns(true);
            mockFileSystem.Setup(x => x.FileExists(fullSearchDefinitionsPath)).Returns(true);
            return (searchDefinitionsPath, mockFileSystem);
        }

        private void AnalyzeCommand(RegexEngine regexEngine)
        {
            var testLogger = new TestLogger();

            var context = new AnalyzeContext()
            {
                Threads = 1,
                RegexEngine = regexEngine,
                FileSystem = fileSystemMock.Object,
                MaxFileSizeInKilobytes = (1024 * scanTargetSizeInMegabytes) + 1024,
                TargetsProvider = new ArtifactProvider(scanTargets),
                Logger = testLogger,
            };

            var options = new AnalyzeOptions()
            {
                PluginFilePaths = new[] { searchDefinitionsPath },
            };

            var analyzeCommand = new AnalyzeCommand(fileSystemMock.Object);
            int result = analyzeCommand.Run(options, ref context);

            if (result != 0) { throw new InvalidOperationException(); }
        }

        private static List<EnumeratedArtifact> GenerateScanTargets(IFileSystem fileSystem, int sizeInMegabytes)
        {
            var scanTargets = new List<EnumeratedArtifact>();

            for (int i = 0; i < 50; i++)
            {
                var target = new EnumeratedArtifact(fileSystem)
                {
                    Uri = new Uri($"{Guid.NewGuid()}", UriKind.RelativeOrAbsolute),
                    Contents = GenerateScanTarget(sizeInMegabytes),
                };
                scanTargets.Add(target);
            }

            return scanTargets;
        }

        private static string GenerateScanTarget(int sizeInMegabytes)
        {
            var sb = new StringBuilder();

            int size = sizeInMegabytes * 1000 * 1024;

            while (sb.Length < size)
            {
                sb.Append($"{Guid.NewGuid()} ");
            }

            return sb.ToString();
        }
    }
}
