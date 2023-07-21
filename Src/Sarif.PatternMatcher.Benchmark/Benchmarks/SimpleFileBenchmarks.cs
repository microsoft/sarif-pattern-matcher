// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using Microsoft.Strings.Interop;

using Moq;

using Newtonsoft.Json;

using Sarif.PatternMatcher.Benchmark;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Benchmark.Benchmarks
{
    [MemoryDiagnoser]
    public class SimpleFileBenchmarks : BenchmarksBase
    {
        private SearchDefinitions searchDefinitions;
        private Mock<IFileSystem> fileSystemMock;
        private string searchDefinitionsPath;

        internal int Run(SimpleOptions _)
        {
            BenchmarkRunner.Run<SimpleFileBenchmarks>();
            return 0;
        }

        [Params(1, 10, 100)]
        public int definitionsCount;

        [GlobalSetup]
        public void Setup()
        {
            searchDefinitions = CreateDefinitions(definitionsCount);

            (string, Mock<IFileSystem>) result = PrepareFileSystemMock();
            searchDefinitionsPath = result.Item1;
            fileSystemMock = result.Item2;
        }

        [Benchmark]
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

        [Benchmark]
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
                        new MatchExpression() { ContentsRegex = "foo", Fixes = new Dictionary<string, SimpleFix>()
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

            string scanTargetFileName = Path.Combine(@"C:\", Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";

            var target = new EnumeratedArtifact(fileSystem: fileSystemMock.Object)
            {
                Uri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                Contents = fileContents,
            };

            var context = new AnalyzeContext()
            {
                CurrentTarget = target,
                RegexEngine = regexEngine,
                TargetsProvider = new ArtifactProvider(new[] { target }),
                Logger = testLogger,
            };

            var options = new AnalyzeOptions()
            {
                PluginFilePaths = new[] { searchDefinitionsPath },
            };
            var analyzeCommand = new AnalyzeCommand();
            analyzeCommand.Run(options, ref context);
        }
    }
}
