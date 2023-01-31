// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;

using BenchmarkDotNet.Attributes;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.RE2.Managed;
using Microsoft.Strings.Interop;

using Moq;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Benchmark.Benchmarks
{
    [MemoryDiagnoser]
    public class AnalyzeCommandBenchmarks
    {
        private SearchDefinitions searchDefinitions;
        private Mock<IFileSystem> fileSystemMock;
        private string searchDefinitionsPath;

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
            AnalyzeCommand(DotNetRegex.Instance);
        }

        [Benchmark]
        public void AnalyzeCommand_SimpleAnalysisCachedDotNetRegex()
        {
            AnalyzeCommand(CachedDotNetRegex.Instance);
        }

        [Benchmark]
        public void AnalyzeCommand_SimpleAnalysisRegex2()
        {
            AnalyzeCommand(RE2Regex.Instance);
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
            string definitionsText = JsonConvert.SerializeObject(searchDefinitions);
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileReadAllText(searchDefinitionsPath)).Returns(definitionsText);

            return (searchDefinitionsPath, mockFileSystem);
        }

        private void AnalyzeCommand(IRegex engine)
        {
            var disabledSkimmers = new HashSet<string>();
            var testLogger = new TestLogger();

            // Acquire skimmers for searchers
            ISet<Skimmer<AnalyzeContext>> skimmers =
                PatternMatcher.AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                    fileSystemMock.Object,
                    new string[] { searchDefinitionsPath },
                    engine);

            string scanTargetFileName = Path.Combine(@"C:\", Guid.NewGuid().ToString() + ".test");
            FlexString fileContents = "bar foo foo";

            var target = new EnumeratedArtifact            
            { 
                Uri = new Uri(scanTargetFileName, UriKind.RelativeOrAbsolute),
                Contents = fileContents,
            };

            var context = new AnalyzeContext()
            {
                CurrentTarget = target,
                Logger = testLogger
            };

            IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = PatternMatcher.AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, skimmers, disabledSkimmers);
            PatternMatcher.AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers);
        }
    }
}
