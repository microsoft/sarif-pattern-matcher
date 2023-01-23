// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.Visitors;
using Microsoft.CodeAnalysis.Sarif.Writers;

using Newtonsoft.Json;

using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public abstract class EndToEndTests : FileDiffingUnitTests
    {
        private static ConcurrentDictionary<string, ISet<Skimmer<AnalyzeContext>>> s_definitionsPathToSkimmersMap;

        public static ISet<Skimmer<AnalyzeContext>> CreateOrRetrievedCachedSkimmer(IFileSystem fileSystem, string regexDefinitionsPath)
        {
            // Load all rules from JSON. This also automatically loads any validations file that
            // lives alongside the JSON. For a JSON file named PlaintextSecrets.json, the
            // corresponding validations assembly is named PlaintextSecrets.dll (i.e., only the
            // extension name changes from .json to .dll).


            s_definitionsPathToSkimmersMap ??= new ConcurrentDictionary<string, ISet<Skimmer<AnalyzeContext>>>();

            if (!s_definitionsPathToSkimmersMap.TryGetValue(regexDefinitionsPath, out ISet<Skimmer<AnalyzeContext>> skimmers))
            {
                skimmers = AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(fileSystem, new string[] { regexDefinitionsPath });
                s_definitionsPathToSkimmersMap.TryAdd(regexDefinitionsPath, skimmers);
            }

            return skimmers;
        }

        protected EndToEndTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected abstract string RuleId { get; }

        protected abstract string Framework { get; }

        protected string PluginDirectory => GetPluginDirectory();

        protected string PluginName => TestBinaryName.Substring("Tests.".Length);

        protected string DefinitionsPath => Path.Combine(PluginDirectory, $"{RuleId}.{TypeUnderTest}.json");

        protected override string TestLogResourceNameRoot => $"Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.TestData.{TypeUnderTest}";

        protected override string TestBinaryTestDataDirectory => Path.Combine(ProductRootDirectory, "src", "Plugins", TestBinaryName, "TestData");

        protected override string ProductTestDataDirectory => Path.Combine(TestBinaryTestDataDirectory, TypeUnderTest);

        protected override IDictionary<string, string> ConstructTestOutputsFromInputResources(IEnumerable<string> inputResourceNames, object parameter)
        {
            var inputFiles = parameter as List<string>;
            var results = new Dictionary<string, string>();

            // INTERESTING BREAKPOINT: unexpected differences in an end-to-end test
            // scan. In practice, debugging the end-to-end tests when multithreaded
            // is difficult. The common scenario is to debug one or a few files and
            // it is hard to step through a discrete repro w/ many other threads
            // traveling the same breakpoints. With this change, we will be
            // single-threaded if the debugger is attached. This introduces two
            // complications, first, the time-to-execute is greatly increased.
            // Second, runtime execution will not literally match test execution
            // outside of the debugger. There are some theoretical problems (such
            // as bugs in test utilization of shared resources) that could result.
            //
            results = Debugger.IsAttached
                ? SingleThreadedConstructTestOutputs(inputResourceNames, inputFiles)
                : MultiThreadedConstructTestOutputs(inputResourceNames, inputFiles);

            return results;
        }

        private Dictionary<string, string> SingleThreadedConstructTestOutputs(IEnumerable<string> inputResourceNames, List<string> inputFiles)
        {
            var results = new Dictionary<string, string>();

            foreach (string inputResourceName in inputResourceNames)
            {
                string name = inputFiles.First(i => inputResourceName.EndsWith(i));
                results[name] = ConstructTestOutputFromInputResource(inputResourceName, name);
            }

            return results;
        }

        private Dictionary<string, string> MultiThreadedConstructTestOutputs(IEnumerable<string> inputResourceNames, List<string> inputFiles)
        {
            var results = new Dictionary<string, string>();
            var dict = new Dictionary<string, Task<string>>();

            foreach (string inputResourceName in inputResourceNames)
            {
                string name = inputFiles.First(i => inputResourceName.EndsWith(i));

                dict[name] = Task.Factory.StartNew(() => ConstructTestOutputFromInputResource(inputResourceName, name));
            }

            Task.WaitAll(dict.Values.ToArray());

            foreach (KeyValuePair<string, Task<string>> item in dict)
            {
                results[item.Key] = item.Value.Result;
            }

            return results;
        }

        protected override string ConstructTestOutputFromInputResource(string inputResourceName, object parameter)
        {
            string logContents = GetResourceText(inputResourceName);

            string filePath = Path.Combine(
                ProductTestDataDirectory,
                @"Inputs\",
                parameter as string);

            IFileSystem fileSystem = FileSystem.Instance;

            // Load all rules from JSON. This also automatically loads any validations file that
            // lives alongside the JSON. For a JSON file named PlaintextSecrets.json, the
            // corresponding validations assembly is named PlaintextSecrets.dll (i.e., only the
            // extension name changes from .json to .dll).
            ISet<Skimmer<AnalyzeContext>> skimmers =
                CreateOrRetrievedCachedSkimmer(fileSystem, DefinitionsPath);

            var sb = new StringBuilder();

            using (var outputTextWriter = new StringWriter(sb))
            using (var logger = new SarifLogger(
                outputTextWriter,
                LogFilePersistenceOptions.PrettyPrint,
                dataToRemove: OptionallyEmittedData.NondeterministicProperties,
                levels: new List<FailureLevel> { FailureLevel.Error, FailureLevel.Warning, FailureLevel.Note, FailureLevel.None },
                kinds: new List<ResultKind> { ResultKind.Fail, ResultKind.Pass }))
            {
                // The analysis will disable skimmers that raise an exception. This
                // hash set stores the disabled skimmers. When a skimmer is disabled,
                // that catastrophic event is logged as a SARIF notification.
                var disabledSkimmers = new HashSet<string>();

                var target = new EnumeratedArtifact
                {
                    Uri = new Uri(filePath, UriKind.Absolute),
                    Contents = logContents,
                };

                var context = new AnalyzeContext
                {
                    CurrentTarget = target,
                    Logger = logger,
                };

                using (context)
                {
                    AnalyzeCommand.AnalyzeTargetHelper(context, skimmers, disabledSkimmers);
                }
            }

            // Now we'll rewrite the log file in order to convert non-deterministic
            // absolute URLs to some stable relative reference (built off the source
            // root.

            SarifLog sarifLog = JsonConvert.DeserializeObject<SarifLog>(sb.ToString());

            string sourceRoot = GitHelper.Default.GetTopLevel(Path.GetDirectoryName(filePath)) + @"\";

            var rebaseUriVisitor = new RebaseUriVisitor("SRC_ROOT", new Uri(sourceRoot));
            rebaseUriVisitor.Visit(sarifLog);

            // It would be nice if RebaseUriVisitor was configurable
            // to avoid the need to clear OriginalUriBaseIds (which
            // is data that is non-deterministic machine-over-machine).
            // https://github.com/microsoft/sarif-sdk/issues/2185
            sarifLog.Runs[0].OriginalUriBaseIds = null;

            return JsonConvert.SerializeObject(sarifLog, Formatting.Indented);
        }

        private string GetPluginDirectory()
        {
            string result = Path.Combine(ThisAssembly.Location,
                                         @"..\..\..",
                                         PluginName,
                                         Framework);

            return Path.GetFullPath(result);
        }

        protected void RunAllTests()
        {
            Directory.Exists(ProductTestDataDirectory).Should().BeTrue();

            string testsDirectory = Path.Combine(ProductTestDataDirectory, @"Inputs\");

            var inputFiles = new List<string>();
            var expectedOutputResourceMap = new Dictionary<string, string>();
            foreach (string testFile in Directory.GetFiles(testsDirectory))
            {
                string testFileName = Path.GetFileName(testFile);

                if (testFileName.EndsWith("Sec101_036.mysqlcredentials.ps1", StringComparison.OrdinalIgnoreCase) ||
                    testFileName.EndsWith("Sec101_037.sqlcredentials.ps1", StringComparison.OrdinalIgnoreCase))
                {
                    // TODO: re-enable these tests after further debugging of validation
                    // fingerprint collisions across all the SQL rule types.
                }
                else
                {
                    inputFiles.Add(testFileName);

                    expectedOutputResourceMap[testFileName] =
                        Path.GetFileNameWithoutExtension(testFileName) + ".sarif";

                }
            }

            RunTest(inputFiles, expectedOutputResourceMap, enforceNotificationsFree: true, parameter: inputFiles);
        }
    }
}
