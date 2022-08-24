// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
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
        protected EndToEndTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected abstract string RuleId { get; }

        protected abstract string Framework { get; }

        protected abstract string PluginName { get; }

        protected override string TestLogResourceNameRoot => $"Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.TestData.{TypeUnderTest}";

        protected override string TestBinaryTestDataDirectory => Path.Combine(ProductRootDirectory, "src", "Plugins", TestBinaryName, "TestData");

        protected override string ProductTestDataDirectory => Path.Combine(TestBinaryTestDataDirectory, PluginName);

        protected override IDictionary<string, string> ConstructTestOutputsFromInputResources(IEnumerable<string> inputResourceNames, object parameter)
        {
            var inputFiles = parameter as List<string>;
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
            string productBinaryName = TestBinaryName.Substring("Tests.".Length);

            string regexDefinitions = Path.Combine(
                Path.GetDirectoryName(typeof(RebaseUriVisitor).Assembly.Location),
                @"..\..\",
                @$"{productBinaryName}\{Framework}\{RuleId}.{TypeUnderTest}.json");

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
                AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(fileSystem, new string[] { regexDefinitions });

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

                var context = new AnalyzeContext
                {
                    TargetUri = new Uri(filePath, UriKind.Absolute),
                    FileContents = logContents,
                    Logger = logger
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

        protected void RunAllTests()
        {
            Directory.Exists(ProductTestDataDirectory).Should().BeTrue();

            string testsDirectory = Path.Combine(ProductTestDataDirectory, @"Inputs\");

            var inputFiles = new List<string>();
            var expectedOutputResourceMap = new Dictionary<string, string>();
            foreach (string testFile in Directory.GetFiles(testsDirectory))
            {
                string testFileName = Path.GetFileName(testFile);
                inputFiles.Add(testFileName);

                expectedOutputResourceMap[testFileName] =
                    Path.GetFileNameWithoutExtension(testFileName) + ".sarif";
            }

            RunTest(inputFiles, expectedOutputResourceMap, enforceNotificationsFree: true, parameter: inputFiles);
        }
    }
}
