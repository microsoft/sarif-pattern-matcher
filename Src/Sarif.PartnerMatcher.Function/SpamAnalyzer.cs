// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Microsoft.CodeAnalysis.Sarif;
using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher;
using Microsoft.CodeAnalysis.Sarif.Writers;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Function
{
    internal static class SpamAnalyzer
    {
        private static IFileSystem fileSystem;

        static SpamAnalyzer()
        {
            FileSystem = Sarif.FileSystem.Instance;
        }

        internal static IFileSystem FileSystem
        {
            get
            {
                fileSystem ??= Sarif.FileSystem.Instance;
                return fileSystem;
            }

            set
            {
                fileSystem = value;
            }
        }

        public static SarifLog Analyze(string filePath, string text, string rulePath)
        {
            string logContents = text;

            string regexDefinitions = Path.Combine(rulePath, @"..\Rules\SEC1001.json");

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
                LoggingOptions.PrettyPrint | LoggingOptions.Verbose,
                dataToRemove: OptionallyEmittedData.NondeterministicProperties))
            {
                // The analysis will disable skimmers that raise an exception. This 
                // hash set stores the disabled skimmers. When a skimmer is disabled, 
                // that catastrophic event is logged as a SARIF notification. 
                var disabledSkimmers = new HashSet<string>();

                var context = new AnalyzeContext
                {
                    TargetUri = new Uri(filePath, UriKind.RelativeOrAbsolute),
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
            return sarifLog;
        }
    }
}
