﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.Writers;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Function
{
    internal static class SpamAnalyzer
    {
        internal static readonly IFileSystem FileSystem;
        internal static ISet<Skimmer<AnalyzeContext>> Skimmers;

        static SpamAnalyzer()
        {
            FileSystem = Sarif.FileSystem.Instance;
        }

        public static SarifLog Analyze(string filePath, string text, string rulePath, string originalFileName)
        {
            if (Skimmers == null)
            {
                IEnumerable<string> regexDefinitions = FileSystem.DirectoryGetFiles(Path.Combine(rulePath, @"..\bin\"), "*.json");

                // Load all rules from JSON. This also automatically loads any validations file that
                // lives alongside the JSON. For a JSON file named PlaintextSecrets.json, the
                // corresponding validations assembly is named PlaintextSecrets.dll (i.e., only the
                // extension name changes from .json to .dll).
                Skimmers = AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(FileSystem, regexDefinitions);
            }

            var sb = new StringBuilder();

            // We should clear every time to prevent colision.
            FileRegionsCache.Instance.ClearCache();

            using (var outputTextWriter = new StringWriter(sb))
            using (var logger = new SarifLogger(
                outputTextWriter,
                LogFilePersistenceOptions.PrettyPrint,
                dataToInsert: OptionallyEmittedData.Hashes | OptionallyEmittedData.RegionSnippets | OptionallyEmittedData.ContextRegionSnippets | OptionallyEmittedData.ComprehensiveRegionProperties,
                levels: new List<FailureLevel> { FailureLevel.Error, FailureLevel.Warning, FailureLevel.Note, FailureLevel.None },
                kinds: new List<ResultKind> { ResultKind.Fail }))
            {
                // The analysis will disable skimmers that raise an exception. This
                // hash set stores the disabled skimmers. When a skimmer is disabled,
                // that catastrophic event is logged as a SARIF notification.
                var disabledSkimmers = new HashSet<string>();

                var context = new AnalyzeContext
                {
                    TargetUri = new Uri(filePath, UriKind.RelativeOrAbsolute),
                    FileContents = text,
                    Logger = logger,
                    DynamicValidation = true,
                };

                using (context)
                {
                    IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, Skimmers, disabledSkimmers);
                    AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers);
                }
            }

            string sarifLog = sb.ToString();

            if (!string.IsNullOrEmpty(originalFileName))
            {
                sarifLog = sarifLog.Replace(filePath, originalFileName);
            }

            return JsonConvert.DeserializeObject<SarifLog>(sarifLog);
        }
    }
}
