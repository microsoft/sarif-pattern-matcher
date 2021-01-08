﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.RE2.Managed;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class AnalyzeCommand : MultithreadedAnalyzeCommandBase<AnalyzeContext, AnalyzeOptions>
    {
        public static ISet<Skimmer<AnalyzeContext>> CreateSkimmersFromDefinitionsFiles(
            IFileSystem fileSystem,
            IEnumerable<string> searchDefinitionsPaths,
            IRegex engine = null)
        {
            engine ??= RE2Regex.Instance;

            var validators = new ValidatorsCache();
            var fileRegionsCache = new FileRegionsCache();

            var skimmers = new HashSet<Skimmer<AnalyzeContext>>();

            // TODO exception handling for bad search definitions files
            foreach (string searchDefinitionsPath in searchDefinitionsPaths)
            {
                string searchDefinitionsText =
                    fileSystem.FileReadAllText(searchDefinitionsPath);

                SearchDefinitions definitions =
                    JsonConvert.DeserializeObject<SearchDefinitions>(searchDefinitionsText);

                string validatorPath = null;
                string definitionsDirectory = Path.GetDirectoryName(searchDefinitionsPath);

                if (!string.IsNullOrEmpty(definitions.ValidatorsAssemblyName))
                {
                    // TODO File.Exists check? Logging if not locatable?
                    validatorPath = Path.Combine(definitionsDirectory, definitions.ValidatorsAssemblyName);
                    validators.ValidatorPaths.Add(validatorPath);
                }
                else
                {
                    // If no explicit name of a validator binary was provided,
                    // we look for one that lives alongside the definitions file.
                    validatorPath = Path.GetFileNameWithoutExtension(searchDefinitionsPath) + ".dll";
                    validatorPath = Path.Combine(definitionsDirectory, validatorPath);

                    if (File.Exists(validatorPath))
                    {
                        validators.ValidatorPaths.Add(validatorPath);
                    }
                }

                Dictionary<string, string> sharedStrings = null;
                if (!string.IsNullOrEmpty(definitions.SharedStringsFileName))
                {
                    string sharedStringsFullPath = Path.Combine(definitionsDirectory, definitions.SharedStringsFileName);
                    sharedStrings = LoadSharedStrings(sharedStringsFullPath, fileSystem);
                }

                PushInheritedData(definitions, sharedStrings);

                foreach (SearchDefinition definition in definitions.Definitions)
                {
                    skimmers.Add(
                        new SearchSkimmer(
                            engine: engine,
                            validators: validators,
                            fileRegionsCache: fileRegionsCache,
                            id: definition.Id,
                            name: definition.Name,
                            description: definition.Description ?? string.Empty,
                            defaultMessageString: definition.Message,
                            matchExpressions: definition.MatchExpressions));

                    const string singleSpace = " ";

                    // Send no-op match operations through engine in order to drive caching of all regexes.
                    if (definition.FileNameAllowRegex != null)
                    {
                        engine.Match(singleSpace, definition.FileNameAllowRegex, RegexDefaults.DefaultOptionsCaseSensitive);
                    }

                    foreach (MatchExpression matchExpression in definition.MatchExpressions)
                    {
                        if (!string.IsNullOrEmpty(matchExpression.FileNameAllowRegex))
                        {
                            engine.Match(singleSpace, matchExpression.FileNameAllowRegex, RegexDefaults.DefaultOptionsCaseSensitive);
                        }

                        if (!string.IsNullOrEmpty(matchExpression.ContentsRegex))
                        {
                            engine.Match(singleSpace, matchExpression.ContentsRegex, RegexDefaults.DefaultOptionsCaseSensitive);
                        }
                    }
                }
            }

            return skimmers;
        }

        internal static void PushInheritedData(SearchDefinitions definitions, Dictionary<string, string> sharedStrings)
        {
            foreach (SearchDefinition definition in definitions.Definitions)
            {
                PushInheritedData(definition, sharedStrings);
            }
        }

        internal static void PushInheritedData(SearchDefinition definition, Dictionary<string, string> sharedStrings)
        {
            definition.FileNameDenyRegex = PushData(definition.FileNameDenyRegex, sharedStrings);
            definition.FileNameAllowRegex = PushData(definition.FileNameAllowRegex, sharedStrings);

            foreach (MatchExpression matchExpression in definition.MatchExpressions)
            {
                matchExpression.FileNameDenyRegex = PushData(matchExpression.FileNameDenyRegex, sharedStrings);
                matchExpression.FileNameDenyRegex ??= definition.FileNameDenyRegex;

                matchExpression.FileNameAllowRegex = PushData(matchExpression.FileNameAllowRegex, sharedStrings);
                matchExpression.FileNameAllowRegex ??= definition.FileNameDenyRegex;

                matchExpression.ContentsRegex = PushData(matchExpression.ContentsRegex, sharedStrings);

                if (matchExpression.Level == 0) { matchExpression.Level = definition.Level; }
            }
        }

        internal static Dictionary<string, string> LoadSharedStrings(string sharedStringsFullPath, IFileSystem fileSystem)
        {
            var result = new Dictionary<string, string>();

            foreach (string line in fileSystem.FileReadAllLines(sharedStringsFullPath))
            {
                int index = line.IndexOf('=');
                if (index == -1) { ThrowInvalidSharedStringsEntry(line); }

                string key = line.Substring(0, index);
                if (!key.StartsWith("$")) { ThrowInvalidSharedStringsEntry(line); }

                result[key] = line.Substring(key.Length + "=".Length);
            }

            return result;
        }

        protected override AnalyzeContext CreateContext(
            AnalyzeOptions options,
            IAnalysisLogger logger,
            RuntimeConditions runtimeErrors,
            PropertiesDictionary policy = null,
            string filePath = null)
        {
            AnalyzeContext context = base.CreateContext(options, logger, runtimeErrors, policy, filePath);

            context.Traces =
                options.Traces.Any() ?
                    (DefaultTraces)Enum.Parse(typeof(DefaultTraces), string.Join("|", options.Traces)) :
                    DefaultTraces.None;

            context.DynamicValidation = options.DynamicValidation;

            return context;
        }

        protected override ISet<Skimmer<AnalyzeContext>> CreateSkimmers(AnalyzeOptions options, AnalyzeContext context)
        {
            return CreateSkimmersFromDefinitionsFiles(this.FileSystem, options.SearchDefinitionsPaths);
        }

        private static string PushData(string text, Dictionary<string, string> sharedStrings)
        {
            if (sharedStrings == null || text?.Contains("$") != true)
            {
                return text;
            }

            foreach (string key in sharedStrings.Keys)
            {
                text = text.Replace(key, sharedStrings[key]);
            }

            return text;
        }

        private static void ThrowInvalidSharedStringsEntry(string line)
        {
            throw new InvalidOperationException(
                "Malformed shared strings entry. Every shared string should consist of a " +
                "key name (prefixed with $) followed by an equals sign and the string value " +
                $"(e.g., $MyKey=MyValue). The malformed line was: {line}");
        }
    }
}
