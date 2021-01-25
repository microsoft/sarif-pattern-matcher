﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
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
            FileRegionsCache fileRegionsCache = FileRegionsCache.Instance;

            var skimmers = new HashSet<Skimmer<AnalyzeContext>>();

            // TODO exception handling for bad search definitions files
            foreach (string searchDefinitionsPath in searchDefinitionsPaths)
            {
                string searchDefinitionsText =
                    fileSystem.FileReadAllText(searchDefinitionsPath);

                SearchDefinitions definitions =
                    JsonConvert.DeserializeObject<SearchDefinitions>(searchDefinitionsText);

                // This would skip files that does not look like rules.
                if (definitions == null || definitions.Definitions == null)
                {
                    continue;
                }

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

                definitions = PushInheritedData(definitions, sharedStrings);

                foreach (SearchDefinition definition in definitions.Definitions)
                {
                    Skimmer<AnalyzeContext> skimmer = skimmers.FirstOrDefault(skimmer => skimmer.Id == definition.Id);

                    if (skimmer != null)
                    {
                        skimmers.Remove(skimmer);
                    }

                    skimmers.Add(
                        new SearchSkimmer(
                            engine: engine,
                            validators: validators,
                            fileRegionsCache: fileRegionsCache,
                            definition));

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

        internal static SearchDefinitions PushInheritedData(SearchDefinitions definitions, Dictionary<string, string> sharedStrings)
        {
            var idToExpressionsMap = new Dictionary<string, List<MatchExpression>>();

            foreach (SearchDefinition definition in definitions.Definitions)
            {
                definition.FileNameDenyRegex = PushData(definition.FileNameDenyRegex,
                                                        definition.SharedStrings,
                                                        sharedStrings);

                definition.FileNameAllowRegex = PushData(definition.FileNameAllowRegex,
                                                         definition.SharedStrings,
                                                         sharedStrings);

                foreach (MatchExpression matchExpression in definition.MatchExpressions)
                {
                    matchExpression.FileNameDenyRegex = PushData(matchExpression.FileNameDenyRegex,
                                                                 definition.SharedStrings,
                                                                 sharedStrings);

                    matchExpression.FileNameDenyRegex ??= definition.FileNameDenyRegex;

                    matchExpression.FileNameAllowRegex = PushData(matchExpression.FileNameAllowRegex,
                                                                 definition.SharedStrings,
                                                                 sharedStrings);

                    matchExpression.FileNameAllowRegex ??= definition.FileNameAllowRegex;

                    matchExpression.ContentsRegex = PushData(matchExpression.ContentsRegex,
                                                             definition.SharedStrings,
                                                             sharedStrings);

                    matchExpression.Id ??= definition.Id;
                    matchExpression.Name ??= definition.Name;
                    matchExpression.Message ??= definition.Message;
                    matchExpression.Description ??= definition.Description;

                    if (matchExpression.Level == 0)
                    {
                        matchExpression.Level = definition.Level;
                    }

                    if (!idToExpressionsMap.TryGetValue(matchExpression.Id, out List<MatchExpression> cachedMatchExpressions))
                    {
                        cachedMatchExpressions = idToExpressionsMap[matchExpression.Id] = new List<MatchExpression>();
                    }

                    cachedMatchExpressions.Add(matchExpression);
                }
            }

            var searchDefinitions = new SearchDefinitions
            {
                Definitions = new List<SearchDefinition>(),
            };

            foreach (KeyValuePair<string, List<MatchExpression>> kv in idToExpressionsMap)
            {
                string ruleId = kv.Key;
                List<MatchExpression> matchExpressions = kv.Value;

                var definition = new SearchDefinition
                {
                    Id = matchExpressions[0].Id,
                    Name = matchExpressions[0].Name,
                    MatchExpressions = matchExpressions,
                    Description = matchExpressions[0].Description,
                };

                searchDefinitions.Definitions.Add(definition);
            }

#if DEBUG
            ValidateSharedStringsExpansion(searchDefinitions);
#endif

            return searchDefinitions;
        }

        internal static Dictionary<string, string> LoadSharedStrings(string sharedStringsFullPath, IFileSystem fileSystem)
        {
            var result = new Dictionary<string, string>();

            foreach (string fileLine in fileSystem.FileReadAllLines(sharedStringsFullPath))
            {
                string line = fileLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith("#")) { continue; }

                int index = line.IndexOf('=');
                if (index == -1) { ThrowInvalidSharedStringsEntry(line); }

                string key = line.Substring(0, index);
                if (!key.StartsWith("$")) { ThrowInvalidSharedStringsEntry(line); }

                string value = line.Substring(key.Length + "=".Length);
                result[key] = value;
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

#if DEBUG
        private static void ValidateSharedStringsExpansion(SearchDefinitions searchDefinitions)
        {
            foreach (SearchDefinition definition in searchDefinitions.Definitions)
            {
                ValidateSharedStringsExpansion(definition.FileNameDenyRegex);
                ValidateSharedStringsExpansion(definition.FileNameAllowRegex);

                foreach (MatchExpression matchExpression in definition.MatchExpressions)
                {
                    ValidateSharedStringsExpansion(matchExpression.ContentsRegex);
                    ValidateSharedStringsExpansion(matchExpression.FileNameDenyRegex);
                    ValidateSharedStringsExpansion(matchExpression.FileNameAllowRegex);
                }
            }
        }

        private static void ValidateSharedStringsExpansion(string text)
        {
            if (string.IsNullOrEmpty(text)) { return; }

            if (text.StartsWith("access_token"))
            {
                return;
            }

            // We failed to expand a pattern that is entirely rendered
            // via a shared string.
            Debug.Assert(!text.StartsWith("$"),
                         "Failed to expand shared string.");

            // We failed to expand a pattern within an expression. We
            // trim a trailing '$' as it is commonly used to denote
            // and end-of-line in search patterns.
            Debug.Assert(!text.Substring(0, text.Length - 1).Contains("$"),
                         "Failed to expand shared string.");
        }
#endif

        private static string PushData(string text, params Dictionary<string, string>[] sharedStringsDictionaries)
        {
            if (text?.Contains("$") != true)
            {
                return text;
            }

            foreach (Dictionary<string, string> sharedStrings in sharedStringsDictionaries)
            {
                if (sharedStrings == null)
                {
                    continue;
                }

                foreach (string key in sharedStrings.Keys)
                {
                    text = text.Replace(key, sharedStrings[key]);
                }
            }

            return text;
        }

        private static void ThrowInvalidSharedStringsEntry(string line)
        {
            throw new InvalidOperationException(
                $"Malformed shared strings entry. Every shared string should consist of a " +
                $"key name (prefixed with $) followed by an equals sign and the string value " +
                $"(e.g., $MyKey=MyValue). The malformed line was: {line}");
        }
    }
}
