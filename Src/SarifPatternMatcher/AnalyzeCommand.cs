// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif;
using Microsoft.CodeAnalysis.Sarif.Driver;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher
{
    public class AnalyzeCommand : MultithreadedAnalyzeCommandBase<AnalyzeContext, AnalyzeOptions>
    {
        public static ISet<Skimmer<AnalyzeContext>> CreateSkimmersFromDefinitionsFiles(IFileSystem fileSystem, IEnumerable<string> searchDefinitionsPaths)
        {
            var validators = new ValidatorsCache(searchDefinitionsPaths);

            var skimmers = new HashSet<Skimmer<AnalyzeContext>>();

            // TODO exception handling for bad search definitions files
            foreach (string searchDefinitionsPath in searchDefinitionsPaths)
            {
                string searchDefinitionsText =
                    fileSystem.FileReadAllText(searchDefinitionsPath);

                SearchDefinitions definitions =
                    JsonConvert.DeserializeObject<SearchDefinitions>(searchDefinitionsText);

                foreach (SearchDefinition definition in definitions.Definitions)
                {
                    IRegex engine = RE2Regex.Instance;

                    skimmers.Add(
                        new SearchSkimmer(
                            engine: engine,
                            validators: validators,
                            id: definition.Id,
                            name: definition.Name,
                            defaultLevel: definition.Level,
                            description: definition.Description ?? string.Empty,
                            defaultNameRegex: definition.DefaultNameRegex,
                            defaultMessageString: definition.Message,
                            matchExpressions: definition.MatchExpressions));

                    string singleSpace = " ";

                    // Send no-op match operations through engine in order to drive caching of all regexes.
                    if (definition.DefaultNameRegex != null)
                    {
                        engine.Match(singleSpace, definition.DefaultNameRegex, RegexDefaults.DefaultOptionsCaseSensitive);
                    }

                    foreach (MatchExpression matchExpression in definition.MatchExpressions)
                    {
                        if (matchExpression.NameRegex != null)
                        {
                            engine.Match(singleSpace, matchExpression.NameRegex, RegexDefaults.DefaultOptionsCaseSensitive);
                        }

                        engine.Match(singleSpace, matchExpression.ContentsRegex, RegexDefaults.DefaultOptionsCaseSensitive);
                    }
                }
            }

            return skimmers;
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
                options.Traces.Count() > 0 ?
                    (DefaultTraces)Enum.Parse(typeof(DefaultTraces), string.Join("|", options.Traces)) :
                    DefaultTraces.None;

            return context;
        }

        protected override ISet<Skimmer<AnalyzeContext>> CreateSkimmers(AnalyzeOptions options, AnalyzeContext context)
        {
            return CreateSkimmersFromDefinitionsFiles(this.FileSystem, options.SearchDefinitionsPaths);
        }
    }
}
