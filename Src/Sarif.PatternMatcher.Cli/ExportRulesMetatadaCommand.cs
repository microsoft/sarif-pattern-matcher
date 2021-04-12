// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.Driver;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal class ExportRulesMetatadaCommand : CommandBase
    {
        public int Run(ExportRulesMetatadaOptions options)
        {
            try
            {
                if (!ValidateOptions(options))
                {
                    return FAILURE;
                }

                ImportSearchDefinitions(options, out List<SearchDefinitions> searchDefinitionsList, out ValidatorsCache validators);

                File.WriteAllText(options.OutputFilePath, ProcessSearchDefinitions(searchDefinitionsList, validators));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return FAILURE;
            }

            return SUCCESS;
        }

        public bool ValidateOptions(ExportRulesMetatadaOptions options)
        {
            if (options.SearchDefinitionsPaths?.Any() != true)
            {
                return false;
            }

            foreach (string searchDefinition in options.SearchDefinitionsPaths)
            {
                if (!FileSystem.FileExists(searchDefinition))
                {
                    return false;
                }
            }

            return !string.IsNullOrEmpty(options.OutputFilePath);
        }

        private void ImportSearchDefinitions(ExportRulesMetatadaOptions options, out List<SearchDefinitions> definitions, out ValidatorsCache validators)
        {
            definitions = new List<SearchDefinitions>();
            validators = new ValidatorsCache();

            foreach (string searchDefinitionsPath in options.SearchDefinitionsPaths)
            {
                string searchDefinitionsText =
                    FileSystem.FileReadAllText(searchDefinitionsPath);

                SearchDefinitions currentDefinitions =
                    JsonConvert.DeserializeObject<SearchDefinitions>(searchDefinitionsText);

                // This would skip files that does not look like rules.
                if (currentDefinitions == null || currentDefinitions.Definitions == null)
                {
                    continue;
                }

                string definitionsDirectory = Path.GetDirectoryName(searchDefinitionsPath);

                string validatorPath;
                if (!string.IsNullOrEmpty(currentDefinitions.ValidatorsAssemblyName))
                {
                    validatorPath = Path.Combine(definitionsDirectory, currentDefinitions.ValidatorsAssemblyName);
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

                definitions.Add(currentDefinitions);
            }
        }

        private string ProcessSearchDefinitions(List<SearchDefinitions> searchDefinitionsList, ValidatorsCache validators)
        {
            var builder = new StringBuilder();
            builder.AppendLine("# Rules");
            builder.AppendLine();

            foreach (SearchDefinitions searchDefinition in searchDefinitionsList.OrderBy(d => d.ValidatorsAssemblyName))
            {
                var hash = new HashSet<string>();

                builder.AppendLine($"## {searchDefinition.ValidatorsAssemblyName} ({searchDefinition.Definitions.Count})");
                builder.AppendLine();

                bool hasOneOrMoreDeprecatedRuleNames = false;

                foreach (SearchDefinition definition in searchDefinition.Definitions)
                {
                    foreach (MatchExpression match in definition.MatchExpressions)
                    {
                        if (!string.IsNullOrWhiteSpace(match.DeprecatedName))
                        {
                            hasOneOrMoreDeprecatedRuleNames = true;
                            break;
                        }
                    }
                }

                string deprecatedNameColumn = hasOneOrMoreDeprecatedRuleNames ? " | Deprecated Name" : string.Empty;
                string deprecatedNameUnderbar = hasOneOrMoreDeprecatedRuleNames ? " | ---" : string.Empty;

                foreach (SearchDefinition definition in searchDefinition.Definitions.OrderBy(d => d.Id))
                {
                    builder.AppendLine($"### {definition.Id}.{definition.Name} ({definition.MatchExpressions.GroupBy(g => g.Id).Count()})");
                    builder.AppendLine($"Id | Name | Validation{deprecatedNameColumn}");
                    builder.AppendLine($"---| --- | ---{deprecatedNameUnderbar}");

                    foreach (MatchExpression match in definition.MatchExpressions.OrderBy(m => m.Id))
                    {
                        string key = match.Id + match.Name;
                        if (!hash.Contains(key))
                        {
                            ValidationMethods validationPair = null;

                            if (!string.IsNullOrEmpty(match.Name))
                            {
                                validationPair = ValidatorsCache.GetValidationMethods(match.Name, validators.RuleNameToValidationMethods);
                            }

                            string deprecatedNameContent = hasOneOrMoreDeprecatedRuleNames ?
                                $" | {match.DeprecatedName ?? "-"}" :
                                string.Empty;

                            builder.AppendLine($"{match.Id} | " +
                                               $"{match.Name} | " +
                                               $"{(validationPair?.IsValidDynamic != null ? "Y" : "-")}" +
                                               deprecatedNameContent);

                            hash.Add(key);
                        }
                    }

                    builder.AppendLine();
                }
            }

            return builder.ToString();
        }
    }
}
