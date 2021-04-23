// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;
using System.Text;

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            return Parser.Default.ParseArguments<
                AnalyzeOptions,
                ExportRulesMetatadaOptions,
                ImportAndAnalyzeOptions,
                ValidateOptions>(args)
              .MapResult(
                (ImportAndAnalyzeOptions options) => new ImportAndAnalyzeCommand().Run(options),
                (AnalyzeOptions options) => new AnalyzeCommand().Run(options),
                (ExportRulesMetatadaOptions options) => new ExportRulesMetatadaCommand().Run(options),
                (ValidateOptions options) => new ValidateCommand().Run(options),
                _ => CommandBase.FAILURE);
        }

        private static void SalParser(string filePath)
        {
            string[] lines = File.ReadAllLines(filePath);

            int i = 1;
            var searchDefinitions = new SearchDefinitions();
            searchDefinitions.SharedStringsFileName = "SalModernization.SharedStrings.txt";
            searchDefinitions.ValidatorsAssemblyName = "SalModernization.dll";
            searchDefinitions.Definitions = new List<SearchDefinition>();

            var dictionary = new Dictionary<string, SearchDefinition>();
            var builder = new StringBuilder();

            foreach (string line in lines)
            {
                if (line.StartsWith(';') || string.IsNullOrEmpty(line))
                {
                    continue;
                }

                if (line.EndsWith("NoChange"))
                {
                    continue;
                }

                string[] parts = null;
                string type = string.Empty;
                if (line.Contains(" Delete"))
                {
                    parts = line.Split(new string[] { "Delete" }, System.StringSplitOptions.RemoveEmptyEntries);
                    type = "Delete";
                }
                else if (line.Contains(" Automatic"))
                {
                    parts = line.Split(new string[] { "Automatic" }, System.StringSplitOptions.RemoveEmptyEntries);
                    type = "Automatic";
                }
                else if (line.Contains(" Manual"))
                {
                    parts = line.Split(new string[] { "Manual" }, System.StringSplitOptions.RemoveEmptyEntries);
                    type = "Manual";
                }

                if (!dictionary.TryGetValue(type, out SearchDefinition searchDefinition))
                {
                    searchDefinition = new SearchDefinition();
                    searchDefinition.Level = FailureLevel.Warning;
                    searchDefinition.Id = $"SEC105/00{i}";
                    searchDefinition.FileNameAllowRegex = "$CSourceFiles";
                    searchDefinition.MatchExpressions = new List<MatchExpression>();
                    switch (type)
                    {
                        case "Delete":
                            searchDefinition.Name = "RemoveObsoleteOrRedundantAnnotations";
                            searchDefinition.Description = "Obsolete or redundant SAL annotation.";
                            searchDefinition.Message = "'{0:scanTarget}' contains a use of the obsolete or redundant SAL v1 '{1:obsoleteAnnotation}' annotation that should be removed.";
                            break;

                        case "Automatic":
                            searchDefinition.Name = "RenameLegacyAnnotationsToCurrentVersion";
                            searchDefinition.Description = "SAL 1 can be replaced with SAL 2.";
                            searchDefinition.Message = "'{0:scanTarget}' contains a use of the obsolete or redundant '{1:obsoleteAnnotation}' annotation and should be replaced for '{2:newAnnotation}'.";
                            break;

                        case "Manual":
                            searchDefinition.Name = "UpdateAnnotationsToCurrentVersion";
                            searchDefinition.Description = "Conversion from SAL 1 to SAL 2 cannot be automatically done.";
                            searchDefinition.Message = "'{0:scanTarget}' contains a use of the SAL v1 '{1:obsoleteAnnotation}' annotation that should be converted manually to the correct SAL v2 pattern.";
                            break;
                    }

                    dictionary[type] = searchDefinition;
                    searchDefinitions.Definitions.Add(searchDefinition);
                    i++;
                }

                string obsolete = parts[0].Trim();
                string regexRule = string.Empty;
                string regex = string.Empty;
                string name = string.Empty;

                if (obsolete.Contains("(") || obsolete.Contains("["))
                {
                    foreach (char c in obsolete)
                    {
                        if (c == '(' || c == '[' || c == ']' || c == ')' || c == '|')
                        {
                            regex += $@"\{c}";
                        }
                        else
                        {
                            regex += c;

                            if (char.IsLetterOrDigit(c))
                            {
                                name += c;
                            }
                        }
                    }

                    regexRule = $@"${searchDefinition.Id}.{name}={regex}";
                }
                else
                {
                    foreach (char c in obsolete)
                    {
                        if (char.IsLetterOrDigit(c))
                        {
                            name += c;
                        }
                    }

                    regexRule = $@"${searchDefinition.Id}.{name}=[^\w_]{obsolete}[^\w_]";
                }

                builder.AppendLine(regexRule);

                switch (type)
                {
                    case "Delete":

                        searchDefinition.MatchExpressions.Add(new MatchExpression
                        {
                            SubId = name,
                            ContentsRegex = $"${searchDefinition.Id}.{name}",
                            MessageArguments = new Dictionary<string, string>
                            {
                                { "obsoleteAnnotation", obsolete },
                            },
                            Fixes = new Dictionary<string, SimpleFix>
                            {
                                {
                                    "deleteAnnotation",
                                    new SimpleFix
                                    {
                                        Description = $"Delete '{obsolete}'.",
                                        Find = obsolete,
                                        ReplaceWith = string.Empty,
                                    }
                                },
                            },
                        });
                        break;

                    case "Automatic":

                        searchDefinition.MatchExpressions.Add(new MatchExpression
                        {
                            SubId = name,
                            ContentsRegex = $"${searchDefinition.Id}.{name}",
                            MessageArguments = new Dictionary<string, string>
                            {
                                { "obsoleteAnnotation", obsolete },
                                { "newAnnotation", parts[1].Trim() },
                            },
                            Fixes = new Dictionary<string, SimpleFix>
                            {
                                {
                                    "updateAnnotation",
                                    new SimpleFix
                                    {
                                        Description = $"Replace '{obsolete}' with '{parts[1].Trim()}'.",
                                        Find = obsolete,
                                        ReplaceWith = parts[1].Trim(),
                                    }
                                },
                            },
                        });
                        break;

                    case "Manual":

                        searchDefinition.MatchExpressions.Add(new MatchExpression
                        {
                            SubId = name,
                            ContentsRegex = $"${searchDefinition.Id}.{name}",
                            MessageArguments = new Dictionary<string, string>
                            {
                                { "obsoleteAnnotation", obsolete },
                            },
                        });
                        break;
                }
            }

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
            settings.Converters.Add(new StringEnumConverter());
            string json = JsonConvert.SerializeObject(
                searchDefinitions,
                Formatting.None,
                settings);
            json = json.Replace(@"""Level"":""None"",", string.Empty);
            json = json.Replace(@"""Kind"":""None"",", string.Empty);
            json = json.Replace(@",""MessageId"":""Default""", string.Empty);
            json = json.Replace(@"""MatchLengthToDecode"":0,", string.Empty);
            json = json.Replace($@",""IsValidatorEnabled"":true", string.Empty);
        }
    }
}
