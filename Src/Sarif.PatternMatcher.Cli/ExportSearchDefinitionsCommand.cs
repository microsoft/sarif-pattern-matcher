// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml.Serialization;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.Models;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal class ExportSearchDefinitionsCommand : CommandBase
    {
        public int Run(ExportSearchDefinitionsOptions options)
        {
            try
            {
                if (!options.Validate())
                {
                    return FAILURE;
                }

                SearchDefinitions searchDefinitions = default;
                switch (options.FileType)
                {
                    case "BannedApi":
                    {
                        searchDefinitions = ExportBannedApi(options.InputFilePath);
                        break;
                    }

                    case "Sal":
                    {
                        searchDefinitions = ExportSal(options.InputFilePath);
                        break;
                    }

                    default:
                    {
                        throw new NotImplementedException();
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
                json = json.Replace(@",""IsValidatorEnabled"":true", string.Empty);

                File.WriteAllText(options.OutputFilePath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return FAILURE;
            }

            return SUCCESS;
        }

        internal static SearchDefinitions ExportBannedApi(string filePath)
        {
            SearchDefinitions searchDefinitions = null;
            string bannedApiInformation = File.ReadAllText(filePath);
            using var reader = new StringReader(bannedApiInformation);
            var serializer = new XmlSerializer(typeof(ArrayOfContentSearcher));
            var arrayOfContentSearcher = (ArrayOfContentSearcher)serializer.Deserialize(reader);

            if (arrayOfContentSearcher == null)
            {
                return searchDefinitions;
            }

            int i = 1;
            searchDefinitions = new SearchDefinitions
            {
                Definitions = new List<SearchDefinition>(),
                SharedStringsFileName = "Security.SharedStrings.txt",
            };
            var mapping = new Dictionary<string, SearchDefinition>();

            foreach (ContentSearcher item in arrayOfContentSearcher.ContentSearcher)
            {
                string[] ruleParts = item.RuleId.Split('/');
                string name = $"UseSecureApi/{ruleParts[1]}";
                if (ruleParts.Length == 4)
                {
                    name = $"UseSecureApi/{ruleParts[1]}/{ruleParts[2]}";
                }

                if (!mapping.TryGetValue(name, out SearchDefinition searchDefinition))
                {
                    searchDefinition = new SearchDefinition
                    {
                        Id = $"SEC104/{i.ToString().PadLeft(3, '0')}",
                        Name = name,
                        Description = "Developers should use secure API in preferance of insecure alternates.",
                        FileNameAllowRegex = "$CSourceFiles",
                        Message = "'{0:scanTarget}' contains a call to '{1:refine}', a potentially insecure API that could be replaced with a more secure alternative: {2:alternative}.",
                        MatchExpressions = new List<MatchExpression>(),
                    };
                    i++;
                }

                string alternativeText = item.FullMatchDetails.Split(':')[1].Trim().TrimEnd('.');

                string message = default;
                string messageId = default;
                ResultKind kind = ResultKind.None;
                FailureLevel level = FailureLevel.None;
                switch (item.Severity)
                {
                    case 1:
                    {
                        level = FailureLevel.Error;
                        break;
                    }

                    case 2:
                    {
                        level = FailureLevel.Warning;
                        break;
                    }

                    case 5:
                    {
                        kind = ResultKind.Pass;
                        messageId = "Default_Secure";
                        message = "'{0:scanTarget}' contains a call to '{1:refine}', a more secure alternative to one or more potentially insecure APIs: {2:alternative}.";
                        break;
                    }
                }

                var matchExpression = new MatchExpression
                {
                    Kind = kind,
                    Level = level,
                    SubId = ruleParts[^1],
                    MessageId = messageId,
                    Message = message,
                    ContentsRegex = item.ContentSearchPatterns?.String ?? string.Empty,
                    MessageArguments = new Dictionary<string, string>
                    {
                        { "alternative", alternativeText },
                    },
                };

                searchDefinition.MatchExpressions.Add(matchExpression);

                mapping[name] = searchDefinition;
            }

            foreach (SearchDefinition item in mapping.Values)
            {
                searchDefinitions.Definitions.Add(item);
            }

            return searchDefinitions;
        }

        internal static SearchDefinitions ExportSal(string filePath)
        {
            string[] lines = File.ReadAllLines(filePath);

            int i = 1;
            var searchDefinitions = new SearchDefinitions
            {
                Definitions = new List<SearchDefinition>(),
                ValidatorsAssemblyName = "SalModernization.dll",
                SharedStringsFileName = "SalModernization.SharedStrings.txt",
            };

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
                            searchDefinition.Message = "The SAL v1 '{0:obsoleteAnnotation}' annotation is obsolete in SAL v2 and should be removed.";
                            break;

                        case "Automatic":
                            searchDefinition.Name = "RenameLegacyAnnotationsToCurrentVersion";
                            searchDefinition.Description = "SAL 1 can be replaced with SAL 2.";
                            searchDefinition.Message = "The SAL v1 '{0:obsoleteAnnotation}' annotation is obsolete and should be replaced with the SAL v2 equivalent '{1:newAnnotation}'.";
                            break;

                        case "Manual":
                            searchDefinition.Name = "UpdateAnnotationsToCurrentVersion";
                            searchDefinition.Description = "Conversion from SAL 1 to SAL 2 cannot be automatically done.";
                            searchDefinition.Message = "The SAL v1 '{0:obsoleteAnnotation}' annotation has changed in SAL v2 and should be converted manually to the correct pattern.";
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

            return searchDefinitions;
        }
    }
}
