// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.Writers;
using Microsoft.RE2.Managed;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class AnalyzeFromContext : AnalyzeCommand
    {
        private readonly AnalyzeContext context;

        public AnalyzeFromContext(AnalyzeContext context, IFileSystem fileSystem = null)
            : base(fileSystem)
        {
            this.context = context;
        }

        internal RuntimeConditions Analyze()
        {
            try
            {
                AnalyzeTargets(this.context, this.context.Skimmers);
            }
            catch (ExitApplicationException<ExitReason> _)
            {
                // These exceptions have already been logged
                return context.RuntimeErrors;
            }
            catch (Exception ex)
            {
                ex = ex.InnerException ?? ex;

                if (!(ex is ExitApplicationException<ExitReason>))
                {
                    // These exceptions escaped our net and must be logged here
                    Errors.LogUnhandledEngineException(context, ex);
                }

                ExecutionException = ex;
                return context.RuntimeErrors;
            }
            finally
            {
                context.Logger.AnalysisStopped(context.RuntimeErrors);
            }

            return context.RuntimeErrors;
        }
    }

    public class AnalyzeCommand : MultithreadedAnalyzeCommandBase<AnalyzeContext, AnalyzeOptions>
    {
        private Tool tool;

        public AnalyzeCommand(IFileSystem fileSystem = null)
            : base(fileSystem)
        {
        }

        public static int AnalyzeFromContext(AnalyzeContext context = null,
                                             IFileSystem fileSystem = null)
        {
            return Analyze(args: null, options: null, context, fileSystem);
        }

        protected override Tool Tool
        {
            get
            {
                if (tool == null)
                {
                    this.tool = Tool.CreateFromAssemblyData(this.GetType().Assembly);
                    this.tool.Driver.Name = "Spmi";
                    this.tool.Driver.InformationUri = new Uri("https://aka.ms/sarif-pattern-matcher");
                }

                return this.tool;
            }

            set => this.tool = value;
        }

        public static int Analyze(string[] args = null,
                                  AnalyzeOptions options = null,
                                  AnalyzeContext context = null,
                                  IFileSystem fileSystem = null)
        {
            if (context != null)
            {
                Task<int> analyzeTask = Task.Factory.StartNew(() =>
                {
                    new AnalyzeFromContext(context).Analyze();
                    return SUCCESS;
                }, context.CancellationToken);

                int msDelay = context.TimeoutInMilliseconds;
                if (Task.WhenAny(analyzeTask, Task.Delay(msDelay)).GetAwaiter().GetResult() == analyzeTask)
                {
                    bool succeeded = (context.RuntimeErrors & ~RuntimeConditions.Nonfatal) == RuntimeConditions.None;

                    Debug.Assert(
                        !(analyzeTask.IsFaulted && succeeded),
                        "Task faulted without setting a fatal runtime condition flag.");

                    // TBD rich return code.

                    return succeeded ? SUCCESS : FAILURE;
                }

                context.RuntimeErrors |= RuntimeConditions.AnalysisTimedOut;
                return FAILURE;
            }

            options ??= ConvertCommandlineArgumentsToAnalysisOptions(args);
            var analyzeCommand = new AnalyzeCommand(fileSystem);
            return analyzeCommand.Run(options);
        }

        public static ISet<Skimmer<AnalyzeContext>> CreateSkimmersFromDefinitionsFiles(IFileSystem fileSystem,
                                                                                       IEnumerable<string> searchDefinitionsPaths,
                                                                                       Tool tool,
                                                                                       IRegex engine = null)
        {
            tool.Extensions ??= new List<ToolComponent>();

            engine ??= RE2Regex.Instance;

            var validators = new ValidatorsCache(validatorBinaryPaths: null, fileSystem);
            FileRegionsCache fileRegionsCache = FileRegionsCache.Instance;

            var skimmers = new HashSet<Skimmer<AnalyzeContext>>();

            foreach (string inputSearchDefinitionsPath in searchDefinitionsPaths)
            {
                string searchDefinitionsPath = Path.GetFullPath(inputSearchDefinitionsPath);

                // INTERESTING BREAKPOINT: debugging definitions JSON load/other failures.
                // Set conditional breakpoint on 'searchDefinitionsPath' to narrow focus.

                if (!fileSystem.FileExists(searchDefinitionsPath))
                {
                    throw new ArgumentException($"Could not locate specified definitions path: '{searchDefinitionsPath}'");
                }

                string searchDefinitionsText =
                    fileSystem.FileReadAllText(searchDefinitionsPath);

                SearchDefinitions definitions =
                    JsonConvert.DeserializeObject<SearchDefinitions>(searchDefinitionsText);

                // This would skip files that does not look like rules.
                if (definitions == null || definitions.Definitions == null)
                {
                    continue;
                }

                string name = definitions.ExtensionName;
                string version = null;

                string semanticVersion = null;
                if (!string.IsNullOrEmpty(definitions.ValidatorsAssemblyName))
                {
                    string directory = Path.GetDirectoryName(searchDefinitionsPath);
                    FileVersionInfo fvi = fileSystem.FileVersionInfoGetVersionInfo(Path.Combine(directory, definitions.ValidatorsAssemblyName));

                    name = $"{fvi?.CompanyName}/{fvi?.FileDescription}/{name}";
                    // TBD add version details. Breaks test baselines currently.
                    //semanticVersion = fvi?.ProductVersion;
                    //version = fvi?.FileVersion;
                }

                var toolComponent = new ToolComponent
                {
                    Name = name,
                    Guid = definitions.Guid,
                    Version = version,
                    SemanticVersion = semanticVersion,
                    Locations = new List<ArtifactLocation>(new[]
                    {
                        new ArtifactLocation
                        {
                            Uri = new Uri(searchDefinitionsPath),
                        },
                    }),
                };

                int extensionIndex = tool.Extensions.Count;
                tool.Extensions.Add(toolComponent);

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

                // INTERESTING BREAKPOINT: debugging failure to expand/process shared strings.
                // Set conditional breakpoint on 'searchDefinitionsPath' to narrow focus.
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
                        new SearchSkimmer(engine: engine,
                                          validators: validators,
                                          definition)
                        {
                            ExtensionIndex = extensionIndex,
                        });

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

        private static AnalyzeOptions ConvertCommandlineArgumentsToAnalysisOptions(string[] args)
        {
            return Parser.Default.ParseArguments<AnalyzeOptions>(args).Value;
        }

        internal static SearchDefinitions PushInheritedData(SearchDefinitions definitions, Dictionary<string, string> sharedStrings)
        {
            var idToExpressionsMap = new Dictionary<string, List<MatchExpression>>();

            int extensionsCount = 0;
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
                    if (matchExpression.RuleEnabledState == RuleEnabledState.Disabled) { continue; }

                    if (matchExpression.SingleLineRegexes?.Count > 0)
                    {
                        for (int i = 0; i < matchExpression.SingleLineRegexes.Count; i++)
                        {
                            string current = matchExpression.SingleLineRegexes[i];
                            matchExpression.SingleLineRegexes[i] =
                                PushData(current,
                                         definition.SharedStrings,
                                         sharedStrings);
                        }
                    }

                    if (matchExpression.IntrafileRegexes?.Count > 0)
                    {
                        matchExpression.IntrafileRegexMetadata =
                            new List<RegexMetadata>(matchExpression.IntrafileRegexes.Count);

                        for (int i = 0; i < matchExpression.IntrafileRegexes.Count; i++)
                        {
                            string regex = matchExpression.IntrafileRegexes[i];
                            matchExpression.IntrafileRegexMetadata.Add(RegexMetadata.None);

                            if (regex.StartsWith("?"))
                            {
                                matchExpression.IntrafileRegexMetadata[i] = RegexMetadata.Optional;

                                // Once we record this regex as optional, mark it with the standard
                                // prefix so that the rest of processing happens as usual.
                                matchExpression.IntrafileRegexes[i] = "$" + regex.Substring(1);
                            }

                            matchExpression.IntrafileRegexes[i] =
                                PushData(matchExpression.IntrafileRegexes[i],
                                         definition.SharedStrings,
                                         sharedStrings);
                        }
                    }

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
                    matchExpression.HelpUri ??= definition.HelpUri;
                    matchExpression.Message ??= definition.Message;
                    matchExpression.Description ??= definition.Description;

                    if (matchExpression.Level == FailureLevel.None)
                    {
                        matchExpression.Level = definition.Level;
                    }

                    if (matchExpression.Kind == ResultKind.None)
                    {
                        matchExpression.Kind = definition.Kind;
                    }

                    UpdateLevelKind(matchExpression);

                    if (!idToExpressionsMap.TryGetValue(matchExpression.Id, out List<MatchExpression> cachedMatchExpressions))
                    {
                        cachedMatchExpressions = idToExpressionsMap[matchExpression.Id] = new List<MatchExpression>();
                    }

                    cachedMatchExpressions.Add(matchExpression);
                }
                extensionsCount++;
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
                    HelpUri = matchExpressions[0].HelpUri,
                    Description = matchExpressions[0].Description,
                };

                searchDefinitions.Definitions.Add(definition);
            }

#if DEBUG
            ValidateSharedStringsExpansion(searchDefinitions);
#endif

            return searchDefinitions;
        }

        internal static void UpdateLevelKind(MatchExpression matchExpression)
        {
            // If level has any value other than "none" and kind is present, then kind SHALL have the value "fail".
            if (matchExpression.Level != FailureLevel.None)
            {
                matchExpression.Kind = ResultKind.Fail;
            }

            if (matchExpression.Kind != ResultKind.Fail)
            {
                matchExpression.Level = FailureLevel.None;
            }
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

                result[key] = line.Substring(key.Length + "=".Length);
            }

            return result;
        }

        public override AnalyzeContext InitializeContextFromOptions(AnalyzeOptions options, ref AnalyzeContext context)
        {
            context = base.InitializeContextFromOptions(options, ref context);

            context.Retry = options.Retry;
            context.RedactSecrets = options.RedactSecrets;
            context.EnhancedReporting = options.EnhancedReporting;
            context.DynamicValidation = options.DynamicValidation;
            context.DisableDynamicValidationCaching = options.DisableDynamicValidationCaching;

            context.SearchDefinitionsPaths = new StringSet(options.SearchDefinitionsPaths);

            return context;
        }

        public override AnalyzeContext ValidateContext(AnalyzeContext context)
        {
            context = base.ValidateContext(context);

            if (ValidateFiles(context, context.SearchDefinitionsPaths, shouldExist: true))
            {

            }

            return context;
        }

        protected override ISet<Skimmer<AnalyzeContext>> CreateSkimmers(AnalyzeContext context)
        {
            ISet<Skimmer<AnalyzeContext>> skimmers =
                CreateSkimmersFromDefinitionsFiles(context.FileSystem, context.SearchDefinitionsPaths, Tool);

            return skimmers;
        }

        protected override AnalyzeContext DetermineApplicabilityAndAnalyze(AnalyzeContext context, IEnumerable<Skimmer<AnalyzeContext>> skimmers, ISet<string> disabledSkimmers)
        {
            context = base.DetermineApplicabilityAndAnalyze(context, skimmers, disabledSkimmers);

            ICollection<IList<Tuple<Result, int?>>> resultLists = ((CachingLogger)context.Logger).Results?.Values;

            if (resultLists != null && context.CurrentTarget.Uri.ToString().EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                var aggregatedResults = new List<Result>();
                foreach (IList<Tuple<Result, int?>> resultList in resultLists)
                {
                    foreach (Tuple<Result, int?> tuple in resultList)
                    {
                        aggregatedResults.Add(tuple.Item1);
                    }
                }

                if (aggregatedResults.Count > 0)
                {
                    var jsonLogicalLocationProcessor = new JsonLogicalLocationProcessor();
                    jsonLogicalLocationProcessor.Process(aggregatedResults, context.CurrentTarget.Contents);
                }
            }

            return context;
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
                         $"Failed to expand shared string: '{text}'");
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

                if (sharedStrings.TryGetValue(text, out string replaceText))
                {
                    text = replaceText;
                    break;
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
