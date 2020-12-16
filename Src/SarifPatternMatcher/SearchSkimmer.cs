// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Resources;
using System.Text;
using System.Text.RegularExpressions;

using Microsoft.CodeAnalysis.Sarif;
using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.SarifPatternMatcher.Strings;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher
{
    public class SearchSkimmer : Skimmer<AnalyzeContext>
    {
        private const string Base64DecodingFormatString = @"\b(?i)[0-9a-z\/+]{{{0}}}==";

        private static readonly Uri s_helpUri =
            new Uri("https://github.com/microsoft/sarif-pattern-matcher");

        private static readonly Regex namedArgumentsRegex =
            new Regex(@"[^}]?{(?<index>\d+):(?<name>[a-zA-Z]+)}[\}]*", RegexDefaults.DefaultOptionsCaseSensitive);

        private readonly string _id;
        private readonly string _name; // TODO there's no mechanism for flowing rule names to rules.
        private readonly IRegex _engine;
        private readonly Regex _defaultNameRegex;
        private readonly ValidatorsCache _validators;
        private readonly IList<MatchExpression> _matchExpressions;
        private readonly MultiformatMessageString _fullDescription;
        private readonly Dictionary<string, int> _argumentNameToIndex;
        private readonly Dictionary<string, MultiformatMessageString> _messageStrings;

        private FileRegionsCache _regionsCache;

        public SearchSkimmer(
            IRegex engine,
            ValidatorsCache validators,
            string id,
            string name,
            FailureLevel defaultLevel,
            string description,
            string defaultNameRegex,
            string defaultMessageString,
            IList<MatchExpression> matchExpressions)
        {
            _id = id;
            _name = name;
            _engine = engine;
            _validators = validators;

            this.DefaultConfiguration.Level = defaultLevel;

            _defaultNameRegex = new Regex(
                defaultNameRegex ?? string.Empty,
                RegexDefaults.DefaultOptionsCaseSensitive);

            _matchExpressions = matchExpressions;

            _fullDescription = new MultiformatMessageString
            {
                Text = description,
            };

            _argumentNameToIndex = GenerateIndicesForNamedArguments(ref defaultMessageString);

            _messageStrings = new Dictionary<string, MultiformatMessageString>
            {
                { "Default", new MultiformatMessageString() { Text = defaultMessageString, } },
            };
        }

        public override Uri HelpUri => s_helpUri;

        public override string Id => _id;

        public override string Name => base.Name;

        public override MultiformatMessageString FullDescription => _fullDescription;

        public override MultiformatMessageString Help => null;

        public override IDictionary<string, MultiformatMessageString> MessageStrings => _messageStrings;

        protected override ResourceManager ResourceManager => SpamResources.ResourceManager;

        public override AnalysisApplicability CanAnalyze(AnalyzeContext context, out string reasonIfNotApplicable)
        {
            reasonIfNotApplicable = SpamResources.TargetDoesNotMeetFileNameCriteria;

            if (!_defaultNameRegex.IsMatch(context.TargetUri.LocalPath))
            {
                return AnalysisApplicability.NotApplicableToSpecifiedTarget;
            }

            reasonIfNotApplicable = null;
            return AnalysisApplicability.ApplicableToSpecifiedTarget;
        }

        public override void Analyze(AnalyzeContext context)
        {
            if (context.FileContents == null)
            {
                lock (context)
                {
                    if (context.FileContents == null)
                    {
                        context.FileContents = File.ReadAllText(context.TargetUri.LocalPath);
                    }
                }
            }

            foreach (MatchExpression matchExpression in _matchExpressions)
            {
                if (matchExpression.Base64DecodedContentLength > 0)
                {
                    string base64DecodingRegexText = string.Format(Base64DecodingFormatString, matchExpression.Base64DecodedContentLength);

                    foreach (FlexMatch flexMatch in _engine.Matches(context.FileContents, base64DecodingRegexText))
                    {
                        // This will run the match expression against the decoded content.
                        RunMatchExpression(
                            binary64DecodedMatch: flexMatch,
                            context,
                            matchExpression);
                    }
                }

                // This runs the match expression against the entire, unencoded file.
                RunMatchExpression(
                    binary64DecodedMatch: null,
                    context,
                    matchExpression);
            }
        }

        private void RunMatchExpression(FlexMatch binary64DecodedMatch, AnalyzeContext context, MatchExpression matchExpression)
        {
            string searchText = binary64DecodedMatch != null
                                   ? Decode(binary64DecodedMatch.Value)
                                   : context.FileContents;

            foreach (FlexMatch flexMatch in _engine.Matches(searchText, matchExpression.ContentsRegex))
            {
                if (!flexMatch.Success) { continue; }

                var regex = new Regex(matchExpression.ContentsRegex, RegexDefaults.DefaultOptionsCaseInsensitive);
                Match match = regex.Match(flexMatch.Value);

                string fingerprint = match.Groups["fingerprint"].Value;

                if (string.IsNullOrEmpty(fingerprint))
                {
                    fingerprint = flexMatch.Value;
                }

                bool dynamic = context.DynamicValidation;

                if (_validators.Validate(matchExpression.SubId, fingerprint, dynamic) == Validation.Invalid ||
                    _validators.Validate(this.Id, fingerprint, dynamic) == Validation.Invalid)
                {
                    // TODO add a trace for this condition.
                    continue;
                }

                // TODO need to emit proper SARIF if a match expression overrides the default format string.
                string messageFormatString = matchExpression.Message ?? this._messageStrings["Default"].Text;

                IList<string> arguments = GetMessageArguments(
                    match,
                    _argumentNameToIndex,
                    context.TargetUri.LocalPath,
                    base64Encoded: binary64DecodedMatch != null,
                    matchExpression.MessageArguments);

                string ruleId = this.Id +
                    (!string.IsNullOrEmpty(matchExpression.SubId) ?
                        "/" + matchExpression.SubId :
                        string.Empty);

                FailureLevel level = matchExpression.Level != 0 ?
                    matchExpression.Level :
                    DefaultConfiguration.Level;

                // If we're matching against decoded contents, the region should
                // relate to the base64-encoded scan target content. We do use
                // the decoded content for the fingerprint, however.
                FlexMatch regionFlexMatch = binary64DecodedMatch ?? flexMatch;

                var region = new Region
                {
                    CharOffset = regionFlexMatch.Index,
                    CharLength = regionFlexMatch.Length,
                };

                _regionsCache ??= new FileRegionsCache();

                region = _regionsCache.PopulateTextRegionProperties(
                    region,
                    context.TargetUri,
                    populateSnippet: true,
                    fileText: context.FileContents);

                var location = new Location()
                {
                    PhysicalLocation = new PhysicalLocation
                    {
                        ArtifactLocation = new ArtifactLocation
                        {
                            Uri = context.TargetUri,
                        },
                        Region = region,
                    },
                };

                var result = new Result()
                {
                    RuleId = ruleId,
                    Level = level,
                    Message = new Message()
                    {
                        Id = "Default",
                        Arguments = arguments,
                    },
                    Locations = new List<Location>(new[] { location }),
                };

                if (matchExpression.Fixes?.Count > 0)
                {
                    // Build arguments
                    var argumentNameToValueMap = new Dictionary<string, string>();

                    foreach (KeyValuePair<string, int> kv in _argumentNameToIndex)
                    {
                        argumentNameToValueMap["{" + kv.Key + "}"] = arguments[kv.Value];
                    }

                    foreach (SimpleFix fix in matchExpression.Fixes.Values)
                    {
                        ExpandArguments(fix, argumentNameToValueMap);
                        AddFixToResult(flexMatch, fix, result);
                    }
                }

                context.Logger.Log(this, result);
            }
        }

        private FlexString Decode(string value)
        {
            byte[] bytes = Convert.FromBase64String(value);
            return Encoding.ASCII.GetString(bytes);
        }

        private void ExpandArguments(SimpleFix fix, Dictionary<string, string> argumentNameToValueMap)
        {
            fix.Find = ExpandArguments(fix.Find, argumentNameToValueMap);
            fix.ReplaceWith = ExpandArguments(fix.ReplaceWith, argumentNameToValueMap);
            fix.Description = ExpandArguments(fix.Description, argumentNameToValueMap);
        }

        private string ExpandArguments(string text, Dictionary<string, string> argumentNameToValueMap)
        {
            foreach (KeyValuePair<string, string> kv in argumentNameToValueMap)
            {
                text = text.Replace(kv.Key, kv.Value);
            }

            return text;
        }

        private void AddFixToResult(FlexMatch flexMatch, SimpleFix simpleFix, Result result)
        {
            result.Fixes ??= new List<Fix>();

            string replacementText = flexMatch.Value.String.Replace(simpleFix.Find, simpleFix.ReplaceWith);

            var fix = new Fix()
            {
                Description = new Message() { Text = simpleFix.Description },
                ArtifactChanges = new List<ArtifactChange>(new[]
                {
                    new ArtifactChange()
                    {
                        ArtifactLocation = result.Locations[0].PhysicalLocation.ArtifactLocation,
                        Replacements = new List<Replacement>(new[]
                        {
                            new Replacement()
                            {
                                DeletedRegion = new Region()
                                {
                                    CharOffset = flexMatch.Index,
                                    CharLength = flexMatch.Length,
                                },
                                InsertedContent = new ArtifactContent()
                                {
                                    Text = replacementText,
                                },
                            },
                        }),
                    },
                }),
            };

            result.Fixes.Add(fix);
        }

        private Dictionary<string, int> GenerateIndicesForNamedArguments(ref string defaultMessageString)
        {
            var namedArgumentsToIndexMap = new Dictionary<string, int>();

            foreach (Match match in namedArgumentsRegex.Matches(defaultMessageString))
            {
                string name = match.Groups["name"].Value;
                string index = match.Groups["index"].Value;

                namedArgumentsToIndexMap[name] = int.Parse(index);

                string find = $"{{{index}:{name}}}";
                string replace = $"{{{index}}}";

                defaultMessageString = defaultMessageString.Replace(find, replace);
            }

            return namedArgumentsToIndexMap;
        }

        private IList<string> GetMessageArguments(
            Match match,
            Dictionary<string, int> namedArgumentToIndexMap,
            string scanTargetPath,
            bool base64Encoded,
            Dictionary<string, string> additionalArguments)
        {
            int argsCount = namedArgumentToIndexMap.Count;

            var arguments = new List<string>(new string[argsCount]);

            foreach (KeyValuePair<string, int> kv in namedArgumentToIndexMap)
            {
                string value = kv.Key == "scanTarget" ?
                    Path.GetFileName(scanTargetPath) :
                    match.Groups[kv.Key]?.Value;

                value = kv.Key == nameof(scanTargetPath) ?
                    scanTargetPath :
                    value;

                // TODO add support for base64 decoding
                value = kv.Key == "encoding"
                    ? (base64Encoded ? "base64-encoded" : "plaintext")
                    : value;

                arguments[kv.Value] = value;
            }

            if (additionalArguments != null)
            {
                foreach (KeyValuePair<string, string> kv in additionalArguments)
                {
                    int index = namedArgumentToIndexMap[kv.Key];
                    arguments[index] = kv.Value;
                }
            }

            return arguments;
        }
    }
}
