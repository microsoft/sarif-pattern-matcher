// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Resources;
using System.Text;
using System.Text.RegularExpressions;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.Strings.Interop;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SearchSkimmer : Skimmer<AnalyzeContext>
    {
        private const string Base64DecodingFormatString = "\\b(?i)[0-9a-z\\/+]{0}";

        private static readonly Uri s_helpUri =
            new Uri("https://github.com/microsoft/sarif-pattern-matcher");

        private static readonly Regex namedArgumentsRegex =
            new Regex(@"[^}]?{(?<index>\d+):(?i)(?<name>[a-z]+)}[\}]*", RegexDefaults.DefaultOptionsCaseSensitive);

        private readonly string _id;
        private readonly string _name; // TODO there's no mechanism for flowing rule names to rules.
        private readonly IRegex _engine;
        private readonly IFileSystem _fileSystem;
        private readonly string _fileNameDenyRegex;
        private readonly string _fileNameAllowRegex;
        private readonly ValidatorsCache _validators;
        private readonly IList<MatchExpression> _matchExpressions;
        private readonly MultiformatMessageString _fullDescription;
        private readonly Dictionary<string, int> _argumentNameToIndex;
        private readonly Dictionary<string, MultiformatMessageString> _messageStrings;
        private string _subId;

        private FileRegionsCache _regionsCache;

        public SearchSkimmer(IRegex engine, ValidatorsCache validators, SearchDefinition definition, IFileSystem fileSystem = null)
            : this(
                  engine,
                  validators,
                  definition.Id,
                  definition.Name,
                  definition.Level,
                  definition.Description,
                  definition.FileNameDenyRegex,
                  definition.FileNameAllowRegex,
                  definition.Message,
                  definition.MatchExpressions,
                  fileSystem)
        {
        }

        public SearchSkimmer(
            IRegex engine,
            ValidatorsCache validators,
            string id,
            string name,
            FailureLevel defaultLevel,
            string description,
            string fileNameDenyRegex,
            string fileNameAllowRegex,
            string defaultMessageString,
            IList<MatchExpression> matchExpressions,
            IFileSystem fileSystem = null)
        {
            _id = id;
            _name = name;
            _engine = engine;
            _validators = validators;

            this.DefaultConfiguration.Level = defaultLevel;

            _fileNameDenyRegex = fileNameDenyRegex;
            _fileNameAllowRegex = fileNameAllowRegex;

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

            _fileSystem = fileSystem ?? FileSystem.Instance;
        }

        public override Uri HelpUri => s_helpUri;

        public override string Id => !string.IsNullOrEmpty(_subId) ?
                    _id + "/" + _subId :
                    _id;

        public override string Name => Id;

        public override MultiformatMessageString FullDescription => _fullDescription;

        public override MultiformatMessageString Help => null;

        public override IDictionary<string, MultiformatMessageString> MessageStrings => _messageStrings;

        protected override ResourceManager ResourceManager => SpamResources.ResourceManager;

        public override AnalysisApplicability CanAnalyze(AnalyzeContext context, out string reasonIfNotApplicable)
        {
            string path = context.TargetUri.LocalPath;
            reasonIfNotApplicable = null;

            foreach (MatchExpression matchExpression in _matchExpressions)
            {
                string regex = matchExpression.FileNameDenyRegex ?? _fileNameDenyRegex;

                if (!string.IsNullOrEmpty(regex) && _engine.IsMatch(path, regex))
                {
                    continue;
                }

                regex = matchExpression.FileNameAllowRegex ?? _fileNameAllowRegex;

                if (!string.IsNullOrEmpty(regex) && !_engine.IsMatch(path, regex))
                {
                    continue;
                }

                reasonIfNotApplicable = null;
                return AnalysisApplicability.ApplicableToSpecifiedTarget;
            }

            reasonIfNotApplicable = SpamResources.TargetDoesNotMeetFileNameCriteria;
            return AnalysisApplicability.NotApplicableToSpecifiedTarget;
        }

        public override void Analyze(AnalyzeContext context)
        {
            if (context.FileContents == null)
            {
                lock (context)
                {
                    if (context.FileContents == null)
                    {
                        context.FileContents = _fileSystem.FileReadAllText(context.TargetUri.LocalPath);
                    }
                }
            }

            foreach (MatchExpression matchExpression in _matchExpressions)
            {
                if (!string.IsNullOrEmpty(matchExpression.FileNameAllowRegex))
                {
                    if (!_engine.IsMatch(context.TargetUri.LocalPath,
                                         matchExpression.FileNameAllowRegex,
                                         RegexDefaults.DefaultOptionsCaseInsensitive))
                    {
                        continue;
                    }
                }

                if (!string.IsNullOrEmpty(matchExpression.FileNameDenyRegex))
                {
                    if (_engine.IsMatch(context.TargetUri.LocalPath,
                                        matchExpression.FileNameDenyRegex,
                                        RegexDefaults.DefaultOptionsCaseInsensitive))
                    {
                        continue;
                    }
                }

                if (matchExpression.MatchLengthToDecode > 0)
                {
                    decimal unencodedLength = matchExpression.MatchLengthToDecode;

                    // Every 3 bytes of a base64-encoded string produces 4 bytes of data.
                    int unpaddedLength = (int)Math.Ceiling(decimal.Divide(unencodedLength * 8M, 6M));
                    int paddedLength = 4 * (int)Math.Ceiling(decimal.Divide(unencodedLength, 3M));

                    // Create proper regex for base64-encoded string which includes padding characters.
                    string base64DecodingRegexText =
                        string.Format(Base64DecodingFormatString, "{" + unpaddedLength + "}") +
                        new string('=', paddedLength - unpaddedLength);

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
            _subId = matchExpression.SubId;

            FailureLevel level = matchExpression.Level != 0 ?
                matchExpression.Level :
                DefaultConfiguration.Level;

            if (!string.IsNullOrEmpty(matchExpression.ContentsRegex))
            {
                RunMatchExpressionForContentsRegex(binary64DecodedMatch, context, matchExpression, level);
            }
            else if (!string.IsNullOrEmpty(matchExpression.FileNameAllowRegex))
            {
                RunMatchExpressionForFileNameRegex(context, matchExpression, level);
            }
            else
            {
                // Both FileNameAllowRegex and ContentRegex are null or empty.
            }
        }

        private void RunMatchExpressionForContentsRegex(
            FlexMatch binary64DecodedMatch,
            AnalyzeContext context,
            MatchExpression matchExpression,
            FailureLevel level)
        {
            string searchText = binary64DecodedMatch != null
                                                   ? Decode(binary64DecodedMatch.Value)
                                                   : context.FileContents;

            foreach (FlexMatch flexMatch in _engine.Matches(searchText, matchExpression.ContentsRegex))
            {
                if (!flexMatch.Success) { continue; }

                Regex regex = CachedDotNetRegex.GetOrCreateRegex(
                                matchExpression.ContentsRegex,
                                RegexDefaults.DefaultOptionsCaseInsensitive);

                Match match = regex.Match(flexMatch.Value);

                string fingerprint = match.Groups["fingerprint"].Value;

                Dictionary<string, string> groups = match.Groups.CopyToDictionary(regex.GetGroupNames());

                if (string.IsNullOrEmpty(fingerprint))
                {
                    fingerprint = flexMatch.Value;
                }

                bool dynamic = context.DynamicValidation;
                string levelText = level.ToString();

                Validation state = 0;
                string validatorMessage = null;

                string validationState = string.Empty;

                if (_validators != null)
                {
                    state = _validators.Validate(
                        matchExpression.SubId ?? _id,
                        fingerprint,
                        groups,
                        ref dynamic,
                        ref levelText,
                        out validatorMessage);

                    level = (FailureLevel)Enum.Parse(typeof(FailureLevel), levelText);

                    switch (state)
                    {
                        case Validation.NoMatch:
                        {
                            // The validator determined the match is a false positive.
                            // i.e., it is not the kind of artifact we're looking for.
                            // We should suspend processing and move to the next match.
                            continue;
                        }

                        case Validation.None:
                        case Validation.ValidatorReturnedIllegalValue:
                        {
                            // The validator returned a bad value.
                            // TODO: we should log this condition
                            // and then continue processing.
                            level = FailureLevel.Error;
                            break;
                        }

                        case Validation.Valid:
                        {
                            level = FailureLevel.Error;
                            validationState = " which was determined to be valid";
                            break;
                        }

                        case Validation.Invalid:
                        {
                            level = FailureLevel.Warning;
                            validationState = " which was determined to be invalid";
                            break;
                        }

                        case Validation.InvalidForConsultedAuthorities:
                        {
                            level = FailureLevel.Warning;
                            validationState = " which was determined to be invalid for all consulted authorities";
                            break;
                        }

                        case Validation.Unknown:
                        {
                            if (!context.DynamicValidation)
                            {
                                if (dynamic)
                                {
                                    // This indicates that dynamic validation was disabled but we
                                    // passed this result to a validator that could have performed
                                    // this work.
                                    validationState = ". No validation occurred for this match as it was not enabled. Pass '--dynamic-validation' on the command-line to enable it";
                                }
                                else
                                {
                                    // No validation was requested. The plugin indicated
                                    // that is can't perform this work in any case.
                                    validationState = string.Empty;
                                }
                            }
                            else if (dynamic)
                            {
                                validationState = ", the validity of which could not be determined";
                            }
                            else
                            {
                                // Validation was requested. But the plugin indicated
                                // that it can't perform this work in any case.
                                validationState = string.Empty;
                            }

                            break;
                        }

                        case Validation.ValidatorNotFound:
                        {
                            // TODO: should we have an explicit indicator in
                            // all cases that tells us whether this is an
                            // expected condition or not?
                            break;
                        }

                        default:
                        {
                            throw new InvalidOperationException($"Unrecognized validation value '{state}'.");
                        }
                    }
                }

                // If we're matching against decoded contents, the region should
                // relate to the base64-encoded scan target content. We do use
                // the decoded content for the fingerprint, however.
                FlexMatch regionFlexMatch = binary64DecodedMatch ?? flexMatch;

                Region region = ConstructRegion(context, regionFlexMatch);

                Dictionary<string, string> messageArguments = matchExpression.MessageArguments != null ?
                    new Dictionary<string, string>(matchExpression.MessageArguments) :
                    new Dictionary<string, string>();

                messageArguments["encoding"] = binary64DecodedMatch != null ?
                    "base64-encoded" :
                    "plaintext";

                messageArguments["validationState"] = validationState;

                IList<string> arguments = GetMessageArguments(
                    match,
                    _argumentNameToIndex,
                    context.TargetUri.LocalPath,
                    validatorMessage: validatorMessage,
                    messageArguments);

                Result result = ConstructResult(
                    context.TargetUri,
                    Id,
                    level,
                    region,
                    flexMatch,
                    matchExpression.Fixes,
                    arguments);

                // This skimmer instance mutates its reporting descriptor state,
                // for example, the sub-id may change for every match
                // expression. We will therefore generate a snapshot of
                // current ReportingDescriptor state when logging.
                context.Logger.Log(this.DeepClone(), result);
            }
        }

        private Region ConstructRegion(AnalyzeContext context, FlexMatch regionFlexMatch)
        {
            var region = new Region
            {
                CharOffset = regionFlexMatch.Index,
                CharLength = regionFlexMatch.Length,
            };

            _regionsCache ??= new FileRegionsCache();

            return _regionsCache.PopulateTextRegionProperties(
                region,
                context.TargetUri,
                populateSnippet: true,
                fileText: context.FileContents);
        }

        private Result ConstructResult(
            Uri targetUri,
            string ruleId,
            FailureLevel level,
            Region region,
            FlexMatch flexMatch,
            IDictionary<string, SimpleFix> fixes,
            IList<string> arguments)
        {
            var location = new Location()
            {
                PhysicalLocation = new PhysicalLocation
                {
                    ArtifactLocation = new ArtifactLocation
                    {
                        Uri = targetUri,
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

            if (fixes?.Count > 0)
            {
                // Build arguments that may be required for fix text.
                var argumentNameToValueMap = new Dictionary<string, string>();

                foreach (KeyValuePair<string, int> kv in _argumentNameToIndex)
                {
                    argumentNameToValueMap["{" + kv.Key + "}"] = arguments[kv.Value];
                }

                foreach (SimpleFix fix in fixes.Values)
                {
                    ExpandArguments(fix, argumentNameToValueMap);
                    AddFixToResult(flexMatch, fix, result);
                }
            }

            return result;
        }

        private void RunMatchExpressionForFileNameRegex(AnalyzeContext context, MatchExpression matchExpression, FailureLevel level)
        {
            IList<string> arguments = GetMessageArguments(
                _argumentNameToIndex,
                context.TargetUri.LocalPath,
                base64Encoded: false,
                matchExpression.MessageArguments);

            var location = new Location()
            {
                PhysicalLocation = new PhysicalLocation
                {
                    ArtifactLocation = new ArtifactLocation
                    {
                        Uri = context.TargetUri,
                    },
                },
            };

            var result = new Result()
            {
                RuleId = Id,
                Level = level,
                Message = new Message()
                {
                    Id = "Default",
                    Arguments = arguments,
                },
                Locations = new List<Location>(new[] { location }),
            };

            context.Logger.Log(this, result);
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
            string validatorMessage,
            Dictionary<string, string> additionalArguments)
        {
            int argsCount = namedArgumentToIndexMap.Count;

            var arguments = new List<string>(new string[argsCount]);

            foreach (KeyValuePair<string, int> kv in namedArgumentToIndexMap)
            {
                string value = kv.Key == "scanTarget"
                    ? Path.GetFileName(scanTargetPath)
                    : match.Groups[kv.Key]?.Value;

                value = kv.Key == nameof(scanTargetPath)
                    ? scanTargetPath
                    : value;

                value = kv.Key == "validatorMessage"
                    ? validatorMessage ?? string.Empty
                    : value;

                arguments[kv.Value] = value;
            }

            if (additionalArguments != null)
            {
                foreach (KeyValuePair<string, string> kv in additionalArguments)
                {
                    if (namedArgumentToIndexMap.TryGetValue(kv.Key, out int index))
                    {
                        arguments[index] = kv.Value;
                    }
                }
            }

            return arguments;
        }

        private IList<string> GetMessageArguments(
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
                    string.Empty;

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
