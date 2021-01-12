// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Resources;
using System.Text;
using System.Text.RegularExpressions;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.RE2.Managed;
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
        private readonly FileRegionsCache _fileRegionsCache;
        private readonly ValidatorsCache _validators;
        private readonly IList<MatchExpression> _matchExpressions;
        private readonly MultiformatMessageString _fullDescription;
        private readonly Dictionary<string, int> _argumentNameToIndex;
        private readonly Dictionary<string, MultiformatMessageString> _messageStrings;
        private readonly Dictionary<MatchExpression, ReportingDescriptor> _matchExpressionToRule;

        public SearchSkimmer(IRegex engine, ValidatorsCache validators, FileRegionsCache fileRegionsCache, SearchDefinition definition, IFileSystem fileSystem = null)
            : this(
                  engine,
                  validators,
                  fileRegionsCache,
                  definition.Id,
                  definition.Name,
                  definition.Description,
                  definition.Message,
                  definition.MatchExpressions,
                  fileSystem)
        {
        }

        public SearchSkimmer(
            IRegex engine,
            ValidatorsCache validators,
            FileRegionsCache fileRegionsCache,
            string id,
            string name,
            string description,
            string defaultMessageString,
            IList<MatchExpression> matchExpressions,
            IFileSystem fileSystem = null)
        {
            _id = id;
            _name = name;
            _engine = engine;
            _validators = validators;
            _fileRegionsCache = fileRegionsCache;
            _argumentNameToIndex = GenerateIndicesForNamedArguments(ref defaultMessageString);
            _fileSystem = fileSystem ?? FileSystem.Instance;
            _matchExpressionToRule = new Dictionary<MatchExpression, ReportingDescriptor>(matchExpressions.Count);

            _fullDescription = new MultiformatMessageString
            {
                Text = description,
            };

            _messageStrings = new Dictionary<string, MultiformatMessageString>
            {
                { "Default", new MultiformatMessageString() { Text = defaultMessageString, } },
                { nameof(SdkResources.NotApplicable_InvalidMetadata), new MultiformatMessageString() { Text = SdkResources.NotApplicable_InvalidMetadata, } },
            };

            foreach (MatchExpression matchExpression in matchExpressions)
            {
                _matchExpressionToRule[matchExpression] = new ReportingDescriptor
                {
                    Id = string.IsNullOrEmpty(matchExpression.SubId) ? id : $"{id}/{matchExpression.SubId}",
                    DefaultConfiguration = this.DefaultConfiguration,
                    FullDescription = _fullDescription,
                    Help = null,
                    HelpUri = s_helpUri,
                    MessageStrings = _messageStrings,
                    Name = $"{id}/{matchExpression.SubId}",
                };
            }

            _matchExpressions = matchExpressions;
        }

        public override Uri HelpUri => s_helpUri;

        public override string Id => _id;

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
                if (!string.IsNullOrEmpty(matchExpression.FileNameDenyRegex) && _engine.IsMatch(path, matchExpression.FileNameDenyRegex))
                {
                    continue;
                }

                if (!string.IsNullOrEmpty(matchExpression.FileNameAllowRegex) && !_engine.IsMatch(path, matchExpression.FileNameAllowRegex))
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
                context.FileContents = _fileSystem.FileReadAllText(context.TargetUri.LocalPath);
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
            FailureLevel level = matchExpression.Level;

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

                ReportingDescriptor reportingDescriptor = _matchExpressionToRule[matchExpression];
                Regex regex = CachedDotNetRegex.GetOrCreateRegex(
                                matchExpression.ContentsRegex,
                                RegexDefaults.DefaultOptionsCaseInsensitive);

                Match match = regex.Match(flexMatch.Value);

                string refinedMatchedPattern = match.Groups["refine"].Value;

                IDictionary<string, string> groups = match.Groups.CopyToDictionary(regex.GetGroupNames());

                if (string.IsNullOrEmpty(refinedMatchedPattern))
                {
                    refinedMatchedPattern = flexMatch.Value;
                }

                string levelText = level.ToString();

                Validation state = 0;
                string fingerprint = null;
                string validatorMessage = null;
                string validationPrefix = string.Empty;
                string validationSuffix = string.Empty;

                if (_validators != null)
                {
                    state = _validators.Validate(reportingDescriptor.Id,
                                                context.DynamicValidation,
                                                ref refinedMatchedPattern,
                                                ref groups,
                                                ref levelText,
                                                ref fingerprint,
                                                ref validatorMessage,
                                                out bool pluginSupportsDynamicValidation);

                    if (!Enum.TryParse<FailureLevel>(levelText, out level))
                    {
                        // An illegal failure level '{0}' was returned validating a result for check '{1}'.
                        context.Logger.LogToolNotification(
                            Errors.CreateNotification(
                                context.TargetUri,
                                "ERR998.ValidatorReturnedIllegalResultLevel",
                                context.Rule.Id,
                                FailureLevel.Error,
                                exception: null,
                                persistExceptionStack: false,
                                messageFormat: SpamResources.ERR998_ValidatorReturnedIllegalValidationState,
                                context.TargetUri.GetFileName(),
                                context.Rule.Id));

                        // If we don't understand the failure level, elevate it to error.
                        level = FailureLevel.Error;
                    }

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
                        case Validation.ValidatorReturnedIllegalValidationState:
                        {
                            // An illegal state '{0}' was returned validating a result for check '{1}'.
                            context.Logger.LogToolNotification(
                                Errors.CreateNotification(
                                    context.TargetUri,
                                    "ERR998.ValidatorReturnedIllegalValidationState",
                                    context.Rule.Id,
                                    FailureLevel.Error,
                                    exception: null,
                                    persistExceptionStack: false,
                                    messageFormat: SpamResources.ERR998_ValidatorReturnedIllegalValidationState,
                                    context.TargetUri.GetFileName(),
                                    context.Rule.Id));

                            level = FailureLevel.Error;
                            continue;
                        }

                        case Validation.Authorized:
                        {
                            level = FailureLevel.Error;

                            // Contributes to building a message fragment such as:
                            // 'SomeFile.txt' contains a valid SomeApi token [...].
                            validationPrefix = "a valid ";
                            break;
                        }

                        case Validation.Unauthorized:
                        {
                            level = FailureLevel.Warning;

                            // Contributes to building a message fragment such as:
                            // 'SomeFile.txt' contains an invalid SomeApi token[...].
                            validationPrefix = "an invalid ";
                            validationSuffix = " which failed authentication";
                            break;
                        }

                        case Validation.Expired:
                        {
                            level = FailureLevel.Warning;

                            // Contributes to building a message fragment such as:
                            // 'SomeFile.txt' contains an expired SomeApi token[...].
                            validationPrefix = "an expired ";
                            break;
                        }

                        case Validation.HostUnknown:
                        {
                            level = FailureLevel.Warning;

                            // Contributes to building a message fragment such as:
                            // 'SomeFile.txt' contains an apparent SomeApi token
                            // which references an unknown host or resource[...].
                            validationPrefix = "an apparent ";
                            validationSuffix = " which references an unknown host or resource";
                            break;
                        }

                        case Validation.InvalidForConsultedAuthorities:
                        {
                            level = FailureLevel.Warning;

                            // Contributes to building a message fragment such as:
                            // 'SomeFile.txt' contains an apparent SomeApi token
                            // which references an unknown host or resource[...].
                            validationPrefix = "an apparently invalid ";
                            validationSuffix = " which was not authenticated by any consulted authority";
                            break;
                        }

                        case Validation.Unknown:
                        {
                            level = FailureLevel.Warning;

                            validationPrefix = "an apparent ";
                            if (!context.DynamicValidation)
                            {
                                if (pluginSupportsDynamicValidation)
                                {
                                    // This indicates that dynamic validation was disabled but we
                                    // passed this result to a validator that could have performed
                                    // this work.
                                    validationSuffix = ". No validation occurred as it was not enabled. Pass '--dynamic-validation' on the command-line to validate this match";
                                }
                                else
                                {
                                    // No validation was requested. The plugin indicated
                                    // that is can't perform this work in any case.
                                    validationSuffix = string.Empty;
                                }
                            }
                            else if (pluginSupportsDynamicValidation)
                            {
                                validationSuffix = ", the validity of which could not be determined by runtime analysis";
                            }
                            else
                            {
                                // Validation was requested. But the plugin indicated
                                // that it can't perform this work in any case.
                                validationSuffix = string.Empty;
                            }

                            break;
                        }

                        case Validation.ValidatorNotFound:
                        {
                            // TODO: should we have an explicit indicator in
                            // all cases that tells us whether this is an
                            // expected condition or not?
                            validationPrefix = "an apparent ";

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

                Region region = ConstructRegion(context, regionFlexMatch, refinedMatchedPattern);

                Dictionary<string, string> messageArguments = matchExpression.MessageArguments != null ?
                    new Dictionary<string, string>(matchExpression.MessageArguments) :
                    new Dictionary<string, string>();

                messageArguments["encoding"] = binary64DecodedMatch != null ?
                    "base64-encoded" :
                    string.Empty; // We don't bother to report a value for plaintext content

                messageArguments["validationPrefix"] = validationPrefix;
                messageArguments["validationSuffix"] = validationSuffix;

                IList<string> arguments = GetMessageArguments(
                    match,
                    _argumentNameToIndex,
                    context.TargetUri.LocalPath,
                    validatorMessage: NormalizeValidatorMessage(validatorMessage),
                    messageArguments);

                Result result = ConstructResult(
                    context.TargetUri,
                    reportingDescriptor.Id,
                    level,
                    region,
                    flexMatch,
                    fingerprint,
                    matchExpression.Fixes,
                    arguments);

                // This skimmer instance mutates its reporting descriptor state,
                // for example, the sub-id may change for every match
                // expression. We will therefore generate a snapshot of
                // current ReportingDescriptor state when logging.
                context.Logger.Log(reportingDescriptor, result);
            }
        }

        private void RunMatchExpressionForFileNameRegex(AnalyzeContext context, MatchExpression matchExpression, FailureLevel level)
        {
            ReportingDescriptor reportingDescriptor = _matchExpressionToRule[matchExpression];

            bool dynamic = context.DynamicValidation;
            string levelText = level.ToString();
            string fingerprint = null, message = null;
            IDictionary<string, string> groups = new Dictionary<string, string>();

            string filePath = context.TargetUri.LocalPath;

            Validation state = 0;
            string fingerprintText = null, validatorMessage = null;
            string validationPrefix = string.Empty, validationSuffix = string.Empty;

            if (_validators != null)
            {
                state = _validators.Validate(reportingDescriptor.Id,
                                            context.DynamicValidation,
                                            ref filePath,
                                            ref groups,
                                            ref levelText,
                                            ref fingerprintText,
                                            ref validatorMessage,
                                            out bool pluginSupportsDynamicValidation);

                if (!Enum.TryParse<FailureLevel>(levelText, out level))
                {
                    // An illegal failure level '{0}' was returned validating a result for check '{1}'.
                    context.Logger.LogToolNotification(
                        Errors.CreateNotification(
                            context.TargetUri,
                            "ERR998.ValidatorReturnedIllegalResultLevel",
                            context.Rule.Id,
                            FailureLevel.Error,
                            exception: null,
                            persistExceptionStack: false,
                            messageFormat: SpamResources.ERR998_ValidatorReturnedIllegalValidationState,
                            context.TargetUri.GetFileName(),
                            context.Rule.Id));

                    // If we don't understand the failure level, elevate it to error.
                    level = FailureLevel.Error;
                }

                switch (state)
                {
                    case Validation.NoMatch:
                    {
                        // The validator determined the match is a false positive.
                        // i.e., it is not the kind of artifact we're looking for.
                        // We should suspend processing and move to the next match.
                        return;
                    }

                    case Validation.None:
                    case Validation.ValidatorReturnedIllegalValidationState:
                    {
                        // An illegal state '{0}' was returned validating a result for check '{1}'.
                        context.Logger.LogToolNotification(
                            Errors.CreateNotification(
                                context.TargetUri,
                                "ERR998.ValidatorReturnedIllegalValidationState",
                                context.Rule.Id,
                                FailureLevel.Error,
                                exception: null,
                                persistExceptionStack: false,
                                messageFormat: SpamResources.ERR998_ValidatorReturnedIllegalValidationState,
                                context.TargetUri.GetFileName(),
                                context.Rule.Id));

                        level = FailureLevel.Error;
                        return;
                    }

                    case Validation.Authorized:
                    {
                        level = FailureLevel.Error;

                        // Contributes to building a message fragment such as:
                        // 'SomeFile.txt' is an exposed SomeSecret file [...].
                        validationPrefix = "an exposed ";
                        break;
                    }

                    case Validation.Expired:
                    {
                        level = FailureLevel.Warning;

                        // Contributes to building a message fragment such as:
                        // 'SomeFile.txt' contains an expired SomeApi token[...].
                        validationPrefix = "an expired ";
                        break;
                    }

                    case Validation.PasswordProtected:
                    {
                        level = FailureLevel.Warning;

                        // Contributes to building a message fragment such as:
                        // 'SomeFile.txt' contains a password-protected SomeSecret file
                        // which could be exfiltrated and potentially brute-forced offline.
                        validationPrefix = "a password-protected ";
                        validationSuffix = " which could be exfiltrated and potentially brute-forced offline";
                        break;
                    }


                    case Validation.HostUnknown:
                    case Validation.Unauthorized:
                    case Validation.InvalidForConsultedAuthorities:
                    {
                        throw new InvalidOperationException();
                    }

                    case Validation.Unknown:
                    {
                        level = FailureLevel.Warning;

                        validationPrefix = "an apparent ";
                        if (!context.DynamicValidation)
                        {
                            if (pluginSupportsDynamicValidation)
                            {
                                // This indicates that dynamic validation was disabled but we
                                // passed this result to a validator that could have performed
                                // this work.
                                validationSuffix = ". No validation occurred as it was not enabled. Pass '--dynamic-validation' on the command-line to validate this match";
                            }
                            else
                            {
                                // No validation was requested. The plugin indicated
                                // that is can't perform this work in any case.
                                validationSuffix = string.Empty;
                            }
                        }
                        else if (pluginSupportsDynamicValidation)
                        {
                            validationSuffix = ", the validity of which could not be determined by runtime analysis";
                        }
                        else
                        {
                            // Validation was requested. But the plugin indicated
                            // that it can't perform this work in any case.
                            validationSuffix = string.Empty;
                        }

                        break;
                    }

                    case Validation.ValidatorNotFound:
                    {
                        // TODO: should we have an explicit indicator in
                        // all cases that tells us whether this is an
                        // expected condition or not?
                        validationPrefix = "an apparent ";

                        break;
                    }

                    default:
                    {
                        throw new InvalidOperationException($"Unrecognized validation value '{state}'.");
                    }
                }
            }

            Dictionary<string, string> messageArguments =
                matchExpression.MessageArguments != null ?
                    new Dictionary<string, string>(matchExpression.MessageArguments) :
                    new Dictionary<string, string>();

            messageArguments["validationPrefix"] = validationPrefix;
            messageArguments["validationSuffix"] = validationSuffix;

            IList<string> arguments = GetMessageArguments(
                match: null,
                _argumentNameToIndex,
                context.TargetUri.LocalPath,
                validatorMessage: NormalizeValidatorMessage(validatorMessage),
                messageArguments);


            Result result = this.ConstructResult(
                    context.TargetUri,
                    reportingDescriptor.Id,
                    level,
                    region: null,
                    flexMatch: null,
                    fingerprint,
                    matchExpression.Fixes,
                    arguments);

            context.Logger.Log(reportingDescriptor, result);
        }


        private string GetValidationPrefix(Validation state)
        {
            string prefix = state switch
            {
                Validation.Expired => "an expired",
                Validation.Authorized => "a valid",
                Validation.Unauthorized => "an invalid",
                Validation.HostUnknown => "an unrecognized",
                Validation.Unknown => "a potentially compromised",
                Validation.InvalidForConsultedAuthorities => "an invalid",
                _ => "an apparent",
            };

            return prefix + " ";
        }

        private string NormalizeValidatorMessage(string validatorMessage)
        {
            if (string.IsNullOrEmpty(validatorMessage)) { return string.Empty; }

            validatorMessage = validatorMessage.Trim(new char[] { ' ', '.' });

            return " (" + validatorMessage[0].ToString().ToLowerInvariant() + validatorMessage.Substring(1) + ")";
        }

        private Region ConstructRegion(AnalyzeContext context, FlexMatch regionFlexMatch, string fingerprint)
        {
            int indexOffset = regionFlexMatch.Value.String.IndexOf(fingerprint);
            int lengthOffset = fingerprint.Length - regionFlexMatch.Length;

            if (indexOffset == -1)
            {
                // If we can't find the fingerprint in the match, that means we matched against
                // base64-decoded content (and therefore there is no region refinement to make).
                indexOffset = 0;
                lengthOffset = 0;
            }

            var region = new Region
            {
                CharOffset = regionFlexMatch.Index + indexOffset,
                CharLength = regionFlexMatch.Length + lengthOffset,
            };

            return _fileRegionsCache.PopulateTextRegionProperties(
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
            string fingerprint,
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

            Dictionary<string, string> fingerprints = BuildFingerprints(fingerprint);

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
                Fingerprints = fingerprints,
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

        private Dictionary<string, string> BuildFingerprints(string fingerprint)
        {
            if (fingerprint == null) { return null; }

            return new Dictionary<string, string>()
            {
                { "SecretFingerprint/v1", fingerprint },
            };
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
                    : match?.Groups[kv.Key]?.Value;

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
