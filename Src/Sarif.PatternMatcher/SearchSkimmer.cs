// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Resources;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Schema;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.Driver.Sdk;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;
using Microsoft.Strings.Interop;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SearchSkimmer : Skimmer<AnalyzeContext>
    {
        public const string SecretHashSha256Current = "secretHashSha256/v0";
        public const string AssetFingerprintCurrent = "assetFingerprint/v0";
        public const string SecretFingerprintCurrent = "secretFingerprint/v0";
        public const string ValidationFingerprintCurrent = "validationFingerprint/v0";
        public const string ValidationFingerprintHashSha256Current = "validationFingerprintHashSha256/v0";

        public const string DynamicValidationNotEnabled = "No validation occurred as it was not enabled. Pass '--dynamic-validation' on the command-line to validate this match";

        public readonly IList<MatchExpression> MatchExpressions;

        private const string DefaultHelpUri = "https://github.com/microsoft/sarif-pattern-matcher";
        private const string Base64DecodingFormatString = "\\b(?i)[0-9a-z\\/+]{0}";

        private static readonly Regex namedArgumentsRegex =
            new Regex(@"[^}]?{(?<index>\d+):(?i)(?<name>[a-z]+)}[\}]*", RegexDefaults.DefaultOptionsCaseSensitive);

        private readonly string _id;
        private readonly string _name; // TODO there's no mechanism for flowing rule names to rules.
        private readonly Uri _helpUri;
        private readonly IRegex _engine;
        private readonly ValidatorsCache _validators;
        private readonly IList<string> _deprecatedNames;
        private readonly MultiformatMessageString _fullDescription;
        private readonly Dictionary<string, MultiformatMessageString> _messageStrings;

        public SearchSkimmer(IRegex engine,
                             ValidatorsCache validators,
                             SearchDefinition definition)
        {
            _engine = engine;
            _id = definition.Id;
            _name = definition.Name;
            _validators = validators;
            _helpUri = new Uri(definition.HelpUri ?? DefaultHelpUri);
            _fullDescription = new MultiformatMessageString { Text = definition.Description };

            _messageStrings = new Dictionary<string, MultiformatMessageString>
            {
                { nameof(SdkResources.NotApplicable_InvalidMetadata), new MultiformatMessageString() { Text = SdkResources.NotApplicable_InvalidMetadata, } },
            };

            foreach (MatchExpression matchExpression in definition.MatchExpressions)
            {
                string matchExpressionMessage = matchExpression.Message;
                matchExpression.ArgumentNameToIndexMap = GenerateIndicesForNamedArguments(ref matchExpressionMessage);

                if (!string.IsNullOrEmpty(matchExpression.DeprecatedName) && _deprecatedNames == null)
                {
                    _deprecatedNames = new List<string>
                    {
                        matchExpression.DeprecatedName,
                    };
                }

                string messageId = matchExpression.MessageId;
                if (_messageStrings.ContainsKey(messageId))
                {
                    continue;
                }

                _messageStrings[messageId] = new MultiformatMessageString
                {
                    Text = matchExpressionMessage,
                };
            }

            MatchExpressions = definition.MatchExpressions;

            if (definition.MatchExpressions?.Count > 0 &&
                definition.MatchExpressions[0].MessageArguments != null &&
                definition.MatchExpressions[0].MessageArguments.TryGetValue("secretKind", out string uiLabel))
            {
                // By convention, our secret skimmers publish the kind of secret associated with a find
                // as a message argument named 'secretKind'. This user-facing string comprises a nice
                // human-readable rule name. We will use this data for this purpose, if available.
                // Moving forward, this concept of a rule 'UI label' would be a good addition to
                // the SARIF format. https://github.com/oasis-tcs/sarif-spec/issues/567.
                //
                //  "MessageArguments": { "secretKind": "legacy format GitHub personal access token" }
                //      will be rendered as:
                //  "Legacy format GitHub personal access token"
                uiLabel = uiLabel[0].ToString().ToUpperInvariant() + uiLabel.Substring(1);
                this.SetProperty("sarif/uiLabel", uiLabel);
            }
        }

        public override Uri HelpUri => _helpUri;

        public override string Id => _id;

        public override string Name => _name;

        public override IList<string> DeprecatedNames => _deprecatedNames;

        public override MultiformatMessageString FullDescription => _fullDescription;

        public override MultiformatMessageString Help => null;

        public override IDictionary<string, MultiformatMessageString> MessageStrings => _messageStrings;

        protected override ResourceManager ResourceManager => SpamResources.ResourceManager;

        public override AnalysisApplicability CanAnalyze(AnalyzeContext context, out string reasonIfNotApplicable)
        {
            string filePath = context.CurrentTarget.Uri.GetFilePath();
            reasonIfNotApplicable = null;

            if (!string.IsNullOrWhiteSpace(context.GlobalFilePathDenyRegex) &&
                _engine.Match(filePath, pattern: context.GlobalFilePathDenyRegex).Success)
            {
                reasonIfNotApplicable = SpamResources.TargetWasFilteredByFileNameDenyRegex;
                return AnalysisApplicability.NotApplicableToSpecifiedTarget;
            }

            foreach (MatchExpression matchExpression in MatchExpressions)
            {
                if (!string.IsNullOrEmpty(matchExpression.FileNameDenyRegex) &&
                    _engine.IsMatch(filePath,
                                    matchExpression.FileNameDenyRegex,
                                    RegexDefaults.DefaultOptionsCaseInsensitive))
                {
                    DriverEventSource.Log.RuleNotCalled(filePath,
                                                        matchExpression.Id,
                                                        $"{matchExpression.Name}\\{matchExpression.Index}",
                                                        DriverEventNames.FilePathDenied,
                                                        data2: matchExpression.FileNameDenyRegex.CsvEscape());

                    continue;
                }

                if (!string.IsNullOrEmpty(matchExpression.FileNameAllowRegex) &&
                    !_engine.IsMatch(filePath,
                                     matchExpression.FileNameAllowRegex,
                                     RegexDefaults.DefaultOptionsCaseInsensitive))
                {
                    DriverEventSource.Log.RuleNotCalled(filePath,
                                                        matchExpression.Id,
                                                        $"{matchExpression.Name}\\{matchExpression.Index}",
                                                        DriverEventNames.FilePathNotAllowed,
                                                        data2: matchExpression.FileNameAllowRegex.CsvEscape());

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
            string filePath = context.CurrentTarget.Uri.GetFilePath();

            for (int i = 0; i < MatchExpressions.Count; i++)
            {
                MatchExpression matchExpression = MatchExpressions[i];
                matchExpression.Index ??= $"{i}";

                if (!string.IsNullOrEmpty(matchExpression.FileNameAllowRegex) &&
                    !_engine.IsMatch(filePath,
                                         matchExpression.FileNameAllowRegex,
                                         RegexDefaults.DefaultOptionsCaseInsensitive))
                {
                    DriverEventSource.Log.RuleNotCalled(filePath,
                                                        matchExpression.Id,
                                                        $"{matchExpression.Name}\\{matchExpression.Index}",
                                                        DriverEventNames.FilePathNotAllowed,
                                                        data2: $"{matchExpression.FileNameAllowRegex}".CsvEscape());
                    continue;
                }

                if (!string.IsNullOrEmpty(matchExpression.FileNameDenyRegex) &&
                    _engine.IsMatch(filePath,
                                    matchExpression.FileNameDenyRegex,
                                    RegexDefaults.DefaultOptionsCaseInsensitive))
                {
                    DriverEventSource.Log.RuleNotCalled(filePath,
                                                        matchExpression.Id,
                                                        $"{matchExpression.Name}\\{matchExpression.Index}",
                                                        DriverEventNames.FilePathDenied,
                                                        data2: $"{matchExpression.FileNameDenyRegex}".CsvEscape());
                    continue;
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

                    foreach (FlexMatch flexMatch in _engine.Matches(context.CurrentTarget.Contents, base64DecodingRegexText))
                    {
                        // This will run the match expression against the decoded content.
                        RunMatchExpression(binary64DecodedMatch: flexMatch,
                                           context,
                                           matchExpression);
                    }
                }

                // This runs the match expression against the entire, unencoded file.
                RunMatchExpression(binary64DecodedMatch: null,
                                   context,
                                   matchExpression);
            }
        }

        internal static void SetPropertiesBasedOnValidationState(ValidationState state,
                                                                 AnalyzeContext context,
                                                                 ResultLevelKind resultLevelKind,
                                                                 ref FailureLevel level,
                                                                 ref ResultKind kind,
                                                                 ref string validationPrefix,
                                                                 ref string validationSuffix,
                                                                 ref string validatorMessage,
                                                                 bool pluginSupportsDynamicValidation)
        {
            switch (state)
            {
                case ValidationState.NoMatch:
                {
                    // The validator determined the match is a false positive.
                    // i.e., it is not the kind of artifact we're looking for.
                    // We should suspend processing and move to the next match.

                    level = FailureLevel.None;
                    break;
                }

                case ValidationState.None:
                case ValidationState.ValidatorReturnedIllegalValidationState:
                {
                    if (context != null)
                    {
                        // An illegal state was returned running check '{0}' against '{1}' ({2}).
                        context.Logger.LogToolNotification(
                            Errors.CreateNotification(context.CurrentTarget.Uri,
                                                      "ERR998.ValidatorReturnedIllegalValidationState",
                                                      context.Rule.Id,
                                                      FailureLevel.Error,
                                                      exception: null,
                                                      persistExceptionStack: false,
                                                      messageFormat: SpamResources.ERR998_ValidatorReturnedIllegalValidationState,
                                                      context.Rule.Id,
                                                      context.CurrentTarget.Uri.GetFileName(),
                                                      validatorMessage));
                    }

                    level = FailureLevel.Error;
                    break;
                }

                case ValidationState.Authorized:
                {
                    level = FailureLevel.Error;

                    // Contributes to building a message fragment such as:
                    // 'SomeFile.txt' contains a valid SomeApi token [...].
                    validationPrefix = "a valid ";
                    validationSuffix = string.Empty;
                    break;
                }

                case ValidationState.PasswordProtected:
                {
                    level = FailureLevel.Warning;

                    // Contributes to building a message fragment such as:
                    // 'SomeFile.txt' contains a valid but password-protected
                    // SomeApi token [...].
                    validationPrefix = "a valid but password-protected ";
                    break;
                }

                case ValidationState.Unauthorized:
                {
                    level = FailureLevel.Note;

                    // Contributes to building a message fragment such as:
                    // 'SomeFile.txt' contains an invalid SomeApi token[...].
                    validationPrefix = "an invalid ";
                    validationSuffix = " which failed authentication";
                    break;
                }

                case ValidationState.Expired:
                {
                    level = FailureLevel.Note;

                    // Contributes to building a message fragment such as:
                    // 'SomeFile.txt' contains an expired SomeApi token[...].
                    validationPrefix = "an expired ";
                    break;
                }

                case ValidationState.UnknownHost:
                {
                    level = FailureLevel.Note;

                    // Contributes to building a message fragment such as:
                    // 'SomeFile.txt' contains an apparent SomeApi token
                    // which references an unknown host or resource[...].
                    validationPrefix = "an apparent ";
                    validationSuffix = " which references an unknown host or resource";
                    break;
                }

                case ValidationState.InvalidForConsultedAuthorities:
                {
                    level = FailureLevel.Note;

                    // Contributes to building a message fragment such as:
                    // 'SomeFile.txt' contains an apparent SomeApi token
                    // which references an unknown host or resource[...].
                    validationPrefix = "an apparently invalid ";
                    validationSuffix = " which was not authenticated by any consulted authority";
                    break;
                }

                case ValidationState.Unknown:
                {
                    validationSuffix = string.Empty;

                    validationPrefix = "an apparent ";
                    if (context?.DynamicValidation == false)
                    {
                        if (pluginSupportsDynamicValidation)
                        {
                            // This indicates that dynamic validation was disabled but we
                            // passed this result to a validator that could have performed
                            // this work.
                            validatorMessage += " " + DynamicValidationNotEnabled;
                            level = FailureLevel.Warning;
                        }
                    }
                    else if (pluginSupportsDynamicValidation)
                    {
                        validationSuffix = ", the validity of which could not be determined by runtime analysis";
                    }

                    break;
                }

                case ValidationState.ValidatorNotFound:
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

            if (resultLevelKind != default)
            {
                kind = resultLevelKind.Kind;
                level = resultLevelKind.Level;
            }
        }

        internal static string NormalizeValidatorMessage(string validatorMessage)
        {
            if (string.IsNullOrEmpty(validatorMessage)) { return string.Empty; }

            validatorMessage = validatorMessage.Trim(new char[] { ' ', '.' });

            return " (" + validatorMessage[0].ToString().ToLowerInvariant() + validatorMessage.Substring(1) + ")";
        }

        internal static string RecoverValidatorMessage(string validatorMessage)
        {
            int dynamicValidationMessageIndex = validatorMessage.IndexOf(DynamicValidationNotEnabled, StringComparison.OrdinalIgnoreCase);

            return dynamicValidationMessageIndex != -1
                ? validatorMessage.Substring(dynamicValidationMessageIndex, DynamicValidationNotEnabled.Length)
                : null;
        }

        internal static Fingerprint CreateFingerprintFromMatch(IDictionary<string, FlexMatch> match)
        {
            var fingerprint = default(Fingerprint);

            foreach (KeyValuePair<string, FlexMatch> kv in match)
            {
                fingerprint.SetProperty(kv.Key,
                                        kv.Value.Value,
                                        ignoreRecognizedKeyNames: true);
            }

            return fingerprint;
        }

        private static void MergeDictionary(IList<Dictionary<string, FlexMatch>> mergeFrom, IDictionary<string, ISet<FlexMatch>> mergedGroups)
        {
            foreach (Dictionary<string, FlexMatch> groups in mergeFrom)
            {
                foreach (KeyValuePair<string, FlexMatch> keyValue in groups)
                {
                    string key = keyValue.Key;

                    // We only persist named groups, not groups specified by index.
                    if (int.TryParse(keyValue.Key, out int val)) { continue; }

                    if (!mergedGroups.TryGetValue(keyValue.Key, out ISet<FlexMatch> flexMatches))
                    {
                        mergedGroups[keyValue.Key] = flexMatches = new HashSet<FlexMatch>(FlexMatchValueComparer.Instance);
                    }

                    flexMatches.Add(keyValue.Value);
                }
            }
        }

        private static void ConstructResultAndLogForFileNameRegex(AnalyzeContext context,
                                                           MatchExpression matchExpression,
                                                           FailureLevel level,
                                                           ResultKind kind,
                                                           ReportingDescriptor reportingDescriptor,
                                                           Fingerprint fingerprint,
                                                           string validatorMessage,
                                                           string validationPrefix,
                                                           string validationSuffix,
                                                           string filePath)
        {
            Dictionary<string, string> messageArguments =
                            matchExpression.MessageArguments != null ?
                                new Dictionary<string, string>(matchExpression.MessageArguments) :
                                new Dictionary<string, string>();

            messageArguments["validationPrefix"] = validationPrefix;
            messageArguments["validationSuffix"] = validationSuffix;

            IList<string> arguments = GetMessageArguments(groups: null,
                                                          matchExpression.ArgumentNameToIndexMap,
                                                          filePath,
                                                          validatorMessage: NormalizeValidatorMessage(validatorMessage),
                                                          messageArguments);

            Result result = ConstructResult(context,
                                            reportingDescriptor.Id,
                                            level,
                                            kind,
                                            region: null,
                                            flexMatch: null,
                                            fingerprint,
                                            matchExpression,
                                            arguments);

            context.Logger.Log(reportingDescriptor, result);
        }

        private static Result ConstructResult(AnalyzeContext context,
                                              string ruleId,
                                              FailureLevel level,
                                              ResultKind kind,
                                              Region region,
                                              FlexMatch flexMatch,
                                              Fingerprint fingerprint,
                                              MatchExpression matchExpression,
                                              IList<string> arguments)
        {
            var location = new Location()
            {
                PhysicalLocation = new PhysicalLocation
                {
                    ArtifactLocation = new ArtifactLocation
                    {
                        Uri = context.CurrentTarget.Uri,
                    },
                    Region = region,
                },
            };

            IDictionary<string, string> partialFingerprints = null;
            if (context.DataToInsert.HasFlag(OptionallyEmittedData.RollingHashPartialFingerprints))
            {
                context.RollingHashMap ??= HashUtilities.RollingHash(context.CurrentTarget.Contents);
                string rollingHash = context.RollingHashMap[location.PhysicalLocation.Region.StartLine];
                partialFingerprints = new Dictionary<string, string>() { { "primaryLocationLineHash", rollingHash } };
            }

            Dictionary<string, string> fingerprints = BuildFingerprints(context.RedactSecrets, fingerprint, out double rank);

            if (!string.IsNullOrEmpty(matchExpression.SubId))
            {
                ruleId = $"{ruleId}/{matchExpression.SubId}";
            }

            // We'll limit rank precision to two decimal places. Because this value
            // is actually converted from a normalized range of 0.0 to 1.0, to the
            // SARIF 0.0 to 100.0 equivalent, this is effectively four decimal places
            // of precision as far as the normalized Shannon entropy is concerned.
            rank = Math.Round(rank, 2, MidpointRounding.AwayFromZero);

            var result = new Result()
            {
                RuleId = ruleId,
                Level = level,
                Kind = kind,
                Message = new Message()
                {
                    Id = matchExpression.MessageId,
                    Arguments = arguments,
                },
                Rank = rank,
                Locations = new List<Location>(new[] { location }),
                Fingerprints = fingerprints,
                PartialFingerprints = partialFingerprints,
            };

            if (matchExpression.Fixes?.Count > 0)
            {
                // Build arguments that may be required for fix text.
                var argumentNameToValueMap = new Dictionary<string, string>();

                foreach (KeyValuePair<string, int> kv in matchExpression.ArgumentNameToIndexMap)
                {
                    argumentNameToValueMap["{" + kv.Key + "}"] = arguments[kv.Value];
                }

                // This will create one fixRegion that will be re-used for all matchExpression.Fixes
                Region fixRegion = result.Locations[0].PhysicalLocation.Region.DeepClone();
                fixRegion.Snippet = null;
                foreach (SimpleFix fix in matchExpression.Fixes.Values)
                {
                    ExpandArguments(fix, argumentNameToValueMap);
                    AddFixToResult(flexMatch, fix, result, fixRegion);
                }
            }

            string secretHashSha256 = null;
            fingerprints?.TryGetValue(SecretHashSha256Current, out secretHashSha256);

            DriverEventSource.Log.RuleFired(context.CurrentTarget.Uri.GetFilePath(),
                                            ruleId,
                                            $"{matchExpression.Name}/{matchExpression.Index}",
                                            level,
                                            secretHashSha256);

            return result;
        }

        private static Dictionary<string, string> BuildFingerprints(bool redactSecrets, Fingerprint fingerprint, out double rank)
        {
            rank = -1;

            if (fingerprint == default)
            {
                return null;
            }

            rank = fingerprint.GetRank();

            // Add all fingerprints with no sensitive information by default.
            var fingerprints = new Dictionary<string, string>()
            {
                { SecretHashSha256Current, fingerprint.GetSecretHash() },
                { AssetFingerprintCurrent, fingerprint.GetAssetFingerprint() },
                { ValidationFingerprintHashSha256Current, fingerprint.GetValidationFingerprintHash() },
            };

            // Add fingerprints that expose sensitive data in plaintext
            // only if they are conditionally requested.
            if (!redactSecrets)
            {
                fingerprints[SecretFingerprintCurrent] = fingerprint.GetSecretFingerprint();
                fingerprints[ValidationFingerprintCurrent] = fingerprint.GetValidationFingerprint();
            }

            return fingerprints;
        }

        private static FlexString Decode(string value)
        {
            byte[] bytes = Convert.FromBase64String(value);
            return Encoding.ASCII.GetString(bytes);
        }

        private static void ExpandArguments(SimpleFix fix, Dictionary<string, string> argumentNameToValueMap)
        {
            fix.Find = ExpandArguments(fix.Find, argumentNameToValueMap);
            fix.ReplaceWith = ExpandArguments(fix.ReplaceWith, argumentNameToValueMap);
            fix.Description = ExpandArguments(fix.Description, argumentNameToValueMap);
        }

        private static string ExpandArguments(string text, Dictionary<string, string> argumentNameToValueMap)
        {
            foreach (KeyValuePair<string, string> kv in argumentNameToValueMap)
            {
                text = text.Replace(kv.Key, kv.Value);
            }

            return text;
        }

        private static void AddFixToResult(FlexMatch flexMatch, SimpleFix simpleFix, Result result, Region region)
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
                                DeletedRegion = region,
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

        private static Dictionary<string, int> GenerateIndicesForNamedArguments(ref string defaultMessageString)
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

        private static IList<string> GetMessageArguments(IDictionary<string, FlexMatch> groups,
                                                  Dictionary<string, int> namedArgumentToIndexMap,
                                                  string scanTargetPath,
                                                  string validatorMessage,
                                                  Dictionary<string, string> additionalArguments)
        {
            int argsCount = namedArgumentToIndexMap.Count;

            var arguments = new List<string>(new string[argsCount]);

            foreach (KeyValuePair<string, int> kv in namedArgumentToIndexMap)
            {
                string value = string.Empty;

                if (kv.Key == "scanTarget")
                {
                    value = Path.GetFileName(scanTargetPath);
                }
                else if (kv.Key == nameof(scanTargetPath))
                {
                    value = scanTargetPath;
                }
                else if (kv.Key == "validatorMessage")
                {
                    value = validatorMessage ?? string.Empty;
                }
                else if (groups != null && groups.TryGetValue(kv.Key, out FlexMatch groupValue))
                {
                    value = groupValue.Value;
                }

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

        private Region ConstructRegionForSecret(AnalyzeContext context, FlexMatch regionFlexMatch)
        {
            var region = new Region
            {
                CharOffset = regionFlexMatch.Index,
                CharLength = regionFlexMatch.Length,
            };

            return PopulateTextRegionProperties(context, region);
        }

        private static Region PopulateTextRegionProperties(AnalyzeContext context, Region region)
        {
            context.Logger.FileRegionsCache ??= new FileRegionsCache();

            return
                context.Logger.FileRegionsCache.PopulateTextRegionProperties(region,
                                                                             context.CurrentTarget.Uri,
                                                                             populateSnippet: true,
                                                                             fileText: context.CurrentTarget.Contents);
        }

        private void RunMatchExpression(FlexMatch binary64DecodedMatch, AnalyzeContext context, MatchExpression matchExpression)
        {
            bool isMalformed = true;

            bool singleIntraRegex =
                matchExpression.IntrafileRegexes?.Count > 0 ||
                matchExpression.SingleLineRegexes?.Count > 0;

            bool simpleRegex = !string.IsNullOrEmpty(matchExpression.ContentsRegex);

            bool contentRegex = simpleRegex || singleIntraRegex;

            if (contentRegex)
            {
                if (simpleRegex)
                {
                    RunMatchExpressionForContentsRegex(binary64DecodedMatch, context, matchExpression);
                }

                if (singleIntraRegex)
                {
                    RunMatchExpressionForSingleLineAndIntrafileRegexes(context, matchExpression);
                }

                isMalformed = false;
            }
            else if (!string.IsNullOrEmpty(matchExpression.FileNameAllowRegex))
            {
                // This should only happen when we don't have any content regex (simple, intra, single)
                // and we are just looking for files with certain patterns.
                RunMatchExpressionForFileNameRegex(context, matchExpression);
                isMalformed = false;
            }

            if (isMalformed)
            {
                throw new InvalidOperationException("Malformed expression contains no regexes.");
            }
        }

        private void RunMatchExpressionForSingleLineAndIntrafileRegexes(AnalyzeContext context, MatchExpression matchExpression)
        {
            if (matchExpression.IntrafileRegexes?.Count > 0)
            {
                RunMatchExpressionForIntrafileRegexes(context, matchExpression);
            }

            if (matchExpression.SingleLineRegexes?.Count > 0)
            {
                RunMatchExpressionForSingleLineRegexes(context, matchExpression);
            }
        }

        private StringBuilder sb;

        private void RunMatchExpressionForIntrafileRegexes(AnalyzeContext context, MatchExpression matchExpression)
        {
            ResultKind kind = matchExpression.Kind;
            FailureLevel level = matchExpression.Level;
            string searchText = context.CurrentTarget.Contents;
            string filePath = context.CurrentTarget.Uri.GetFilePath();

            var mergedGroups = new Dictionary<string, ISet<FlexMatch>>();

            DriverEventSource.Log.RuleReserved1Start(SpamEventNames.RunRulePhase0Regex,
                                                    filePath,
                                                    matchExpression.Id,
                                                    $"{matchExpression.Name}/{matchExpression.Index}",
                                                    "IntrafileRegex",
                                                    data2: $@"{{""searchText.GetHashCode()"":""{searchText.GetHashCode()}""}}");

            if (!string.IsNullOrWhiteSpace(context.EventsFilePath))
            {
                sb ??= new StringBuilder();
                sb.Clear();
            }

            for (int i = 0; i < matchExpression.IntrafileRegexes?.Count; i++)
            {
                string regex = matchExpression.IntrafileRegexes[i];

                Debug.Assert(!regex.StartsWith("$"), $"Unexpanded regex variable: {regex}");

                if (!Matches(regex,
                             searchText,
                             out List<Dictionary<string, FlexMatch>> matches,
                             context))
                {
                    if (matchExpression.RegexMetadata[i] == RegexMetadata.Optional)
                    {
                        sb?.Append(@$"{(sb.Length > 0 ? ", " : string.Empty)}[optional no match]{regex}");
                        continue;
                    }

                    sb?.Append(@$"{(sb.Length > 0 ? ", " : string.Empty)}{regex}");
                    DriverEventSource.Log.RuleReserved1Stop(SpamEventNames.RunRulePhase0Regex,
                                                            filePath,
                                                            matchExpression.Id,
                                                            $"{matchExpression.Name}/{matchExpression.Index}",
                                                            "IntrafileRegex",
                                                            data2: @$"{{""matchCount"":0,""regex"":""{regex}""}}".CsvEscape());
                    return;
                }

                sb?.Append(@$"{(sb.Length > 0 ? ", " : string.Empty)}{regex}");
                MergeDictionary(matches, mergedGroups);
            }

            DriverEventSource.Log.RuleReserved1Stop(SpamEventNames.RunRulePhase0Regex,
                                                    filePath,
                                                    matchExpression.Id,
                                                    $"{matchExpression.Name}/{matchExpression.Index}",
                                                    "IntrafileRegex",
                                                    data2: $"{sb}".CsvEscape());

            sb?.Clear();

            if (mergedGroups.Count > 0)
            {
                ValidateMatch(context,
                              matchExpression,
                              mergedGroups,
                              groups: null,
                              ref kind,
                              ref level);
            }
        }

        private void RunMatchExpressionForSingleLineRegexes(AnalyzeContext context, MatchExpression matchExpression)
        {
            IList<string> regexes = matchExpression.SingleLineRegexes;

            if (regexes == null || regexes.Count == 0)
            {
                return;
            }

            if (!string.IsNullOrWhiteSpace(context.EventsFilePath))
            {
                sb ??= new StringBuilder();
                sb.Clear();
            }

            ResultKind kind = matchExpression.Kind;
            string searchText = context.CurrentTarget.Contents;
            FailureLevel level = matchExpression.Level;

            string firstRegex = matchExpression.SingleLineRegexes[0];

            // 'm' is multiline mode, i.e., ^ and $ match the beginning and
            // end of lines as well as the beginning or end of the search text.
            string lineRegex = $"(?m)^.*{firstRegex}.*";

            string filePath = context.CurrentTarget.Uri.GetFilePath();

            DriverEventSource.Log.RuleReserved1Start(SpamEventNames.RunRulePhase0Regex,
                                                     filePath,
                                                     matchExpression.Id,
                                                     $"{matchExpression.Name}/{matchExpression.Index}",
                                                     "ExtractLinesRegex",
                                                     data2: $@"{{""searchText.GetHashCode()"":""{searchText.GetHashCode()}""}}");

            if (!Matches(lineRegex,
                        searchText,
                        out List<Dictionary<string, FlexMatch>> singleLineMatches,
                        context))
            {
                DriverEventSource.Log.RuleReserved1Stop(SpamEventNames.RunRulePhase0Regex,
                                                        filePath,
                                                        matchExpression.Id,
                                                        $"{matchExpression.Name}/{matchExpression.Index}",
                                                        "ExtractLinesRegex",
                                                        data2: $"No match: {lineRegex}".CsvEscape());
                return;
            }

            DriverEventSource.Log.RuleReserved1Stop(SpamEventNames.RunRulePhase0Regex,
                                                    filePath,
                                                    matchExpression.Id,
                                                    $"{matchExpression.Name}/{matchExpression.Index}",
                                                    "ExtractLinesRegex",
                                                    data2: $"Matched: {lineRegex}".CsvEscape());

            var combinations = new List<IDictionary<string, FlexMatch>>();

            foreach (Dictionary<string, FlexMatch> lineMatch in singleLineMatches)
            {
                if (matchExpression.SingleLineRegexes.Count == 1)
                {
                    combinations.Add(lineMatch);
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(context.EventsFilePath))
                {
                    sb ??= new StringBuilder();
                    sb.Clear();
                }

                DriverEventSource.Log.RuleReserved1Start(SpamEventNames.RunRulePhase0Regex,
                                                         filePath,
                                                         matchExpression.Id,
                                                         $"{matchExpression.Name}/{matchExpression.Index}",
                                                         "IntralineRegex",
                                                         data2: $@"{{""searchText.GetHashCode()"":""{searchText.GetHashCode()}""}}");

                if (IntralineMatch(context, filePath, lineMatch, matchExpression))
                {
                    combinations.Add(lineMatch);
                }
            }

            ValidateMatch(context,
                         matchExpression,
                         mergedGroups: null,
                         groups: combinations,
                         ref kind,
                         ref level);
        }

        private bool IntralineMatch(AnalyzeContext context, string filePath, Dictionary<string, FlexMatch> lineMatch, MatchExpression matchExpression)
        {
            string lineText = lineMatch["0"].Value;

            for (int i = 1; i < matchExpression.SingleLineRegexes.Count; i++)
            {
                string regex = matchExpression.SingleLineRegexes[i];

                if (!Matches(regex,
                             lineText,
                             out List<Dictionary<string, FlexMatch>> intralineMatches,
                             context))
                {
                    if (matchExpression.RegexMetadata[i] == RegexMetadata.Optional)
                    {
                        sb?.Append(@$"{(sb.Length > 0 ? ", " : string.Empty)}[optional no match]{regex}");
                        continue;
                    }

                    sb?.Append(@$"{(sb.Length > 0 ? ", " : string.Empty)}{regex}");
                    DriverEventSource.Log.RuleReserved1Stop(SpamEventNames.RunRulePhase0Regex,
                                                            filePath,
                                                            matchExpression.Id,
                                                            $"{matchExpression.Name}/{matchExpression.Index}",
                                                            "IntralineRegex",
                                                            data2: $"No match: {regex}".CsvEscape());

                    return false;
                }

                // TODO: we only support a single intraline match per expression. How should
                // we report or error out in cases where this expectation isn't met?
                Dictionary<string, FlexMatch> intralineMatch = intralineMatches[0];

                // We will copy the component groups into the per-line match.
                foreach (KeyValuePair<string, FlexMatch> kv in intralineMatch)
                {
                    if (int.TryParse(kv.Key, out int val)) { continue; }

                    kv.Value.Index += lineMatch["0"].Index;
                    lineMatch[kv.Key] = kv.Value;
                }

                sb?.Append(@$"{(sb.Length > 0 ? ", " : string.Empty)}{regex}");
            }

            DriverEventSource.Log.RuleReserved1Stop(SpamEventNames.RunRulePhase0Regex,
                                        filePath,
                                        matchExpression.Id,
                                        $"{matchExpression.Name}/{matchExpression.Index}",
                                        "IntralineRegex",
                                        data2: $"Matched: {sb}".CsvEscape());

            sb?.Clear();

            return true;
        }

        private void ValidateMatch(AnalyzeContext context,
                                   MatchExpression matchExpression,
                                   Dictionary<string, ISet<FlexMatch>> mergedGroups,
                                   IList<IDictionary<string, FlexMatch>> groups,
                                   ref ResultKind kind,
                                   ref FailureLevel level)
        {
            string validatorMessage = null;
            string validationPrefix = string.Empty;
            string validationSuffix = string.Empty;
            ReportingDescriptor reportingDescriptor = this;

            if (_validators != null && matchExpression.IsValidatorEnabled)
            {
                string filePath = context.CurrentTarget.Uri.GetFilePath();
                string ruleName = matchExpression.Name ?? reportingDescriptor.Name;
                IEnumerable<ValidationResult> validationResults = _validators.Validate(reportingDescriptor.Id,
                                                                                       ruleName,
                                                                                       context,
                                                                                       mergedGroups,
                                                                                       groups,
                                                                                       matchExpression.Properties,
                                                                                       out bool pluginSupportsDynamicValidation);
                if (validationResults != null)
                {
                    foreach (ValidationResult validationResult in validationResults)
                    {
                        if (validationResult.ValidationState == ValidationState.None ||
                            validationResult.ValidationState == ValidationState.NoMatch ||
                            validationResult.ValidationState == ValidationState.ValidatorReturnedIllegalValidationState)
                        {
                            continue;
                        }

                        validatorMessage = validationResult.Message;
                        SetPropertiesBasedOnValidationState(validationResult.ValidationState,
                                                            context,
                                                            validationResult.ResultLevelKind,
                                                            ref level,
                                                            ref kind,
                                                            ref validationPrefix,
                                                            ref validationSuffix,
                                                            ref validatorMessage,
                                                            pluginSupportsDynamicValidation);
                        validationResult.Message = validatorMessage;
                        validationResult.ResultLevelKind = new ResultLevelKind { Kind = kind, Level = level };

                        // TODO: we do not have the ability to provide arbitrary match data from
                        // groups to the result construction API, except for the single-line
                        // match case. This could be a good improvement for intrafile analysis.
                        IDictionary<string, FlexMatch> namedGroups =
                            groups?[0] ??
                            mergedGroups.ToDictionary(mg => mg.Key, mg => mg.Value.FirstOrDefault());

                        ConstructResultAndLogForContentsRegex(binary64DecodedMatch: null,
                                                              context,
                                                              matchExpression,
                                                              filePath,
                                                              validationResult.RegionFlexMatch,
                                                              reportingDescriptor,
                                                              namedGroups,
                                                              validationPrefix,
                                                              validationSuffix,
                                                              validationResult);
                    }
                }
            }
        }

        private void RunMatchExpressionForContentsRegex(FlexMatch binary64DecodedMatch,
                                                        AnalyzeContext context,
                                                        MatchExpression matchExpression)
        {
            ResultKind kind = matchExpression.Kind;
            FailureLevel level = matchExpression.Level;
            string filePath = context.CurrentTarget.Uri.GetFilePath();
            string searchText = binary64DecodedMatch != null
                                                   ? Decode(binary64DecodedMatch.Value).String
                                                   : context.CurrentTarget.Contents;

            DriverEventSource.Log.RuleReserved1Start(SpamEventNames.RunRulePhase0Regex,
                                                     filePath,
                                                     matchExpression.Id,
                                                     $"{matchExpression.Name}/{matchExpression.Index}",
                                                     "ContentsRegex",
                                                     data2: $@"{{""searchText.GetHashCode()"":""{searchText.GetHashCode()}""}}");

            // INTERESTING BREAKPPOINT: debug static analysis match failures.
            // Set a conditional breakpoint on 'matchExpression.Name' to filter by specific rules.
            // Set a conditional breakpoint on 'searchText' to filter on specific target text patterns.
            bool matched = Matches(matchExpression.ContentsRegex,
                                   searchText,
                                   out List<Dictionary<string, FlexMatch>> matches,
                                   context);

            DriverEventSource.Log.RuleReserved1Stop(SpamEventNames.RunRulePhase0Regex,
                                                    filePath,
                                                    matchExpression.Id,
                                                    $"{matchExpression.Name}/{matchExpression.Index}",
                                                    "ContentsRegex",
                                                    data2: @$"{{""matchCount"":{matches?.Count ?? 0},""regex"":""{matchExpression.ContentsRegex}""}}".CsvEscape());

            if (!matched)
            {
                return;
            }

            foreach (Dictionary<string, FlexMatch> match in matches)
            {
                ReportingDescriptor reportingDescriptor = this;

                Debug.Assert(!match.ContainsKey("scanTargetFullPath"), "Full path should only be populated by engine.");
                match["scanTargetFullPath"] = new FlexMatch { Value = filePath };
                match["retry"] = new FlexMatch { Value = context.Retry ? bool.TrueString : bool.FalseString };
                match["enhancedReporting"] = new FlexMatch { Value = context.EnhancedReporting ? bool.TrueString : bool.FalseString };
                match.AddProperties(matchExpression.Properties);

                FlexMatch flexMatch = match["0"];
                if (match.TryGetValue("refine", out FlexMatch refineMatch))
                {
                    flexMatch = refineMatch;
                }

                if (match.TryGetValue("secret", out FlexMatch secretFlexMatch))
                {
                    flexMatch = secretFlexMatch;
                }

                Fingerprint fingerprint = default;
                string validatorMessage = null;
                string validationPrefix = string.Empty;
                string validationSuffix = string.Empty;

                if (_validators != null && matchExpression.IsValidatorEnabled)
                {
                    string ruleName = matchExpression.Name ?? reportingDescriptor.Name;
                    IEnumerable<ValidationResult> validationResults = _validators.Validate(this.Id,
                                                                                           ruleName,
                                                                                           context,
                                                                                           match,
                                                                                           out bool pluginSupportsDynamicValidation);

                    if (validationResults != null)
                    {
                        foreach (ValidationResult validationResult in validationResults)
                        {
                            if (validationResult.ValidationState == ValidationState.None ||
                                validationResult.ValidationState == ValidationState.NoMatch ||
                                validationResult.ValidationState == ValidationState.ValidatorReturnedIllegalValidationState)
                            {
                                continue;
                            }

                            validatorMessage = validationResult.Message;
                            SetPropertiesBasedOnValidationState(validationResult.ValidationState,
                                                                context,
                                                                validationResult.ResultLevelKind,
                                                                ref level,
                                                                ref kind,
                                                                ref validationPrefix,
                                                                ref validationSuffix,
                                                                ref validatorMessage,
                                                                pluginSupportsDynamicValidation);

                            validationResult.Message = validatorMessage;
                            validationResult.ResultLevelKind = new ResultLevelKind { Kind = kind, Level = level };
                            ConstructResultAndLogForContentsRegex(binary64DecodedMatch,
                                                                  context,
                                                                  matchExpression,
                                                                  filePath,
                                                                  validationResult.RegionFlexMatch ?? flexMatch,
                                                                  reportingDescriptor,
                                                                  match,
                                                                  validationPrefix,
                                                                  validationSuffix,
                                                                  validationResult);
                        }
                    }
                }
                else
                {
                    Debug.Assert(fingerprint == default, "Fingerprint should be default.");
                    fingerprint = CreateFingerprintFromMatch(match);

                    var result = new ValidationResult
                    {
                        Fingerprint = fingerprint,
                        Message = validatorMessage,
                        ResultLevelKind = new ResultLevelKind { Kind = kind, Level = level },
                    };

                    ConstructResultAndLogForContentsRegex(binary64DecodedMatch,
                                                          context,
                                                          matchExpression,
                                                          filePath,
                                                          flexMatch,
                                                          reportingDescriptor,
                                                          match,
                                                          validationPrefix,
                                                          validationSuffix,
                                                          result);
                }
            }
        }

        private bool Matches(string contentsRegex,
                             string searchText,
                             out List<Dictionary<string, FlexMatch>> matches,
                             AnalyzeContext context)
        {
            var re2regex = _engine as RE2Regex;

            long maxMemoryInKB =
                context.MaxMemoryInKilobytes == -1
                    ? context.MaxMemoryInKilobytes
                    : 1024 * context.MaxMemoryInKilobytes;

            if (re2regex != null)
            {
                return re2regex.Matches(contentsRegex,
                                        searchText,
                                        out matches,
                                        ref context.TextToRE2DataMap,
                                        maxMemoryInKB);
            }

            return _engine.Matches(contentsRegex,
                                   searchText,
                                   out matches,
                                   maxMemoryInKB);
        }

        private void ConstructResultAndLogForContentsRegex(FlexMatch binary64DecodedMatch,
                                                           AnalyzeContext context,
                                                           MatchExpression matchExpression,
                                                           string filePath,
                                                           FlexMatch flexMatch,
                                                           ReportingDescriptor reportingDescriptor,
                                                           IDictionary<string, FlexMatch> groups,
                                                           string validationPrefix,
                                                           string validationSuffix,
                                                           ValidationResult validationResult)
        {
            // If we're matching against decoded contents, the region should
            // relate to the base64-encoded scan target content. We do use
            // the decoded content for the fingerprint, however.
            FlexMatch regionFlexMatch = binary64DecodedMatch ??
                                        flexMatch ??
                                        validationResult.RegionFlexMatch;

            Region region = ConstructRegionForSecret(context, regionFlexMatch);

            string toRedact = binary64DecodedMatch != null
                ? binary64DecodedMatch.Value.String
                : validationResult.Fingerprint.Secret;

            if (context.RedactSecrets)
            {
                RedactSecretFromSnippet(region, toRedact);
            }

            Dictionary<string, string> messageArguments = matchExpression.MessageArguments != null ?
                new Dictionary<string, string>(matchExpression.MessageArguments) :
                new Dictionary<string, string>();

            messageArguments["encoding"] = binary64DecodedMatch != null ?
                "base64-encoded" :
                string.Empty; // We don't bother to report a value for plaintext content

            messageArguments["validationPrefix"] = validationPrefix;
            messageArguments["validationSuffix"] = validationSuffix;

            messageArguments["truncatedSecret"] = binary64DecodedMatch != null ?
                binary64DecodedMatch.Value.String.Truncate() :
                validationResult.Fingerprint.Secret.Truncate();

            IList<string> arguments = GetMessageArguments(groups,
                                                          matchExpression.ArgumentNameToIndexMap,
                                                          filePath,
                                                          validatorMessage: NormalizeValidatorMessage(validationResult.Message),
                                                          messageArguments);

            Result result = ConstructResult(context,
                                            reportingDescriptor.Id,
                                            validationResult.ResultLevelKind.Level,
                                            validationResult.ResultLevelKind.Kind,
                                            region,
                                            flexMatch,
                                            validationResult.Fingerprint,
                                            matchExpression,
                                            arguments);

            if ((context.DataToInsert & OptionallyEmittedData.ContextRegionSnippets) == OptionallyEmittedData.ContextRegionSnippets)
            {
                Region contextRegion = ConstructMultilineContextSnippet(context, region);

                if (context.RedactSecrets)
                {
                    RedactSecretFromSnippet(contextRegion, toRedact);
                }

                result.Locations[0].PhysicalLocation.ContextRegion = contextRegion;
            }

            // This skimmer instance mutates its reporting descriptor state,
            // for example, the sub-id may change for every match
            // expression. We will therefore generate a snapshot of
            // current ReportingDescriptor state when logging.
            context.Logger.Log(reportingDescriptor, result, this.ExtensionIndex);
        }

        internal static void RedactSecretFromSnippet(Region region, string secret)
        {
            string anonymizedSecret = secret.Anonymize();
            region.Snippet.Text = region.Snippet.Text.Replace(secret, anonymizedSecret);
        }

        private static Region ConstructMultilineContextSnippet(AnalyzeContext context, Region region)
        {
            context.Logger.FileRegionsCache ??= new FileRegionsCache();

            return
                context.Logger.FileRegionsCache.ConstructMultilineContextSnippet(region, context.CurrentTarget.Uri);
        }

        private void RunMatchExpressionForFileNameRegex(AnalyzeContext context, MatchExpression matchExpression)
        {
            ResultKind kind = matchExpression.Kind;
            FailureLevel level = matchExpression.Level;
            ReportingDescriptor reportingDescriptor = this;
            IDictionary<string, FlexMatch> groups = new Dictionary<string, FlexMatch>();

            if (!string.IsNullOrEmpty(context.CurrentTarget.Contents))
            {
                groups["content"] = new FlexMatch
                {
                    Index = 0,
                    Length = (int)context.CurrentTarget.SizeInBytes,
                    Success = true,
                    Value = context.CurrentTarget.Contents,
                };
            }

            Fingerprint fingerprint = default;
            string validatorMessage = null;
            string validationPrefix = string.Empty, validationSuffix = string.Empty;
            string filePath = context.CurrentTarget.Uri.GetFilePath();
            if (_validators != null && matchExpression.IsValidatorEnabled)
            {
                groups["scanTargetFullPath"] = new FlexMatch() { Value = filePath };
                string ruleName = matchExpression.Name ?? reportingDescriptor.Name;
                IEnumerable<ValidationResult> validationResults = _validators.Validate(this.Id,
                                                                                       ruleName,
                                                                                       context,
                                                                                       groups,
                                                                                       out bool pluginSupportsDynamicValidation);

                if (validationResults != null)
                {
                    foreach (ValidationResult validationResult in validationResults)
                    {
                        validatorMessage = validationResult.Message;

                        switch (validationResult.ValidationState)
                        {
                            case ValidationState.NoMatch:
                            {
                                // The validator determined the match is a false positive.
                                // i.e., it is not the kind of artifact we're looking for.
                                // We should suspend processing and move to the next match.
                                level = FailureLevel.None;
                                break;
                            }

                            case ValidationState.None:
                            case ValidationState.ValidatorReturnedIllegalValidationState:
                            {
                                // An illegal state was returned running check '{0}' against '{1}' ({2}).
                                context.Logger.LogToolNotification(
                                    Errors.CreateNotification(
                                        context.CurrentTarget.Uri,
                                        "ERR998.ValidatorReturnedIllegalValidationState",
                                        context.Rule.Id,
                                        FailureLevel.Error,
                                        exception: null,
                                        persistExceptionStack: false,
                                        messageFormat: SpamResources.ERR998_ValidatorReturnedIllegalValidationState,
                                        context.Rule.Id,
                                        context.CurrentTarget.Uri.GetFileName(),
                                        validatorMessage));

                                level = FailureLevel.Error;
                                break;
                            }

                            case ValidationState.Authorized:
                            {
                                level = FailureLevel.Error;

                                // Contributes to building a message fragment such as:
                                // 'SomeFile.txt' is an exposed SomeSecret file [...].
                                validationPrefix = "an exposed ";
                                break;
                            }

                            case ValidationState.Expired:
                            {
                                level = FailureLevel.Note;

                                // Contributes to building a message fragment such as:
                                // 'SomeFile.txt' contains an expired SomeApi token[...].
                                validationPrefix = "an expired ";
                                break;
                            }

                            case ValidationState.PasswordProtected:
                            {
                                level = FailureLevel.Warning;

                                // Contributes to building a message fragment such as:
                                // 'SomeFile.txt' contains a password-protected SomeSecret file
                                // which could be exfiltrated and potentially brute-forced offline.
                                validationPrefix = "a password-protected ";
                                validationSuffix = " which could be exfiltrated and potentially brute-forced offline";
                                break;
                            }

                            case ValidationState.UnknownHost:
                            case ValidationState.Unauthorized:
                            case ValidationState.InvalidForConsultedAuthorities:
                            {
                                throw new InvalidOperationException();
                            }

                            case ValidationState.Unknown:
                            {
                                level = FailureLevel.Note;

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

                            case ValidationState.ValidatorNotFound:
                            {
                                // TODO: should we have an explicit indicator in
                                // all cases that tells us whether this is an
                                // expected condition or not?
                                validationPrefix = "an apparent ";

                                break;
                            }

                            default:
                            {
                                throw new InvalidOperationException($"Unrecognized validation value '{validationResult.ValidationState}'.");
                            }
                        }

                        if (validationResult.ResultLevelKind != default)
                        {
                            kind = validationResult.ResultLevelKind.Kind;
                            level = validationResult.ResultLevelKind.Level;
                        }

                        ConstructResultAndLogForFileNameRegex(context,
                                                              matchExpression,
                                                              level,
                                                              kind,
                                                              reportingDescriptor,
                                                              validationResult.Fingerprint,
                                                              validatorMessage,
                                                              validationPrefix,
                                                              validationSuffix,
                                                              filePath);
                    }
                }
            }
            else
            {
                ConstructResultAndLogForFileNameRegex(context,
                                                      matchExpression,
                                                      level,
                                                      kind,
                                                      reportingDescriptor,
                                                      fingerprint,
                                                      validatorMessage,
                                                      validationPrefix,
                                                      validationSuffix,
                                                      filePath);
            }
        }

        private bool DoesTargetFileExceedSizeLimits(ulong fileLength, long maxFileSize)
        {
            // Ensure that the byte of the file does not exceed the limit set by the
            // file-size-in-kilobytes command line argument, which defaults to ~10MB.
            ulong fileSize = fileLength / 1024;

            return maxFileSize > -1 && fileSize > (ulong)maxFileSize;
        }
    }
}
