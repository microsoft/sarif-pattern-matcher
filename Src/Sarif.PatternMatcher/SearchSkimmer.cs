// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Resources;
using System.Text;
using System.Text.RegularExpressions;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;
using Microsoft.Strings.Interop;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SearchSkimmer : Skimmer<AnalyzeContext>
    {
        public const string AssetFingerprint = "AssetFingerprint/v1";
        public const string GlobalFingerprint = "GlobalFingerprint/v1";
        public const string ValidationFingerprint = "ValidationFingerprint/v1";
        public const string ValidationFingerprintHash = "ValidationFingerprintHash/v1";
        public const string DynamicValidationNotEnabled = "No validation occurred as it was not enabled. Pass '--dynamic-validation' on the command-line to validate this match";

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
        private readonly Dictionary<string, MultiformatMessageString> _messageStrings;

        public SearchSkimmer(IRegex engine, ValidatorsCache validators, FileRegionsCache fileRegionsCache, SearchDefinition definition, IFileSystem fileSystem = null)
        {
            _engine = engine;
            _id = definition.Id;
            _name = definition.Name;
            _validators = validators;
            _fileRegionsCache = fileRegionsCache;
            _fullDescription = new MultiformatMessageString { Text = definition.Description };
            _fileSystem = fileSystem ?? FileSystem.Instance;

            _messageStrings = new Dictionary<string, MultiformatMessageString>
            {
                { nameof(SdkResources.NotApplicable_InvalidMetadata), new MultiformatMessageString() { Text = SdkResources.NotApplicable_InvalidMetadata, } },
            };

            foreach (MatchExpression matchExpression in definition.MatchExpressions)
            {
                string matchExpressionMessage = matchExpression.Message;
                matchExpression.ArgumentNameToIndexMap = GenerateIndicesForNamedArguments(ref matchExpressionMessage);

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

            _matchExpressions = definition.MatchExpressions;
        }

        public override Uri HelpUri => s_helpUri;

        public override string Id => _id;

        public override string Name => _name;

        public override MultiformatMessageString FullDescription => _fullDescription;

        public override MultiformatMessageString Help => null;

        public override IDictionary<string, MultiformatMessageString> MessageStrings => _messageStrings;

        protected override ResourceManager ResourceManager => SpamResources.ResourceManager;

        public override AnalysisApplicability CanAnalyze(AnalyzeContext context, out string reasonIfNotApplicable)
        {
            string filePath = context.TargetUri.GetFilePath();
            reasonIfNotApplicable = null;

            if (!string.IsNullOrWhiteSpace(context.GlobalFileDenyRegex) &&
                _engine.Match(filePath, pattern: context.GlobalFileDenyRegex).Success)
            {
                reasonIfNotApplicable = SpamResources.TargetWasFilteredByFileNameDenyRegex;
                return AnalysisApplicability.NotApplicableToSpecifiedTarget;
            }

            foreach (MatchExpression matchExpression in _matchExpressions)
            {
                if (!string.IsNullOrEmpty(matchExpression.FileNameDenyRegex) && _engine.IsMatch(filePath, matchExpression.FileNameDenyRegex))
                {
                    continue;
                }

                if (!string.IsNullOrEmpty(matchExpression.FileNameAllowRegex) && !_engine.IsMatch(filePath, matchExpression.FileNameAllowRegex))
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
            string filePath = context.TargetUri.OriginalString;

            if (filePath.StartsWith("file://"))
            {
                filePath = context.TargetUri.LocalPath;
            }

            if (context.FileContents == null)
            {
                try
                {
                    context.FileContents = _fileSystem.FileReadAllText(filePath);
                }
                catch (Exception e)
                {
                    if (e is IOException || e is UnauthorizedAccessException)
                    {
                        // We should log and return here because we want the rule to continue to run. i.e., the issue is likely
                        // in permissions with the scan target, not a general problem with the rule. In other cases, we 'throw',
                        // which will result in the rule getting disabled.
                        context.Logger.LogToolNotification(
                            Errors.CreateNotification(
                                context.TargetUri,
                                "ERR998.ExceptionInAnalyze",
                                context.Rule.Id,
                                FailureLevel.Error,
                                e,
                                persistExceptionStack: true,
                                messageFormat: null,
                                e.GetType().Name,
                                context.TargetUri.GetFileName(),
                                context.Rule.Name));
                        return;
                    }

                    throw;
                }
            }

            if (context.FileSizeInKilobytes != -1 && context.FileContents.String.Length / 1024 > context.FileSizeInKilobytes)
            {
                return;
            }

            foreach (MatchExpression matchExpression in _matchExpressions)
            {
                if (!string.IsNullOrEmpty(matchExpression.FileNameAllowRegex))
                {
                    if (!_engine.IsMatch(filePath,
                                         matchExpression.FileNameAllowRegex,
                                         RegexDefaults.DefaultOptionsCaseInsensitive))
                    {
                        continue;
                    }
                }

                if (!string.IsNullOrEmpty(matchExpression.FileNameDenyRegex))
                {
                    if (_engine.IsMatch(filePath,
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
                            Errors.CreateNotification(context.TargetUri,
                                                      "ERR998.ValidatorReturnedIllegalValidationState",
                                                      context.Rule.Id,
                                                      FailureLevel.Error,
                                                      exception: null,
                                                      persistExceptionStack: false,
                                                      messageFormat: SpamResources.ERR998_ValidatorReturnedIllegalValidationState,
                                                      context.Rule.Id,
                                                      context.TargetUri.GetFileName(),
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
                    level = FailureLevel.Note;
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

            if (dynamicValidationMessageIndex == -1) { return null; }

            return validatorMessage.Substring(dynamicValidationMessageIndex, DynamicValidationNotEnabled.Length);
        }

        private void RunMatchExpression(FlexMatch binary64DecodedMatch, AnalyzeContext context, MatchExpression matchExpression)
        {
            if (!string.IsNullOrEmpty(matchExpression.ContentsRegex))
            {
                RunMatchExpressionForContentsRegex(binary64DecodedMatch, context, matchExpression);
            }
            else if (!string.IsNullOrEmpty(matchExpression.FileNameAllowRegex))
            {
                RunMatchExpressionForFileNameRegex(context, matchExpression);
            }
            else
            {
                // Both FileNameAllowRegex and ContentRegex are null or empty.
            }
        }

        private void RunMatchExpressionForContentsRegex(FlexMatch binary64DecodedMatch,
                                                        AnalyzeContext context,
                                                        MatchExpression matchExpression)
        {
            ResultKind kind = matchExpression.Kind;
            FailureLevel level = matchExpression.Level;
            string filePath = context.TargetUri.GetFilePath();
            string searchText = binary64DecodedMatch != null
                                                   ? Decode(binary64DecodedMatch.Value)
                                                   : context.FileContents;

            if (!_engine.Matches(matchExpression.ContentsRegex, searchText, out List<Dictionary<string, FlexMatch>> matches))
            {
                return;
            }

            foreach (Dictionary<string, FlexMatch> match in matches)
            {
                ReportingDescriptor reportingDescriptor = this;

                IDictionary<string, string> groups = match.CopyToDictionary();

                Debug.Assert(!groups.ContainsKey("scanTargetFullPath"), "Full path should always exist.");
                groups["scanTargetFullPath"] = filePath;
                groups["enhancedReporting"] = context.EnhancedReporting ? bool.TrueString : bool.FalseString;

                if (matchExpression.Properties != null)
                {
                    foreach (KeyValuePair<string, string> kv in matchExpression.Properties)
                    {
                        // We will never allow a group returned by a dynamically executing
                        // regex to overwrite a static value in the match expression. This
                        // allows the match expression to provide a default value that
                        // may be replaced by the analysis.
                        if (!groups.ContainsKey(kv.Key))
                        {
                            groups[kv.Key] = kv.Value;
                        }
                    }
                }

                FlexMatch flexMatch = match["0"];
                string refinedMatchedPattern = flexMatch.Value;
                if (match.TryGetValue("refine", out FlexMatch refineMatch))
                {
                    refinedMatchedPattern = refineMatch.Value;
                }

                Fingerprint fingerprint = default;
                string validatorMessage = null;
                string validationPrefix = string.Empty;
                string validationSuffix = string.Empty;

                if (_validators != null && matchExpression.IsValidatorEnabled)
                {
                    IEnumerable<ValidationResult> validationResults = _validators.Validate(reportingDescriptor.Name,
                                                                                           context,
                                                                                           ref refinedMatchedPattern,
                                                                                           groups,
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
                                                                  flexMatch,
                                                                  reportingDescriptor,
                                                                  groups,
                                                                  refinedMatchedPattern,
                                                                  validationPrefix,
                                                                  validationSuffix,
                                                                  validationResult);
                        }
                    }
                }
                else
                {
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
                                                          groups,
                                                          refinedMatchedPattern,
                                                          validationPrefix,
                                                          validationSuffix,
                                                          result);
                }
            }
        }

        private void ConstructResultAndLogForContentsRegex(FlexMatch binary64DecodedMatch,
                                                           AnalyzeContext context,
                                                           MatchExpression matchExpression,
                                                           string filePath,
                                                           FlexMatch flexMatch,
                                                           ReportingDescriptor reportingDescriptor,
                                                           IDictionary<string, string> groups,
                                                           string refinedMatchedPattern,
                                                           string validationPrefix,
                                                           string validationSuffix,
                                                           ValidationResult validationResult)
        {
            // If we're matching against decoded contents, the region should
            // relate to the base64-encoded scan target content. We do use
            // the decoded content for the fingerprint, however.
            FlexMatch regionFlexMatch = binary64DecodedMatch ?? flexMatch;

            Region region = ConstructRegion(context, regionFlexMatch, refinedMatchedPattern, validationResult.OverrideIndex, validationResult.OverrideLength);

            Dictionary<string, string> messageArguments = matchExpression.MessageArguments != null ?
                new Dictionary<string, string>(matchExpression.MessageArguments) :
                new Dictionary<string, string>();

            messageArguments["encoding"] = binary64DecodedMatch != null ?
                "base64-encoded" :
                string.Empty; // We don't bother to report a value for plaintext content

            messageArguments["validationPrefix"] = validationPrefix;
            messageArguments["validationSuffix"] = validationSuffix;
            messageArguments["truncatedSecret"] = validationResult.Fingerprint.Secret.Truncate();

            IList<string> arguments = GetMessageArguments(groups,
                                                          matchExpression.ArgumentNameToIndexMap,
                                                          filePath,
                                                          validatorMessage: NormalizeValidatorMessage(validationResult.Message),
                                                          messageArguments);

            Result result = ConstructResult(context.TargetUri,
                                            reportingDescriptor.Id,
                                            validationResult.ResultLevelKind.Level,
                                            validationResult.ResultLevelKind.Kind,
                                            region,
                                            flexMatch,
                                            validationResult.Fingerprint,
                                            matchExpression,
                                            arguments);

            // This skimmer instance mutates its reporting descriptor state,
            // for example, the sub-id may change for every match
            // expression. We will therefore generate a snapshot of
            // current ReportingDescriptor state when logging.
            context.Logger.Log(reportingDescriptor, result);
        }

        private void RunMatchExpressionForFileNameRegex(AnalyzeContext context, MatchExpression matchExpression)
        {
            ResultKind kind = matchExpression.Kind;
            FailureLevel level = matchExpression.Level;
            ReportingDescriptor reportingDescriptor = this;
            IDictionary<string, string> groups = new Dictionary<string, string>();

            if (!string.IsNullOrEmpty(context.FileContents))
            {
                groups["content"] = context.FileContents;
            }

            Fingerprint fingerprint = default;
            string validatorMessage = null;
            string validationPrefix = string.Empty, validationSuffix = string.Empty;
            string filePath = context.TargetUri.IsAbsoluteUri
                ? context.TargetUri.LocalPath
                : context.TargetUri.OriginalString;
            if (_validators != null && matchExpression.IsValidatorEnabled)
            {
                IEnumerable<ValidationResult> validationResults = _validators.Validate(reportingDescriptor.Name,
                                                 context,
                                                 ref filePath,
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
                                        context.TargetUri,
                                        "ERR998.ValidatorReturnedIllegalValidationState",
                                        context.Rule.Id,
                                        FailureLevel.Error,
                                        exception: null,
                                        persistExceptionStack: false,
                                        messageFormat: SpamResources.ERR998_ValidatorReturnedIllegalValidationState,
                                        context.Rule.Id,
                                        context.TargetUri.GetFileName(),
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

        private void ConstructResultAndLogForFileNameRegex(AnalyzeContext context,
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

            IList<string> arguments = GetMessageArguments(
                groups: null,
                matchExpression.ArgumentNameToIndexMap,
                filePath,
                validatorMessage: NormalizeValidatorMessage(validatorMessage),
                messageArguments);

            Result result = this.ConstructResult(context.TargetUri,
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

        private Region ConstructRegion(AnalyzeContext context, FlexMatch regionFlexMatch, string fingerprint, int? overrideIndex, int? overrideLength)
        {
            // TODO: this code is wrong!! We no longer use the fingerprint to refine the region

            int indexOffset = overrideIndex ?? regionFlexMatch.Value.String.IndexOf(fingerprint);
            int lengthOffset = (overrideLength ?? fingerprint.Length) - regionFlexMatch.Length;

            if (indexOffset == -1 || indexOffset >= regionFlexMatch.Length)
            {
                // If we can't find the fingerprint in the match, that means we matched against
                // base64-decoded content (and therefore there is no region refinement to make).
                indexOffset = 0;
                lengthOffset = 0;
            }

            if ((indexOffset + regionFlexMatch.Length + lengthOffset) > regionFlexMatch.Length)
            {
                // match should be within the original full string
                // update lengthOffset to till end of regionFlexMatch
                lengthOffset = indexOffset - regionFlexMatch.Length;
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

        private Result ConstructResult(Uri targetUri,
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
                        Uri = targetUri,
                    },
                    Region = region,
                },
            };

            Dictionary<string, string> fingerprints = BuildFingerprints(fingerprint, out double rank);

            if (!string.IsNullOrEmpty(matchExpression.SubId))
            {
                ruleId = $"{ruleId}/{matchExpression.SubId}";
            }

            // We'll limit rank precision to two decimal places. Because this value
            // is actually converted from a nomalized range of 0.0 to 1.0, to the
            // SARIF 0.0 to 100.0 equivalent, this is effectively four decimal places
            // of precision in terms of the normalized Shannon entropy value.
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
            };

            if (matchExpression.Fixes?.Count > 0)
            {
                // Build arguments that may be required for fix text.
                var argumentNameToValueMap = new Dictionary<string, string>();

                foreach (KeyValuePair<string, int> kv in matchExpression.ArgumentNameToIndexMap)
                {
                    argumentNameToValueMap["{" + kv.Key + "}"] = arguments[kv.Value];
                }

                foreach (SimpleFix fix in matchExpression.Fixes.Values)
                {
                    ExpandArguments(fix, argumentNameToValueMap);
                    AddFixToResult(flexMatch, fix, result);
                }
            }

            return result;
        }

        private Dictionary<string, string> BuildFingerprints(Fingerprint fingerprint, out double rank)
        {
            rank = -1;

            if (fingerprint == default)
            {
                return null;
            }

            rank = fingerprint.GetRank();

            return new Dictionary<string, string>()
            {
                { AssetFingerprint, fingerprint.GetAssetFingerprintText() },
                { ValidationFingerprint, fingerprint.GetValidationFingerprintText() },
                { ValidationFingerprintHash, fingerprint.GetValidationFingerprintHashText() },
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
            IDictionary<string, string> groups,
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
                else if (groups != null && groups.TryGetValue(kv.Key, out string groupValue))
                {
                    value = groupValue;
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
    }
}
