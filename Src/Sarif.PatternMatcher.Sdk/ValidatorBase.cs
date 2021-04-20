// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;

using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public abstract class ValidatorBase
    {
        public const string ScanIdentityHttpCustomHeaderKey =
            "Automation-Scan-Description";

        private static readonly RegexOptions s_options =
            RegexOptions.ExplicitCapture | RegexOptions.Compiled;

        private static readonly Regex s_noSuchHostIsKnown =
            new Regex($@"No such host is known", s_options);

        private static readonly Regex s_networkPathNotFound =
            new Regex($@"The network path was not found", s_options);

        private static readonly Regex s_remoteNameCouldNotBeResolved =
            new Regex($@"The remote name could not be resolved: '(?<asset>[^']+)'", s_options);

        private static readonly Regex s_underlyingConnectionWasClosed =
            new Regex($@"The underlying connection was closed: Could not establish " +
                         "trust relationship for the SSL/TLS secure channel.", s_options);

        private static bool shouldUseDynamicCache;

        static ValidatorBase()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            ServicePointManager.DefaultConnectionLimit = Debugger.IsAttached
                ? ServicePointManager.DefaultConnectionLimit
                : int.MaxValue;
        }

        protected ValidatorBase()
        {
            FingerprintToResultCache = new ConcurrentDictionary<Fingerprint, Tuple<ValidationState, string>>();
            PerFileFingerprintCache = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        protected virtual string ScanIdentityHttpCustomHeaderValue =>
            "This call originates with a build of the SARIF pattern matcher " +
            "(https://github.com/microsoft/sarif-pattern/matcher. Someone is " +
            "running an automated scan and attempting to validate detected credentials.";

        protected virtual string UserAgentValue => "SARIF Pattern Matcher scan tool";

        /// <summary>
        /// Gets a cache of fingerprint to previously generated validation
        /// results. Useful to avoid repeating expensive dynamic validations
        /// of logically unique secrets. Dictionary values consist of a
        /// string representing a cached validation state and a user-facing
        /// message.
        /// </summary>
        protected IDictionary<Fingerprint, Tuple<ValidationState, string>> FingerprintToResultCache { get; }

        /// <summary>
        /// Gets a cache of file + fingerprint combinations that have been
        /// observed previously. Our scanner will only detect and validate
        /// a unique fingerprint once per file. Many regexes will produce
        /// multiple matches that resolve to the same unique credential in
        /// a file (one of the perils of multiline regex matching). It is
        /// possible that this cache may drop the location of a second
        /// actual match that happens to be duplicated in the file. In
        /// practice, we will not worry about this scenario: it will be
        /// sufficient that we flag one instance of the unique secret.
        /// </summary>
        protected ISet<string> PerFileFingerprintCache { get; }

        public static IEnumerable<ValidationResult> IsValidStatic(ValidatorBase validator,
                                           ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string message)
        {
            IEnumerable<ValidationResult> validationResults = validator.IsValidStaticHelper(ref matchedPattern,
                                                                                            ref groups,
                                                                                            ref message);

            foreach (ValidationResult validationResult in validationResults)
            {
                if (validationResult.ValidationState == ValidationState.NoMatch)
                {
                    continue;
                }

                string scanTarget = groups["scanTargetFullPath"];
                string key = $"{scanTarget}#{validationResult.Fingerprint}";

                if (validator.PerFileFingerprintCache.Contains(key))
                {
                    validationResult.ValidationState = ValidationState.NoMatch;
                    continue;
                }

                validator.PerFileFingerprintCache.Add(key);
            }

            return validationResults;
        }

        public static ValidationState IsValidDynamic(ValidatorBase validator,
                                            ref Fingerprint fingerprint,
                                            ref string message,
                                            ref Dictionary<string, string> options,
                                            ref ResultLevelKind resultLevelKind)
        {
            resultLevelKind = default;

            if (shouldUseDynamicCache &&
                validator.FingerprintToResultCache.TryGetValue(fingerprint, out Tuple<ValidationState, string> result))
            {
                message = result.Item2;
                return result.Item1;
            }

            ValidationState validationState =
                validator.IsValidDynamicHelper(ref fingerprint,
                                               ref message,
                                               ref options,
                                               ref resultLevelKind);

            validator.FingerprintToResultCache[fingerprint] =
                new Tuple<ValidationState, string>(validationState, message);

            return validationState;
        }

        public static void DisableDynamicValidationCaching(bool disable)
        {
            shouldUseDynamicCache = !disable;
        }

        public static bool ContainsDigitAndChar(string matchedPattern)
        {
            bool oneDigit = false, oneLetter = false;

            foreach (char ch in matchedPattern)
            {
                if (char.IsDigit(ch)) { oneDigit = true; }
                if (char.IsLetter(ch)) { oneLetter = true; }
                if (oneDigit && oneLetter) { return true; }
            }

            return false;
        }

        public static string CreateUnexpectedResponseCodeMessage(HttpStatusCode status, string asset = null)
        {
            return CreateUnexpectedResponseCodeMessage(status, ref asset);
        }

        public static string CreateUnexpectedResponseCodeMessage(HttpStatusCode status, ref string asset)
        {
            return asset == null ?
                $"An unexpected HTTP response code was received: '{status}'." :
                $"An unexpected HTTP response code was received from '{asset}': '{status}'.";
        }

        public static ValidationState ReturnUnhandledException(ref string message,
                                                               Exception e,
                                                               string asset = null,
                                                               string account = null)
        {
            if (TestExceptionForMessage(e, s_noSuchHostIsKnown, ref asset))
            {
                return ReturnUnknownHost(ref message, asset);
            }

            if (TestExceptionForMessage(e, s_networkPathNotFound, ref asset))
            {
                return ReturnUnknownHost(ref message, asset);
            }

            if (TestExceptionForMessage(e, s_remoteNameCouldNotBeResolved, ref asset))
            {
                return ReturnUnknownHost(ref message, asset);
            }

            if (TestExceptionForMessage(e, s_underlyingConnectionWasClosed, ref asset))
            {
                return ReturnUnknownHost(ref message, asset);
            }

            message = (account == null) ?
                $"An unexpected exception was caught attempting to validate '{asset}': {e.Message}" :
                $"An unexpected exception was caught attempting to validate the '{account}' account on '{asset}': {e.Message}";

            return ValidationState.Unknown;
        }

        public static ValidationState ReturnUnknownHost(ref string message, string host)
        {
            message = $"'{host}' is unknown.";
            return ValidationState.UnknownHost;
        }

        public static ValidationState ReturnUnauthorizedAccess(ref string message,
                                                               string asset,
                                                               string assetIdentifier = null,
                                                               string account = null)
        {
            assetIdentifier += assetIdentifier != null ? " " : string.Empty;
            message = (account == null) ?
                $"The provided secret is not authorized to access {assetIdentifier}'{asset}'." :
                $"The provided '{account}' account secret is not authorized to access {assetIdentifier}'{asset}'.";

            return ValidationState.Unauthorized;
        }

        public static ValidationState ReturnAuthorizedAccess(ref string message,
                                                    string asset,
                                                    string account = null)
        {
            message = (account == null) ?
                $"The compromised asset is '{asset}'." :
                $"The '{account}' account is compromised for '{asset}'.";

            return ValidationState.Authorized;
        }

        public static ValidationState ReturnUnknownAuthorization(ref string message,
                                                                 string asset,
                                                                 string account = null)
        {
            message = (account == null) ?
                $"The potentially compromised asset is '{asset}'." :
                $"The '{account}' account is potentially compromised for '{asset}'.";

            return ValidationState.Unknown;
        }

        public static string ParseExpression(IRegex regexEngine, string matchedPattern, string expression)
        {
            FlexMatch match = regexEngine.Match(matchedPattern, expression);
            return match?.Success ?? false ? ParseValue(match.Value) : null;
        }

        internal static string ParseValue(string value)
        {
            // If ParseExpression passed us white space, we shouldn't pretend we successfully
            // found a value.  Return null in both cases to make it clear, nothing useful was found.
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            // If the string is of the form "secret=value", look for the first '=' and return everything following
            // Otherwise, simply return the string.

            int indexOfFirstEqualSign = value.IndexOf('=');

            if (indexOfFirstEqualSign < 0)
            {
                return value.Trim();
            }

            if (indexOfFirstEqualSign == value.Length - 1)
            {
                // the string looks like "secret=" with no value.
                return null;
            }

            return value.Substring(indexOfFirstEqualSign + 1).Trim();
        }

        protected HttpClient CreateHttpClient()
        {
            var httpClientHandler = new HttpClientHandler()
            {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 10,
            };

            var httpClient = new HttpClient(httpClientHandler);

            httpClient.DefaultRequestHeaders.Add(ScanIdentityHttpCustomHeaderKey,
                                                 ScanIdentityHttpCustomHeaderValue);

            httpClient.DefaultRequestHeaders.Add("User-Agent",
                                                 UserAgentValue);

            return httpClient;
        }

        /// <summary>
        /// Validate if the match is a secret or credential.
        /// </summary>
        /// <param name="matchedPattern">
        /// The matched text to be validated. This pattern can be further refined
        /// to a substring of the original parameter value, with the result that
        /// the refined matched pattern will be used as the code region associated
        /// with the match.
        /// </param>
        /// <param name="groups">
        /// Capture groups from the regex match. Dictionary entries can be modified or new entries
        /// added in order to refine or add argument values that will be used in result messages.
        /// </param>
        /// <param name="message">
        /// A message that can be used to pass additional information back to the user.
        /// </param>
        /// <returns>Return an ienumerable of ValidationResult.</returns>
        protected abstract IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             ref Dictionary<string, string> groups,
                                                                             ref string message);

        protected virtual ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                      ref string message,
                                                      ref Dictionary<string, string> options,
                                                      ref ResultLevelKind resultLevelKind)
        {
            return ValidationState.NoMatch;
        }

        private static bool TestExceptionForMessage(Exception e, Regex regex, ref string asset)
        {
            if (e == null)
            {
                return false;
            }

            Match match = regex.Match(e.Message);
            if (match.Success)
            {
                asset = asset ?? match.Groups?["asset"].Value;
                return true;
            }

            if (TestExceptionForMessage(e.InnerException, regex, ref asset))
            {
                return true;
            }

            var aggregateException = e as AggregateException;
            if (aggregateException?.InnerExceptions != null)
            {
                foreach (Exception aggregatedException in aggregateException.InnerExceptions)
                {
                    if (TestExceptionForMessage(aggregatedException, regex, ref asset))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    }
}
