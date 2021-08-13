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
    public abstract class ValidatorBase2
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

        [ThreadStatic]
        private static HttpClient s_httpClient;

        private static bool shouldUseDynamicCache;
        private HttpClient httpClient;
        private string scanIdentityGuid;

        static ValidatorBase2()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            ServicePointManager.DefaultConnectionLimit = Debugger.IsAttached
                ? ServicePointManager.DefaultConnectionLimit
                : int.MaxValue;
        }

        protected ValidatorBase2()
        {
            PerFileFingerprintCache = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            FingerprintToResultCache = new ConcurrentDictionary<Fingerprint, Tuple<ValidationState, ResultLevelKind, string>>();
        }

        protected virtual string ScanIdentityGuid
        {
            get
            {
                scanIdentityGuid ??= $"{Guid.NewGuid()}";
                return scanIdentityGuid;
            }

            set
            {
                if (!Guid.TryParse(value, out _))
                {
                    throw new ArgumentException($"'{value}' is not a GUID.");
                }

                scanIdentityGuid = value;
            }
        }

        protected virtual string ScanIdentityHttpCustomHeaderValue =>
            "This call originates with a build of the SARIF pattern matcher " +
            "(https://github.com/microsoft/sarif-pattern-matcher. Someone is " +
            "running an automated scan and attempting to validate detected credentials.";

        protected virtual string UserAgentValue => "SARIF Pattern Matcher scan tool";

        /// <summary>
        /// Gets a cache of fingerprint to previously generated validation
        /// results. Useful to avoid repeating expensive dynamic validations
        /// of logically unique secrets. Dictionary values consist of a
        /// string representing a cached validation state and a user-facing
        /// message.
        /// </summary>
        protected IDictionary<Fingerprint, Tuple<ValidationState, ResultLevelKind, string>> FingerprintToResultCache { get; }

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

        public IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
        {
            IEnumerable<ValidationResult> validationResults = IsValidStaticHelper(groups);

            foreach (ValidationResult validationResult in validationResults)
            {
                if (validationResult.ValidationState == ValidationState.NoMatch)
                {
                    continue;
                }

                string scanTarget = groups["scanTargetFullPath"].Value;
                string key = $"{scanTarget}#{validationResult.Fingerprint}";

                if (PerFileFingerprintCache.Contains(key))
                {
                    validationResult.ValidationState = ValidationState.NoMatch;
                    continue;
                }

                PerFileFingerprintCache.Add(key);
            }

            return validationResults;
        }

        public ValidationState IsValidDynamic(
                                                     ref Fingerprint fingerprint,
                                                     ref string message,
                                                     Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            resultLevelKind = default;

            if (shouldUseDynamicCache &&
                FingerprintToResultCache.TryGetValue(fingerprint, out Tuple<ValidationState, ResultLevelKind, string> result))
            {
                message = result.Item3;
                resultLevelKind = result.Item2;
                return result.Item1;
            }

            ValidationState validationState =
                IsValidDynamicHelper(ref fingerprint,
                                               ref message,
                                               options,
                                               ref resultLevelKind);

            FingerprintToResultCache[fingerprint] =
                new Tuple<ValidationState, ResultLevelKind, string>(validationState, resultLevelKind, message);

            return validationState;
        }

        public void DisableDynamicValidationCaching(bool disable)
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

        public static ValidationState ReturnUnexpectedResponseCode(ref string message,
                                                                   HttpStatusCode status,
                                                                   string asset = null,
                                                                   string account = null)
        {
            if (string.IsNullOrEmpty(asset))
            {
                message = $"An unexpected HTTP response code was received: '{status}'.";
            }
            else if (string.IsNullOrEmpty(account))
            {
                message = $"An unexpected HTTP response code was received from '{asset}': '{status}'.";
            }
            else
            {
                message = $"An unexpected HTTP response code was received from '{account}' account on '{asset}': {status}.";
            }

            return ValidationState.Unknown;
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

        public static string ParseExpression(IRegex regexEngine, FlexMatch baseMatch, string expression, ref FlexMatch match)
        {
            match = regexEngine.Match(baseMatch.Value, expression);

            if (match.Success)
            {
                match.Index = baseMatch.Index + match.Index;

                string value = ParseValue(match.Value);

                match = new FlexMatch
                {
                    Value = value,
                    Index = match.Index + match.Value.String.IndexOf(value),
                    Length = value.Length,
                };
            }

            return match.Value;
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

        internal void SetHttpClient(HttpClient client)
        {
            httpClient = client;
        }

        protected HttpClient CreateOrRetrieveCachedHttpClient()
        {
            // The httpClient is the property that will be used for tests only.
            if (httpClient != null)
            {
                return httpClient;
            }

            if (s_httpClient == null)
            {
                var httpClientHandler = new HttpClientHandler()
                {
                    AllowAutoRedirect = true,
                    MaxAutomaticRedirections = 10,
                };

                s_httpClient = new HttpClient(httpClientHandler);

                s_httpClient.DefaultRequestHeaders.Add(ScanIdentityHttpCustomHeaderKey,
                                                     ScanIdentityHttpCustomHeaderValue);

                s_httpClient.DefaultRequestHeaders.Add("User-Agent",
                                                     UserAgentValue);
            }

            return s_httpClient;
        }

        /// <summary>
        /// Validate if the match is a secret or credential.
        /// </summary>
        /// <param name="groups">
        /// Capture groups from the regex match. Dictionary entries can be modified or new entries
        /// added in order to refine or add argument values that will be used in result messages.
        /// </param>
        ///
        /// <returns>Return an enumerable ValidationResult collection.</returns>
        protected abstract IEnumerable<ValidationResult> IsValidStaticHelper(Dictionary<string, FlexMatch> groups);

        protected virtual ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                               ref string message,
                                                               Dictionary<string, string> options,
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
                asset ??= match.Groups?["asset"].Value;
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
