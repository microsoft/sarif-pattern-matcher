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

        protected bool shouldUseDynamicCache;

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

        private HttpClient httpClient;
        private string scanIdentityGuid;

        static ValidatorBase()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            ServicePointManager.DefaultConnectionLimit = Debugger.IsAttached
                ? ServicePointManager.DefaultConnectionLimit
                : int.MaxValue;
        }

        protected ValidatorBase()
        {
            FingerprintToResultCache = new ConcurrentDictionary<Fingerprint, Tuple<ValidationState, ResultLevelKind, string>>();
        }

        public virtual string ScanIdentityGuid
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

        public static bool IsBase64EncodingOfPrintableCharacters(string secret)
        {
            byte[] secretBytes = null;

            try
            {
                secretBytes = Convert.FromBase64String(secret);
            }
            catch (FormatException)
            {
                return false;
            }

            foreach (byte secretByte in secretBytes)
            {
                // https://www.asciihex.com/ascii-printable-characters

                int byteValue = Convert.ToInt32(secretByte);

                if (byteValue < 32 || byteValue > 126)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Determines whether the input string contains both digit and letter.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <returns>true if the input string contains both digit and letter; otherwise, false.</returns>
        public static bool ContainsDigitAndChar(string text)
        {
            // TODO, change the function name as ContainsDigitAndLetter and also fixed the 44 references
            return ContainAtLeastNDigits(text, 1) && ContainAtLeastNLetters(text, 1);
        }

        /// <summary>
        /// Determines whether the input string contains both lowercase and uppercase letter.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <returns>true if the input string contains both lowercase and uppercase letter; otherwise, false.</returns>
        public static bool ContainLowercaseAndUppercaseLetter(string text)
        {
            return ContainAtLeastNLowercaseLetters(text, 1) && ContainAtLeastNUppercaseLetters(text, 1);
        }

        /// <summary>
        /// Determines whether the input string contains at least n digits.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <param name="n">The number of digits required.</param>
        /// <returns>true if the input string contains at least n digits; otherwise, false.</returns>
        public static bool ContainAtLeastNDigits(string text, int n)
        {
            int digitCount = 0;

            foreach (char c in text)
            {
                if (char.IsDigit(c))
                {
                    digitCount++;
                }

                if (digitCount >= n)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines whether the input string contains at least n letters.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <param name="n">The number of letters required.</param>
        /// <returns>true if the input string contains at least n letters; otherwise, false.</returns>
        public static bool ContainAtLeastNLetters(string text, int n)
        {
            int letterCount = 0;

            foreach (char c in text)
            {
                if (char.IsLetter(c))
                {
                    letterCount++;
                }

                if (letterCount >= n)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines whether the input string contains at least n uppercase letters.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <param name="n">The number of uppercase letters required.</param>
        /// <returns>true if the input string contains at least n uppercase letters; otherwise, false.</returns>
        public static bool ContainAtLeastNUppercaseLetters(string text, int n)
        {
            int upperCount = 0;

            foreach (char c in text)
            {
                if (char.IsUpper(c))
                {
                    upperCount++;
                }

                if (upperCount >= n)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines whether the input string contains at least n lowercase letters.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <param name="n">The number of lowercase letters required.</param>
        /// <returns>true if the input string contains at least n lowercase letters; otherwise, false.</returns>
        public static bool ContainAtLeastNLowercaseLetters(string text, int n)
        {
            int lowerCount = 0;

            foreach (char c in text)
            {
                if (char.IsLower(c))
                {
                    lowerCount++;
                }

                if (lowerCount >= n)
                {
                    return true;
                }
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
                message = $"An unexpected HTTP response code was received: '{status}'";
            }
            else if (string.IsNullOrEmpty(account))
            {
                message = $"An unexpected HTTP response code was received from '{asset}': '{status}'";
            }
            else
            {
                message = $"An unexpected HTTP response code was received from '{account}' account on '{asset}': {status}";
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
                $"An unexpected exception was caught attempting to validate '{asset}': {e}" :
                $"An unexpected exception was caught attempting to validate the '{account}' account on '{asset}': {e}";

            return ValidationState.Unknown;
        }

        public static ValidationState ReturnUnknownHost(ref string message, string host)
        {
            message = $"'{host}' is unknown";
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
                $"The provided '{account}' account secret is not authorized to access {assetIdentifier}'{asset}'";

            return ValidationState.Unauthorized;
        }

        public static ValidationState ReturnAuthorizedAccess(ref string message,
                                                    string asset,
                                                    string account = null)
        {
            message = (account == null) ?
                $"The compromised asset is '{asset}'." :
                $"The '{account}' account is compromised for '{asset}'";

            return ValidationState.Authorized;
        }

        public static ValidationState ReturnUnknownAuthorization(ref string message,
                                                                 string asset,
                                                                 string account = null)
        {
            message = (account == null) ?
                $"The potentially compromised asset is '{asset}'." :
                $"The '{account}' account is potentially compromised for '{asset}'";

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

        public void DisableDynamicValidationCaching(bool disable)
        {
            shouldUseDynamicCache = !disable;
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
