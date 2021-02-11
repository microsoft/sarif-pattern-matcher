// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.HelpersUtiliesAndExtensions;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins
{
    public abstract class ValidatorBase
    {
        public static readonly HashSet<string> LocalhostList = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "localhost",
            "(local)",
            "127.0.0.1",
        };

        static ValidatorBase()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            ServicePointManager.DefaultConnectionLimit = Debugger.IsAttached
                ? ServicePointManager.DefaultConnectionLimit
                : int.MaxValue;
        }

        protected ValidatorBase()
        {
            FingerprintToResultCache = new Dictionary<string, Tuple<string, string>>();
            PerFileFingerprintCache = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Gets a cache of fingerprint to previously generated validation
        /// results. Useful to avoid repeating expensive dynamic validations
        /// of logically unique secrets. Dictionary values consist of a
        /// string representing a cached validation state and a user-facing
        /// message.
        /// </summary>
        protected IDictionary<string, Tuple<string, string>> FingerprintToResultCache { get; }

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

        public static string IsValidStatic(ValidatorBase validator,
                                           ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            validator.MatchCleanup(ref matchedPattern,
                                    ref groups,
                                    ref failureLevel,
                                    ref fingerprint,
                                    ref message);

            string state = validator.HostExclusion(ref groups);

            if (state == nameof(ValidationState.NoMatch))
            {
                return state;
            }

            state = validator.IsValidStaticHelper(ref matchedPattern,
                                                  ref groups,
                                                  ref failureLevel,
                                                  ref fingerprint,
                                                  ref message);

            if (state == nameof(ValidationState.NoMatch))
            {
                return state;
            }

            string scanTarget = groups["scanTargetFullPath"];
            string key = scanTarget + "#" + fingerprint;

            if (validator.PerFileFingerprintCache.Contains(key))
            {
                return nameof(ValidationState.NoMatch);
            }

            validator.PerFileFingerprintCache.Add(key);

            return state;
        }

        public static string IsValidDynamic(ValidatorBase validator,
                                            ref string fingerprint,
                                            ref string message)
        {
            if (validator.FingerprintToResultCache.TryGetValue(fingerprint, out Tuple<string, string> result))
            {
                message = result.Item2;
                return result.Item1;
            }

            string validationState =
                validator.IsValidDynamicHelper(ref fingerprint,
                                               ref message);

            if (fingerprint != null)
            {
                validator.FingerprintToResultCache[fingerprint] =
                    new Tuple<string, string>(validationState, message);
            }

            return validationState;
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

        public static string ReturnUnhandledException(ref string message, Exception e, string asset = null, string account = null)
        {
            if (TestExceptionForMessage(e, "No such host is known", asset))
            {
                return ReturnUnknownHost(ref message, asset);
            }

            if (TestExceptionForMessage(e, "The network path was not found", asset))
            {
                return ReturnUnknownHost(ref message, asset);
            }

            if (TestExceptionForMessage(e, "The remote name could not be resolved", asset))
            {
                return ReturnUnknownHost(ref message, asset);
            }

            string sslMessage = "The underlying connection was closed: Could not establish trust relationship for the SSL/TLS secure channel.";
            if (TestExceptionForMessage(e, sslMessage, asset))
            {
                return ReturnUnknownHost(ref message, asset);
            }

            message = (account == null) ?
                $"An unexpected exception was caught attempting to validate '{asset}': {e.Message}" :
                $"An unexpected exception was caught attempting to validate the '{account} account on '{asset}': {e.Message}";

            return nameof(ValidationState.Unknown);
        }

        public static string ReturnUnknownHost(ref string message, string host)
        {
            message = $"'{host}' is unknown.";
            return nameof(ValidationState.UnknownHost);
        }

        public static string ReturnUnauthorizedAccess(ref string message,
                                                      string asset,
                                                      string assetIdentifier = null,
                                                      string account = null)
        {
            assetIdentifier += assetIdentifier != null ? " " : string.Empty;
            message = (account == null) ?
                $"The provided secret is not authorized to access {assetIdentifier}'{asset}'." :
                $"The provided '{account}' account secret is not authorized to access {assetIdentifier}'{asset}'.";

            return nameof(ValidationState.Unauthorized);
        }

        public static string ReturnAuthorizedAccess(ref string message,
                                                    string asset,
                                                    string account = null)
        {
            message = (account == null) ?
                $"The compromised asset is '{asset}'." :
                $"The '{account}' account is compromised for '{asset}'.";

            return nameof(ValidationState.Authorized);
        }

        public static string ReturnUnknownAuthorization(ref string message,
                                                        string asset,
                                                        string account = null)
        {
            message = (account == null) ?
                $"The potentially compromised asset is '{asset}'." :
                $"The '{account}' account is potentially compromised for '{asset}'.";

            return nameof(ValidationState.Unknown);
        }

        public static string ParseExpression(IRegex regexEngine, string matchedPattern, string expression)
        {
            FlexMatch match = regexEngine.Match(matchedPattern, expression);
            return match?.Success ?? false ? ParseValue(match.Value) : null;
        }

        public static void StandardizeLocalhostName(Dictionary<string, string> groups)
        {
            if (groups.TryGetNonEmptyValue("host", out string host))
            {
                if (LocalhostList.Contains(host))
                {
                    groups["host"] = "localhost";
                }
            }
        }

        public virtual string HostExclusion(ref Dictionary<string, string> groups, IEnumerable<string> hostList = null)
        {
            if (hostList == null)
            {
                return nameof(ValidationState.Unknown);
            }

            if (!groups.TryGetNonEmptyValue("host", out string host))
            {
                return nameof(ValidationState.NoMatch);
            }

            // Other rules will handle these cases.
            foreach (string hostToExclude in hostList)
            {
                if (host.EndsWith(hostToExclude, StringComparison.OrdinalIgnoreCase))
                {
                    return nameof(ValidationState.NoMatch);
                }
            }

            return nameof(ValidationState.Unknown);
        }

        public virtual void MatchCleanup(ref string matchedPattern,
                                             ref Dictionary<string, string> groups,
                                             ref string failureLevel,
                                             ref string fingerprintText,
                                             ref string message)
        {

        }

        internal static string ParseValue(string value)
        {
            // If ParseExpression passed us white space, we shouldn't pretend we successfully
            // found a value.  Return null in both cases to make it clear, nothing useful was found.
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            // If the string is of the form "key=value", look for the first '=' and return everything following
            // Otherwise, simply return the string.

            int indexOfFirstEqualSign = value.IndexOf('=');

            if (indexOfFirstEqualSign < 0)
            {
                return value.Trim();
            }

            if (indexOfFirstEqualSign == value.Length - 1)
            {
                // the string looks like "key=" with no value.
                return null;
            }

            return value.Substring(indexOfFirstEqualSign + 1).Trim();
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
        /// <param name="failureLevel">
        /// The current failure level associated with the match (if a match occurs). This parameter can be
        /// set to a different failure level by the callee, if appropriate.
        /// </param>
        /// <param name="fingerprintText">
        /// A SARIF fingerprint that identifies a logically unique secret. This parameter should be
        /// set to null if no fingerprint can be computed that definitively identifies the secret.
        /// </param>
        /// <param name="message">
        /// A message that can be used to pass additional information back to the user.
        /// </param>
        /// <returns>Return the validation state.</returns>
        protected abstract string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message);

        protected virtual string IsValidDynamicHelper(ref string fingerprintText,
                                                      ref string message)
        {
            return null;
        }

        private static bool TestExceptionForMessage(Exception e, string message, string asset)
        {
            if (e == null)
            {
                return false;
            }

            if (e.Message.StartsWith(message))
            {
                return true;
            }

            if (TestExceptionForMessage(e.InnerException, message, asset))
            {
                return true;
            }

            var aggregateException = e as AggregateException;
            if (aggregateException != null && aggregateException.InnerExceptions != null)
            {
                foreach (Exception aggregatedException in aggregateException.InnerExceptions)
                {
                    if (TestExceptionForMessage(aggregatedException, message, asset))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    }
}
