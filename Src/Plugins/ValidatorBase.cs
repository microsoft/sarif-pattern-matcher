﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins
{
    internal abstract class ValidatorBase
    {
        static ValidatorBase()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            ServicePointManager.DefaultConnectionLimit = Debugger.IsAttached
                ? ServicePointManager.DefaultConnectionLimit
                : Environment.ProcessorCount;
        }

        protected ValidatorBase()
        {
            FingerprintToResultCache = new Dictionary<string, Tuple<string, string>>();
        }

        /// <summary>
        /// Gets a cache of fingerprint to previously generated validation
        /// results. Useful to avoid repeating expensive dynamic validations
        /// of logically unique secrets. Dictionary values consist of a
        /// string representing a cached validation state and a user-facing
        /// message.
        /// </summary>
        protected IDictionary<string, Tuple<string, string>> FingerprintToResultCache { get; }

        public static string IsValidStatic(ValidatorBase validator,
                                           ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return
                validator.IsValidStaticHelper(ref matchedPattern,
                                              ref groups,
                                              ref failureLevel,
                                              ref fingerprint,
                                              ref message);
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

        public static string ReturnValueForUnknownHostException(ref string message, Exception e, string asset)
        {
            if (e.Message.Equals("No such host is known."))
            {
                return ReturnUnknownHost(ref message, asset);
            }

            var aggregateException = e as AggregateException;
            if ((aggregateException?.InnerExceptions[0].Message.Equals("No such host is known.")).Value)
            {
                return ReturnUnknownHost(ref message, asset);
            }

            return ReturnUnhandledException(ref message, e, asset);
        }

        public static string ReturnUnknownHost(ref string message, string host)
        {
            message = $"The host '{host}' is unknown.";
            return nameof(ValidationState.UnknownHost);
        }

        public static string ReturnUnhandledException(ref string message,
                                                      Exception e,
                                                      string asset,
                                                      string account = null)
        {
            message = (account == null) ?
                $"An unexpected exception was caught attempting to validate '{asset}': {e.Message}" :
                $"An unexpected exception was caught attempting to validate the '{account} account on '{asset}': {e.Message}";

            return nameof(ValidationState.Unknown);
        }

        public static string ReturnUnauthorizedAccess(ref string message,
                                                      string asset,
                                                      string account = null)
        {
            message = (account == null) ?
                $"The provided secret is not authorized to access '{asset}'." :
                $"The provided '{account}' account secret is not authorized to access '{asset}'.";

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
    }
}
