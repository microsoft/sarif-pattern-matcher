// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins
{
    internal abstract class ValidatorBase
    {
        protected ValidatorBase()
        {
            FingerprintToResultCache = new Dictionary<string, string>();
        }

        /// <summary>
        /// Gets a cache of fingerprint to previously generated validation
        /// results. Useful to avoid repeating expensive dynamic validations
        /// of logically unique secrets.
        /// </summary>
        protected IDictionary<string, string> FingerprintToResultCache { get; }

        public static string CreateReturnValueForException(Exception e, string asset)
        {
            if (e.Message.Equals("No such host is known."))
            {
                return CreateReturnValueForUnknownHost(asset);
            }

            var aggregateException = e as AggregateException;
            if ((aggregateException?.InnerExceptions[0].Message.Equals("No such host is known.")).Value)
            {
                return CreateReturnValueForUnknownHost(asset);
            }

            return nameof(ValidationState.HostUnknown) +
                       $"#An unexpected exception was caught attempting to validate '{asset}': " +
                       e.ToString();
        }

        public static string CreateReturnValueForUnknownHost(string host)
        {
            return nameof(ValidationState.Unknown) +
                $"#The host '{host}' is unknown.";
        }

        public static string CreateReturnValueForUnauthorizedAccess(string asset)
        {
            return nameof(ValidationState.Unauthorized) +
                $"#to '{asset}'.";
        }

        public static string CreateReturnValueForCompromisedAsset(string asset, string user = null)
        {
            return user == null ?
                nameof(ValidationState.Authorized) + $"#The compromised asset is '{asset}'." :
                nameof(ValidationState.Authorized) + $"#The '{user}' account is compromised for '{asset}'.";
        }

        public static string CreateReturnValueForFileException(Exception e, string asset)
        {
            if (e.Message.Equals("The specified network password is not correct."))
            {
                return nameof(ValidationState.Unknown) + $"#The file '{asset}' is secure and we could not validate.";
            }

            return nameof(ValidationState.Unknown) +
                       $"#An unexpected exception was caught attempting to validate '{asset}': " +
                       e.ToString();
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
        /// <param name="performDynamicValidation">
        /// Execute dynamic validation of matched pattern, if available.
        /// </param>
        /// <param name="failureLevel">
        /// The current failure level associated with the match (if a match occurs). This parameter can be
        /// set to a different failure level by the callee, if appropriate.
        /// </param>
        /// <param name="fingerprint">
        /// A SARIF fingerprint that identifies a logically unique secret. This parameter should be
        /// set to null if no fingerprint can be computed that definitively identifies the secret.
        /// </param>
        /// <returns>Return the validation state.</returns>
        protected abstract string IsValid(
            ref string matchedPattern,
            ref Dictionary<string, string> groups,
            ref bool performDynamicValidation,
            ref string failureLevel,
            ref string fingerprint);
    }
}
