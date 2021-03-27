// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GoogleServiceAccountKeyValidator : ValidatorBase
    {
        internal static GoogleServiceAccountKeyValidator Instance;

        static GoogleServiceAccountKeyValidator()
        {
            Instance = new GoogleServiceAccountKeyValidator();
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref failureLevel,
                                 ref fingerprint,
                                 ref message);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue("key", out string key))
            {
                return ValidationState.NoMatch;
            }

            // We might not succuessfully get account/client id
            groups.TryGetNonEmptyValue("account", out string account);

            fingerprintText = new Fingerprint()
            {
                Account = account,
                Key = key,
            }.ToString();

            // We have high confidence in these particular patterns as they are extracted directly from
            // Google docs and JSON definitions
            return ValidationState.Unknown;
        }
    }
}
