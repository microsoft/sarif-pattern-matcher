// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GitHubAppCredentialsValidator : ValidatorBase
    {
        internal static GitHubAppCredentialsValidator Instance;

        static GitHubAppCredentialsValidator()
        {
            Instance = new GitHubAppCredentialsValidator();
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
                                                    ref string failureLevel,
                                                    ref string message,
                                                    out Fingerprint fingerprint)
        {
            return ValidatorBase.IsValidStatic(Instance,
                                               ref matchedPattern,
                                               ref groups,
                                               ref failureLevel,
                                               ref message,
                                               out fingerprint);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string failureLevel,
                                                               ref string message,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;

            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            // It is highly likely we do not have a key if we can't
            // find at least one letter and digit within the pattern.
            if (!ContainsDigitAndChar(secret))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint()
            {
                Id = id,
                Secret = secret,
                Platform = nameof(AssetPlatform.GitHub),
            };

            return ValidationState.Unknown;
        }
    }
}
