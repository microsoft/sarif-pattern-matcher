// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SquareCredentialsValidator : ValidatorBase
    {
        internal static SquareCredentialsValidator Instance;

        static SquareCredentialsValidator()
        {
            Instance = new SquareCredentialsValidator();
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

            if (!groups.TryGetValue("id", out string id) ||
                !groups.TryGetValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint
            {
                Id = id,
                Secret = secret,
                Platform = nameof(AssetPlatform.Square),
            };

            return ValidationState.Unknown;
        }
    }
}
