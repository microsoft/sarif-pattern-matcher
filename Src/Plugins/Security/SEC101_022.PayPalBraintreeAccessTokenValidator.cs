// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class PayPalBraintreeAccessTokenValidator : ValidatorBase
    {
        internal static PayPalBraintreeAccessTokenValidator Instance;

        static PayPalBraintreeAccessTokenValidator()
        {
            Instance = new PayPalBraintreeAccessTokenValidator();
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string message,
                                           out Fingerprint fingerprint)
        {
            return IsValidStatic(Instance,
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
            if (!groups.TryGetNonEmptyValue("key", out string key))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint()
            {
                Key = key,
                Platform = nameof(AssetPlatform.PayPal),
            };

            return ValidationState.Unknown;
        }
    }
}
