// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GoogleGCMServiceAccountValidator : ValidatorBase
    {
        internal static GoogleGCMServiceAccountValidator Instance;

        static GoogleGCMServiceAccountValidator()
        {
            Instance = new GoogleGCMServiceAccountValidator();
        }

        public static string IsValidStatic(ref string matchedPattern,
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

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            fingerprintText = new Fingerprint()
            {
                Resource = matchedPattern,
                Platform = nameof(AssetPlatform.Google),
            }.ToString();

            return nameof(ValidationState.Unknown);
        }
    }
}
