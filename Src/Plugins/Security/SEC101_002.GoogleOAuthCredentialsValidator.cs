// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GoogleOAuthCredentialsValidator : ValidatorBase
    {
        internal static GoogleOAuthCredentialsValidator Instance;

        static GoogleOAuthCredentialsValidator()
        {
            Instance = new GoogleOAuthCredentialsValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance, groups);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(Dictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetValue("id", out FlexMatch id) ||
                !groups.TryGetValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                RegionFlexMatch = secret,
                Fingerprint = new Fingerprint
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Google),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }
    }
}
