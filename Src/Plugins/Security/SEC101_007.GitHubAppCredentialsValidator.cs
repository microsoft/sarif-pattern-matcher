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

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  ref Dictionary<string, string> groups,
                                                                  ref string message)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref message);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             ref Dictionary<string, string> groups,
                                                                             ref string message)
        {
            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationResult.NoMatch;
            }

            // It is highly likely we do not have a key if we can't
            // find at least one letter and digit within the pattern.
            if (!ContainsDigitAndChar(secret))
            {
                return ValidationResult.NoMatch;
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id,
                    Secret = secret,
                    Platform = nameof(AssetPlatform.GitHub),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }
    }
}
