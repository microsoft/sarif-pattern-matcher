﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GitHubAppCredentialsValidator : ValidatorBase
    {
        internal static GitHubAppCredentialsValidator Instance;

        static GitHubAppCredentialsValidator()
        {
            Instance = new GitHubAppCredentialsValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance, groups);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(Dictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            // It is highly likely we do not have a key if we can't
            // find at least one letter and digit within the pattern.
            if (!ContainsDigitAndChar(secret.Value))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.GitHub),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }
    }
}
