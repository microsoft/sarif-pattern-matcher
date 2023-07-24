// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GitHubLegacyPatValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch secret = groups["secret"];

            ValidationResult validationResult;
            if (groups.TryGetNonEmptyValue("checksum", out FlexMatch checksum))
            {
                // TODO: #365 Utilize checksum https://github.com/microsoft/sarif-pattern-matcher/issues/365

                validationResult = new ValidationResult
                {
                    Fingerprint = new Fingerprint
                    {
                        Secret = secret.Value,
                        Platform = nameof(AssetPlatform.GitHub),
                    },
                };

                return new[] { validationResult };
            }

            // It is highly likely we do not have a key if we can't
            // find at least one letter and digit within the pattern.
            if (!secret.Value.ToString().ContainsDigitAndLetter())
            {
                return ValidationResult.CreateNoMatch();
            }

            string matchedPattern = groups["0"].Value;

            if (matchedPattern.IndexOf("raw", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("tree", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("blob", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("gist", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("spec", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("repos", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("assets", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("commit", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("using ref", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("githubusercontent.com", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ValidationResult.CreateNoMatch();
            }

            validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.GitHub),
                },
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            HttpClient client = CreateOrRetrieveCachedHttpClient();

            return new GitHubTokenValidationHelper().ValidateToken(client, ref fingerprint, ref message);
        }
    }
}
