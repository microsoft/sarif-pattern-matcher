// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/006.GitHubLegacyPatValidator
    /// </summary>
    public class GitHubLegacyPatValidatorTests
    {
        [Fact]
        public void GitHubLegacyPatValidator_TestStatic()
        {
            ValidationState expectedValidationState = ValidationState.Unknown;

            string matchedPattern = "ghp_stuffchecksum"; // Insert new GitHub PAT here
            var groups = new Dictionary<string, FlexMatch>();
            groups.Add("0", new FlexMatch() { Value = matchedPattern });
            groups.Add("secret", new FlexMatch() { Value = matchedPattern });
            groups.Add("checksum", new FlexMatch() { Value = "checksum" });
            groups.Add("scanTargetFullPath", new FlexMatch() { Value = "GitHitPatTest" });

            var gitHubLegacyPatValidator = new GitHubLegacyPatValidator();
            var perFileFingerprintCache = new HashSet<string>();
            IEnumerable<ValidationResult> validationResults = gitHubLegacyPatValidator.IsValidStatic(groups, perFileFingerprintCache);
            foreach (ValidationResult validationResult in validationResults)
            {
                Assert.Equal(matchedPattern, validationResult.Fingerprint.Secret);
                Assert.Equal(nameof(AssetPlatform.GitHub), validationResult.Fingerprint.Platform);
                Assert.Equal(expectedValidationState, validationResult.ValidationState);
            }
        }

        [Fact]
        public void GitHubLegacyPatValidator_TestDynamic()
        {
            ValidationState expectedValidationState = ValidationState.Unauthorized;

            string fingerprintText = "[platform=GitHub][secret=ghp_000000000001234567890123456789012345]";

            string message = null;
            ResultLevelKind resultLevelKind = default;
            var fingerprint = new Fingerprint(fingerprintText);
            var options = new Dictionary<string, string>();

            var gitHubLegacyPatValidator = new GitHubLegacyPatValidator();
            ValidationState actualValidationState = gitHubLegacyPatValidator.IsValidDynamic(ref fingerprint,
                                                                                      ref message,
                                                                                      options,
                                                                                      ref resultLevelKind);

            Assert.Equal(expectedValidationState, actualValidationState);
        }
    }
}
