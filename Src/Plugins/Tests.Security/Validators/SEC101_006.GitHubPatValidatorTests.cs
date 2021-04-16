// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class GitHubPatValidatorTests
    {
        [Fact]
        public void GitHubPatValidator_TestStatic()
        {
            ValidationState expectedValidationState = ValidationState.Unknown;

            string matchedPattern = "ghp_stuffchecksum"; // Insert new GitHub PAT here
            Dictionary<string, string> groups = new Dictionary<string, string>();
            groups.Add("secret", "stuff");
            groups.Add("checksum", "checksum");
            groups.Add("scanTargetFullPath", "GitHitPatTest");

            string message = null;
            string failureLevel = null;

            ValidationState actualValidationState = GitHubPatValidator.IsValidStatic(ref matchedPattern, ref groups, ref failureLevel, ref message, out Fingerprint fingerprint);

            Assert.Equal(matchedPattern, fingerprint.Secret);
            Assert.Equal(AssetPlatform.GitHub.ToString(), fingerprint.Platform);
            Assert.Equal(expectedValidationState, actualValidationState);
        }

        [Fact]
        public void GitHubPatValidator_TestDynamic()
        {
            ValidationState expectedValidationState = ValidationState.Unauthorized;

            string fingerprintText = "[platform=GitHub][secret=ghp_000000000001234567890123456789012345]";

            string message = null;
            var fingerprint = new Fingerprint(fingerprintText);
            var options = new Dictionary<string, string>();

            ValidationState actualValidationState = GitHubPatValidator.IsValidDynamic(ref fingerprint, ref message, ref options);

            Assert.Equal(expectedValidationState, actualValidationState);
        }
    }
}
