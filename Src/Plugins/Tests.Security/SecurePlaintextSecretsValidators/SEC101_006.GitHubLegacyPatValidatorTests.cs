// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using FluentAssertions;

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

        [Fact]
        public void GitHubLegacyPatValidator_ValidatePat_ShouldReturnAuthorizedWhenPatIsLive()
        {
            const string id = "123";
            const string login = "login";
            const string userName = "userName";

            var sb = new StringBuilder();
            var validator = new GitHubLegacyPatValidator();
            var fingerprint = new Fingerprint { Secret = "secret" };
            string uri = "https://api.github.com/user";

            var mockHandler = new HttpMockHelper();

            using var defaultRequest = new HttpRequestMessage(HttpMethod.Get, uri);
            defaultRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "secret");

            var okResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    $@"{{
                        ""id"":""{id}"",
                        ""login"":""{login}"",
                        ""name"":""{userName}"",
                        ""node_id"":""abcd1234""
                    }}
                ")
            };

            mockHandler.Mock(defaultRequest, okResponse);
            using var httpClient = new HttpClient(mockHandler);
            validator.SetHttpClient(httpClient);

            string message = string.Empty;
            ResultLevelKind resultLevelKind = default;
            var keyValuePairs = new Dictionary<string, string>();
            var actualFingerprint = new Fingerprint(fingerprint.ToString());

            ValidationState state = validator.IsValidDynamic(
                ref actualFingerprint,
                ref message,
                keyValuePairs,
                ref resultLevelKind);

            if (state != ValidationState.Authorized)
            {
                sb.AppendLine($"The test was expecting '{nameof(ValidationState.Authorized)}' but found '{state}' for '{uri}'.");
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
