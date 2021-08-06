// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class GitHubAppCredentialsValidatorTests
    {
        [Fact]
        public void GitHubAppCredentialsValidator_MockHttpTests()
        {
            var testCases = new[]
            {
                new
                {
                    Title = "Testing NotFound StatusCode (app was deleted)",
                    HttpStatusCode = HttpStatusCode.NotFound,
                    HttpContent = (HttpContent)null,
                    ExpectedValidationState = ValidationState.Expired,
                    ExpectedMessage = string.Empty
                },
                new
                {
                    Title = "Testing invalid credentials",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent(
                        "error=incorrect_client_credentials&error_description=The+client_id+and%2For+client_secret+passed+are+incorrect.&error_uri=https%3A%2F%2Fdocs.github.com%2Fapps%2Fmanaging-oauth-apps%2Ftroubleshooting-oauth-app-access-token-request-errors%2F%23incorrect-client-credentials",
                        Encoding.UTF8,
                        "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = "The provided secret is not authorized to access 'Iv1.01234567testtest'."
                },
                new
                {
                    Title = "Testing valid credentials",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent(
                        "error=redirect_uri_mismatch&error_description=The+redirect_uri+MUST+match+the+registered+callback+URL+for+this+application.&error_uri=https%3A%2F%2Fdocs.github.com%2Fapps%2Fmanaging-oauth-apps%2Ftroubleshooting-authorization-request-errors%2F%23redirect-uri-mismatch2",
                        Encoding.UTF8,
                        "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The compromised asset is 'Iv1.01234567testtest'."
                },
                new
                {
                    Title = "Testing unknown response",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent(
                        "some unknown content",
                        Encoding.UTF8,
                        "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected HTTP response code was received from 'Iv1.01234567testtest': 'OK'."
                },
                new
                {
                    Title = "Testing BadRequest StatusCode",
                    HttpStatusCode = HttpStatusCode.BadRequest,
                    HttpContent = (HttpContent)null,
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected HTTP response code was received from 'Iv1.01234567testtest': 'BadRequest'."
                },
            };

            const string fingerprintText = "[id=Iv1.01234567testtest][secret=secret]";

            var sb = new StringBuilder();
            foreach (var testCase in testCases)
            {
                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                ValidatorHelper.ResetStaticInstance<GitHubAppCredentialsValidator>();
                using var httpClient = new HttpClient(HttpMockHelper.Mock(testCase.HttpStatusCode, testCase.HttpContent));
                GitHubAppCredentialsValidator.Instance.SetHttpClient(httpClient);

                ValidationState currentState = GitHubAppCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                                                            ref message,
                                                                                            keyValuePairs,
                                                                                            ref resultLevelKind);
                if (currentState != testCase.ExpectedValidationState)
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedValidationState}' but found '{currentState}'.");
                }

                if (!message.Equals(testCase.ExpectedMessage))
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedMessage}' but found '{message}'.");
                }
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
