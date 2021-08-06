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
    public class NpmAuthorTokenValidatorTests
    {
        [Fact]
        public void NpmAuthorTokenValidator_MockHttpTests()
        {
            var testCases = new[]
            {
                new
                {
                    Title = "Testing Unauthorized StatusCode",
                    HttpStatusCode = HttpStatusCode.Unauthorized,
                    HttpContent = (HttpContent)null,
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty
                },
                new
                {
                    Title = "Testing NotFound StatusCode",
                    HttpStatusCode = HttpStatusCode.NotFound,
                    HttpContent = (HttpContent)null,
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected HTTP response code was received: 'NotFound'."
                },
                new
                {
                    Title = "Testing Valid credentials - empty content",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent(string.Empty).As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = string.Empty
                },
                new
                {
                    Title = "Testing Valid credentials - readonly",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent(@"
{
    ""objects"": [
        {
            ""token"": ""abc123"",
            ""key"": ""some long key"",
            ""cidr_whitelist"": null,
            ""readonly"": true,
            ""automation"": false,
            ""created"": ""2020-12-23T15:35:05.255Z"",
            ""updated"": ""2020-12-23T15:35:05.255Z""
        }
    ],
    ""total"": 1,
    ""urls"": {}
}
", Encoding.UTF8, "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The token has 'read' permissions."
                },
                new
                {
                    Title = "Testing Valid credentials - automation",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent(@"
{
    ""objects"": [
        {
            ""token"": ""abc123"",
            ""key"": ""some long key"",
            ""cidr_whitelist"": null,
            ""readonly"": false,
            ""automation"": true,
            ""created"": ""2020-12-23T15:35:05.255Z"",
            ""updated"": ""2020-12-23T15:35:05.255Z""
        }
    ],
    ""total"": 1,
    ""urls"": {}
}
", Encoding.UTF8, "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The token has 'automation' permissions."
                },
                new
                {
                    Title = "Testing Valid credentials - publish",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent(@"
{
    ""objects"": [
        {
            ""token"": ""abc123"",
            ""key"": ""some long key"",
            ""cidr_whitelist"": null,
            ""readonly"": false,
            ""automation"": false,
            ""created"": ""2020-12-23T15:35:05.255Z"",
            ""updated"": ""2020-12-23T15:35:05.255Z""
        }
    ],
    ""total"": 1,
    ""urls"": {}
}
", Encoding.UTF8, "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The token has 'publish' permissions."
                },
            };

            const string fingerprintText = "[secret=abc123]";

            var sb = new StringBuilder();
            foreach (var testCase in testCases)
            {
                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                ValidatorHelper.ResetStaticInstance<NpmAuthorTokenValidator>();
                using var httpClient = new HttpClient(HttpMockHelper.Mock(testCase.HttpStatusCode, testCase.HttpContent));
                NpmAuthorTokenValidator.Instance.SetHttpClient(httpClient);

                ValidationState currentState = NpmAuthorTokenValidator.IsValidDynamic(ref fingerprint,
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
