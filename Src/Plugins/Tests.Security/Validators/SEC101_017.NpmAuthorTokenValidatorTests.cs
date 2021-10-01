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
            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing Unauthorized StatusCode",
                    HttpStatusCodes = new[] {HttpStatusCode.Unauthorized },
                    HttpContents = new[] { (HttpContent)null },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing NotFound StatusCode",
                    HttpStatusCodes = new[] { HttpStatusCode.NotFound },
                    HttpContents = new[] { (HttpContent)null },
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected HTTP response code was received: 'NotFound'."
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - empty content",
                    HttpStatusCodes = new[] { HttpStatusCode.OK },
                    HttpContents = new[] { new StringContent(string.Empty).As<HttpContent>() },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - readonly",
                    HttpStatusCodes = new[] { HttpStatusCode.OK },
                    HttpContents = new[] { new StringContent(@"
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
", Encoding.UTF8, "application/json").As<HttpContent>() },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The token has 'read' permissions."
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - automation",
                    HttpStatusCodes = new[] { HttpStatusCode.OK },
                    HttpContents = new[] { new StringContent(@"
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
", Encoding.UTF8, "application/json").As<HttpContent>() },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The token has 'automation' permissions."
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - publish",
                    HttpStatusCodes = new[] { HttpStatusCode.OK },
                    HttpContents = new[] { new StringContent(@"
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
", Encoding.UTF8, "application/json").As<HttpContent>() },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The token has 'publish' permissions."
                },
            };

            const string fingerprintText = "[secret=abc123]";

            var sb = new StringBuilder();
            var npmAuthorTokenValidator = new NpmAuthorTokenValidator();
            foreach (HttpMockTestCase testCase in testCases)
            {
                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                using var httpClient = new HttpClient(HttpMockHelper.Mock(testCase.HttpStatusCodes[0], testCase.HttpContents[0]));
                npmAuthorTokenValidator.SetHttpClient(httpClient);

                ValidationState currentState = npmAuthorTokenValidator.IsValidDynamic(ref fingerprint,
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
