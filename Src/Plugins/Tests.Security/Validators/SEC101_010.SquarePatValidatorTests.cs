// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class SquarePatValidatorTests
    {
        [Fact]
        public void SquarePatValidator_MockHttpTests()
        {
            const string pat = "abcd1234";
            const string uri = "https://connect.squareup.com/v2/catalog/list";
            string fingerprintText = $"[secret={pat}]";

            using var requestWithPat = new HttpRequestMessage(HttpMethod.Get, uri);
            requestWithPat.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pat);

            string unexpectedResponseCodeResponse = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing OK StatusCode",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent>() { null },
                    ExpectedValidationState = ValidationState.Authorized,
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithPat },
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unauthorized StatusCode",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.Unauthorized },
                    HttpContents = new List<HttpContent>() { null },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithPat },
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing NotFound StatusCode",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.NotFound },
                    HttpContents = new List<HttpContent>() { null },
                    ExpectedValidationState = ValidationState.Unknown,
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithPat },
                    ExpectedMessage = "An unexpected HTTP response code was received: 'NotFound'."
                },
            };

            var sb = new StringBuilder();
            var squarePatValidator = new SquarePatValidator();
            var mockHandler = new HttpMockHelper();
            foreach (HttpMockTestCase testCase in testCases)
            {
                for (int i = 0; i < testCase.HttpStatusCodes.Count; i++)
                {
                    mockHandler.Mock(testCase.HttpRequestMessages[i], testCase.HttpStatusCodes[i], testCase.HttpContents[i]);
                }

                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                using var httpClient = new HttpClient(mockHandler);
                squarePatValidator.SetHttpClient(httpClient);

                ValidationState currentState = squarePatValidator.IsValidDynamic(ref fingerprint,
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
                mockHandler.Clear();
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
