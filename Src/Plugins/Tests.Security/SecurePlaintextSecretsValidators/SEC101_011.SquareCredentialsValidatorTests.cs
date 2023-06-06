// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/011.SquareCredentialsValidator
    /// </summary>
    public class SquareCredentialsValidatorTests
    {
        [Fact]
        public void SquareCredentialsValidator_Test()
        {
            string fingerprintText = "";
            if (string.IsNullOrEmpty(fingerprintText))
            {
                return;
            }

            string message = null;
            ResultLevelKind resultLevelKind = default;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            var squareCredentialsValidator = new SquareCredentialsValidator();
            squareCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                      ref message,
                                                      keyValuePairs,
                                                      ref resultLevelKind);
        }

        [Fact]
        public void SquareCredentialsValidator_MockHttpTests()
        {
            string id = "a";
            string secret = "b";
            const string codeForRequest = "123";
            const string uri = "https://connect.squareup.com/oauth2/token";
            string fingerprintText = $"[id={id}][secret={secret}]";

            var requestParams = new Dictionary<string, string>()
            {
                { "client_id", id },
                { "code", codeForRequest },
                { "client_secret", secret },
                { "grant_type", "authorization_code" },
            };

            using var requestWithCredentials = new HttpRequestMessage(HttpMethod.Post, uri);
            requestWithCredentials.Content = new FormUrlEncodedContent(requestParams);

            string authorizedResponse = string.Empty;
            string unauthorizedResponse = string.Empty;
            string unexpectedResponseCodeResponse = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing unexpected OK StatusCode",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent>() { null },
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithCredentials },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedResponseCodeResponse, HttpStatusCode.OK),
                    ExpectedMessage = unexpectedResponseCodeResponse,
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.Unauthorized },
                    HttpContents = new List<HttpContent>() {
                        new StringContent($"{{\"message\": \"Authorization code not found for app [{id}]\",\"type\": \"service.not_authorized\"}}",
                                                                  Encoding.UTF8,
                                                                  "application/json").As<HttpContent>(),
                    },
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithCredentials },
                    ExpectedValidationState =  ValidatorBase.ReturnAuthorizedAccess(ref authorizedResponse, id),
                    ExpectedMessage = authorizedResponse
                },
                new HttpMockTestCase
                {
                    Title = "Testing Invalid credentials",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.Unauthorized },
                    HttpContents = new List<HttpContent>() {
                        new StringContent("{\n\"message\": \"Not Authorized\",\n\"type\": \"service.not_authorized\"\n}",
                                                    Encoding.UTF8,
                                                    "application/json").As<HttpContent>(),
                    },
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithCredentials },
                    ExpectedValidationState = ValidatorBase.ReturnUnauthorizedAccess(ref unauthorizedResponse, id),
                    ExpectedMessage = unauthorizedResponse,
                },
            };


            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();
            var squareCredentialsValidator = new SquareCredentialsValidator();
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
                squareCredentialsValidator.SetHttpClient(httpClient);

                ValidationState currentState = squareCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                                                         ref message,
                                                                                         keyValuePairs,
                                                                                         ref resultLevelKind);
                if (currentState != testCase.ExpectedValidationState)
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedValidationState}' but found '{currentState}'.");
                }

                if (testCase.ExpectedMessage != message?.Split(Environment.NewLine)[0])
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedMessage}' but found '{message}'.");
                }

                mockHandler.Clear();
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
