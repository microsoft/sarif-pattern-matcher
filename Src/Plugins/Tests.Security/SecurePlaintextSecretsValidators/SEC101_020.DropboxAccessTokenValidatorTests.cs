// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
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
    /// <summary>
    /// Testing SEC101/020.DropboxAccessTokenValidator
    /// </summary
    public class DropboxAccessTokenValidatorTests
    {
        [Fact]
        public void DropboxAccessTokenValidator_MockHttpTests()
        {
            const string NoAccessMessage = "Your app is not permitted to access this endpoint";
            const string DisabledMessage = "This app is currently disabled.";
            const string uri = "https://api.dropboxapi.com/2/file_requests/count";
            const string secret = "abc123";
            string fingerprintText = $"[secret={secret}]";
            var dropboxAccessTokenValidator = new DropboxAccessTokenValidator();

            using var requestWithToken = new HttpRequestMessage(HttpMethod.Get, uri);
            requestWithToken.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);

            string tmpMsg = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Valid Credential",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { null },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Authorized
                },
                new HttpMockTestCase
                {
                    Title = "App Deleted",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.BadRequest },
                    HttpContents = new List<HttpContent> { new StringContent(DisabledMessage, Encoding.UTF8, "application/text")},
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Expired
                },
                new HttpMockTestCase
                {
                    Title = "No Access",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.BadRequest },
                    HttpContents = new List<HttpContent> { new StringContent(NoAccessMessage, Encoding.UTF8, "application/text") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Authorized
                },
                new HttpMockTestCase
                {
                    Title = "Bad Request - Unexpected Response Code",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.BadRequest },
                    HttpContents = new List<HttpContent> { new StringContent("Unknown message", Encoding.UTF8, "application/text") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref tmpMsg, HttpStatusCode.BadRequest),
                    ExpectedMessage = tmpMsg
                },
                new HttpMockTestCase
                {
                    Title = "Invalid Credential",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Unauthorized},
                    HttpContents = new List<HttpContent> { null },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Unauthorized
                },
                new HttpMockTestCase
                {
                    Title = "Unexpected Response Code",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.InternalServerError },
                    HttpContents = new List<HttpContent> { null },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref tmpMsg, HttpStatusCode.InternalServerError),
                    ExpectedMessage = tmpMsg
                },
            };

            var sb = new StringBuilder();
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
                dropboxAccessTokenValidator.SetHttpClient(httpClient);

                ValidationState currentState = dropboxAccessTokenValidator.IsValidDynamic(ref fingerprint,
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
