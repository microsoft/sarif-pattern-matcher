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
    public class DropboxAppCredentialsValidatorTests
    {
        [Fact]
        public void DropboxAppCredentialsValidator_MockHttpTests()
        {
            const string NoAccessMessage = "Your app is not permitted to access this endpoint";
            const string DisabledMessage = "This app is currently disabled.";
            const string uri = "https://api.dropboxapi.com/2/file_requests/count";
            const string id = "5678";
            const string secret = "abc123";
            string fingerprintText = $"[id={id}][secret={secret}]";
            var dropboxAppCredentialsValidator = new DropboxAppCredentialsValidator();

           
            string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", id, secret)));
            using var requestWithCredentials = new HttpRequestMessage(HttpMethod.Post, uri);
            requestWithCredentials.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            requestWithCredentials.Headers.Add("Dropbox-API-Arg", @"{""resource"": {"".tag"": ""path"",""path"": ""/a.docx""},""format"": ""jpeg"",""size"": ""w64h64"",""mode"": ""strict""}");

            string tmpMsg = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Valid Credential",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { null },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithCredentials },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Authorized
                },
                new HttpMockTestCase
                {
                    Title = "App Deleted",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.BadRequest },
                    HttpContents = new List<HttpContent> { new StringContent(DisabledMessage, Encoding.UTF8, "application/text")},
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithCredentials },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Expired
                },
                new HttpMockTestCase
                {
                    Title = "No Access",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.BadRequest },
                    HttpContents = new List<HttpContent> { new StringContent(NoAccessMessage, Encoding.UTF8, "application/text") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithCredentials },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Authorized
                },
                new HttpMockTestCase
                {
                    Title = "Bad Request - Unexpected Response Code",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.BadRequest },
                    HttpContents = new List<HttpContent> { new StringContent("Unknown message", Encoding.UTF8, "application/text") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithCredentials },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref tmpMsg, HttpStatusCode.BadRequest),
                    ExpectedMessage = tmpMsg
                },
                new HttpMockTestCase
                {
                    Title = "Invalid Credential",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Unauthorized},
                    HttpContents = new List<HttpContent> { null },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithCredentials },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Unauthorized
                },
                new HttpMockTestCase
                {
                    Title = "Unexpected Response Code",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.InternalServerError },
                    HttpContents = new List<HttpContent> { null },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithCredentials },
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
                dropboxAppCredentialsValidator.SetHttpClient(httpClient);

                ValidationState currentState = dropboxAppCredentialsValidator.IsValidDynamic(ref fingerprint,
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
