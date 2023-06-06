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

using Newtonsoft.Json;

using Xunit;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/025.SendGridApiKeyValidator
    /// </summary>
    public class SendGridApiKeyValidatorTests
    {
        [Fact]
        public void SendGridApiKeyValidator_MockHttpTests()
        {
            const string secret = "secret";
            string asset = secret.Truncate();
            string fingerprintText = $"[secret={secret}]";
            string unknownMessage = null, unhandledMessage = null;

            var requestWithToken = new HttpRequestMessage(HttpMethod.Get, SendGridApiKeyValidator.ApiUri);
            requestWithToken.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);

            var scopes = new SendGridApiKeyValidator.ScopeResponse
            {
                Scopes = new List<string> { "mail.send", "sender_verification_eligible" }
            };

            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonConvert.SerializeObject(scopes))
            };

            var emptyResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonConvert.SerializeObject(new SendGridApiKeyValidator.ScopeResponse()))
            };

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Invalid Credential",
                    HttpRequestMessages = new [] { requestWithToken },
                    HttpResponseMessages = new [] { HttpMockHelper.UnauthorizedResponse },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Unauthorized
                },
                new HttpMockTestCase
                {
                    Title = "Unknown StatusCode",
                    HttpRequestMessages = new [] { requestWithToken },
                    HttpResponseMessages = new [] { HttpMockHelper.NotFoundResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unknownMessage, HttpStatusCode.NotFound),
                    ExpectedMessage = unknownMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Unhandled Exception",
                    HttpRequestMessages = new HttpRequestMessage[] { null },
                    HttpResponseMessages = new HttpResponseMessage[] { null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref unhandledMessage, new NullReferenceException(), asset),
                    ExpectedMessage = unhandledMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Valid Credential",
                    HttpRequestMessages = new HttpRequestMessage[] { requestWithToken },
                    HttpResponseMessages = new HttpResponseMessage[] { response },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = $"The secret has the '{string.Join(",", scopes.Scopes)}' permission(s).",
                },
                new HttpMockTestCase
                {
                    Title = "Valid Credential with no scopes",
                    HttpRequestMessages = new HttpRequestMessage[] { requestWithToken },
                    HttpResponseMessages = new HttpResponseMessage[] { emptyResponse },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = string.Empty,
                },
            };

            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();
            var validator = new SendGridApiKeyValidator();

            foreach (HttpMockTestCase testCase in testCases)
            {
                for (int i = 0; i < testCase.HttpRequestMessages.Count; i++)
                {
                    mockHandler.Mock(testCase.HttpRequestMessages[i], testCase.HttpResponseMessages[i]);
                }

                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                using var httpClient = new HttpClient(mockHandler);
                validator.SetHttpClient(httpClient);

                ValidationState currentState = validator.IsValidDynamic(ref fingerprint,
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
