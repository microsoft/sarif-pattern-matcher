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

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/027.MailChimpApiKeyValidator
    /// </summary>
    public class MailChimpApiKeyValidatorTests
    {
        [Fact]
        public void MailChimpApiKeyValidator_MockHttpTests()
        {
            const string key1 = "key1";
            const string key2 = "key2";
            const string accountName = "account";
            string secret = $"[secret={key1}-{key2}]";

            string authorizedMessage = null, unknownMessage = null, exceptionMessage = null;

            var request = new HttpRequestMessage(HttpMethod.Get, string.Format(MailChimpApiKeyValidator.ApiUri, key2));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", key1);

            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonConvert.SerializeObject(new MailChimpApiKeyValidator.Account
                {
                    AccountName = accountName
                }))
            };

            string tmpMsg = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Valid Credential",
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    HttpResponseMessages = new List<HttpResponseMessage>{ response },
                    ExpectedValidationState = ValidatorBase.ReturnAuthorizedAccess(ref authorizedMessage, asset: accountName),
                    ExpectedMessage = authorizedMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Invalid Credential",
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    HttpResponseMessages = new List<HttpResponseMessage>{ HttpMockHelper.UnauthorizedResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty,
                },
                new HttpMockTestCase
                {
                    Title = "Unknown StatusCode (BadRequest)",
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    HttpResponseMessages = new List<HttpResponseMessage>{ HttpMockHelper.BadRequestResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unknownMessage, HttpStatusCode.BadRequest),
                    ExpectedMessage = unknownMessage,
                },
                new HttpMockTestCase
                {
                    Title = "HttpClient throwing NullReferenceException",
                    HttpRequestMessages = new List<HttpRequestMessage>{ null },
                    HttpResponseMessages = new List<HttpResponseMessage>{ null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref exceptionMessage, new NullReferenceException()),
                    ExpectedMessage = exceptionMessage,
                },
            };

            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();
            var validator = new MailChimpApiKeyValidator();

            foreach (HttpMockTestCase testCase in testCases)
            {
                for (int i = 0; i < testCase.HttpRequestMessages.Count; i++)
                {
                    mockHandler.Mock(testCase.HttpRequestMessages[i], testCase.HttpResponseMessages[i]);
                }

                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(secret);
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
