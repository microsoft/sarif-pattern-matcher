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
    /// Testing SEC101/021.DropboxAppCredentialsValidator
    /// </summary>
    public class DropboxAppCredentialsValidatorTests
    {
        [Fact]
        public void DropboxAppCredentialsValidator_MockHttpTests()
        {
            const string fingerprintText = "[id=345def][secret=abc123]";
            var fingerprint = new Fingerprint(fingerprintText);

            string id = fingerprint.Id;
            string secret = fingerprint.Secret;
            string asset = secret.Truncate();

            using HttpRequestMessage defaultRequest = DropboxAppCredentialsValidator.GenerateRequestMessage(id, secret);

            var AppDisabledResponse = new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("App has been disabled")
            };
            var InvalidClientResponse = new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("invalid_client")
            };
            var NoContentResponse = new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent(string.Empty)
            };

            string nullRefResponseMessage = string.Empty;
            string unexpectedResponseCodeMessage = string.Empty;
            string unexpectedResponseCodeMessage2 = string.Empty;
            var resLevel = new ResultLevelKind();

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Nullref Exception",
                    HttpRequestMessages = new List<HttpRequestMessage> { null },
                    HttpResponseMessages = new List<HttpResponseMessage> { null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref nullRefResponseMessage, new NullReferenceException(), asset),
                    ExpectedMessage = nullRefResponseMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unexpected Status Code (Unauthorized)",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.UnauthorizedResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedResponseCodeMessage, HttpStatusCode.Unauthorized, account: id),
                    ExpectedMessage = unexpectedResponseCodeMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing InternalServerError Status Code",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.InternalServerErrorResponse },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing BadRequest Status Code (no content)",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { NoContentResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedResponseCodeMessage2, HttpStatusCode.BadRequest, account: id),
                    ExpectedMessage = unexpectedResponseCodeMessage2
                },
                new HttpMockTestCase
                {
                    Title = "Testing Disabled App",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { AppDisabledResponse },
                    ExpectedValidationState = ValidationState.Expired,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing invalid_client",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { InvalidClientResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty
                }
            };

            var sb = new StringBuilder();
            var validator = new DropboxAppCredentialsValidator();
            var mockHandler = new HttpMockHelper();

            foreach (HttpMockTestCase testCase in testCases)
            {
                for (int i = 0; i < testCase.HttpRequestMessages.Count; i++)
                {
                    mockHandler.Mock(testCase.HttpRequestMessages[i], testCase.HttpResponseMessages[i]);
                }

                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var keyValuePairs = new Dictionary<string, string>();

                using var httpClient = new HttpClient(mockHandler);
                validator.SetHttpClient(httpClient);
                ValidationState currentState = validator.IsValidDynamic(ref fingerprint,
                                                                        ref message,
                                                                        keyValuePairs,
                                                                        ref resultLevelKind);

                if (currentState != testCase.ExpectedValidationState)
                {
                    sb.AppendLine($"The test '{testCase.Title}' was expecting '{testCase.ExpectedValidationState}' but found '{currentState}'.");
                }

                if (testCase.ExpectedMessage != message?.Split(Environment.NewLine)[0])
                {
                    sb.AppendLine($"The test '{testCase.Title}' was expecting '{testCase.ExpectedMessage}' but found '{message}'.");
                }

                mockHandler.Clear();
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
