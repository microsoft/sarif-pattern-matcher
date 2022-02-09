// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.Validators
{
    /// <summary>
    /// Testing SEC101/045.PostmanApiKeyValidator
    /// </summary>
    public class PostmanApiKeyValidatorTests
    {
        private const string fingerprintText = "[secret=supersecretvalue]";

        [Fact]
        public void PostmanApiKeyValidator_MockHttpTests()
        {
            var fingerprint = new Fingerprint(fingerprintText);
            string secret = fingerprint.Secret;
            HttpRequestMessage request = PostmanApiKeyValidator.GenerateRequestMessage(secret);

            string unexpectedResponseMessage = string.Empty;
            string nullRefResponseMessage = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Null Ref Exception",
                    HttpRequestMessages = new List<HttpRequestMessage>{ null },
                    HttpResponseMessages = new List<HttpResponseMessage>{ null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref nullRefResponseMessage, new NullReferenceException()),
                    ExpectedMessage = nullRefResponseMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Authorized (Ok response code)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.OKResponse },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = string.Empty,
                },
                new HttpMockTestCase
                {
                    Title = "Unauthorized (Unauthorized response code)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.UnauthorizedResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty,
                },
                new HttpMockTestCase
                {
                    Title = "Unexpected (server error response code)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.InternalServerErrorResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedResponseMessage, HttpStatusCode.InternalServerError),
                    ExpectedMessage = unexpectedResponseMessage,
                }
            };

            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();
            var validator = new PostmanApiKeyValidator();

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
