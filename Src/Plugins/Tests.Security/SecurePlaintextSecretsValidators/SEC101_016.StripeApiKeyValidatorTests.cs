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
    /// Testing SEC101/016.StripeApiKeyValidator
    /// </summary
    public class StripeApiKeyValidatorTests
    {
        private readonly string[] fingerprintStrings = new string[] { "[secret=_production_secret]", "[secret=_test_secret]" };

        [Fact]
        public void StripeApiKeyValidator_MockHttpTests()
        {
            var sb = new StringBuilder();
            int expectedLength = 0;

            foreach (string fingerprintText in fingerprintStrings)
            {
                sb.Append(RunTestsForFingerprint(fingerprintText, ref expectedLength));
            }

            sb.Length.Should().Be(expectedLength, sb.ToString());
        }

        private string RunTestsForFingerprint(string fingerprintText, ref int expectedLength)
        {
            var sb = new StringBuilder();
            var fingerprint = new Fingerprint(fingerprintText);
            string secret = fingerprint.Secret;

            sb.AppendLine($"Running tests for: {fingerprintText}");
            expectedLength += sb.Length;

            string keyKind = secret.Contains("_test_") ? "test" : "live production";
            string defaultMessage = $"The detected secret is a {keyKind} secret.";

            var request = new HttpRequestMessage(HttpMethod.Get, StripeApiKeyValidator.StripeUri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);

            string unexpectedResponseMessage = string.Empty;
            string unhandledErrorResponseMessage = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Returns Authorized (OK Status Code)",
                    HttpRequestMessages = new[] { request },
                    HttpResponseMessages = new[] {HttpMockHelper.OKResponse },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = defaultMessage
                },
                new HttpMockTestCase
                {
                    Title = "Returns Unauthorized (Unauthorized Status Code)",
                    HttpRequestMessages = new[] { request },
                    HttpResponseMessages = new[] {HttpMockHelper.UnauthorizedResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = defaultMessage
                },
                new HttpMockTestCase
                {
                    Title = "Returns Unexpected Response Code (InternalServerError Status Code)",
                    HttpRequestMessages = new[] { request },
                    HttpResponseMessages = new[] {HttpMockHelper.InternalServerErrorResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedResponseMessage, HttpStatusCode.InternalServerError),
                    ExpectedMessage = unexpectedResponseMessage
                },
                new HttpMockTestCase
                {
                    Title = "Generates Null Reference Exception",
                    HttpRequestMessages = new List<HttpRequestMessage> { null },
                    HttpResponseMessages = new List<HttpResponseMessage> { null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref unhandledErrorResponseMessage, new NullReferenceException()),
                    ExpectedMessage = unhandledErrorResponseMessage
                },
            };

            var mockHandler = new HttpMockHelper();
            var validator = new StripeApiKeyValidator();

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

                if (testCase.ExpectedMessage != message?.Split(Environment.NewLine)[0])
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedMessage}' but found '{message}'.");
                }
                mockHandler.Clear();
            }

            return sb.ToString();
        }
    }
}
