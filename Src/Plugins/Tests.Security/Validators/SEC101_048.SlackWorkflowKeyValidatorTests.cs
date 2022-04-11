﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.SecurePlaintextSecretsValidators;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/048.SlackWorkflowKeyValidator
    /// </summary>
    public class SlackWorkflowKeyValidatorTests
    {
        [Fact]
        public void SlackWorkflowValidator_MockHttpTests()
        {
            const string fingerprintText = "[id=id][secret=secret]";
            var fingerprint = new Fingerprint(fingerprintText);

            string unexpectedResponseCodeMessage = null, nullRefResponseMessage = null;
            string id = fingerprint.Id;
            string secret = fingerprint.Secret;
            string uri = string.Format(SlackWorkflowKeyValidator.WorkflowUri, id, secret);

            var request = new HttpRequestMessage(HttpMethod.Post, uri);

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Raise NullReferenceException",
                    HttpRequestMessages = new List<HttpRequestMessage>{ null },
                    HttpResponseMessages = new List<HttpResponseMessage>{ null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref nullRefResponseMessage, new NullReferenceException()),
                    ExpectedMessage = nullRefResponseMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid Credentials",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.OKResponse },
                    ExpectedValidationState = ValidationState.Authorized,
                },
                new HttpMockTestCase
                {
                    Title = "Testing invalid webhook (NotFound StatusCode)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.NotFoundResponse },
                    ExpectedValidationState = ValidationState.UnknownHost,
                    ExpectedMessage = "The specified Slack workflow key could not be found."
                },
                new HttpMockTestCase
                {
                    Title = "Testing Invalid Credentials (Forbidden StatusCode)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.ForbiddenResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                },
                new HttpMockTestCase
                {
                    Title = "Testing Invalid Credentials (Unauthorized StatusCode)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.UnauthorizedResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                },
                new HttpMockTestCase
                {
                    Title = "Testing NotFound StatusCode",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.InternalServerErrorResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedResponseCodeMessage, HttpStatusCode.InternalServerError),
                    ExpectedMessage = unexpectedResponseCodeMessage
                },
            };

            var sb = new StringBuilder();
            var httpMock = new HttpMockHelper();
            var validator = new SlackWorkflowKeyValidator();
            foreach (HttpMockTestCase testCase in testCases)
            {
                string message = null;
                ResultLevelKind resultLevelKind = default;
                var keyValuePairs = new Dictionary<string, string>();

                httpMock.Mock(testCase.HttpRequestMessages[0], testCase.HttpResponseMessages[0]);
                using var httpClient = new HttpClient(httpMock);
                validator.SetHttpClient(httpClient);

                ValidationState currentState = validator.IsValidDynamic(ref fingerprint,
                                                                        ref message,
                                                                        keyValuePairs,
                                                                        ref resultLevelKind);
                if (currentState != testCase.ExpectedValidationState)
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedValidationState}' but found '{currentState}'.");
                }

                if (message != testCase.ExpectedMessage)
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedMessage}' but found '{message}'.");
                }

                httpMock.Clear();
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
