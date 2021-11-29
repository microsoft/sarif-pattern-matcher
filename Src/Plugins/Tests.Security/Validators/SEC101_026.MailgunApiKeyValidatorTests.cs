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

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/026.MailgunApiCredentialsValidator
    /// </summary>
    public class MailgunApiCredentialsValidatorTests
    {
        private const string fingerprintText = "[id=whoami][secret=supersecretvalue]";

        [Fact]
        public void MailgunApiCredentialsValidatorTests_MockHttpTests()
        {
            var fingerprint = new Fingerprint(fingerprintText);

            string id = fingerprint.Id;
            string secret = fingerprint.Secret;
            string scanIdentityGuid = $"{Guid.NewGuid()}";
            using HttpRequestMessage request = MailgunApiCredentialsValidator.GenerateRequestMessage(id, secret, scanIdentityGuid);

            string nullRefResponseMessage = string.Empty;
            string authorizedResponseMessage = string.Empty;
            string unauthorizedResponseMessage = string.Empty;
            string unexpectedResponseMessage = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Null Ref Exception",
                    HttpRequestMessages = new List<HttpRequestMessage>{ null },
                    HttpResponseMessages = new List<HttpResponseMessage>{ null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref nullRefResponseMessage, new NullReferenceException(), asset: id),
                    ExpectedMessage = nullRefResponseMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Bad Request (Authorized response code)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.BadRequestResponse },
                    ExpectedValidationState = ValidatorBase.ReturnAuthorizedAccess(ref authorizedResponseMessage, asset: id),
                    ExpectedMessage = authorizedResponseMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Unauthorized (Unauthorized response code)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.UnauthorizedResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnauthorizedAccess(ref unauthorizedResponseMessage, asset: id),
                    ExpectedMessage = unauthorizedResponseMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Unexpected (Server error response code)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.InternalServerErrorResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedResponseMessage, HttpStatusCode.InternalServerError),
                    ExpectedMessage = unexpectedResponseMessage,
                }
            };

            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();
            var validator = new MailgunApiCredentialsValidator();

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
