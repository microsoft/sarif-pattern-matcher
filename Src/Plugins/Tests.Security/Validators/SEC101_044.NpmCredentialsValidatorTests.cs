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
    public class NpmCredentialsValidatorTests
    {
        [Fact]
        public void NpmCredentialsValidator_MockHttp()
        {
            const string id = "id";
            const string host = "host";
            const string secret = "secret";
            string uri = $"https://{host}";
            using var requestWithNoCredentials = new HttpRequestMessage(HttpMethod.Get, uri);

            string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", id, secret)));

            using var requestWithCredentials = new HttpRequestMessage(HttpMethod.Get, uri);
            requestWithCredentials.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

            string fingerprintText = $"[host={host}][id={id}][secret={secret}]";

            var authorizedResponse = new HttpResponseMessage(HttpStatusCode.OK);
            var notFoundResponse = new HttpResponseMessage(HttpStatusCode.NotFound);
            var unauthorizedResponse = new HttpResponseMessage(HttpStatusCode.Unauthorized);

            string authorizedMessage = string.Empty, unauthorizedMessage = string.Empty, unexpectedMessage = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Endpoint does not require credential",
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithNoCredentials },
                    HttpResponseMessages = new List<HttpResponseMessage>{ authorizedResponse },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.NoMatch,
                },
                new HttpMockTestCase
                {
                    Title = "Credential is valid",
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithNoCredentials, requestWithCredentials },
                    HttpResponseMessages = new List<HttpResponseMessage>
                    {
                        unauthorizedResponse,
                        authorizedResponse
                    },
                    ExpectedValidationState = ValidatorBase.ReturnAuthorizedAccess(ref authorizedMessage, asset: host, account: id),
                    ExpectedMessage = authorizedMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Credential is invalid",
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithNoCredentials, requestWithCredentials },
                    HttpResponseMessages = new List<HttpResponseMessage>
                    {
                        unauthorizedResponse,
                        unauthorizedResponse
                    },
                    ExpectedValidationState = ValidatorBase.ReturnUnauthorizedAccess(ref unauthorizedMessage, asset: host, account: id),
                    ExpectedMessage = unauthorizedMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Unexpected NotFound StatusCode",
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithNoCredentials, requestWithCredentials },
                    HttpResponseMessages = new List<HttpResponseMessage>
                    {
                        unauthorizedResponse,
                        notFoundResponse
                    },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedMessage,
                                                                                         HttpStatusCode.NotFound,
                                                                                         asset: host,
                                                                                         account: id),
                    ExpectedMessage = unexpectedMessage,
                },
            };

            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();
            var npmCredentialsValidator = new NpmCredentialsValidator();
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
                npmCredentialsValidator.SetHttpClient(httpClient);

                ValidationState currentState = npmCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                                                      ref message,
                                                                                      keyValuePairs,
                                                                                      ref resultLevelKind);

                if (currentState != testCase.ExpectedValidationState)
                {
                    sb.AppendLine($"The test '{testCase.Title}' was expecting '{testCase.ExpectedValidationState}' but found '{currentState}'.");
                }

                if (message != testCase.ExpectedMessage)
                {
                    sb.AppendLine($"The test '{testCase.Title}' was expecting '{testCase.ExpectedMessage}' but found '{message}'.");
                }

                mockHandler.Clear();
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
