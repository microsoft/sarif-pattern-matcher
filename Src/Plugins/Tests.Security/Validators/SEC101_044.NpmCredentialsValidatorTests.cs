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

            var mockHandler = new HttpMockHelper();

            string fingerprintText = $"[host={host}][id={id}][secret={secret}]";

            var testCases = new TestCase[]
            {
                new TestCase
                {
                    HttpContents = new List<HttpContent>{ null },
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithNoCredentials },
                    ExpectedMessage = string.Empty,
                    Title = "Endpoint does not require credential",
                    ExpectedValidationState = ValidationState.NoMatch,
                },
                new TestCase
                {
                    HttpContents = new List<HttpContent>{ null, null },
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.Unauthorized, HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithNoCredentials, requestWithCredentials },
                    ExpectedMessage = $"The '{id}' account is compromised for '{host}'.",
                    Title = "Credential is valid",
                    ExpectedValidationState = ValidationState.Authorized,
                },
                new TestCase
                {
                    HttpContents = new List<HttpContent>{ null, null },
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithNoCredentials, requestWithCredentials },
                    ExpectedMessage = $"The provided '{id}' account secret is not authorized to access '{host}'.",
                    Title = "Credential is invalid",
                    ExpectedValidationState = ValidationState.Unauthorized,
                },
                new TestCase
                {
                    HttpContents = new List<HttpContent>{ null, null },
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.Unauthorized, HttpStatusCode.NotFound },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithNoCredentials, requestWithCredentials },
                    ExpectedMessage = $"An unexpected HTTP response code was received from '{id}' account on '{host}': NotFound.",
                    Title = "Unexpected NotFound StatusCode",
                    ExpectedValidationState = ValidationState.Unknown,
                },
            };

            var sb = new StringBuilder();
            foreach (TestCase testCase in testCases)
            {
                for (int i = 0; i < testCase.HttpStatusCodes.Count; i++)
                {
                    mockHandler.Mock(testCase.HttpRequestMessages[i], testCase.HttpStatusCodes[i], testCase.HttpContents[i]);
                }

                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                ValidatorHelper.ResetStaticInstance<NpmCredentialsValidator>();
                using var httpClient = new HttpClient(mockHandler);
                NpmCredentialsValidator.Instance.SetHttpClient(httpClient);

                ValidationState currentState = NpmCredentialsValidator.IsValidDynamic(ref fingerprint,
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

        private struct TestCase
        {
            public List<HttpContent> HttpContents { get; set; }
            public List<HttpStatusCode> HttpStatusCodes { get; set; }
            public List<HttpRequestMessage> HttpRequestMessages { get; set; }

            public string Title { get; set; }
            public string ExpectedMessage { get; set; }
            public ValidationState ExpectedValidationState { get; set; }
        }
    }
}
