﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class HttpAuthorizationRequestHeaderValidatorTests
    {
        private const string TestScheme = "http";
        private const string TestKey = "somekey";
        private const string TestHost = "www.host.com";
        private const string TestResource = "/some-path";
        private const ValidationState ExpectedValidationState = ValidationState.NoMatch;

        [Fact]
        public void HttpAuthorizationRequestHeaderValidator_Test()
        {
            string fingerprintText = string.Format("[host={0}][resource={1}][scheme={2}][secret={3}]", TestHost, TestResource, TestScheme, TestKey);

            string message = null;
            ResultLevelKind resultLevelKind = default;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            ValidationState actualValidationState = HttpAuthorizationRequestHeaderValidator.IsValidDynamic(ref fingerprint,
                                                                                                           ref message,
                                                                                                           keyValuePairs,
                                                                                                           ref resultLevelKind);
            Assert.Equal(ExpectedValidationState, actualValidationState);
        }

        [Fact]
        public void HttpAuthorizationRequestHeaderValidator_MockHttpTests()
        {
            string fingerprintText = string.Format("[host={0}][resource={1}][scheme={2}][secret={3}]", TestHost, TestResource, TestScheme, TestKey);
            var fingerprint = new Fingerprint(fingerprintText);
            string uri = TestScheme + "://" + TestHost + TestResource;

            using var requestDummy = new HttpRequestMessage(HttpMethod.Get, uri);
            requestDummy.Headers.Authorization = new AuthenticationHeaderValue("Basic", HttpAuthorizationRequestHeaderValidator.TestScanIdentityGuid);

            using var requestReal = new HttpRequestMessage(HttpMethod.Get, uri);
            requestReal.Headers.Authorization = new AuthenticationHeaderValue("Basic", fingerprint.Secret);

            var testCases = new TestCase[] {
            new TestCase
            {
                Title = "Dummy Status OK",
                HttpContents = new List<HttpContent> { null },
                HttpStatusCodes = new List<HttpStatusCode> {HttpStatusCode.OK },
                HttpRequestMessages = new List<HttpRequestMessage> {requestDummy },
                ExpectedMessage = string.Empty,
                ExpectedValidationState = ValidationState.NoMatch
            },
            new TestCase
            {
                Title = "Dummy Status NotFound",
                HttpContents = new List<HttpContent> { null },
                HttpStatusCodes = new List<HttpStatusCode> {HttpStatusCode.NotFound },
                HttpRequestMessages = new List<HttpRequestMessage>{requestDummy },
                ExpectedMessage = string.Empty,
                ExpectedValidationState = ValidationState.NoMatch
            },
             new TestCase
            {
                Title = "Dummy Status NonAuthoritativeInformation",
                HttpContents = new List<HttpContent> { null },
                HttpStatusCodes = new List<HttpStatusCode> {HttpStatusCode.NonAuthoritativeInformation },
                HttpRequestMessages = new List<HttpRequestMessage>{ requestDummy },
                ExpectedMessage = string.Empty,
                ExpectedValidationState = ValidationState.NoMatch
            },
            new TestCase
            {
                Title = "Valid Credentials",
                HttpContents = new List<HttpContent> { null, null },
                HttpStatusCodes = new List<HttpStatusCode> {HttpStatusCode.Unauthorized, HttpStatusCode.OK },
                HttpRequestMessages = new List<HttpRequestMessage>{ requestDummy, requestReal },
                ExpectedMessage = string.Empty,
                ExpectedValidationState = ValidationState.Authorized
            },
             new TestCase
            {
                Title = "Invalid (HttpStatus Forbidden)",
                HttpContents = new List<HttpContent> { null, null },
                HttpStatusCodes = new List<HttpStatusCode> {HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden },
                HttpRequestMessages = new List<HttpRequestMessage>{ requestDummy, requestReal  },
                ExpectedMessage = string.Empty,
                ExpectedValidationState = ValidationState.Unauthorized
            },
              new TestCase
            {
                Title = "Invalid (HttpStatus Unauthorized)",
                 HttpContents = new List<HttpContent> { null, null },
                HttpStatusCodes = new List<HttpStatusCode> {HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized },
                HttpRequestMessages = new List<HttpRequestMessage>{ requestDummy, requestReal  },
                ExpectedMessage = string.Empty,
                ExpectedValidationState = ValidationState.Unauthorized
            },
              new TestCase
            {
                Title = "Dummy and Response Status Codes match (HTTP Status 500)",
                HttpContents = new List<HttpContent> { null, null },
                HttpStatusCodes = new List<HttpStatusCode> {HttpStatusCode.InternalServerError, HttpStatusCode.InternalServerError },
                HttpRequestMessages = new List<HttpRequestMessage>{ requestDummy, requestReal   },
                ExpectedMessage = string.Empty,
                ExpectedValidationState = ValidationState.NoMatch
            },
              new TestCase
            {
                Title = "Unexpected Response Code (Dummy is Unauthorized, Response is 500)",
                 HttpContents = new List<HttpContent> { null, null },
                HttpStatusCodes = new List<HttpStatusCode> {HttpStatusCode.Unauthorized, HttpStatusCode.InternalServerError },
                HttpRequestMessages = new List<HttpRequestMessage>{ requestDummy, requestReal  },
                ExpectedMessage = string.Empty,
                ExpectedValidationState = ValidationState.Unknown
            },
            };

            var mockHandler = new HttpMockHelper();

            var sb = new StringBuilder();
          
            foreach (TestCase testCase in testCases)
            {
                for (int i = 0; i < testCase.HttpStatusCodes.Count; i++)
                {
                    mockHandler.Mock(testCase.HttpRequestMessages[i], testCase.HttpStatusCodes[i], testCase.HttpContents[i]);
                }
                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var keyValuePairs = new Dictionary<string, string>();
                ValidatorHelper.ResetStaticInstance<HttpAuthorizationRequestHeaderValidator>();
                using var httpClient = new HttpClient(mockHandler);
                HttpAuthorizationRequestHeaderValidator.Instance.SetHttpClient(httpClient);

                ValidationState currentState = HttpAuthorizationRequestHeaderValidator.IsValidDynamic(ref fingerprint,
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
