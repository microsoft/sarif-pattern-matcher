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
    /// Testing SEC101/003.GoogleApiKeyValidator
    /// </summary
    public class GoogleApiKeyValidatorTests
    {
        [Fact]
        public void GoogleApiKeyValidator_MockHttpTests()
        {
            const string uriTemplate = "https://maps.googleapis.com/maps/api/directions/json?key={0}&origin=Seattle&destination=Redmond&units=metric&language=en&mode=driving";

            string secret = "AIzaabc123";
            string fingerprintText = $"[secret={secret}]";
            string uri = string.Format(uriTemplate, secret);
            var awsCredentialsValidator = new GoogleApiKeyValidator();

            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Add("Accept", "application/json");
            string errorMessage = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Returns OK Status",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { new StringContent("{\"routes\" : [{ \"summary\" : \"WA-520 E\" }], \"status\" : \"OK\"}") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Authorized
                },
                new HttpMockTestCase
                {
                    Title = "Returns OK Status with RevokedKey error",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { new StringContent("{\"error_message\":\"Google has disabled the use of APIs from this API project. \",\"routes\":[],\"status\":\"REQUEST_DENIED\"}") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Unauthorized
                },
                new HttpMockTestCase
                {
                    Title = "Returns OK Status with Expired error",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { new StringContent("{\"error_message\":\"The provided API key is expired. \",\"routes\":[],\"status\":\"REQUEST_DENIED\"}") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Expired
                },
                new HttpMockTestCase
                {
                    Title = "Returns OK Status with EnableBilling error",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { new StringContent("{\"error_message\":\"You must enable Billing on the Google Cloud Project at https://console.cloud.google.com/project/_/billing/enable Learn more at https://developers.google.com/maps/gmp-get-started. \",\"routes\":[],\"status\":\"REQUEST_DENIED\"}") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Authorized
                },
                new HttpMockTestCase
                {
                    Title = "Returns OK Status with KeyNotAuthorized error",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { new StringContent("{\"error_message\":\"This API key is not authorized to use this service or API. \",\"routes\":[],\"status\":\"REQUEST_DENIED\"}") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Authorized
                },
                new HttpMockTestCase
                {
                    Title = "Returns OK Status with Invalid error",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { new StringContent("{\"error_message\":\"The provided API key is invalid. \",\"routes\":[],\"status\":\"REQUEST_DENIED\"}") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.NoMatch
                },
                new HttpMockTestCase
                {
                    Title = "Returns OK Status with unknown error",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { new StringContent("{\"error_message\":\"The unknown error. \",\"routes\":[],\"status\":\"UNKNOWN\"}") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    ExpectedMessage = "An unexpected exception was caught attempting to validate api key: UNKNOWN: The unknown error. ",
                    ExpectedValidationState = ValidationState.Unknown
                },
                new HttpMockTestCase
                {
                    Title = "Returns Unexpected Http Status code",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Forbidden },
                    HttpContents = new List<HttpContent> { new StringContent("{ \"error\": \"Forbidden access.\" }") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ request },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref errorMessage, HttpStatusCode.Forbidden),
                    ExpectedMessage = errorMessage,
                },
            };

            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();

            foreach (HttpMockTestCase testCase in testCases)
            {
                for (int i = 0; i < testCase.HttpStatusCodes.Count; i++)
                {
                    mockHandler.Mock(testCase.HttpRequestMessages[i], testCase.HttpStatusCodes[i], testCase.HttpContents[i]);
                }

                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                using var httpClient = new HttpClient(mockHandler);
                awsCredentialsValidator.SetHttpClient(httpClient);

                ValidationState currentState = awsCredentialsValidator.IsValidDynamic(ref fingerprint,
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
