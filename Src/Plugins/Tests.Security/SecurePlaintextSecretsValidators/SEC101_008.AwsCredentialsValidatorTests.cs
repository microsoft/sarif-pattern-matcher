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
    /// Testing SEC101/008.AwsCredentialsValidator
    /// </summary
    public class AwsCredentialsValidatorTests
    {
        [Fact]
        public void AwsCredentialsValidatorValidator_MockHttpTests()
        {
            const string uri = "https://iam.amazonaws.com/";
            const string payload = "Action=GetAccountAuthorizationDetails&Version=2010-05-08";
            const string id = "AKIAABC";
            const string secret = "abc123";
            string fingerprintText = $"[id={id}][secret={secret}]";
            var awsCredentialsValidator = new AwsCredentialsValidator();

            using var requestWithToken = new HttpRequestMessage(HttpMethod.Post, uri);
            requestWithToken.Content = new StringContent(payload, Encoding.UTF8, "application/x-www-form-urlencoded");
            using var requestSigner = new AwsHttpRequestSigner(id, secret);
            requestSigner.SignRequest(requestWithToken, "us-east-1", "iam", awsCredentialsValidator.TimeStamp);

            string errorMessage = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Returns OK Status with policies",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { new StringContent("<GetAccountAuthorizationDetailsResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><GetAccountAuthorizationDetailsResult><Policies><member><PolicyName>AWSSupportServiceRolePolicy</PolicyName></member><member><PolicyName>AWSTrustedAdvisorServiceRolePolicy</PolicyName></member></Policies></GetAccountAuthorizationDetailsResult></GetAccountAuthorizationDetailsResponse>") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedMessage = $"id '{id}' is authorized for role policies 'AWSSupportServiceRolePolicy, AWSTrustedAdvisorServiceRolePolicy'.",
                    ExpectedValidationState = ValidationState.Authorized
                },
                new HttpMockTestCase
                {
                    Title = "Returns OK Status with no policies",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpContents = new List<HttpContent> { new StringContent("<GetAccountAuthorizationDetailsResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><GetAccountAuthorizationDetailsResult><Policies></Policies></GetAccountAuthorizationDetailsResult></GetAccountAuthorizationDetailsResponse>") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedMessage = $"id '{id}' is authorized for role policies ''.",
                    ExpectedValidationState = ValidationState.Authorized
                },
                new HttpMockTestCase
                {
                    Title = "Returns Forbidden with invalid token error",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Forbidden },
                    HttpContents = new List<HttpContent> { new StringContent("<ErrorResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><Error><Code>InvalidClientTokenId</Code> <Message>The security token included in the request is invalid.</Message></Error></ErrorResponse>") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.NoMatch
                },
                new HttpMockTestCase
                {
                    Title = "Returns Forbidden with signature doesn't match error",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Forbidden },
                    HttpContents = new List<HttpContent> { new StringContent("<ErrorResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.NoMatch
                },
                new HttpMockTestCase
                {
                    Title = "Returns Forbidden with access denied error",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Forbidden },
                    HttpContents = new List<HttpContent> { new StringContent("<ErrorResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><Error><Code>AccessDenied</Code> <Message>User: arn:aws:iam::123:user/example.com@@ead123 is not authorized to perform: iam:GetAccountAuthorizationDetails on resource: *</Message></Error></ErrorResponse>") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedMessage = "the compromised AWS identity is 'arn:aws:iam::123:user/example.com@@ead123",
                    ExpectedValidationState = ValidationState.Authorized
                },
                new HttpMockTestCase
                {
                    Title = "Returns Forbidden with unknown error",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Forbidden },
                    HttpContents = new List<HttpContent> { new StringContent("<ErrorResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><Error><Code>Unknown</Code></Error></ErrorResponse>") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedMessage = string.Empty,
                    ExpectedValidationState = ValidationState.Unauthorized
                },
                new HttpMockTestCase
                {
                    Title = "Returns Unexpected Response Code",
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.BadRequest },
                    HttpContents = new List<HttpContent> { new StringContent("<Unexpected/>") },
                    HttpRequestMessages = new List<HttpRequestMessage>{ requestWithToken },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref errorMessage, HttpStatusCode.BadRequest, id),
                    ExpectedMessage = errorMessage
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
