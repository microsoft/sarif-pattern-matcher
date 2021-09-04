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
    public class SlackWebhookValidatorTests
    {
        [Fact]
        public void SlackWebhookValidatorMockHttp_Test()
        {

            const string id = "6789";
            const string secret = "xoxb-1234";
            string uri = $"https://hooks.slack.com/services/{id}/{secret}";
            string fingerprintText = $"[id={id}][secret={secret}]";
            string TestGuid = Guid.NewGuid().ToString();

            var webhookRequest = new HttpRequestMessage(HttpMethod.Post, uri);
            webhookRequest.Content = new StringContent(TestGuid, Encoding.UTF8, "application/json");

            var slackWebhookValidator = new SlackWebhookValidator();
            string tmpMessage = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing Valid Webhook",
                    // We authenticated and a bogus payload was read
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.BadRequest },
                    HttpRequestMessages = new List<HttpRequestMessage>() { webhookRequest },
                    HttpContents = new List<HttpContent>() { null },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing Invalid App id",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.NotFound },
                    HttpRequestMessages = new List<HttpRequestMessage>() { webhookRequest },
                    HttpContents = new List<HttpContent>() { null },
                    ExpectedValidationState = ValidationState.UnknownHost,
                    ExpectedMessage = "The specified Slack app could not be found."
                },
                new HttpMockTestCase
                {
                    Title = "Testing Invalid Webhook",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.Forbidden },
                    HttpRequestMessages = new List<HttpRequestMessage>() { webhookRequest },
                    HttpContents = new List<HttpContent>() { null },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unexpected Response Code",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.InternalServerError },
                    HttpRequestMessages = new List<HttpRequestMessage>() { webhookRequest },
                    HttpContents = new List<HttpContent>() { null },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref tmpMessage, HttpStatusCode.InternalServerError, account: id),
                    ExpectedMessage = tmpMessage
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
                keyValuePairs["TestGuid"] = TestGuid;

                using var httpClient = new HttpClient(mockHandler);
                slackWebhookValidator.SetHttpClient(httpClient);

                ValidationState currentState = slackWebhookValidator.IsValidDynamic(ref fingerprint,
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
