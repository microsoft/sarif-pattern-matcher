// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
    /// Testing SEC101/005.SlackApiKeyValidator
    /// </summary
    public class SlackApiKeyValidatorTests
    {
        [Fact]
        public void SlackApiKeyValidator_Test()
        {
            string fingerprintText = "";
            if (string.IsNullOrEmpty(fingerprintText))
            {
                return;
            }

            string message = null;
            ResultLevelKind resultLevelKind = default;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            var SlackApiKey = new SlackApiKeyValidator();
            SlackApiKey.IsValidDynamic(ref fingerprint,
                                               ref message,
                                               keyValuePairs,
                                               ref resultLevelKind);
        }

        [Fact]
        public void SlackApiKeyValidator_MockHttp_Test()
        {
            const string uri = "https://slack.com/api/auth.test";
            const string token = "xoxb-1234";
            string fingerprintText = $"[secret={token}]";
            var dict = new Dictionary<string, string>
            {
                { "token", token },
            };

            var requestWithToken = new HttpRequestMessage(HttpMethod.Post, uri);
            requestWithToken.Content = new FormUrlEncodedContent(dict);

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing Valid Token",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithToken },
                    // In all cases JSON is formatted in the order receieved from slack.
                    HttpContents = new List<HttpContent>() {
                                       new StringContent(@"{""ok"": true,
                                                        ""url"": ""testteam.slack.com"",
                                                        ""team"":""test team"",
                                                        ""user"": ""testbot"",
                                                        ""team_id"": ""1234ABCD"",
                                                        ""user_id"": ""5678EFGH"",
                                                        ""bot_id"": ""0987ZYXV"",
                                                        ""is_enterprise_install"": false}",
                                                        Encoding.UTF8,
                                                        "application/json").As<HttpContent>(),
                                                        },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "Bot token (id: 0987ZYXV) was authenticated to channel 'testteam.slack.com',  team 'test team' (id: 1234ABCD),  user 'testbot' (id: 5678EFGH).  The token is not associated with an enterprise installation."
                },
                new HttpMockTestCase
                {
                    Title = "Testing Invalid Token",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithToken },
                    HttpContents = new List<HttpContent>() {
                                      new StringContent("{\"ok\": true," +
                                                        "\"error\": \"invalid_auth\"}",
                                                        Encoding.UTF8,
                                                        "application/json").As<HttpContent>(),
                                                        },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing Revoked Token",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithToken },
                    HttpContents = new List<HttpContent>() {
                                      new StringContent("{\"ok\": true," +
                                                        "\"error\": \"token_revoked\"}",
                                                         Encoding.UTF8,
                                                         "application/json").As<HttpContent>(),
                                                          },
                    ExpectedValidationState = ValidationState.Expired,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing Inactive Token",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithToken },
                    HttpContents = new List<HttpContent>(){
                                      new StringContent("{\"ok\": true," +
                                                        "\"error\": \"account_inactive\"}",
                                                        Encoding.UTF8,
                                                        "application/json").As<HttpContent>(),
                                                        },
                    ExpectedValidationState = ValidationState.Expired,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unknown Slack Error",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithToken },
                    HttpContents = new List<HttpContent>() {
                                      new StringContent("{\"ok\": true," +
                                                        "\"error\": \"unknown_error\"}",
                                                        Encoding.UTF8,
                                                        "application/json").As<HttpContent>(),
                                                        },
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected error was observed attempting to validate the token: 'unknown_error'"
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unknown Status code",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.InternalServerError },
                    HttpRequestMessages = new List<HttpRequestMessage>() { requestWithToken },
                    HttpContents = new List<HttpContent>() { null },
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected HTTP response code was received: 'InternalServerError'",
                },
            };

            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();
            var SlackApiKey = new SlackApiKeyValidator();
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
                SlackApiKey.SetHttpClient(httpClient);

                ValidationState currentState = SlackApiKey.IsValidDynamic(ref fingerprint,
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
