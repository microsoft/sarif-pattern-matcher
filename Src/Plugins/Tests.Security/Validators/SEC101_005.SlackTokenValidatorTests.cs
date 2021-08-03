// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class SlackTokenValidatorTests
    {
        [Fact]
        public void SlackTokenValidator_Test()
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

            SlackTokenValidator.IsValidDynamic(ref fingerprint,
                                               ref message,
                                               keyValuePairs,
                                               ref resultLevelKind);
        }

        [Fact]
        public void SlackTokenValidatorMockHttp_Test()
        {
            var testCases = new[]
            {
                new
                {
                    Title = "Testing Valid Token",
                    HttpStatusCode = HttpStatusCode.OK,
                    // In all cases JSON is formatted in the order receieved from slack.
                    HttpContent = new StringContent("{\"ok\": true," +
                                                    "\"url\": \"testteam.slack.com\"," +
                                                    "\"team\":\"test team\"," +
                                                    "\"user\": \"testbot\"," +
                                                    "\"team_id\": \"1234ABCD\"," +
                                                    "\"user_id\": \"5678EFGH\"," +
                                                    "\"bot_id\": \"0987ZYXV\"," +
                                                    "\"is_enterprise_install\": false}",
                                                    Encoding.UTF8,
                                                    "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "Bot token (id: 0987ZYXV) was authenticated to channel 'testteam.slack.com',  team 'test team' (id: 1234ABCD),  user 'testbot' (id: 5678EFGH).  The token is not associated with an enterprise installation."
                },
                new
                {
                    Title = "Testing Invalid Token",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent("{\"ok\": true," +
                                                    "\"error\": \"invalid_auth\"}",
                                                    Encoding.UTF8,
                                                    "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = "The provided secret is not authorized to access 'xoxb-1234'."
                },
                new
                {
                    Title = "Testing Revoked Token",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent("{\"ok\": true," +
                                                    "\"error\": \"token_revoked\"}",
                                                     Encoding.UTF8,
                                                     "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Expired,
                    ExpectedMessage = string.Empty
                },
                new
                {
                    Title = "Testing Inactive Token",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent("{\"ok\": true," +
                                                    "\"error\": \"account_inactive\"}",
                                                    Encoding.UTF8,
                                                    "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Expired,
                    ExpectedMessage = string.Empty
                },
                new
                {
                    Title = "Testing Unknown Slack Error",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = new StringContent("{\"ok\": true," +
                                                    "\"error\": \"unknown_error\"}",
                                                    Encoding.UTF8,
                                                    "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected error was observed attempting to validate token: 'unknown_error'"
                },
                new
                {
                    Title = "Testing Unknown Status code",
                    HttpStatusCode = HttpStatusCode.InternalServerError,
                    HttpContent = (HttpContent)null,
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected HTTP response code was received: 'InternalServerError'.",
                },
            };

            const string fingerprintText = "[secret=xoxb-1234]";

            var sb = new StringBuilder();
            foreach (var testCase in testCases)
            {
                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                MockHelper.ResetStaticInstance<SlackTokenValidator>();
                using var httpClient = new HttpClient(MockHelper.MockHttpMessageHandler(testCase.HttpStatusCode, testCase.HttpContent));
                SlackTokenValidator.Instance.SetHttpClient(httpClient);

                ValidationState currentState = SlackTokenValidator.IsValidDynamic(ref fingerprint,
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
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
