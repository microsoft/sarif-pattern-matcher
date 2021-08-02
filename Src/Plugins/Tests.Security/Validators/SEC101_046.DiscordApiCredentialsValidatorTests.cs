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
    public class DiscordApiCredentialsValidatorTests
    {
        [Fact]
        public void DiscordApiCredentialsValidator_Test()
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

            DiscordApiCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                          ref message,
                                                          keyValuePairs,
                                                          ref resultLevelKind);
        }

        [Fact]
        public void DiscorddCredentialsValidator_MockHttpTests()
        {
            var testCases = new[]
            {
                new
                {
                    Title = "Testing Valid Credentials",
                    HttpStatusCode = HttpStatusCode.OK,
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The compromised asset is 'a'.",
                    HttpContent = (HttpContent)null,
                },
                new
                {
                    Title = "Testing Invalid Credentials",
                    HttpStatusCode = HttpStatusCode.Unauthorized,
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = "The provided secret is not authorized to access 'a'.",
                    HttpContent = (HttpContent)null,
                },
                new
                {
                    Title = "Testing Unknown Status code",
                    HttpStatusCode = HttpStatusCode.NotFound,
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected HTTP response code was received: 'NotFound'.",
                    HttpContent = (HttpContent)null,
                },
            };
            const string fingerprintText = "[id=a][secret=b]";

            var sb = new StringBuilder();
            foreach (var testCase in testCases)
            {
                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                MockHelper.ResetStaticInstance<SquareCredentialsValidator>();
                using var httpClient = new HttpClient(MockHelper.MockHttpMessageHandler(testCase.HttpStatusCode, testCase.HttpContent));
                DiscordApiCredentialsValidator.Instance.SetHttpClient(httpClient);

                ValidationState currentState = DiscordApiCredentialsValidator.IsValidDynamic(ref fingerprint,
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
