// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    [Collection("MockHttpTests")]
    public class SquareCredentialsValidatorTests
    {
        [Fact]
        public void SquareCredentialsValidator_Test()
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

            SquareCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                      ref message,
                                                      keyValuePairs,
                                                      ref resultLevelKind);
        }

        [Fact]
        public void SquareCredentialsValidator_MockHttpTests()
        {
            var testCases = new[]
            {
                new
                {
                    Title = "Testing unexpected OK StatusCode",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = (HttpContent)null,
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected HTTP response code was received: 'OK'."
                },
                new
                {
                    Title = "Testing Valid credentials",
                    HttpStatusCode = HttpStatusCode.Unauthorized,
                    HttpContent = new StringContent("{\"message\": \"Authorization code not found for app [a]\",\"type\": \"service.not_authorized\"}",
                                                                  Encoding.UTF8,
                                                                  "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The compromised asset is 'a'."
                },
                new
                {
                    Title = "Testing Invalid credentials",
                    HttpStatusCode = HttpStatusCode.Unauthorized,
                    HttpContent = new StringContent("{\n\"message\": \"Not Authorized\",\n\"type\": \"service.not_authorized\"\n}",
                                                    Encoding.UTF8,
                                                    "application/json").As<HttpContent>(),
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = "The provided secret is not authorized to access 'a'."
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

                ConstructorInfo constructor = typeof(SquareCredentialsValidator).GetConstructor(BindingFlags.Static | BindingFlags.NonPublic, null, new Type[0], null);
                constructor.Invoke(null, null);

                using var httpClient = new HttpClient(MockHelper.MockHttpMessageHandler(testCase.HttpStatusCode, testCase.HttpContent));
                SquareCredentialsValidator.Instance.SetHttpClient(httpClient);

                ValidationState currentState = SquareCredentialsValidator.IsValidDynamic(ref fingerprint,
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
