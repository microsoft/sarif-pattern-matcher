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
    public class SquarePatValidatorTests
    {
        [Fact]
        public void SquarePatValidator_MockHttpTests()
        {
            var testCases = new[]
            {
                new
                {
                    Title = "Testing OK StatusCode",
                    HttpStatusCode = HttpStatusCode.OK,
                    HttpContent = (HttpContent)null,
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = string.Empty
                },
                new
                {
                    Title = "Testing Unauthorized StatusCode",
                    HttpStatusCode = HttpStatusCode.Unauthorized,
                    HttpContent = (HttpContent)null,
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty
                },
                new
                {
                    Title = "Testing NotFound StatusCode",
                    HttpStatusCode = HttpStatusCode.NotFound,
                    HttpContent = (HttpContent)null,
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected HTTP response code was received: 'NotFound'."
                },
            };

            const string fingerprintText = "[secret=secret]";

            var sb = new StringBuilder();
            foreach (var testCase in testCases)
            {
                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                ValidatorHelper.ResetStaticInstance<SquarePatValidator>();
                using var httpClient = new HttpClient(HttpMockHelper.Mock(testCase.HttpStatusCode, testCase.HttpContent));
                SquarePatValidator.Instance.SetHttpClient(httpClient);

                ValidationState currentState = SquarePatValidator.IsValidDynamic(ref fingerprint,
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
