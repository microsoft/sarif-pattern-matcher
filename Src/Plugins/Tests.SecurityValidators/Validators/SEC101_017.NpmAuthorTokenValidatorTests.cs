// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net.Http;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.Validators
{
    /// <summary>
    /// Testing SEC101/017.NpmAuthorTokenValidator
    /// </summary
    public class NpmAuthorTokenValidatorTests
    {
        [Fact]
        public void NpmAuthorTokenValidator_MockHttpTests()
        {
            HttpMockTestCase[] testCases = NpmAuthorTokenTestCases.CreateTestCases(out Fingerprint fingerprint);
            var sb = new StringBuilder();
            var npmAuthorTokenValidator = new NpmAuthorTokenValidator();
            var mockHandler = new HttpMockHelper();

            foreach (HttpMockTestCase testCase in testCases)
            {
                for (int i = 0; i < testCase.HttpRequestMessages.Count; i++)
                {
                    mockHandler.Mock(testCase.HttpRequestMessages[i], testCase.HttpResponseMessages[i]);
                }

                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var keyValuePairs = new Dictionary<string, string>();

                using var httpClient = new HttpClient(mockHandler);
                npmAuthorTokenValidator.SetHttpClient(httpClient);
                ValidationState currentState = npmAuthorTokenValidator.IsValidDynamic(ref fingerprint,
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
    }
}
