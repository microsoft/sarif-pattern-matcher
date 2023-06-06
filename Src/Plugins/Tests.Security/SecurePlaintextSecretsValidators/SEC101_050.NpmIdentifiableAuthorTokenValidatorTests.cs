// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/050.NpmIdentifiableAuthorTokenValidator
    /// </summary>
    public class NpmIdentifiableAuthorTokenValidatorTests
    {
        [Fact]
        public void NpmIdentifiableAuthorTokenValidator_MockHttpTests()
        {
            HttpMockTestCase[] testCases = NpmLegacyAuthorTokenTestCases.CreateTestCases(out Fingerprint fingerprint);
            var sb = new StringBuilder();
            var NpmIdentifiableAuthorTokenValidator = new NpmIdentifiableAuthorTokenValidator();
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
                NpmIdentifiableAuthorTokenValidator.SetHttpClient(httpClient);
                ValidationState currentState = NpmIdentifiableAuthorTokenValidator.IsValidDynamic(ref fingerprint,
                                                                                                  ref message,
                                                                                                  keyValuePairs,
                                                                                                  ref resultLevelKind);

                if (currentState != testCase.ExpectedValidationState)
                {
                    sb.AppendLine($"The test '{testCase.Title}' was expecting '{testCase.ExpectedValidationState}' but found '{currentState}'.");
                }

                if (testCase.ExpectedMessage != message?.Split(Environment.NewLine)[0])
                {
                    sb.AppendLine($"The test '{testCase.Title}' was expecting '{testCase.ExpectedMessage}' but found '{message}'.");
                }

                mockHandler.Clear();
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
