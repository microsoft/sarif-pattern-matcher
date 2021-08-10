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
    public class CratesApiKeyValidatorTests
    {
        [Fact]
        public void CratesApiKeyValidator_Test()
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

            CratesApiKeyValidator.IsValidDynamic(ref fingerprint,
                                                 ref message,
                                                 keyValuePairs,
                                                 ref resultLevelKind);
        }

        [Fact]
        public void DiscordCredentialsValidator_MockHttpTests()
        {
            string unknownMessage = null;
            const string fingerprintText = "[secret=b]";
            ValidatorBase.ReturnUnexpectedResponseCode(ref unknownMessage, HttpStatusCode.NotFound);

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing Valid Credentials",
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.OK },
                    ExpectedValidationState = ValidationState.Authorized,
                },
                new HttpMockTestCase
                {
                    Title = "Testing Invalid Credentials",
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.Forbidden },
                    ExpectedValidationState = ValidationState.Unauthorized,
                },
                new HttpMockTestCase
                {
                    Title = "Testing NotFound StatusCode",
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.NotFound },
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = unknownMessage
                },
            };

            var sb = new StringBuilder();
            foreach (HttpMockTestCase testCase in testCases)
            {
                string message = null;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                ValidatorHelper.ResetStaticInstance<CratesApiKeyValidator>();

                using var httpClient = new HttpClient(HttpMockHelper.Mock(testCase.HttpStatusCodes[0], null));
                CratesApiKeyValidator.Instance.SetHttpClient(httpClient);

                ValidationState currentState = CratesApiKeyValidator.IsValidDynamic(ref fingerprint,
                                                                                    ref message,
                                                                                    keyValuePairs,
                                                                                    ref resultLevelKind);
                if (currentState != testCase.ExpectedValidationState)
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedValidationState}' but found '{currentState}'.");
                }

                if (message != testCase.ExpectedMessage)
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedMessage}' but found '{message}'.");
                }
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
