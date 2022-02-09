// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.Validators
{
    /// <summary>
    /// Testing SEC101/047.CratesApiKeyValidator
    /// </summary>
    public class CratesApiKeyValidatorTests
    {
        [Fact]
        public void CratesApiKeyValidator_MockHttpTests()
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
                    Title = "Testing Invalid Credentials (Forbidden StatusCode)",
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.Forbidden },
                    ExpectedValidationState = ValidationState.Unauthorized,
                },
                new HttpMockTestCase
                {
                    Title = "Testing Invalid Credentials (Unauthorized StatusCode)",
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.Unauthorized },
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
            var cratesApiKeyValidator = new CratesApiKeyValidator();
            foreach (HttpMockTestCase testCase in testCases)
            {
                string message = null;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                using var httpClient = new HttpClient(Helpers.HttpMockHelper.Mock(testCase.HttpStatusCodes[0], null));
                cratesApiKeyValidator.SetHttpClient(httpClient);

                ValidationState currentState = cratesApiKeyValidator.IsValidDynamic(ref fingerprint,
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
