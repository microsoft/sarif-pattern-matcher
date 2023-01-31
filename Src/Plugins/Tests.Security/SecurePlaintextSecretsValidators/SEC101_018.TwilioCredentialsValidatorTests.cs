// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/018.TwilioCredentialsValidator
    /// </summary
    public class TwilioCredentialsValidatorTests
    {
        [Fact]
        public void TwilioCredentialsValidator_MockHttpTests()
        {
            const string id = "id";
            const string secret = "secret";
            const string uri = "https://api.twilio.com/2010-04-01/Accounts.json";
            string fingerprintText = $"[id={id}][secret={secret}]";
            string authorizedMessage = string.Empty;
            string unexpectedMessage = string.Empty;
            string unauthorizedMessage = string.Empty;
            string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", id, secret)));

            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing Valid Credentials",
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.OK },
                    ExpectedValidationState = ValidatorBase.ReturnAuthorizedAccess(ref authorizedMessage, asset: id),
                    ExpectedMessage = authorizedMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Invalid Credentials (Unauthorized StatusCode)",
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.Unauthorized },
                    ExpectedValidationState = ValidatorBase.ReturnUnauthorizedAccess(ref unauthorizedMessage, asset: id),
                    ExpectedMessage = unauthorizedMessage,
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid Test Credentials (Forbidden StatusCode)",
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.Forbidden },
                    HttpContents = new List<HttpContent> { new StringContent($@"
{{
    ""code"": 20008, 
    ""message"": ""{TwilioCredentialsValidator.TestCredentialMessage}"", 
    ""more_info"": ""https://www.twilio.com/docs/errors/20008"", 
    ""status"": 403
}}
") },
                    ExpectedValidationState = ValidatorBase.ReturnAuthorizedAccess(ref authorizedMessage, asset: id),
                    ExpectedMessage = authorizedMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing NotFound StatusCode",
                    HttpStatusCodes = new List<HttpStatusCode>{ HttpStatusCode.NotFound },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedMessage, HttpStatusCode.NotFound, asset: id),
                    ExpectedMessage = unexpectedMessage
                },
            };

            var sb = new StringBuilder();
            var httpMockHelper = new HttpMockHelper();
            var twilioCredentialsValidator = new TwilioCredentialsValidator();
            foreach (HttpMockTestCase testCase in testCases)
            {
                string message = null;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                HttpContent content = testCase.HttpContents?[0];
                httpMockHelper.Mock(request, testCase.HttpStatusCodes[0], content);

                using var httpClient = new HttpClient(httpMockHelper);
                twilioCredentialsValidator.SetHttpClient(httpClient);

                ValidationState currentState = twilioCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                                                         ref message,
                                                                                         keyValuePairs,
                                                                                         ref resultLevelKind);
                if (currentState != testCase.ExpectedValidationState)
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedValidationState}' but found '{currentState}'.");
                }

                if (testCase.ExpectedMessage != message?.Split(Environment.NewLine)[0])
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedMessage}' but found '{message}'.");
                }

                httpMockHelper.Clear();
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
