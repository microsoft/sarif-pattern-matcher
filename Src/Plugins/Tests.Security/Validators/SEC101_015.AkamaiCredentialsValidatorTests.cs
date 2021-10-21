// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/026.AkamaiCredentialsValidatorTests
    /// </summary>
    public class AkamaiCredentialsValidatorTests
    {
        private const string fingerprintText = "[host=https://nothere][id=whoami][resource=empty][secret=c3VwZXJzZWNyZXR2YWx1ZQ==]";

        [Fact]
        public void AkamaiCredentialsValidatorTests_MockHttpTests()
        {
            Fingerprint fingerprint = new Fingerprint(fingerprintText);

            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;
            string resource = fingerprint.Resource;
            var options = new Dictionary<string, string>();
            options.Add("datetime", DateTime.UtcNow.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            options.Add("scanIdentityGuid", $"{Guid.NewGuid()}");

            DateTime now = DateTime.Parse(options["datetime"]);

            var request = AkamaiCredentialsValidator.GenerateRequestMessage(id, host, secret, resource, options["scanIdentityGuid"], now);

            string nullRefResponseMessage = string.Empty;
            string unexpectedResponseMessage = string.Empty;
            string unhandledResponseMessage = string.Empty;



            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Null Ref Exception",
                    HttpRequestMessages = new List<HttpRequestMessage>{ null },
                    HttpResponseMessages = new List<HttpResponseMessage>{ null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref nullRefResponseMessage, new NullReferenceException()),
                    ExpectedMessage = nullRefResponseMessage,
                },
                new HttpMockTestCase
                {
                     Title = "Authorized (Ok response code)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.OKResponse },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = string.Empty,
                },
                new HttpMockTestCase
                {
                    Title = "Unexpected (BadRequest response code)",
                    HttpRequestMessages = new[]{ request },
                    HttpResponseMessages = new[]{ HttpMockHelper.BadRequestResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedResponseMessage, HttpStatusCode.BadRequest),
                    ExpectedMessage = unexpectedResponseMessage,
                }
            };

            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();
            var validator = new AkamaiCredentialsValidator();

            foreach (HttpMockTestCase testCase in testCases)
            {
                for (int i = 0; i < testCase.HttpRequestMessages.Count; i++)
                {
                    mockHandler.Mock(testCase.HttpRequestMessages[i], testCase.HttpResponseMessages[i]);
                }



                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;

                using var httpClient = new HttpClient(mockHandler);
                validator.SetHttpClient(httpClient);
                ValidationState currentState;

                if (testCase.Title != "Null Ref Exception")
                {
                    currentState = validator.IsValidDynamic(ref fingerprint,
                                                            ref message,
                                                            options,
                                                            ref resultLevelKind);
                }
                else
                {
                    currentState = validator.IsValidDynamic(ref fingerprint,
                                                            ref message,
                                                            new Dictionary<string, string>(),
                                                            ref resultLevelKind);
                }

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
