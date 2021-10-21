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
    public class NuGetCredentialsValidatorTests
    {
        private const ValidationState ExpectedValidationState = ValidationState.Unknown;

        [Fact]
        public void NuGetCredentialsValidator_Test()
        {
            string fingerprintText = "[host=<packageSources>\n    <clear />\n    <add key=\"sourceName\" value=\"https://api.nuget.org/v3/index.json\" />\n  </packageSources>][id=username][secret=password]";
            var fingerprint = new Fingerprint(fingerprintText);
            string message = null;
            ResultLevelKind resultLevelKind = default;
            var keyValuePairs = new Dictionary<string, string>();

            var nuGetCredentialsValidator = new NuGetCredentialsValidator();
            ValidationState actualValidationState = nuGetCredentialsValidator.IsValidDynamic(ref fingerprint, ref message, keyValuePairs, ref resultLevelKind);
            Assert.Equal(ExpectedValidationState, actualValidationState);
        }

        [Fact]
        public void ExtractHostsWorksOnCommonFormat()
        {
            string xmlString = @"<packageSources>
    <add key=""nuget.org"" value=""https://api.nuget.org/v3/index.json"" protocolVersion=""3"" />
    <add key = ""Contoso"" value = ""https://contoso.com/packages/"" />

       <add key = ""Test Source"" value = ""c:\packages"" />
      </packageSources> ";

            List<string> hosts = NuGetCredentialsValidator.ExtractHosts(xmlString);

            Assert.Equal(3, hosts.Count);
            Assert.Contains("https://api.nuget.org/v3/index.json", hosts);
            Assert.Contains("https://contoso.com/packages/", hosts);
            Assert.Contains(@"c:\packages", hosts);
        }

        [Fact]
        public void ExtractHostsWorksOnUnCommonFormat()
        {
            string xmlString = @"<packageSources>\nstuff\n<\/packageSources>";

            List<string> hosts = NuGetCredentialsValidator.ExtractHosts(xmlString);

            Assert.Single(hosts);
            Assert.Contains("stuff", hosts);
        }

        [Fact]
        public void NuGetCredentialsValidator_MockHttpTests()
        {
            const string fingerprintText = "[host=https://somehost.com][id=345def][secret=abc123]";
            var fingerprint = new Fingerprint(fingerprintText);

            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;

            var emptyRequest = new HttpRequestMessage(HttpMethod.Get, host);

            var randomKeyRequest = new HttpRequestMessage(HttpMethod.Get, host);
            byte[] randomByteArray = Encoding.ASCII.GetBytes($"{id}:{NuGetCredentialsValidator.RandomGuid}");
            randomKeyRequest.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(randomByteArray));

            using var requestWithCreds = new HttpRequestMessage(HttpMethod.Get, host);
            byte[] byteArray = Encoding.ASCII.GetBytes($"{id}:{secret}");
            requestWithCreds.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

            string nullRefResponseMessage = string.Empty;
            string nullRef2ndResponseMessage = string.Empty;
            string unexpectedResponseCodeMessage = string.Empty;
            string authorizedResponseMessage = string.Empty;
            string forbiddenResponseMessage = string.Empty;
            string unauthorizedResponseMessage = string.Empty;

            // Nuget Validator makes up to 3 requests:
            // 1. No auth header (emptyRequest)
            // 2. Auth header with known *bad* auth (randomKeyRequest)
            // 3. Auth Header with credentials to test (requestWithCreds)
            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Nullref Exception in ValidateWithEmptyAndRandomKey",
                    HttpRequestMessages = new List<HttpRequestMessage> { null },
                    HttpResponseMessages = new List<HttpResponseMessage> { null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref nullRefResponseMessage, new NullReferenceException(), host, id),
                    ExpectedMessage = nullRefResponseMessage
                },
                new HttpMockTestCase
                {
                    Title = "Nullref Exception in IsValidDynamicHelper",
                    HttpRequestMessages = new List<HttpRequestMessage> { emptyRequest, randomKeyRequest, null },
                    HttpResponseMessages = new List<HttpResponseMessage> { HttpMockHelper.UnauthorizedResponse, HttpMockHelper.UnauthorizedResponse, null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref nullRef2ndResponseMessage, new NullReferenceException(), host, id),
                    ExpectedMessage = nullRefResponseMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing No Match (OK on emptyRequest)",
                    HttpRequestMessages = new[] { emptyRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.OKResponse },
                    ExpectedValidationState = ValidationState.NoMatch,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing No Match (NotFound on emptyRequest)",
                    HttpRequestMessages = new[] { emptyRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.NotFoundResponse },
                    ExpectedValidationState = ValidationState.NoMatch,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing No Match (NonAuthoritativeInformation on emptyRequest)",
                    HttpRequestMessages = new[] { emptyRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.NonAuthoritativeInformationResponse },
                    ExpectedValidationState = ValidationState.NoMatch,
                    ExpectedMessage = string.Empty
                },
                //All test cases below this line return "Unauthorized" to the emptyRequest
                new HttpMockTestCase
                {
                    Title = "Testing No Match (OK on randomKeyRequest)",
                    HttpRequestMessages = new[] { emptyRequest, randomKeyRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.UnauthorizedResponse, HttpMockHelper.OKResponse },
                    ExpectedValidationState = ValidationState.NoMatch,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing No Match (NotFound on randomKeyRequest)",
                    HttpRequestMessages = new[] { emptyRequest, randomKeyRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.UnauthorizedResponse, HttpMockHelper.NotFoundResponse },
                    ExpectedValidationState = ValidationState.NoMatch,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing No Match (NonAuthoritativeInformation on randomKeyRequest)",
                    HttpRequestMessages = new[] { emptyRequest, randomKeyRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.UnauthorizedResponse, HttpMockHelper.NonAuthoritativeInformationResponse },
                    ExpectedValidationState = ValidationState.NoMatch,
                    ExpectedMessage = string.Empty
                },
                //All Test Cases Below this line return "Unauthorized" on both emptyRequest and randomKeyRequest
                new HttpMockTestCase
                {
                    Title = "Testing Authorized (OK on requestWithCreds)",
                    HttpRequestMessages = new[] { emptyRequest, randomKeyRequest, requestWithCreds },
                    HttpResponseMessages = new[] { HttpMockHelper.UnauthorizedResponse, HttpMockHelper.UnauthorizedResponse, HttpMockHelper.OKResponse },
                    ExpectedValidationState = ValidatorBase.ReturnAuthorizedAccess(ref authorizedResponseMessage, asset: host, account: id),
                    ExpectedMessage = authorizedResponseMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unauthorized (Forbidden on requestWithCreds)",
                    HttpRequestMessages = new[] { emptyRequest, randomKeyRequest, requestWithCreds },
                    HttpResponseMessages = new[] { HttpMockHelper.UnauthorizedResponse, HttpMockHelper.UnauthorizedResponse, HttpMockHelper.ForbiddenResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnauthorizedAccess(ref forbiddenResponseMessage, asset: host, account: id),
                    ExpectedMessage = forbiddenResponseMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unauthorized (Unauthorized on requestWithCreds)",
                    HttpRequestMessages = new[] { emptyRequest, randomKeyRequest, requestWithCreds },
                    HttpResponseMessages = new[] { HttpMockHelper.UnauthorizedResponse, HttpMockHelper.UnauthorizedResponse, HttpMockHelper.UnauthorizedResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnauthorizedAccess(ref unauthorizedResponseMessage, asset: host, account: id),
                    ExpectedMessage = unauthorizedResponseMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing UnexpectedResponseCode (BadRequest on requestWithCreds)",
                    HttpRequestMessages = new[] { emptyRequest, randomKeyRequest, requestWithCreds },
                    HttpResponseMessages = new[] { HttpMockHelper.UnauthorizedResponse, HttpMockHelper.UnauthorizedResponse, HttpMockHelper.BadRequestResponse },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedResponseCodeMessage, HttpStatusCode.BadRequest, asset: host, account: id),
                    ExpectedMessage = unexpectedResponseCodeMessage
                },
            };

            var sb = new StringBuilder();
            var validator = new NuGetCredentialsValidator();
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
                validator.SetHttpClient(httpClient);
                ValidationState currentState = validator.IsValidDynamic(ref fingerprint,
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
