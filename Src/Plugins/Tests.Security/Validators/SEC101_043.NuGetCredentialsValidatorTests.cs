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
        [Fact]
        public void ExtractHostsWorksOnCommonFormat()
        {
            const string xmlString = @"
            <packageSources>
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
        public void ExtractHostsWorksOnUncommonFormat()
        {
            const string xmlString = @"<packageSources>\nstuff\n<\/packageSources>";

            List<string> hosts = NuGetCredentialsValidator.ExtractHosts(xmlString);

            Assert.Single(hosts);
            Assert.Contains("stuff", hosts);
        }

        [Fact]
        public void NuGetCredentialsValidator_MockHttpTests()
        {
            const string id = "id";
            const string host = "http://host";
            const string secret = "secret";
            const string fakeSecret = "05C89BF5-9DF2-4F8C-8F93-FF3EF66E643D";
            string fingerprintText = $"[host={host}][id={id}][secret={secret}]";

            using var emptyRequest = new HttpRequestMessage(HttpMethod.Get, host);

            using var fakeRequest = new HttpRequestMessage(HttpMethod.Get, host);
            // Making a request with a random generated guid.
            byte[] byteArray = Encoding.ASCII.GetBytes($"{id}:{fakeSecret}");

            fakeRequest.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

            using var realRequest = new HttpRequestMessage(HttpMethod.Get, host);
            // Making a request with a random generated guid.
            byteArray = Encoding.ASCII.GetBytes($"{id}:{secret}");

            realRequest.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

            string unknownMessage = string.Empty;
            string authorizedMessage = string.Empty;
            string unauthorizedMessage = string.Empty;

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing OK StatusCode (host does not need secret)",
                    HttpContents = new List<HttpContent> { null },
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage> { emptyRequest },
                    ExpectedValidationState = ValidationState.NoMatch,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unauthorized -> OK (host got unauthorized)",
                    HttpContents = new List<HttpContent> { null, null },
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Unauthorized, HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage> { emptyRequest, fakeRequest },
                    ExpectedValidationState = ValidationState.NoMatch,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unauthorized -> Unauthorized -> OK (real credential)",
                    HttpContents = new List<HttpContent> { null, null, null },
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage> { emptyRequest, fakeRequest, realRequest },
                    ExpectedValidationState = ValidatorBase.ReturnAuthorizedAccess(ref authorizedMessage, asset: host, account: id),
                    ExpectedMessage = authorizedMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unauthorized -> Unauthorized -> Unauthorized (invalid credential)",
                    HttpContents = new List<HttpContent> { null, null, null },
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized },
                    HttpRequestMessages = new List<HttpRequestMessage> { emptyRequest, fakeRequest, realRequest },
                    ExpectedValidationState = ValidatorBase.ReturnUnauthorizedAccess(ref unauthorizedMessage, asset: host, account: id),
                    ExpectedMessage = unauthorizedMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unauthorized -> Unauthorized -> PaymentRequired",
                    HttpContents = new List<HttpContent> { null, null, null },
                    HttpStatusCodes = new List<HttpStatusCode> { HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.PaymentRequired },
                    HttpRequestMessages = new List<HttpRequestMessage> { emptyRequest, fakeRequest, realRequest },
                    ExpectedValidationState = ValidatorBase.ReturnUnknownAuthorization(ref unknownMessage, asset: host, account: id),
                    ExpectedMessage = unknownMessage
                },
            };

            var sb = new StringBuilder();
            var httpMockHelper = new HttpMockHelper();
            var nugetCredentialsValidadtor = new NuGetCredentialsValidator();
            foreach (HttpMockTestCase testCase in testCases)
            {
                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                for (int i = 0; i < testCase.HttpStatusCodes.Count; i++)
                {
                    httpMockHelper.Mock(testCase.HttpRequestMessages[i], testCase.HttpStatusCodes[i], testCase.HttpContents[i]);
                }

                using var httpClient = new HttpClient(httpMockHelper);
                nugetCredentialsValidadtor.SetHttpClient(httpClient);

                ValidationState currentState = nugetCredentialsValidadtor.IsValidDynamic(ref fingerprint,
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

                httpMockHelper.Clear();
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
