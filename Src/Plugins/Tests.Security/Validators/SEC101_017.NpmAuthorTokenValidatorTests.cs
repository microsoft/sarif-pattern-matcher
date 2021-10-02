// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Newtonsoft.Json;

using Xunit;

using static Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.NpmAuthorTokenValidator;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class NpmAuthorTokenValidatorTests
    {
        [Fact]
        public void NpmAuthorTokenValidator_MockHttpTests()
        {
            const string fingerprintText = "[secret=abc123]";
            var fingerprint = new Fingerprint(fingerprintText);

            var defaultRequest = new HttpRequestMessage(HttpMethod.Get, Uri);
            defaultRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", fingerprint.Secret);

            var ValidReadOnlyResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonConvert.SerializeObject(
                    new TokensRoot
                    {
                        Tokens = new List<Object>()
                        {
                            new Object()
                            {
                                Token = "abc123",
                                Key = "some long key",
                                CidrWhitelist = null,
                                Readonly = true,
                                Automation = false,
                                Created = System.DateTime.Parse("2020-12-23T15:35:05.255Z"), 
                                Updated = System.DateTime.Parse("2020-12-23T15:35:05.255Z"),
                            }
                        },
                        Total = 1
                    }
                    ))
            };

            var ValidReadAutomationResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonConvert.SerializeObject(
                    new TokensRoot
                    {
                        Tokens = new List<Object>()
                        {
                            new Object()
                            {
                                Token = "abc123",
                                Key = "some long key",
                                CidrWhitelist = null,
                                Readonly = false,
                                Automation = true,
                                Created = System.DateTime.Parse("2020-12-23T15:35:05.255Z"),
                                Updated = System.DateTime.Parse("2020-12-23T15:35:05.255Z"),
                            }
                        },
                        Total = 1
                    }
                    ))
            };

            var ValidPublishResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonConvert.SerializeObject(
                    new TokensRoot
                    {
                        Tokens = new List<Object>()
                        {
                            new Object()
                            {
                                Token = "abc123",
                                Key = "some long key",
                                CidrWhitelist = null,
                                Readonly = false,
                                Automation = false,
                                Created = System.DateTime.Parse("2020-12-23T15:35:05.255Z"),
                                Updated = System.DateTime.Parse("2020-12-23T15:35:05.255Z"),
                            }
                        },
                        Total = 1
                    }
                    ))
            };

            var ValidEmptyContentResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(string.Empty).As<HttpContent>()
            };


            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing Unauthorized StatusCode",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.UnauthorizedResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing NotFound StatusCode",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.NotFoundResponse },
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = "An unexpected HTTP response code was received: 'NotFound'."
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - empty content",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { ValidEmptyContentResponse },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = string.Empty
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - readonly",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { ValidReadOnlyResponse },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The token has 'read' permissions."
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - automation",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { ValidReadAutomationResponse},
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The token has 'automation' permissions."
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - publish",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { ValidPublishResponse },
                    ExpectedValidationState = ValidationState.Authorized,
                    ExpectedMessage = "The token has 'publish' permissions."
                },
            };

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
