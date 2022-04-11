// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.SecurePlaintextSecretsValidators;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Newtonsoft.Json;

using static Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.SecurePlaintextSecretsValidators.NpmAuthorTokenHelper;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class NpmAuthorTokenTestCases
    {
        public static HttpMockTestCase[] CreateTestCases(out Fingerprint fingerprint)
        {
            const string fingerprintText = "[secret=abc123]";
            fingerprint = new Fingerprint(fingerprintText);
            string secret = fingerprint.Secret;

            var defaultRequest = new HttpRequestMessage(HttpMethod.Get, NpmAuthorTokenHelper.Uri);
            defaultRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);

            string readOnlyResponseJson = JsonConvert.SerializeObject(
                    new TokensRoot
                    {
                        Tokens = new List<NpmAuthorTokenHelper.Object>()
                        {
                            new NpmAuthorTokenHelper.Object()
                            {
                                Token = "abc123",
                                Key = "some long key",
                                CidrWhitelist = null,
                                Readonly = true,
                                Automation = false,
                                Created = DateTime.Parse("2020-12-23T15:35:05.255Z"),
                                Updated = DateTime.Parse("2020-12-23T15:35:05.255Z"),
                            }
                        },
                        Total = 1
                    }
                    );

            string automationResponseJson = JsonConvert.SerializeObject(
                    new TokensRoot
                    {
                        Tokens = new List<NpmAuthorTokenHelper.Object>()
                        {
                            new NpmAuthorTokenHelper.Object()
                            {
                                Token = "abc123",
                                Key = "some long key",
                                CidrWhitelist = null,
                                Readonly = false,
                                Automation = true,
                                Created = DateTime.Parse("2020-12-23T15:35:05.255Z"),
                                Updated = DateTime.Parse("2020-12-23T15:35:05.255Z"),
                            }
                        },
                        Total = 1
                    }
                    );

            string publishResponseJson = JsonConvert.SerializeObject(
                    new TokensRoot
                    {
                        Tokens = new List<NpmAuthorTokenHelper.Object>()
                        {
                            new NpmAuthorTokenHelper.Object()
                            {
                                Token = "abc123",
                                Key = "some long key",
                                CidrWhitelist = null,
                                Readonly = false,
                                Automation = false,
                                Created = DateTime.Parse("2020-12-23T15:35:05.255Z"),
                                Updated = DateTime.Parse("2020-12-23T15:35:05.255Z"),
                            }
                        },
                        Total = 1
                    }
                    );

            var validReadOnlyResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(readOnlyResponseJson)
            };

            var validReadAutomationResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(automationResponseJson)
            };

            var validPublishResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(publishResponseJson)
            };

            var validEmptyContentResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(string.Empty)
            };

            string unhandledMessage = string.Empty;
            string notFoundMessage = string.Empty;
            string emptyContentReturnMessage = string.Empty;
            string readonlyContentReturnMessage = string.Empty;
            string automationContentReturnMessage = string.Empty;
            string publishContentReturnMessage = string.Empty;

            var resLevel = new ResultLevelKind();

            return new HttpMockTestCase[]
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
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref notFoundMessage, HttpStatusCode.NotFound),
                    ExpectedMessage = notFoundMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - empty content",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { validEmptyContentResponse },
                    ExpectedValidationState = CheckInformation(string.Empty, secret, ref emptyContentReturnMessage, ref resLevel),
                    ExpectedMessage = emptyContentReturnMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - readonly",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { validReadOnlyResponse },
                    ExpectedValidationState = CheckInformation(readOnlyResponseJson, secret, ref readonlyContentReturnMessage, ref resLevel),
                    ExpectedMessage = readonlyContentReturnMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - automation",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { validReadAutomationResponse},
                    ExpectedValidationState = CheckInformation(automationResponseJson, secret, ref automationContentReturnMessage, ref resLevel),
                    ExpectedMessage = automationContentReturnMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid credentials - publish",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { validPublishResponse },
                    ExpectedValidationState = CheckInformation(publishResponseJson, secret, ref publishContentReturnMessage, ref resLevel),
                    ExpectedMessage = publishContentReturnMessage
                },
                 new  HttpMockTestCase
                {
                    Title = "Null Reference Exception",
                    HttpRequestMessages = new List<HttpRequestMessage> { null },
                    HttpResponseMessages = new List<HttpResponseMessage> { null },
                    ExpectedValidationState = ValidatorBase.ReturnUnhandledException(ref unhandledMessage, new NullReferenceException()),
                    ExpectedMessage = unhandledMessage
                }
            };
        }
    }
}
