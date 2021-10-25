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

using Newtonsoft.Json;

using Xunit;

using static Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.AzureDevOpsConfiguration.DoNotGrantAllPipelinesAccessToServiceConnectionsValidator;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.AzureDevOpsConfiguration.Validators
{
    /// <summary>
    /// Testing AZC102/190.DoNotGrantAllPipelinesAccessValidator
    /// </summary
    public class DoNotGrantAllPipelinesAccessValidatorTests
    {
        [Fact]
        public void DoNotGrantAllPipelinesAccessValidator_MockHttpTests()
        {
            var fingerprint = new Fingerprint
            {
                Host = "testorg.visualstudio.com",
                Resource = "TestProject",
                Id = "A1B326D6-0D73-4C01-A64B-FB43FE5E2A13",
            };
            string adoPat = "testpat";

            var defaultRequest = new HttpRequestMessage(
                HttpMethod.Get,
                string.Format(PipelinePermissionAPI,
                              fingerprint.Host,
                              fingerprint.Resource,
                              fingerprint.Id));

            defaultRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            defaultRequest.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(
                    ASCIIEncoding.ASCII.GetBytes(
                        string.Format("{0}:{1}", string.Empty, adoPat))));

            string allPipelinesHaveAccessResponseJson = JsonConvert.SerializeObject(
                    new PipelinePermission
                    {
                        AllPipelines = new AllPipeLines
                        {
                            Authorized = true,
                        }
                    });

            string allPipelinesNoAccessJson = JsonConvert.SerializeObject(
                    new PipelinePermission
                    {
                        AllPipelines = null,
                    });

            var ValidAllAcessResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(allPipelinesHaveAccessResponseJson)
            };

            var ValidNoAccessResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(allPipelinesNoAccessJson)
            };

            var ValidEmptyContentResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(string.Empty)
            };

            string unhandledMessage = string.Empty;
            string notFoundMessage = string.Empty;
            string emptyContentReturnMessage = string.Empty;
            string allPipelinesHaveAccessMessage = string.Empty;
            string allPipelinesNoAccessMessage = string.Empty;

            var resLevel = new ResultLevelKind();

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing Unauthorized StatusCode",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.UnauthorizedResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = DoNotGrantAllPipelinesAccessToServiceConnectionsValidator.NotAuthorizedMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Forbidden StatusCode",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { HttpMockHelper.ForbiddenResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = DoNotGrantAllPipelinesAccessToServiceConnectionsValidator.NotAuthorizedMessage
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
                    HttpResponseMessages = new[] { ValidEmptyContentResponse },
                    ExpectedValidationState = VerifyResponse(string.Empty, ref emptyContentReturnMessage),
                    ExpectedMessage = emptyContentReturnMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid API call - allPipelines have access",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { ValidAllAcessResponse },
                    ExpectedValidationState = VerifyResponse(allPipelinesHaveAccessResponseJson, ref allPipelinesHaveAccessMessage),
                    ExpectedMessage = allPipelinesHaveAccessMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid API call - allPipelines no access",
                    HttpRequestMessages = new[] { defaultRequest },
                    HttpResponseMessages = new[] { ValidNoAccessResponse },
                    ExpectedValidationState = VerifyResponse(allPipelinesNoAccessJson, ref allPipelinesNoAccessMessage),
                    ExpectedMessage = allPipelinesNoAccessMessage
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

            var sb = new StringBuilder();
            var pipelineAccessValidator = new DoNotGrantAllPipelinesAccessToServiceConnectionsValidator();
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
                pipelineAccessValidator.SetHttpClient(httpClient);
                SetAdoPat(adoPat);
                ValidationState currentState = pipelineAccessValidator.IsValidDynamic(ref fingerprint,
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
