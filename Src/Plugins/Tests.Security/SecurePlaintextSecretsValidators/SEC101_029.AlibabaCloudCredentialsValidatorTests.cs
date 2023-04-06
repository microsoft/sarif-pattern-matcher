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

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/029.AlibabaCloudCredentialsValidator
    /// </summary>
    public class AlibabaCloudCredentialsValidatorTests
    {
        [Fact]
        public void AlibabaCloudCredentialsKeyValidator_MockedDynamicAnalysis()
        {
            string unknownStatusCodeMessage = null, unhandledExceptionMessage = null;

            var fingerprint = new Fingerprint("[id=LTAIid1][secret=abc]");
            var expectedFingerprint = new Fingerprint("[id=LTAIid1][secret=abc]");
            string asset = expectedFingerprint.Secret.Truncate();
            string uri = string.Format(AlibabaCloudCredentialsValidator.UriTemplate);

            DateTime timestamp = DateTime.UtcNow;
            string nonce = Guid.NewGuid().ToString();
            using var defaultRequest = new HttpRequestMessage(HttpMethod.Get, uri);
            var signer = new AlibabaEcsRequestSigner(timestamp, nonce);
            signer.SignRequest(defaultRequest, fingerprint.Id, fingerprint.Secret);

            ValidatorBase.ReturnUnexpectedResponseCode(ref unknownStatusCodeMessage, HttpStatusCode.InternalServerError);
            ValidatorBase.ReturnUnhandledException(ref unhandledExceptionMessage, new NullReferenceException(), asset);

            var okResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"RequestId\":\"7D066872-0FE5-5BC6-9A17-FF7D5A7479B4\",\"Regions\":{\"Region\":[{\"RegionId\":\"us-east-1\",\"RegionEndpoint\":\"ecs.us-east-1.aliyuncs.com\",\"LocalName\":\"美国（弗吉尼亚）\"}]}}")
            };

            var testCases = new HttpMockTestCase[]
            {
                new  HttpMockTestCase
                {
                    Title = "Auth request returns HttpStatusCode.OK",
                    ExpectedValidationState = ValidationState.Authorized,
                    HttpRequestMessages = new List<HttpRequestMessage> { defaultRequest },
                    HttpResponseMessages = new [] { okResponse },
                    ExpectedMessage = string.Empty,
                    ExpectedFingerprint = expectedFingerprint,
                },
                new  HttpMockTestCase
                {
                    Title = "Auth request returns HttpStatusCode.Forbidden",
                    ExpectedValidationState = ValidationState.Unauthorized,
                    HttpRequestMessages = new List<HttpRequestMessage> { defaultRequest },
                    HttpResponseMessages = new [] { HttpMockHelper.ForbiddenResponse },
                    ExpectedMessage = string.Empty,
                    ExpectedFingerprint = expectedFingerprint,
                },
                new  HttpMockTestCase
                {
                    Title = "Auth request returns HttpStatusCode.BadRequest",
                    HttpRequestMessages = new List<HttpRequestMessage> { defaultRequest },
                    HttpResponseMessages = new [] { HttpMockHelper.BadRequestResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty,
                    ExpectedFingerprint = expectedFingerprint,
                },
                new  HttpMockTestCase
                {
                    Title = "Auth request returns HttpStatusCode.NotFound",
                    HttpRequestMessages = new List<HttpRequestMessage> { defaultRequest },
                    HttpResponseMessages = new [] { HttpMockHelper.NotFoundResponse },
                    ExpectedValidationState = ValidationState.Unauthorized,
                    ExpectedMessage = string.Empty,
                    ExpectedFingerprint = expectedFingerprint,
                },
                new  HttpMockTestCase
                {
                    Title = "Unexpected Response Code (500 internal server error)",
                    HttpRequestMessages = new List<HttpRequestMessage> { defaultRequest },
                    HttpResponseMessages = new [] { HttpMockHelper.InternalServerErrorResponse },
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = unknownStatusCodeMessage,
                },
                new  HttpMockTestCase
                {
                    Title = "Null Reference Exception",
                    HttpRequestMessages = new List<HttpRequestMessage> { null },
                    HttpResponseMessages = new List<HttpResponseMessage> { null },
                    ExpectedValidationState = ValidationState.Unknown,
                    ExpectedMessage = unhandledExceptionMessage
                }
            };

            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();
            var validator = new AlibabaCloudCredentialsValidator
            {
                Timestamp = timestamp,
                SignatureNonce = nonce,
            };

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
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedValidationState}' but found '{currentState}'.");
                }

                if (testCase.ExpectedMessage != message?.Split(Environment.NewLine)[0])
                {
                    sb.AppendLine($"The test case '{testCase.Title}' was expecting '{testCase.ExpectedMessage}' but found '{message}'.");
                }

                mockHandler.Clear();
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
