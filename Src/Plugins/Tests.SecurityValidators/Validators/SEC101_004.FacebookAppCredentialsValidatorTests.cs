// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.Helpers;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Newtonsoft.Json;

using Xunit;

using static Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.FacebookAppCredentialsValidator;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.Validators
{
    /// <summary>
    /// Testing SEC101/004.FacebookAppCredentialsValidator
    /// </summary>
    public class FacebookAppCredentialsValidatorTests
    {
        [Fact]
        public void FacebookAppCredentialsValidator_MockHttp()
        {
            const string id = "id";
            const string name = "name";
            const string secret = "secret";
            const string creatorId = "creatorId";
            const string tokenType = "tokenType";
            const string accessToken = "accessToken";

            string fingerprintText = $"[id={id}][secret={secret}]";

            string unauthorizedMessage = null, unexpectedStatusCodeMessage = null, authorizedMessage = null;

            var accessTokenObject = new AccessTokenObject
            {
                TokenType = tokenType,
                AccessToken = accessToken
            };

            var creatorObject = new CreatorObject
            {
                Id = id,
                CreatorUid = creatorId,
            };

            var accountNameObject = new AccountObject
            {
                Id = id,
                Name = name
            };

            string oauthUri = string.Format(OAuthUri, id, secret);
            string creatorUri = string.Format(CreatorUri, id, accessToken);
            string accountInformationUri = string.Format(AccountInformationUri, creatorId, accessToken);

            var oauthRequest = new HttpRequestMessage(HttpMethod.Get, oauthUri);
            var creatorRequest = new HttpRequestMessage(HttpMethod.Get, creatorUri);
            var accountInformationRequest = new HttpRequestMessage(HttpMethod.Get, accountInformationUri);

            var testCases = new HttpMockTestCase[]
            {
                new HttpMockTestCase
                {
                    Title = "Testing Invalid Secret",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.BadRequest },
                    HttpRequestMessages = new List<HttpRequestMessage>() { oauthRequest },
                    HttpContents = new List<HttpContent> { null },
                    ExpectedValidationState = ValidatorBase.ReturnUnauthorizedAccess(ref unauthorizedMessage, asset: id),
                    ExpectedMessage = unauthorizedMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Unknown StatusCode",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.NotFound },
                    HttpRequestMessages = new List<HttpRequestMessage>() { oauthRequest },
                    HttpContents = new List<HttpContent> { null },
                    ExpectedValidationState = ValidatorBase.ReturnUnexpectedResponseCode(ref unexpectedStatusCodeMessage,
                                                                                         HttpStatusCode.NotFound,
                                                                                         asset: id),
                    ExpectedMessage = unexpectedStatusCodeMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid Secret but BadRequest StatusCode",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.OK, HttpStatusCode.BadRequest },
                    HttpRequestMessages = new List<HttpRequestMessage>() { oauthRequest, creatorRequest },
                    HttpContents = new List<HttpContent>
                    {
                        new StringContent(JsonConvert.SerializeObject(accessTokenObject)),
                        null
                    },
                    ExpectedValidationState = ValidatorBase.ReturnUnauthorizedAccess(ref unauthorizedMessage, asset: id),
                    ExpectedMessage = unauthorizedMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid Secret but BadRequest StatusCode",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.BadRequest },
                    HttpRequestMessages = new List<HttpRequestMessage>() { oauthRequest, creatorRequest, accountInformationRequest },
                    HttpContents = new List<HttpContent>
                    {
                        new StringContent(JsonConvert.SerializeObject(accessTokenObject)),
                        new StringContent(JsonConvert.SerializeObject(creatorObject)),
                        null
                    },
                    ExpectedValidationState = ValidatorBase.ReturnUnauthorizedAccess(ref unauthorizedMessage, asset: id),
                    ExpectedMessage = unauthorizedMessage
                },
                new HttpMockTestCase
                {
                    Title = "Testing Valid Secret",
                    HttpStatusCodes = new List<HttpStatusCode>() { HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.OK },
                    HttpRequestMessages = new List<HttpRequestMessage>() { oauthRequest, creatorRequest, accountInformationRequest },
                    HttpContents = new List<HttpContent>
                    {
                        new StringContent(JsonConvert.SerializeObject(accessTokenObject)),
                        new StringContent(JsonConvert.SerializeObject(creatorObject)),
                        new StringContent(JsonConvert.SerializeObject(accountNameObject))
                    },
                    ExpectedValidationState = ValidatorBase.ReturnAuthorizedAccess(ref authorizedMessage, asset: $"{id}:{name}"),
                    ExpectedMessage = authorizedMessage
                },
            };

            var sb = new StringBuilder();
            var mockHandler = new HttpMockHelper();
            var facebookAppCredentialsValidator = new FacebookAppCredentialsValidator();
            foreach (HttpMockTestCase testCase in testCases)
            {
                for (int i = 0; i < testCase.HttpStatusCodes.Count; i++)
                {
                    mockHandler.Mock(testCase.HttpRequestMessages[i], testCase.HttpStatusCodes[i], testCase.HttpContents[i]);
                }

                string message = string.Empty;
                ResultLevelKind resultLevelKind = default;
                var fingerprint = new Fingerprint(fingerprintText);
                var keyValuePairs = new Dictionary<string, string>();

                using var httpClient = new HttpClient(mockHandler);
                facebookAppCredentialsValidator.SetHttpClient(httpClient);

                ValidationState currentState = facebookAppCredentialsValidator.IsValidDynamic(ref fingerprint,
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
                mockHandler.Clear();
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
