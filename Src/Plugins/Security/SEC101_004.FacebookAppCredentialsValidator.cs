// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class FacebookAppCredentialsValidator : DynamicValidatorBase
    {
        internal const string OAuthUri = "https://graph.facebook.com/oauth/access_token?client_id={0}&client_secret={1}&grant_type=client_credentials";
        internal const string CreatorUri = "https://graph.facebook.com/{0}?access_token={1}&fields=creator_uid";
        internal const string AccountInformationUri = "https://graph.facebook.com/{0}?access_token={1}";

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch id = groups["id"];
            FlexMatch secret = groups["secret"];

            // It is highly likely we do not have a key if we can't
            // find at least one letter and digit within the pattern.
            if (!ContainsDigitAndChar(secret.Value))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Facebook),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string id = fingerprint.Id;
            string secret = fingerprint.Secret;

            ValidationState state = RetrieveInformation(
                string.Format(OAuthUri, id, secret),
                id,
                ref message,
                out AccessTokenObject obj);

            if (state == ValidationState.Authorized)
            {
                return CheckInformation(id, obj.AccessToken, ref message);
            }

            return state;
        }

        private ValidationState CheckInformation(string id, string accessToken, ref string message)
        {
            ValidationState state = RetrieveInformation(
                string.Format(CreatorUri, id, accessToken),
                id,
                ref message,
                out CreatorObject obj);

            if (state == ValidationState.Authorized)
            {
                return RetrieveAccountInformation(id, obj.CreatorUid, accessToken, ref message);
            }

            return state;
        }

        private ValidationState RetrieveAccountInformation(string id, string creatorUid, string accessToken, ref string message)
        {
            ValidationState state = RetrieveInformation(
                string.Format(AccountInformationUri, creatorUid, accessToken),
                id,
                ref message,
                out AccountObject obj);

            if (state == ValidationState.Authorized)
            {
                return ReturnAuthorizedAccess(ref message, asset: $"{obj.Id}:{obj.Name}");
            }

            return state;
        }

        private ValidationState RetrieveInformation<T>(string url, string id, ref string message, out T obj)
        {
            HttpClient httpClient = CreateOrRetrieveCachedHttpClient();
            obj = default;

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);

                using HttpResponseMessage response = httpClient
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case System.Net.HttpStatusCode.OK:
                    {
                        obj = JsonConvert.DeserializeObject<T>(response
                            .Content
                            .ReadAsStringAsync()
                            .GetAwaiter()
                            .GetResult());

                        if (obj == null)
                        {
                            return ValidationState.Unknown;
                        }

                        return ValidationState.Authorized;
                    }

                    case System.Net.HttpStatusCode.BadRequest:
                    case System.Net.HttpStatusCode.InternalServerError:
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: id);
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, asset: id);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: id);
            }
        }

        internal class AccessTokenObject
        {
            [JsonProperty("access_token")]
            public string AccessToken { get; set; }

            [JsonProperty("token_type")]
            public string TokenType { get; set; }
        }

        internal class CreatorObject
        {
            [JsonProperty("creator_uid")]
            public string CreatorUid { get; set; }

            [JsonProperty("id")]
            public string Id { get; set; }
        }

        internal class AccountObject
        {
            [JsonProperty("name")]
            public string Name { get; set; }

            [JsonProperty("id")]
            public string Id { get; set; }
        }
    }
}
