// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class FacebookAppCredentialsValidator : ValidatorBase
    {
        internal static FacebookAppCredentialsValidator Instance;

        static FacebookAppCredentialsValidator()
        {
            Instance = new FacebookAppCredentialsValidator();
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
                                                    ref string message,
                                                    out ResultLevelKind resultLevelKind,
                                                    out Fingerprint fingerprint)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref message,
                                 out resultLevelKind,
                                 out fingerprint);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     ref Dictionary<string, string> options,
                                                     out ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options,
                                  out resultLevelKind);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string message,
                                                               out ResultLevelKind resultLevelKind,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;
            resultLevelKind = default;

            if (!groups.TryGetValue("id", out string id) ||
                !groups.TryGetValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint
            {
                Id = id,
                Secret = secret,
                Platform = nameof(AssetPlatform.Facebook),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options,
                                                                out ResultLevelKind resultLevelKind)
        {
            resultLevelKind = new ResultLevelKind();

            string id = fingerprint.Id;
            string secret = fingerprint.Secret;

            ValidationState state = RetrieveInformation(
                $"https://graph.facebook.com/oauth/access_token?client_id={id}&client_secret={secret}&grant_type=client_credentials",
                id,
                ref message,
                out AccessTokenObject obj);

            if (state == ValidationState.AuthorizedError)
            {
                return CheckInformation(id, obj.AccessToken, ref message);
            }

            return state;
        }

        private ValidationState CheckInformation(string id, string accessToken, ref string message)
        {
            ValidationState state = RetrieveInformation(
                $"https://graph.facebook.com/{id}?access_token={accessToken}&fields=creator_uid",
                id,
                ref message,
                out CreatorObject obj);

            if (state == ValidationState.AuthorizedError)
            {
                return RetrieveAccountInformation(id, obj.CreatorUid, accessToken, ref message);
            }

            return state;
        }

        private ValidationState RetrieveAccountInformation(string id, string creatorUid, string accessToken, ref string message)
        {
            ValidationState state = RetrieveInformation(
                $"https://graph.facebook.com/{creatorUid}?access_token={accessToken}",
                id,
                ref message,
                out AccountObject obj);

            if (state == ValidationState.AuthorizedError)
            {
                return ReturnAuthorizedAccess(ref message, asset: $"{obj.Id}:{obj.Name}");
            }

            return state;
        }

        private ValidationState RetrieveInformation<T>(string url, string id, ref string message, out T obj)
        {
            using HttpClient httpClient = CreateHttpClient();
            obj = default;

            try
            {
                using HttpResponseMessage httpResponse = httpClient.GetAsync(url).GetAwaiter().GetResult();

                switch (httpResponse.StatusCode)
                {
                    case System.Net.HttpStatusCode.OK:
                    {
                        obj = JsonConvert.DeserializeObject<T>(httpResponse
                            .Content
                            .ReadAsStringAsync()
                            .GetAwaiter()
                            .GetResult());

                        if (obj == null)
                        {
                            return ValidationState.Unknown;
                        }

                        return ValidationState.AuthorizedError;
                    }

                    case System.Net.HttpStatusCode.BadRequest:
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: id);
                    }

                    default:
                    {
                        message = $"Unexpected response status code: '{httpResponse.StatusCode}'";
                        return ReturnUnknownAuthorization(ref message, asset: id);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: id);
            }
        }

        private class AccessTokenObject
        {
            [JsonProperty("access_token")]
            public string AccessToken { get; set; }

            [JsonProperty("token_type")]
            public string TokenType { get; set; }
        }

        private class CreatorObject
        {
            [JsonProperty("creator_uid")]
            public string CreatorUid { get; set; }

            [JsonProperty("id")]
            public string Id { get; set; }
        }

        private class AccountObject
        {
            [JsonProperty("name")]
            public string Name { get; set; }

            [JsonProperty("id")]
            public string Id { get; set; }
        }
    }
}
