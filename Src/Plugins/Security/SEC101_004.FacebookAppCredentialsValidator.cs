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
    public class FacebookAppCredentialsValidator : ValidatorBase
    {
        internal static FacebookAppCredentialsValidator Instance;

        static FacebookAppCredentialsValidator()
        {
            Instance = new FacebookAppCredentialsValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 groups);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  options,
                                  ref resultLevelKind);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             Dictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetValue("id", out FlexMatch id) ||
                !groups.TryGetValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                RegionFlexMatch = secret,
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
                                                                Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string id = fingerprint.Id;
            string secret = fingerprint.Secret;

            ValidationState state = RetrieveInformation(
                $"https://graph.facebook.com/oauth/access_token?client_id={id}&client_secret={secret}&grant_type=client_credentials",
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
                $"https://graph.facebook.com/{id}?access_token={accessToken}&fields=creator_uid",
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
                $"https://graph.facebook.com/{creatorUid}?access_token={accessToken}",
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
            using HttpClient httpClient = CreateHttpClient();
            obj = default;

            try
            {
                using HttpResponseMessage response = httpClient.GetAsync(url).GetAwaiter().GetResult();

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
                        message = CreateUnexpectedResponseCodeMessage(response.StatusCode, asset: id);
                        return ValidationState.Unknown;

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
