// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class FacebookAppCredentialsValidator : ValidatorBase
    {
        internal static FacebookAppCredentialsValidator Instance;

        static FacebookAppCredentialsValidator()
        {
            Instance = new FacebookAppCredentialsValidator();
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return ValidatorBase.IsValidStatic(Instance,
                                               ref matchedPattern,
                                               ref groups,
                                               ref failureLevel,
                                               ref fingerprint,
                                               ref message);
        }

        public static string IsValidDynamic(ref string fingerprint, ref string message)
        {
            return ValidatorBase.IsValidDynamic(Instance,
                                                ref fingerprint,
                                                ref message);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetValue("id", out string id) ||
                !groups.TryGetValue("key", out string key))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint
            {
                Id = id,
                Key = key,
                Platform = nameof(AssetPlatform.Facebook),
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);
            string id = fingerprint.Id;
            string key = fingerprint.Key;

            using var httpClient = new HttpClient();

            try
            {
                using HttpResponseMessage httpResponse = httpClient
                    .GetAsync($"https://graph.facebook.com/oauth/access_token?client_id={id}&client_secret={key}&grant_type=client_credentials")
                    .GetAwaiter()
                    .GetResult();

                switch (httpResponse.StatusCode)
                {
                    case System.Net.HttpStatusCode.OK:
                    {
                        return ReturnAuthorizedAccess(ref message, asset: id);
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
                return ReturnUnhandledException(ref message, e, asset: fingerprint.Id);
            }
        }
    }
}
