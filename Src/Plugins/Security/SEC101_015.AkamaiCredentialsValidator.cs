// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class AkamaiCredentialsValidator : ValidatorBase
    {
        internal static AkamaiCredentialsValidator Instance;

        static AkamaiCredentialsValidator()
        {
            Instance = new AkamaiCredentialsValidator();
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
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options,
                                  ref resultLevelKind);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string message,
                                                               out ResultLevelKind resultLevelKind,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;
            resultLevelKind = default;

            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("secret", out string secret) ||
                !groups.TryGetNonEmptyValue("resource", out string resource))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint()
            {
                Id = id,
                Secret = secret,
                Resource = resource,
                Host = host,
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;
            string resource = fingerprint.Resource;

            try
            {
                string timestamp = $"{DateTime.UtcNow:yyyyMMddTHH:mm:ss}";
                string header = $"client_token={id};access_token={resource};timestamp={timestamp}+0000;nonce={Guid.NewGuid()}";
                string textToSign = $"EG1-HMAC-SHA256 {header};";

                // Generating signing key based on timestamp.
                using var hmac = new HMACSHA256(Convert.FromBase64String(secret));
                string signingKey = Convert.ToBase64String(hmac.ComputeHash(Convert.FromBase64String(timestamp)));

                // Generating signature based on textToSign and signingKey.
                using var hmacSignature = new HMACSHA256(Convert.FromBase64String(signingKey));
                string signature = Convert.ToBase64String(hmacSignature.ComputeHash(Convert.FromBase64String(textToSign)));

                using HttpClient httpClient = CreateHttpClient();
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                    $"EG1-HMAC-SHA256",
                    $"{header};signature={signature}");

                using HttpResponseMessage httpResponse = httpClient
                    .GetAsync($"{host}/ccu/v2/queues/default")
                    .GetAwaiter()
                    .GetResult();
                switch (httpResponse.StatusCode)
                {
                    case System.Net.HttpStatusCode.OK:
                    {
                        return ValidationState.Authorized;
                    }

                    default:
                    {
                        message = CreateUnexpectedResponseCodeMessage(httpResponse.StatusCode);
                        return ValidationState.Unknown;
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e);
            }
        }
    }
}
