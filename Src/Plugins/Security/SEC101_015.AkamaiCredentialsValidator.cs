// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class AkamaiCredentialsValidator : ValidatorBase
    {
        internal static AkamaiCredentialsValidator Instance;

        static AkamaiCredentialsValidator()
        {
            Instance = new AkamaiCredentialsValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance, groups);
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

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(Dictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("host", out FlexMatch host) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret) ||
                !groups.TryGetNonEmptyValue("resource", out FlexMatch resource))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                RegionFlexMatch = secret,
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Resource = resource.Value,
                    Host = host.Value,
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

                HttpClient httpClient = CreateHttpClient();
                using var request = new HttpRequestMessage(HttpMethod.Get, $"{host}/ccu/v2/queues/default");
                request.Headers.Authorization = new AuthenticationHeaderValue(
                    $"EG1-HMAC-SHA256",
                    $"{header};signature={signature}");

                using HttpResponseMessage httpResponse = httpClient
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
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
                        return ReturnUnexpectedResponseCode(ref message, httpResponse.StatusCode);
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
