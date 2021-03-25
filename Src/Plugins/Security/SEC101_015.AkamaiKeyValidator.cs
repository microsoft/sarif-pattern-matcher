﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class AkamaiKeyValidator : ValidatorBase
    {
        internal static AkamaiKeyValidator Instance;

        static AkamaiKeyValidator()
        {
            Instance = new AkamaiKeyValidator();
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref failureLevel,
                                 ref fingerprint,
                                 ref message);
        }

        public static string IsValidDynamic(ref string fingerprint, ref string message, ref Dictionary<string, string> options)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("key", out string key) ||
                !groups.TryGetNonEmptyValue("pwd", out string pwd) ||
                !groups.TryGetNonEmptyValue("host", out string host))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint()
            {
                Id = id,
                Password = pwd,
                Key = key,
                Host = host,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText, ref string message, ref Dictionary<string, string> options)
        {
            var fingerprint = new Fingerprint(fingerprintText, false);

            string id = fingerprint.Id;
            string key = fingerprint.Key;
            string host = fingerprint.Host;
            string pwd = fingerprint.Password;

            using HttpClient httpClient = CreateHttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                $"EG1-HMAC-SHA256",
                $"client_token={id};access_token={key};timestamp={DateTime.UtcNow:yyyyMMddTHH:mm:ss}+0000;nonce={Guid.NewGuid()};signature={pwd}");

            try
            {
                using HttpResponseMessage httpResponse = httpClient
                    .GetAsync($"{host}/ccu/v2/queues/default")
                    .GetAwaiter()
                    .GetResult();
                switch (httpResponse.StatusCode)
                {
                    case System.Net.HttpStatusCode.OK:
                    {
                        return nameof(ValidationState.AuthorizedError);
                    }

                    default:
                    {
                        message = CreateUnexpectedResponseCodeMessage(httpResponse.StatusCode);
                        return nameof(ValidationState.Unknown);
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
