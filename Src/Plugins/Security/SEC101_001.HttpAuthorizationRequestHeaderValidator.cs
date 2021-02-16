// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class HttpAuthorizationRequestHeaderValidator : ValidatorBase
    {
        internal static HttpAuthorizationRequestHeaderValidator Instance;

        static HttpAuthorizationRequestHeaderValidator()
        {
            Instance = new HttpAuthorizationRequestHeaderValidator();
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
            if (!groups.TryGetValue("host", out string host) ||
                !groups.TryGetValue("key", out string key))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint
            {
                Host = host,
                Key = key,
                Resource = (groups.ContainsKey("resource") && groups["resource"] != "/")
                    ? groups["resource"]
                    : string.Empty,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);
            string host = fingerprint.Host;
            string resource = fingerprint.Resource ?? string.Empty;
            string uri = host + resource;

            try
            {
                using HttpClient client = CreateHttpClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Guid.NewGuid().ToString());

                using HttpResponseMessage responseDummy = client
                    .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                if (responseDummy.StatusCode == HttpStatusCode.OK)
                {
                    return nameof(ValidationState.NoMatch);
                }

                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", fingerprint.Key);
                using HttpResponseMessage response = client
                    .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return ReturnAuthorizedAccess(ref message, asset: host);
                    }

                    case HttpStatusCode.Forbidden:
                    case HttpStatusCode.Unauthorized:
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: host);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: host);
            }

            // Since we are just handling 200, 401, and 403.
            // We will return unknown for all the others if that happen.
            return nameof(ValidationState.Unknown);
        }
    }
}
