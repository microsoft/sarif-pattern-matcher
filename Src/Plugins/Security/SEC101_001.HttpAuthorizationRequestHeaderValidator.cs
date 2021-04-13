// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class HttpAuthorizationRequestHeaderValidator : ValidatorBase
    {
        internal static HttpAuthorizationRequestHeaderValidator Instance;

        static HttpAuthorizationRequestHeaderValidator()
        {
            Instance = new HttpAuthorizationRequestHeaderValidator();
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
                                                    ref string failureLevel,
                                                    ref string message,
                                                    out Fingerprint fingerprint)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref failureLevel,
                                 ref message,
                                 out fingerprint);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint, ref string message, ref Dictionary<string, string> options)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string failureLevel,
                                                               ref string message,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;

            if (!groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("scheme", out string scheme) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            groups.TryGetNonEmptyValue("path", out string path);

            fingerprint = new Fingerprint
            {
                Host = host,
                Path = path,
                Scheme = scheme,
                Secret = secret,
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options)
        {
            string host = fingerprint.Host;
            string scheme = fingerprint.Scheme ?? "https";
            string path = fingerprint.Path ?? string.Empty;
            string uri = scheme + "://" + host + path;

            try
            {
                using HttpClient client = CreateHttpClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Guid.NewGuid().ToString());

                using HttpResponseMessage responseDummy = client
                    .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                if (responseDummy.StatusCode == HttpStatusCode.OK ||
                    responseDummy.StatusCode == HttpStatusCode.NotFound ||
                    responseDummy.StatusCode == HttpStatusCode.NonAuthoritativeInformation)
                {
                    return ValidationState.NoMatch;
                }

                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", fingerprint.Secret);
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

                    default:
                    {
                        // If this happen, it means it does not matter if we add the authentication.
                        if (responseDummy.StatusCode == response.StatusCode)
                        {
                            return ValidationState.NoMatch;
                        }

                        message = CreateUnexpectedResponseCodeMessage(response.StatusCode, asset: host);
                        return ValidationState.Unknown;
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: host);
            }
        }
    }
}
