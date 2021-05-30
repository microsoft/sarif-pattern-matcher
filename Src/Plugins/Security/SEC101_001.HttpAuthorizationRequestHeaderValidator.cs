// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class HttpAuthorizationRequestHeaderValidator : ValidatorBase
    {
        internal static HttpAuthorizationRequestHeaderValidator Instance;

        static HttpAuthorizationRequestHeaderValidator()
        {
            Instance = new HttpAuthorizationRequestHeaderValidator();
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
            if (!groups.TryGetNonEmptyValue("host", out FlexMatch host) ||
                !groups.TryGetNonEmptyValue("scheme", out FlexMatch scheme) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            groups.TryGetNonEmptyValue("path", out FlexMatch path);

            var validationResult = new ValidationResult
            {
                RegionFlexMatch = secret,
                Fingerprint = new Fingerprint
                {
                    Host = host.Value,
                    Path = path?.Value,
                    Scheme = scheme.Value,
                    Secret = secret.Value,
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
            string host = fingerprint.Host;
            string scheme = fingerprint.Scheme ?? "https";
            string path = fingerprint.Path ?? string.Empty;
            string uri = scheme + "://" + host + path;

            try
            {
                HttpClient client = CreateHttpClient();
                using var requestDummy = new HttpRequestMessage(HttpMethod.Get, uri);
                requestDummy.Headers.Authorization = new AuthenticationHeaderValue("Basic", ScanIdentityId);

                using HttpResponseMessage responseDummy = client
                    .SendAsync(requestDummy, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                if (responseDummy.StatusCode == HttpStatusCode.OK ||
                    responseDummy.StatusCode == HttpStatusCode.NotFound ||
                    responseDummy.StatusCode == HttpStatusCode.NonAuthoritativeInformation)
                {
                    return ValidationState.NoMatch;
                }

                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", fingerprint.Secret);
                using HttpResponseMessage response = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
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

                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, asset: host);
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
