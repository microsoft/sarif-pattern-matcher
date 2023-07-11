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
    public class HttpAuthorizationRequestHeaderValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
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
                Fingerprint = new Fingerprint
                {
                    Host = host.Value,
                    Path = path?.Value,
                    Scheme = scheme.Value,
                    Secret = secret.Value,
                },
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string host = fingerprint.Host;
            string scheme = fingerprint.Scheme ?? "https";
            string path = fingerprint.Path ?? string.Empty;
            string uri = scheme + "://" + host + path;

            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();
                using var requestDummy = new HttpRequestMessage(HttpMethod.Get, uri);

                if (options.TryGetValue("TestGuid", out string testingGuid))
                {
                    requestDummy.Headers.Authorization = new AuthenticationHeaderValue("Basic", testingGuid);
                }
                else
                {
                    requestDummy.Headers.Authorization = new AuthenticationHeaderValue("Basic", this.ScanIdentityGuid);
                }

                using HttpResponseMessage responseDummy = client.ReadResponseHeaders(requestDummy);

                if (responseDummy.StatusCode == HttpStatusCode.OK ||
                    responseDummy.StatusCode == HttpStatusCode.NotFound ||
                    responseDummy.StatusCode == HttpStatusCode.NonAuthoritativeInformation)
                {
                    return ValidationState.NoMatch;
                }

                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", fingerprint.Secret);
                using HttpResponseMessage response = client.ReadResponseHeaders(request);

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
