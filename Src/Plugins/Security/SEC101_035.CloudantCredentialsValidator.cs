// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Internal
{
    public class CloudantCredentialsValidator : ValidatorBase
    {
        internal static CloudantCredentialsValidator Instance;

        static CloudantCredentialsValidator()
        {
            Instance = new CloudantCredentialsValidator();
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

            // We need uri and neither account nor password, or uri and both account and password.  Use XOR
            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            groups.TryGetNonEmptyValue("resource", out string resource);

            fingerprint = new Fingerprint()
            {
                Id = id,
                Host = host,
                Secret = secret,
                Resource = resource,
                Platform = nameof(AssetPlatform.Cloudant),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                       ref string message,
                                                       ref Dictionary<string, string> options)
        {
            // TODO: Create a unit test for this. https://github.com/microsoft/sarif-pattern-matcher/issues/258

            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;
            string resource = fingerprint.Resource ?? id;

            string uri = null;

            try
            {
                string asset = $"{resource}.{host}";
                uri = $"https://{asset}";

                var handler = new HttpClientHandler();
                handler.Credentials = new NetworkCredential(id, secret);

                using var client = new HttpClient(handler)
                {
                    BaseAddress = new Uri(uri),
                };

                using (HttpResponseMessage response = client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult())
                {
                    string text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        return ReturnAuthorizedAccess(ref message, asset);
                    }

                    if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
                    {
                        return ReturnUnknownHost(ref message, asset);
                    }

                    message = CreateUnexpectedResponseCodeMessage(response.StatusCode, uri);
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: uri);
            }

            return ValidationState.Unknown;
        }
    }
}
