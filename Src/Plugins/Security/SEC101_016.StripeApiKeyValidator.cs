// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class StripeApiKeyValidator : ValidatorBase
    {
        internal static StripeApiKeyValidator Instance;

        static StripeApiKeyValidator()
        {
            Instance = new StripeApiKeyValidator();
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
            if (!groups.TryGetNonEmptyValue("key", out string key))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint
            {
                Key = key,
                Platform = nameof(AssetPlatform.Stripe),
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message,
                                                       ref Dictionary<string, string> options)
        {
            var fingerprint = new Fingerprint(fingerprintText);

            string key = fingerprint.Key;

            string keyKind = key.Contains("_test_") ? "test" : "live production";

            try
            {
                message = $"The detected secret is a {keyKind} key.";

                using HttpClient client = CreateHttpClient();

                client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", key);

                using HttpResponseMessage response = client
                    .GetAsync($"https://api.stripe.com/v1/customers")
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return nameof(ValidationState.AuthorizedError);
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        return nameof(ValidationState.Unauthorized);
                    }

                    default:
                    {
                        message += $" An unexpected response code was returned attempting to " +
                                  $"validate: '{response.StatusCode}'";
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e);
            }

            return nameof(ValidationState.Unknown);
        }
    }
}
