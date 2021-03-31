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
    public class StripeApiKeyValidator : ValidatorBase
    {
        internal static StripeApiKeyValidator Instance;

        private static readonly HashSet<string> WellKnownKeys = new HashSet<string>
        {
            // This is a well-known secret used as example from stripe website (check examples section). https://stripe.com/payments
            "sk_test_BQokikJOvBiI2HlWgH4olfQ2",
        };

        static StripeApiKeyValidator()
        {
            Instance = new StripeApiKeyValidator();
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
            if (!groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            if (WellKnownKeys.Contains(secret))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint
            {
                Secret = secret,
                Platform = nameof(AssetPlatform.Stripe),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                       ref string message,
                                                       ref Dictionary<string, string> options)
        {
            string secret = fingerprint.Secret;

            string keyKind = secret.Contains("_test_") ? "test" : "live production";

            try
            {
                message = $"The detected secret is a {keyKind} secret.";

                using HttpClient client = CreateHttpClient();

                client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", secret);

                using HttpResponseMessage response = client
                    .GetAsync($"https://api.stripe.com/v1/customers")
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return ValidationState.AuthorizedError;
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        return ValidationState.Unauthorized;
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

            return ValidationState.Unknown;
        }
    }
}
