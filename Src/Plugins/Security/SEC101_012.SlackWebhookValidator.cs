// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SlackWebhookValidator : ValidatorBase
    {
        internal static SlackWebhookValidator Instance;

        static SlackWebhookValidator()
        {
            Instance = new SlackWebhookValidator();
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

            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint
            {
                Id = id,
                Secret = secret,
                Platform = nameof(AssetPlatform.Slack),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options)
        {
            string id = fingerprint.Id;
            string secret = fingerprint.Secret;
            string uri = $"https://hooks.slack.com/services/{id}/{secret}";

            using HttpClient client = CreateHttpClient();

            string payload = Guid.NewGuid().ToString();
            var content = new StringContent(payload, Encoding.UTF8, "application/json");

            try
            {
                using HttpResponseMessage response =
                    client.PostAsync(uri, content).GetAwaiter().GetResult();

                HttpStatusCode status = response.StatusCode;

                switch (status)
                {
                    case HttpStatusCode.BadRequest:
                    {
                        // We authenticated and our bogus payload was read.
                        return ValidationState.AuthorizedError;
                    }

                    case HttpStatusCode.NotFound:
                    {
                        // The slack app itself could not be found.
                        message = "The specified Slack app could not be found.";
                        return ValidationState.UnknownHost;
                    }

                    case HttpStatusCode.Forbidden:
                    {
                        return ValidationState.Unauthorized;
                    }

                    default:
                    {
                        message = CreateUnexpectedResponseCodeMessage(status);
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
