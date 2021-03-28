// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class MailgunApiKeyValidator : ValidatorBase
    {
        internal static MailgunApiKeyValidator Instance = new MailgunApiKeyValidator();

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
            if (!groups.TryGetNonEmptyValue("key", out string key) ||
                !groups.TryGetNonEmptyValue("account", out string account))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint
            {
                Key = key,
                Account = account,
                Platform = nameof(AssetPlatform.Mailgun),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                       ref string message,
                                                       ref Dictionary<string, string> options)
        {
            string key = fingerprint.Key;
            string account = fingerprint.Account;

            try
            {
                using HttpClient client = CreateHttpClient();

                string credentials = $"api:{key}";
                byte[] bytes = Encoding.UTF8.GetBytes(credentials);
                credentials = Convert.ToBase64String(bytes);

                client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Basic", credentials);

                var content = new MultipartFormDataContent();
                content.Add(new StringContent(Guid.NewGuid().ToString()), "subject");

                using HttpResponseMessage response = client
                    .PostAsync($"https://api.mailgun.net/v3/{account}/messages", content)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.BadRequest:
                    {
                        return ReturnAuthorizedAccess(ref message, asset: account);
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: account);
                    }

                    default:
                    {
                        message = $"An unexpected response code was returned attempting to " +
                                  $"validate the '{account}' account: '{response.StatusCode}'";
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: account);
            }

            return ValidationState.Unknown;
        }
    }
}
