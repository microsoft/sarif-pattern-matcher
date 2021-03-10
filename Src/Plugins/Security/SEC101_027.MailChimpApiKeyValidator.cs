// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class MailChimpApiKeyValidator : ValidatorBase
    {
        internal static MailChimpApiKeyValidator Instance;

        static MailChimpApiKeyValidator()
        {
            Instance = new MailChimpApiKeyValidator();
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

        public static string IsValidDynamic(ref string fingerprint, ref string message)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message);
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

            fingerprintText = new Fingerprint()
            {
                Key = key,
                Platform = nameof(AssetPlatform.MailChimp),
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);

            string key = fingerprint.Key;

            try
            {
                using HttpClient client = CreateHttpClient();
                string[] keys = key.Split('-');

                client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Basic", keys[0]);

                using HttpResponseMessage response = client
                    .GetAsync($"https://{keys[1]}.api.mailchimp.com/3.0/?fields=account_name", HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        string content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        Account account = JsonConvert.DeserializeObject<Account>(content);

                        return ReturnAuthorizedAccess(ref message, asset: account.AccountName);
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        return nameof(ValidationState.Unauthorized);
                    }

                    default:
                    {
                        message = CreateUnexpectedResponseCodeMessage(response.StatusCode);
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

        private class Account
        {
            [JsonProperty("account_name")]
            public string AccountName { get; set; }
        }
    }
}
