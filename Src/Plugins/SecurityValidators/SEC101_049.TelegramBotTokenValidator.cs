// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators
{
    public class TelegramBotTokenValidator : DynamicValidatorBase
    {
        // https://core.telegram.org/bots/api#getme
        internal const string GetMeApi = "https://api.telegram.org/bot{0:secret}/getMe";

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch secret = groups["secret"];

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Telegram),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string secret = fingerprint.Secret;
            string uri = string.Format(GetMeApi, secret);

            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();

                using var request = new HttpRequestMessage(HttpMethod.Get, uri);

                using HttpResponseMessage response = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        string content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        ResultRoot resultRoot = JsonConvert.DeserializeObject<ResultRoot>(content);

                        fingerprint.Id = resultRoot?.Result?.Username;
                        message = $"The compromised Telegram bot account is '{fingerprint.Id}'.";
                        return ValidationState.Authorized;
                    }

                    case HttpStatusCode.Forbidden:
                    case HttpStatusCode.Unauthorized:
                    {
                        return ValidationState.Unauthorized;
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e);
            }
        }

        internal class Result
        {
            [JsonProperty("username")]
            public string Username { get; set; }

            [JsonProperty("can_join_groups")]
            public bool CanJoinGroups { get; set; }

            [JsonProperty("can_read_all_group_messages")]
            public bool CanReadAllGroupMessages { get; set; }

            [JsonProperty("supports_inline_queries")]
            public bool SupportsInlineQueries { get; set; }
        }

        internal class ResultRoot
        {
            [JsonProperty("ok")]
            public bool Ok { get; set; }

            [JsonProperty("result")]
            public Result Result { get; set; }
        }
    }
}
