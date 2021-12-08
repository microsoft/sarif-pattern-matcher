// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SlackApiKeyValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch secret = groups["secret"];

            // It is highly likely we do not have a key if we can't
            // find at least one letter and digit within the pattern.
            if (!ContainsDigitAndChar(secret.Value))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Slack),
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
            const string uri = "https://slack.com/api/auth.test";

            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();
                var dict = new Dictionary<string, string>
                {
                    { "token", fingerprint.Secret },
                };

                using var request = new HttpRequestMessage(HttpMethod.Post, uri);
                request.Content = new FormUrlEncodedContent(dict);

                using HttpResponseMessage response = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                if (response.StatusCode != HttpStatusCode.OK)
                {
                    return ReturnUnexpectedResponseCode(ref message, response.StatusCode);
                }

                string content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                AuthTestResponse authResponse = JsonSerializer.Deserialize<AuthTestResponse>(content);

                switch (authResponse.Error)
                {
                    case "token_revoked":
                    case "account_inactive": { return ValidationState.Expired; }
                    case "invalid_auth": { return ValidationState.Unauthorized; }
                }

                if (!string.IsNullOrEmpty(authResponse.Error))
                {
                    message = $"An unexpected error was observed " +
                              $"attempting to validate the token: '{authResponse.Error}'";
                    return ValidationState.Unknown;
                }

                message = BuildAuthTestResponseMessage(authResponse);
                return ValidationState.Authorized;
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e);
            }
        }

        private static string BuildAuthTestResponseMessage(AuthTestResponse response)
        {
            string tokenLabel = GetTokenLabel(response);

            string isEnterprise = response.IsEnterpriseInstall
                ? "is"
                : "is not";

            return $"{tokenLabel} was authenticated to channel '{response.Url}', " +
                   $" team '{response.Team}' (id: {response.TeamId}), " +
                   $" user '{response.User}' (id: {response.UserId}). " +
                   $" The token {isEnterprise} associated with an enterprise installation.";
        }

        private static string GetTokenLabel(AuthTestResponse response)
        {
            if (!string.IsNullOrEmpty(response.BotId))
            {
                return $"Bot token (id: {response.BotId})";
            }

            return "Token";
        }

        private class AuthTestResponse
        {
            [JsonPropertyName("error")]
            public string Error { get; set; }

            [JsonPropertyName("team")]
            public string Team { get; set; }

            [JsonPropertyName("user")]
            public string User { get; set; }

            [JsonPropertyName("url")]
            public string Url { get; set; }

            [JsonPropertyName("team_id")]
            public string TeamId { get; set; }

            [JsonPropertyName("user_id")]
            public string UserId { get; set; }

            [JsonPropertyName("bot_id")]
            public string BotId { get; set; }

            [JsonPropertyName("is_enterprise_install")]
            public bool IsEnterpriseInstall { get; set; }
        }
    }
}
