// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SlackTokenValidator : ValidatorBase
    {
        internal static SlackTokenValidator Instance = new SlackTokenValidator();

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
                                                    ref string message,
                                                    out ResultLevelKind resultLevelKind,
                                                    out Fingerprint fingerprint)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref message,
                                 out resultLevelKind,
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
                                                               ref string message,
                                                               out ResultLevelKind resultLevelKind,
                                                               out Fingerprint fingerprint)
        {
            resultLevelKind = default;
            fingerprint = new Fingerprint
            {
                Secret = matchedPattern,
                Platform = nameof(AssetPlatform.Slack),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options)
        {
            var client = new WebClient();
            var data = new NameValueCollection();

            data["token"] = fingerprint.Secret;

            byte[] bytes = client.UploadValues("https://slack.com/api/auth.test",
                                                  "POST",
                                                  data);

            string json = Encoding.UTF8.GetString(bytes);

            if (json.Contains("invalid_auth"))
            {
                return ValidationState.Unauthorized;
            }

            AuthTestResponse response = JsonSerializer.Deserialize<AuthTestResponse>(json);

            switch (response.Error)
            {
                case "token_revoked":
                case "account_inactive": { return ValidationState.Expired; }
                case "invalid_auth": { return ValidationState.Unauthorized; }
            }

            if (!string.IsNullOrEmpty(response.Error))
            {
                message = $"An unexpected error was observed " +
                          $"attempting to validate token: '{response.Error}'";
                return ValidationState.Unknown;
            }

            message = BuildAuthTestResponseMessage(response);
            return ValidationState.AuthorizedError;
        }

        private string BuildAuthTestResponseMessage(AuthTestResponse response)
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

        private string GetTokenLabel(AuthTestResponse response)
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
