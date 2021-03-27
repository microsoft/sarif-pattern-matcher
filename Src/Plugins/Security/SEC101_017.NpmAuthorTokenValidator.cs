// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class NpmAuthorTokenValidator : ValidatorBase
    {
        internal static NpmAuthorTokenValidator Instance;

        static NpmAuthorTokenValidator()
        {
            Instance = new NpmAuthorTokenValidator();
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
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

        public static ValidationState IsValidDynamic(ref string fingerprint, ref string message, ref Dictionary<string, string> options)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue("key", out string key))
            {
                return ValidationState.NoMatch;
            }

            fingerprintText = new Fingerprint
            {
                Key = key,
                Platform = nameof(AssetPlatform.Npm),
            }.ToString();

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message,
                                                       ref Dictionary<string, string> options)
        {
            var fingerprint = new Fingerprint(fingerprintText);

            string key = fingerprint.Key;

            try
            {
                using HttpClient client = CreateHttpClient();

                client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", key);

                using HttpResponseMessage response = client
                    .GetAsync($"https://registry.npmjs.com/-/npm/v1/tokens", HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return CheckInformation(response.Content.ReadAsStringAsync().GetAwaiter().GetResult(), key, ref message);
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

        private static ValidationState CheckInformation(string content, string key, ref string message)
        {
            TokensRoot tokensRoot = JsonConvert.DeserializeObject<TokensRoot>(content);
            if (tokensRoot?.Tokens?.Count > 0)
            {
                foreach (Object obj in tokensRoot.Tokens)
                {
                    if (!key.Contains(obj.Token))
                    {
                        continue;
                    }

                    if (obj.Readonly)
                    {
                        message = "The token has 'read' permissions.";
                        return ValidationState.AuthorizedWarning;
                    }

                    if (obj.Automation)
                    {
                        message = "The token has 'automation' permissions.";
                        return ValidationState.AuthorizedError;
                    }

                    message = "The token has 'publish' permissions.";
                    return ValidationState.AuthorizedError;
                }
            }

            return ValidationState.AuthorizedError;
        }

        private class Object
        {
            [JsonProperty("token")]
            public string Token { get; set; }

            [JsonProperty("key")]
            public string Key { get; set; }

            [JsonProperty("cidr_whitelist")]
            public object CidrWhitelist { get; set; }

            [JsonProperty("readonly")]
            public bool Readonly { get; set; }

            [JsonProperty("automation")]
            public bool Automation { get; set; }

            [JsonProperty("created")]
            public DateTime Created { get; set; }

            [JsonProperty("updated")]
            public DateTime Updated { get; set; }
        }

        private class TokensRoot
        {
            [JsonProperty("objects")]
            public List<Object> Tokens { get; set; }

            [JsonProperty("total")]
            public int Total { get; set; }
        }
    }
}
